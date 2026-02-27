using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace IdentityHub.Application.Handlers;

public class ChangePasswordHandler : IRequestHandler<ChangePasswordCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IPasswordService _passwordService;
    private readonly ISecurityAuditService _auditService;
    private readonly IEmailService _emailService;
    private readonly ILogger<ChangePasswordHandler> _logger;

    public ChangePasswordHandler(
        UserManager<ApplicationUser> userManager,
        IHttpContextAccessor httpContextAccessor,
        IPasswordService passwordService,
        ISecurityAuditService auditService,
        IEmailService emailService,
        ILogger<ChangePasswordHandler> logger)
    {
        _userManager = userManager;
        _httpContextAccessor = httpContextAccessor;
        _passwordService = passwordService;
        _auditService = auditService;
        _emailService = emailService;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(ChangePasswordCommand request, CancellationToken ct)
    {
        try
        {
            // Get current user from context
            var userId = _httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return new UnauthorizedObjectResult(
                    ApiResponse<object>.ErrorResponse("User not authenticated")
                );
            }

            // Get user from database
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("User not found")
                );
            }

            // Validate passwords match
            if (request.NewPassword != request.ConfirmPassword)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("New passwords do not match")
                );
            }

            // Check if current password is correct
            var passwordValid = await _userManager.CheckPasswordAsync(user, request.CurrentPassword);
            if (!passwordValid)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Current password is incorrect")
                );
            }

            // Validate new password strength
            var isPasswordStrong = await _passwordService.ValidatePasswordStrengthAsync(request.NewPassword);
            if (!isPasswordStrong)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse(
                        "New password does not meet security requirements. " +
                        "Must be 12+ characters with uppercase, lowercase, digits, and special characters"
                    )
                );
            }

            // Check password reuse
            var isReused = await _passwordService.IsPasswordReusedAsync(userId, request.NewPassword);
            if (isReused)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Password has been used before. Please choose a different password.")
                );
            }

            // Change password
            var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Failed to change password", errors)
                );
            }

            // Update password change timestamp
            user.LastPasswordChangeAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log password change
            var ipAddress = GetClientIpAddress();
            await _auditService.LogPasswordChangeAsync(user.Id.ToString(), ipAddress, ct);

            // Send notification email
            await _emailService.SendEmailAsync(
                user.Email!,
                "Password Changed",
                "Your password has been successfully changed.",
                ct
            );

            _logger.LogInformation($"Password changed successfully for user: {user.UserName}");

            return new OkObjectResult(
                ApiResponse<object>.SuccessResponse(
                    new { message = "Password changed successfully" },
                    "Your password has been updated"
                )
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Password change error");
            return new BadRequestObjectResult(
                ApiResponse<object>.ErrorResponse("An unexpected error occurred")
            );
        }
    }

    private string GetClientIpAddress()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context?.Connection.RemoteIpAddress != null)
        {
            return context.Connection.RemoteIpAddress.ToString();
        }
        return "Unknown";
    }
}
