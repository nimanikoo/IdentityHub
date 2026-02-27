using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace IdentityHub.Application.Handlers;

public class ResetPasswordHandler : IRequestHandler<ResetPasswordCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPasswordService _passwordService;
    private readonly ISecurityAuditService _auditService;
    private readonly IEmailService _emailService;
    private readonly ILogger<ResetPasswordHandler> _logger;

    public ResetPasswordHandler(
        UserManager<ApplicationUser> userManager,
        IPasswordService passwordService,
        ISecurityAuditService auditService,
        IEmailService emailService,
        ILogger<ResetPasswordHandler> logger)
    {
        _userManager = userManager;
        _passwordService = passwordService;
        _auditService = auditService;
        _emailService = emailService;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(ResetPasswordCommand request, CancellationToken ct)
    {
        try
        {
            // Validate passwords match
            if (request.NewPassword != request.ConfirmPassword)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Passwords do not match")
                );
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                // Don't reveal if user exists
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Invalid reset link or email")
                );
            }

            // Check if user is active
            if (!user.IsActive)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Account is disabled.")
                );
            }

            // Validate new password strength
            var isPasswordStrong = await _passwordService.ValidatePasswordStrengthAsync(request.NewPassword);
            if (!isPasswordStrong)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse(
                        "Password does not meet security requirements. " +
                        "Must be 12+ characters with uppercase, lowercase, digits, and special characters"
                    )
                );
            }

            // Check password reuse
            var isReused = await _passwordService.IsPasswordReusedAsync(user.Id.ToString(), request.NewPassword);
            if (isReused)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Password has been used before. Please choose a different password.")
                );
            }

            // Reset password
            var result = await _userManager.ResetPasswordAsync(user, request.ResetToken, request.NewPassword);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Failed to reset password", errors)
                );
            }

            // Update password change timestamp
            user.LastPasswordChangeAt = DateTime.UtcNow;
            user.RequirePasswordChange = false;
            await _userManager.UpdateAsync(user);

            // Log password reset
            var ipAddress = GetClientIpAddress();
            await _auditService.LogPasswordChangeAsync(user.Id.ToString(), ipAddress, ct);

            // Send confirmation email
            await _emailService.SendEmailAsync(
                user.Email!,
                "Password Reset Successful",
                "Your password has been successfully reset. You can now log in with your new password.",
                ct
            );

            _logger.LogInformation($"Password reset successfully for user: {user.Email}");

            return new OkObjectResult(
                ApiResponse<object>.SuccessResponse(
                    new { message = "Password reset successfully" },
                    "Your password has been updated"
                )
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Password reset error");
            return new BadRequestObjectResult(
                ApiResponse<object>.ErrorResponse("An unexpected error occurred")
            );
        }
    }

    private string GetClientIpAddress()
    {
        return "Unknown";
    }
}