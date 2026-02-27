using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace IdentityHub.Application.Handlers;

public class ForgotPasswordHandler : IRequestHandler<ForgotPasswordCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly ISecurityAuditService _auditService;
    private readonly ILogger<ForgotPasswordHandler> _logger;
    private readonly IConfiguration _configuration;

    public ForgotPasswordHandler(
        UserManager<ApplicationUser> userManager,
        IEmailService emailService,
        ISecurityAuditService auditService,
        ILogger<ForgotPasswordHandler> logger,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _emailService = emailService;
        _auditService = auditService;
        _logger = logger;
        _configuration = configuration;
    }

    public async Task<IActionResult> Handle(ForgotPasswordCommand request, CancellationToken ct)
    {
        try
        {
            // Find user by email
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                // Don't reveal if email exists
                return new OkObjectResult(
                    ApiResponse<object>.SuccessResponse(
                        new { message = "If the email exists, a password reset link has been sent." },
                        "Email sent"
                    )
                );
            }

            // Check if user is active
            if (!user.IsActive)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Account is disabled.")
                );
            }

            // Generate password reset token
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Create reset link (adjust the URL based on your frontend)
            var appUrl = _configuration["AppSettings:AppUrl"] ?? "http://localhost:3000";
            var resetLink = $"{appUrl}/reset-password?email={Uri.EscapeDataString(user.Email!)}&token={Uri.EscapeDataString(resetToken)}";

            // Send password reset email
            var emailSent = await _emailService.SendPasswordResetEmailAsync(user.Email!, resetLink, ct);
            if (!emailSent)
            {
                _logger.LogWarning($"Failed to send password reset email to {user.Email}");
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Failed to send reset email. Please try again.")
                );
            }

            _logger.LogInformation($"Password reset email sent to: {user.Email}");

            // Don't reveal if user exists
            return new OkObjectResult(
                ApiResponse<object>.SuccessResponse(
                    new { message = "If the email exists, a password reset link has been sent." },
                    "Email sent"
                )
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Forgot password error");
            return new BadRequestObjectResult(
                ApiResponse<object>.ErrorResponse("An unexpected error occurred")
            );
        }
    }
}
