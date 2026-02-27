using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace IdentityHub.Application.Handlers;

public class SendOtpHandler : IRequestHandler<SendOtpCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOtpService _otpService;
    private readonly IEmailService _emailService;
    private readonly ISecurityAuditService _auditService;
    private readonly ILogger<SendOtpHandler> _logger;

    public SendOtpHandler(
        UserManager<ApplicationUser> userManager,
        IOtpService otpService,
        IEmailService emailService,
        ISecurityAuditService auditService,
        ILogger<SendOtpHandler> logger)
    {
        _userManager = userManager;
        _otpService = otpService;
        _emailService = emailService;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(SendOtpCommand request, CancellationToken ct)
    {
        try
        {
            // Find user
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                // Don't reveal if user exists
                return new OkObjectResult(
                    ApiResponse<object>.SuccessResponse(
                        new { message = "If the account exists, OTP has been sent." },
                        "OTP sent successfully"
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

            // Generate OTP
            var otp = await _otpService.GenerateOtpAsync(user, ct);

            // Save OTP to user
            var updateResult = await _userManager.UpdateAsync(user);
            if (!updateResult.Succeeded)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Failed to generate OTP")
                );
            }

            // Send OTP via email
            var emailSent = await _emailService.SendOtpEmailAsync(user.Email!, otp, ct);
            if (!emailSent)
            {
                _logger.LogWarning($"Failed to send OTP email to {user.Email}");
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Failed to send OTP. Please try again.")
                );
            }

            _logger.LogInformation($"OTP sent successfully to user: {user.UserName}");

            return new OkObjectResult(
                ApiResponse<object>.SuccessResponse(
                    new { message = "OTP sent to email" },
                    "OTP sent successfully. Check your email."
                )
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending OTP");
            return new BadRequestObjectResult(
                ApiResponse<object>.ErrorResponse("An unexpected error occurred")
            );
        }
    }
}