using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using SignInResult = Microsoft.AspNetCore.Mvc.SignInResult;

namespace IdentityHub.Application.Handlers;

public class VerifyOtpHandler : IRequestHandler<VerifyOtpCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOtpService _otpService;
    private readonly ISecurityAuditService _auditService;
    private readonly ILogger<VerifyOtpHandler> _logger;

    public VerifyOtpHandler(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IOtpService otpService,
        ISecurityAuditService auditService,
        ILogger<VerifyOtpHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _otpService = otpService;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(VerifyOtpCommand request, CancellationToken ct)
    {
        try
        {
            // Find user
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                await _auditService.LogOtpAttemptAsync("unknown", false, ct);
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Invalid credentials")
                );
            }

            // Check if user is active
            if (!user.IsActive)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Account is disabled.")
                );
            }

            // Check if OTP is expired
            var isExpired = await _otpService.IsOtpExpiredAsync(user);
            if (isExpired)
            {
                await _auditService.LogOtpAttemptAsync(user.Id.ToString(), false, ct);
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("OTP has expired. Please request a new one.")
                );
            }

            // Verify OTP
            var otpValid = await _otpService.VerifyOtpAsync(user, request.OtpCode, ct);
            if (!otpValid)
            {
                await _userManager.UpdateAsync(user);
                await _auditService.LogOtpAttemptAsync(user.Id.ToString(), false, ct);
                
                _logger.LogWarning($"Invalid OTP attempt for user: {user.UserName}");
                
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Invalid OTP or too many attempts")
                );
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log successful OTP verification
            await _auditService.LogOtpAttemptAsync(user.Id.ToString(), true, ct);

            // Create principal with claims
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            principal.SetScopes("openid", "profile", "email");

            _logger.LogInformation($"OTP verified successfully for user: {user.UserName}");

            return new SignInResult(principal);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "OTP verification error");
            return new BadRequestObjectResult(
                ApiResponse<object>.ErrorResponse("An unexpected error occurred")
            );
        }
    }
}
