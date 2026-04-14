using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using SignInResult = Microsoft.AspNetCore.Mvc.SignInResult;

namespace IdentityHub.Application.Handlers;

public class LoginWithOtpHandler : IRequestHandler<LoginWithOtpCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOtpService _otpService;
    private readonly ISecurityAuditService _auditService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<LoginWithOtpHandler> _logger;

    public LoginWithOtpHandler(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IOtpService otpService,
        ISecurityAuditService auditService,
        IHttpContextAccessor httpContextAccessor,
        ILogger<LoginWithOtpHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _otpService = otpService;
        _auditService = auditService;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(LoginWithOtpCommand request, CancellationToken ct)
    {
        try
        {
            var ipAddress = GetClientIpAddress();
            var userAgent = GetUserAgent();

            // Find user
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user == null)
            {
                await _auditService.LogLoginAttemptAsync(request.Username, false, ipAddress, userAgent, ct);
                return OAuthError("Invalid credentials.");
            }

            // Check if user is active
            if (!user.IsActive)
            {
                await _auditService.LogLoginAttemptAsync(user.Id.ToString(), false, ipAddress, userAgent, ct);
                return OAuthError("Account is disabled.");
            }

            // Check if OTP is expired
            var isExpired = await _otpService.IsOtpExpiredAsync(user);
            if (isExpired)
            {
                await _auditService.LogLoginAttemptAsync(user.Id.ToString(), false, ipAddress, userAgent, ct);
                return OAuthError("OTP has expired. Please request a new one.");
            }

            // Verify OTP
            var otpValid = await _otpService.VerifyOtpAsync(user, request.OtpCode, ct);
            if (!otpValid)
            {
                await _userManager.UpdateAsync(user);
                await _auditService.LogLoginAttemptAsync(user.Id.ToString(), false, ipAddress, userAgent, ct);
                return OAuthError("Invalid OTP or too many attempts.");
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log successful login
            await _auditService.LogLoginAttemptAsync(user.Id.ToString(), true, ipAddress, userAgent, ct);

            // Create principal with claims
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            principal.SetScopes("openid", "profile", "email");

            _logger.LogInformation($"User logged in via OTP: {user.UserName}");

            return new SignInResult(principal);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "OTP login error");
            return OAuthError("An unexpected error occurred during login.");
        }
    }

    private IActionResult OAuthError(string msg)
    {
        var props = new AuthenticationProperties(new Dictionary<string, string?>
        {
            ["error"] = OpenIddictConstants.Errors.InvalidGrant,
            ["error_description"] = msg
        });
        return new ForbidResult(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, props);
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

    private string GetUserAgent()
    {
        var context = _httpContextAccessor.HttpContext;
        return context?.Request.Headers["User-Agent"].ToString() ?? "Unknown";
    }
}