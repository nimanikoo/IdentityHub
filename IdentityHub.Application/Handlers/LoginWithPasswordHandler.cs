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

public class LoginWithPasswordHandler : IRequestHandler<LoginWithPasswordCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ISecurityAuditService _auditService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<LoginWithPasswordHandler> _logger;

    private const int MaxLoginAttempts = 5;
    private const int LockoutDurationMinutes = 15;

    public LoginWithPasswordHandler(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ISecurityAuditService auditService,
        IHttpContextAccessor httpContextAccessor,
        ILogger<LoginWithPasswordHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _auditService = auditService;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(LoginWithPasswordCommand request, CancellationToken ct)
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

            // Check if account is locked out
            if (await _userManager.IsLockedOutAsync(user))
            {
                await _auditService.LogLoginAttemptAsync(user.Id.ToString(), false, ipAddress, userAgent, ct);
                return OAuthError("Account is temporarily locked. Please try again later.");
            }

            // Verify password
            var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!passwordValid)
            {
                // Increment failed login attempts
                user.FailedLoginAttempts++;
                
                // Lock account if max attempts exceeded
                if (user.FailedLoginAttempts >= MaxLoginAttempts)
                {
                    await _userManager.SetLockoutEnabledAsync(user, true);
                    await _userManager.SetLockoutEndDateAsync(user, DateTime.UtcNow.AddMinutes(LockoutDurationMinutes));
                }

                await _userManager.UpdateAsync(user);
                await _auditService.LogLoginAttemptAsync(user.Id.ToString(), false, ipAddress, userAgent, ct);

                _logger.LogWarning($"Failed login attempt for user: {user.UserName}. Attempt: {user.FailedLoginAttempts}");
                
                return OAuthError("Invalid credentials.");
            }

            // Reset failed attempts on successful login
            if (user.FailedLoginAttempts > 0)
            {
                user.FailedLoginAttempts = 0;
                await _userManager.UpdateAsync(user);
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log successful login
            await _auditService.LogLoginAttemptAsync(user.Id.ToString(), true, ipAddress, userAgent, ct);

            // Create principal with claims
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            principal.SetScopes("openid", "profile", "email");

            _logger.LogInformation($"User logged in successfully: {user.UserName}");

            return new SignInResult(principal);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error");
            return OAuthError("An unexpected error occurred during login.");
        }
    }

    private IActionResult OAuthError(string msg)
    {
        var props = new AuthenticationProperties(new Dictionary<string, string?>
        {
            ["error"] = "invalid_grant",
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
