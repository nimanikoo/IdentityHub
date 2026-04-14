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

public class LoginWithLdapHandler : IRequestHandler<LoginWithLdapCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILdapService _ldapService;
    private readonly ISecurityAuditService _auditService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<LoginWithLdapHandler> _logger;

    public LoginWithLdapHandler(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILdapService ldapService,
        ISecurityAuditService auditService,
        IHttpContextAccessor httpContextAccessor,
        ILogger<LoginWithLdapHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _ldapService = ldapService;
        _auditService = auditService;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(LoginWithLdapCommand request, CancellationToken ct)
    {
        try
        {
            var ipAddress = GetClientIpAddress();
            var userAgent = GetUserAgent();

            // Validate LDAP credentials
            var ldapValid = await _ldapService.ValidateCredentialsAsync(request.Username, request.Password, ct);
            if (!ldapValid)
            {
                await _auditService.LogLoginAttemptAsync(request.Username, false, ipAddress, userAgent, ct);
                return OAuthError("Invalid LDAP credentials.");
            }

            // Get user info from LDAP
            var ldapUserInfo = await _ldapService.GetUserInfoAsync(request.Username, ct);
            if (ldapUserInfo == null)
            {
                await _auditService.LogLoginAttemptAsync(request.Username, false, ipAddress, userAgent, ct);
                return OAuthError("Failed to retrieve user information from LDAP.");
            }

            // Check if user exists in database
            var user = await _userManager.FindByNameAsync(request.Username);

            if (user == null)
            {
                // Create new user from LDAP
                user = new ApplicationUser
                {
                    UserName = ldapUserInfo.Username,
                    Email = ldapUserInfo.Email,
                    FirstName = ldapUserInfo.FirstName,
                    LastName = ldapUserInfo.LastName,
                    LdapId = ldapUserInfo.LdapId,
                    IsLdapUser = true,
                    EmailConfirmed = true, // LDAP validated
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user);
                if (!result.Succeeded)
                {
                    await _auditService.LogLoginAttemptAsync(request.Username, false, ipAddress, userAgent, ct);
                    _logger.LogError($"Failed to create LDAP user: {request.Username}");
                    return OAuthError("Failed to provision user account.");
                }

                _logger.LogInformation($"New LDAP user created: {user.UserName}");
            }
            else
            {
                // Update existing user with latest LDAP info
                user.Email = ldapUserInfo.Email;
                user.FirstName = ldapUserInfo.FirstName;
                user.LastName = ldapUserInfo.LastName;
                user.UpdatedAt = DateTime.UtcNow;
                
                await _userManager.UpdateAsync(user);
            }

            // Check if user is active
            if (!user.IsActive)
            {
                await _auditService.LogLoginAttemptAsync(user.Id.ToString(), false, ipAddress, userAgent, ct);
                return OAuthError("Account is disabled.");
            }

            // Update last login time
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Log successful login
            await _auditService.LogLoginAttemptAsync(user.Id.ToString(), true, ipAddress, userAgent, ct);

            // Create principal with claims
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            principal.SetScopes("openid", "profile", "email");

            _logger.LogInformation($"LDAP user logged in successfully: {user.UserName}");

            return new SignInResult(principal);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LDAP login error");
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
