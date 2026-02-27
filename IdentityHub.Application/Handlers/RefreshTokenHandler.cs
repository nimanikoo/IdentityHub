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

public class RefreshTokenHandler : IRequestHandler<RefreshTokenCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<RefreshTokenHandler> _logger;

    public RefreshTokenHandler(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IHttpContextAccessor httpContextAccessor,
        ILogger<RefreshTokenHandler> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(RefreshTokenCommand request, CancellationToken ct)
    {
        try
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                return OAuthError("Invalid request context.");
            }

            // Authenticate using the refresh token
            var authenticate = await httpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            if (!authenticate.Succeeded)
            {
                return OAuthError("The refresh token is no longer valid.");
            }

            var principal = authenticate.Principal;

            // Get user from principal
            var user = await _userManager.GetUserAsync(principal);
            if (user == null)
            {
                return OAuthError("User not found.");
            }

            // Check if user is active
            if (!user.IsActive)
            {
                return OAuthError("Account is disabled.");
            }

            // Create new principal with fresh claims
            var newPrincipal = await _signInManager.CreateUserPrincipalAsync(user);

            // Preserve requested scopes
            var scopes = principal.GetScopes();
            if (scopes.Any())
            {
                newPrincipal.SetScopes(scopes);
            }
            else
            {
                // Default scopes if none specified
                newPrincipal.SetScopes("openid", "profile", "email");
            }

            _logger.LogInformation($"Token refreshed for user: {user.UserName}");

            return new SignInResult(newPrincipal);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh error");
            return OAuthError("An unexpected error occurred during token refresh.");
        }
    }

    private IActionResult OAuthError(string msg)
    {
        var props = new AuthenticationProperties(new Dictionary<string, string?>
        {
            ["error"] = OpenIddictConstants.Errors.InvalidGrant,
            ["error_description"] = msg
        });

        return new ForbidResult(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, props);
    }
}