using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore;
using MediatR;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using IdentityHub.Application.Features.Auth.Commands;
using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthorizationController : ControllerBase
{
    private readonly IMediator _mediator;

    public AuthorizationController(IMediator mediator, SignInManager<IdentityUser> signInManager)
    {
        _mediator = mediator;
    }
    
    [HttpPost("/connect/token")]
    [IgnoreAntiforgeryToken] // برای درخواست‌های سرویس‌به‌سرویس
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest();
        if (request == null) return BadRequest("The OpenID Connect request cannot be retrieved.");

        var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

        var command = new ExchangeTokenCommand(request, principal);
        var result = await _mediator.Send(command);

        if (!result.Succeeded)
        {
            return Forbid(new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = result.Error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = result.ErrorDescription
            }), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return SignIn(result.Data, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("/connect/logout")]
    public IActionResult Logout()
    {
        return SignOut(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}