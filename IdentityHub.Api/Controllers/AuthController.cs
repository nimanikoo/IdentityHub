using Microsoft.AspNetCore.Mvc;
using MediatR;
using IdentityHub.Application.Requests.Command;
using Microsoft.AspNetCore.Authorization;

namespace IdentityHub.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;

    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }
    
    [HttpPost("login/password")]
    public async Task<IActionResult> Login([FromBody] LoginWithPasswordCommand command)
    {
        var result = await _mediator.Send(command);
        return Ok(result);
    }

    [HttpPost("login/otp")]
    public async Task<IActionResult> LoginOtp([FromBody] LoginWithOtpCommand command)
    {
        var result = await _mediator.Send(command);
        return Ok(result);
    }
    
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst("user_name")?.Value 
                     ?? User.FindFirst("sub")?.Value;

        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        var result = await _mediator.Send(new LogoutCommand(userId));

        if (!result.Succeeded)
            return BadRequest(result);

        return Ok(result);
    }
    
}