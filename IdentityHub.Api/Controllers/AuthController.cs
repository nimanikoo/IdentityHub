using IdentityHub.Application.Requests.Command;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Api.Controllers;

/// <summary>
/// Authentication Controller
/// Provides endpoints for user authentication flows
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IMediator mediator, ILogger<AuthController> logger)
    {
        _mediator = mediator;
        _logger = logger;
    }

    /// <summary>
    /// Register a new user account
    /// POST: api/auth/register
    /// </summary>
    [HttpPost("register")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"Register request for user: {command.Username}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Login with username and password
    /// POST: api/auth/login
    /// </summary>
    [HttpPost("login")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginWithPasswordCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"Login request for user: {command.Username}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Send OTP to user's email
    /// POST: api/auth/send-otp
    /// </summary>
    [HttpPost("send-otp")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> SendOtp([FromBody] SendOtpCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"Send OTP request for user: {command.Username}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Verify OTP and complete login
    /// POST: api/auth/verify-otp
    /// </summary>
    [HttpPost("verify-otp")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"Verify OTP request for user: {command.Username}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Login with OTP (request OTP)
    /// POST: api/auth/login-with-otp
    /// </summary>
    [HttpPost("login-with-otp")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> LoginWithOtp([FromBody] LoginWithOtpCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"Login with OTP request for user: {command.Username}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Login with LDAP/Active Directory credentials
    /// POST: api/auth/login-ldap
    /// </summary>
    [HttpPost("login-ldap")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> LoginWithLdap([FromBody] LoginWithLdapCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"LDAP login request for user: {command.Username}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Change password (requires authentication)
    /// POST: api/auth/change-password
    /// </summary>
    [HttpPost("change-password")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Change password request");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Request password reset (forgot password)
    /// POST: api/auth/forgot-password
    /// </summary>
    [HttpPost("forgot-password")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"Forgot password request for email: {command.Email}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Reset password using token
    /// POST: api/auth/reset-password
    /// </summary>
    [HttpPost("reset-password")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation($"Reset password request for email: {command.Email}");
        return await _mediator.Send(command, cancellationToken);
    }

    /// <summary>
    /// Logout user
    /// POST: api/auth/logout
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Logout request");
        return await _mediator.Send(new LogoutCommand(), cancellationToken);
    }

    /// <summary>
    /// Refresh access token
    /// POST: api/auth/refresh-token
    /// </summary>
    [HttpPost("refresh-token")]
    [AllowAnonymous]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenCommand command, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Refresh token request");
        return await _mediator.Send(command, cancellationToken);
    }
}