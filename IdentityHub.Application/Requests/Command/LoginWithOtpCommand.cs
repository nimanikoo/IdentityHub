using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Login with OTP Command
/// Combines OTP send and verify in single flow
/// </summary>
public record LoginWithOtpCommand(
    string Username,
    string? OtpCode = null
) : IRequest<IActionResult>;
