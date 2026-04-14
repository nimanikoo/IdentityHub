using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Verify OTP Command
/// Verifies OTP and returns authentication token
/// </summary>
public record VerifyOtpCommand(
    string Username,
    string OtpCode
) : IRequest<IActionResult>;
