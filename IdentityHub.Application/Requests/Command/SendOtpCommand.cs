using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Send OTP Command
/// Generates and sends OTP to user's email
/// </summary>
public record SendOtpCommand(
    string Username
) : IRequest<IActionResult>;
