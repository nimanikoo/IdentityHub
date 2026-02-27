using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Forgot Password Command
/// Initiates password reset flow by sending reset link to email
/// </summary>
public record ForgotPasswordCommand(
    string Email
) : IRequest<IActionResult>;
