using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Login with Password Command
/// Authenticates user with username and password
/// </summary>
public record LoginWithPasswordCommand(
    string Username,
    string Password
) : IRequest<IActionResult>;
