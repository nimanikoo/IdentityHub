using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Logout Command
/// Revokes user's tokens and clears session
/// </summary>
public record LogoutCommand : IRequest<IActionResult>;
