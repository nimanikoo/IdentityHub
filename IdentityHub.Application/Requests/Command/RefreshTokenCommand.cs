using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Refresh Token Command
/// Refreshes access token using refresh token
/// </summary>
public record RefreshTokenCommand(
    string RefreshToken
) : IRequest<IActionResult>;
