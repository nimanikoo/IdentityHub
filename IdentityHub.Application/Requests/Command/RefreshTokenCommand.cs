using IdentityHub.Application.Common.Models;
using IdentityHub.Application.DTOs;
using MediatR;

namespace IdentityHub.Application.Requests.Command;

public record RefreshTokenCommand(string AccessToken, string RefreshToken) : IRequest<Result<AuthResponse>>;
