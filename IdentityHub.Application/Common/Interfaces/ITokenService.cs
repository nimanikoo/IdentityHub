using IdentityHub.Application.Common.Models;
using IdentityHub.Application.DTOs;
using IdentityHub.Domain.Entities;

namespace IdentityHub.Application.Common.Interfaces;

public interface ITokenService
{
    Task<AuthResponse> GenerateTokensAsync(ApplicationUser user);
    Task<Result<AuthResponse>> RefreshTokenAsync(string token, string refreshToken);
}