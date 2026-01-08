using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Application.Common.Models;
using IdentityHub.Application.DTOs;
using IdentityHub.Domain.Entities;
using IdentityHub.Infrastructure.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IdentityHub.Infrastructure.Services;

public class TokenService : ITokenService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly JwtSettings _jwtSettings;

    public TokenService(UserManager<ApplicationUser> userManager, IOptions<JwtSettings> jwtOptions)
    {
        _userManager = userManager;
        _jwtSettings = jwtOptions.Value;
    }

    public async Task<AuthResponse> GenerateTokensAsync(ApplicationUser user)
    {
        var accessToken = await GenerateAccessToken(user);

        var refreshToken = GenerateRefreshToken();

        await _userManager.SetAuthenticationTokenAsync(user, "IdentityHub", "RefreshToken", refreshToken);

        return new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = _jwtSettings.AccessTokenExpirationSeconds,
            TokenType = "Bearer"
        };
    }

    public async Task<Result<AuthResponse>> RefreshTokenAsync(string token, string refreshToken)
    {
        var principal = GetPrincipalFromExpiredToken(token);
        if (principal == null)
        {
            return Result<AuthResponse>.Failure("InvalidToken", "توکن نامعتبر است.");
        }

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var user = await _userManager.FindByIdAsync(userId!);

        if (user == null)
        {
            return Result<AuthResponse>.Failure("UserNotFound", "کاربر یافت نشد.");
        }

        var savedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "IdentityHub", "RefreshToken");

        if (savedRefreshToken != refreshToken)
        {
            return Result<AuthResponse>.Failure("InvalidRefreshToken", "رفرش توکن نامعتبر است.");
        }
        
        var newToken = await GenerateTokensAsync(user); 
        return Result<AuthResponse>.Success(newToken);
    }
    
    private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret)),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || 
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principal;
        }
        catch
        {
            return null;
        }
    }
    
    private async Task<string> GenerateAccessToken(ApplicationUser user)
    {
        var userRoles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new("sub", user.Id.ToString()),
            new("jti", Guid.NewGuid().ToString()),
            new("user_id", user.Id.ToString()),
            new("user_name", user.UserName!),
            new("phone_number", user.PhoneNumber ?? ""),
            new("security_stamp", user.SecurityStamp ?? "") 
        };

        foreach (var role in userRoles)
        {
            claims.Add(new Claim(role, role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(_jwtSettings.AccessTokenExpirationSeconds),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}