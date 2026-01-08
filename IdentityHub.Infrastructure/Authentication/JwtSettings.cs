namespace IdentityHub.Infrastructure.Authentication;

public class JwtSettings
{
    public string Secret { get; set; } 
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public int AccessTokenExpirationSeconds { get; set; }
    public int RefreshTokenExpirationSeconds { get; set; }
}