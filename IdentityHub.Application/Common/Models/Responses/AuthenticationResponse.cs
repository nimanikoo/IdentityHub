namespace IdentityHub.Application.Common.Models.Responses;

public class AuthenticationResponse
{
    public bool Success { get; set; }
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? Message { get; set; }
    public List<string>? Errors { get; set; }
}
