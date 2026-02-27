using IdentityHub.Domain.Entities;

namespace IdentityHub.Application.Common.Interfaces.Services;

public interface ILdapService
{
    Task<bool> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default);
    Task<LdapUserInfo?> GetUserInfoAsync(string username, CancellationToken cancellationToken = default);
}

public class LdapUserInfo
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string? LdapId { get; set; }
}
