using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Domain.Entities;

public class ApplicationUser : IdentityUser<Guid>
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
    public bool IsActive { get; set; } = true;
    
    // OTP Management
    public string? OtpCode { get; set; }
    public DateTime? OtpExpiration { get; set; }
    public int OtpAttempts { get; set; } = 0;
    
    // LDAP Management
    public string? LdapId { get; set; }
    public bool IsLdapUser { get; set; } = false;
    
    // Security
    public DateTime? LastLoginAt { get; set; }
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LastPasswordChangeAt { get; set; }
    public bool RequirePasswordChange { get; set; } = false;
    
    // Account Status
    public DateTime? EmailConfirmedAt { get; set; }
}