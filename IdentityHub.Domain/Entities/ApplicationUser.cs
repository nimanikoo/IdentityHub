using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Domain.Entities;

public class ApplicationUser : IdentityUser<Guid>
{
    public string? OtpCode { get; set; }
    public DateTime? OtpExpiration { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
}