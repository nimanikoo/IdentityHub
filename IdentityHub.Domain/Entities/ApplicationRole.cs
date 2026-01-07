using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Domain.Entities;

public class ApplicationRole : IdentityRole<Guid>
{
    public string? Description { get; set; }
}