namespace IdentityHub.Application.DTOs;

public record UserDto
{
    public Guid Id { get; set; }
    public string? FullName { get; set; }
    public bool IsActive { get; set; }
}