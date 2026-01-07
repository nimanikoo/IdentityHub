using IdentityHub.Application.DTOs;
using IdentityHub.Domain.Entities;

namespace IdentityHub.Application.Mappings;

public static class UserMappingExtensions
{
    public static UserDto ToDto(this ApplicationUser user)
    {
        return new UserDto
        {
            Id = user.Id,
            FullName = $"{user.FirstName} {user.LastName}",
            IsActive = user.IsActive
        };
    }
}