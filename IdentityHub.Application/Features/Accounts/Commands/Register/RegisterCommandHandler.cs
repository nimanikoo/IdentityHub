using IdentityHub.Application.Common.Models;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Application.Features.Accounts.Commands.Register;

public record RegisterCommand(string Username, string Password, string PhoneNumber, string Email) : IRequest<Result<string>>;


public class RegisterHandler : IRequestHandler<RegisterCommand, Result<string>>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public RegisterHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<Result<string>> Handle(RegisterCommand request, CancellationToken cancellationToken)
    {
        if ( _userManager.Users.Any(u => u.UserName == request.Username))
            return Result<string>.Failure("DuplicateUser", "این نام کاربری قبلاً گرفته شده است.");

        var user = new ApplicationUser
        {
            UserName = request.Username,
            Email = request.Email,
            PhoneNumber = request.PhoneNumber,
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return Result<string>.Failure("RegistrationFailed", errors);
        }

        await _userManager.AddToRoleAsync(user, "User");
        return Result<string>.Success(user.Id.ToString());
    }
}