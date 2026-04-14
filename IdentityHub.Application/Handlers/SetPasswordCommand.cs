using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Handlers;

public record SetPasswordCommand(string Email, string Token, string NewPassword) : IRequest<IActionResult>;

public class SetPasswordHandler : IRequestHandler<SetPasswordCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public SetPasswordHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<IActionResult> Handle(SetPasswordCommand cmd, CancellationToken ct)
    {
        var user = await _userManager.FindByEmailAsync(cmd.Email);
        if (user == null)
            return new BadRequestObjectResult("User not found.");

        var result = await _userManager.ResetPasswordAsync(user, cmd.Token, cmd.NewPassword);

        if (!result.Succeeded)
            return new BadRequestObjectResult(result.Errors);

        return new OkObjectResult("Password updated successfully.");
    }
}