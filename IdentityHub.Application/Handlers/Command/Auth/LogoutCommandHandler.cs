using IdentityHub.Application.Common.Models;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Application.Handlers.Command.Auth;

public class LogoutCommandHandler : IRequestHandler<LogoutCommand, Result<bool>>
{
    private readonly UserManager<ApplicationUser> _userManager;

    public LogoutCommandHandler(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<Result<bool>> Handle(LogoutCommand request, CancellationToken cancellationToken)
    {
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user == null) 
            return Result<bool>.Failure("UserNotFound", "کاربر یافت نشد.");

        var result = await _userManager.RemoveAuthenticationTokenAsync(user, "IdentityHub", "RefreshToken");

        if (!result.Succeeded)
        {
            return Result<bool>.Failure("LogoutFailed", "خطا در خروج از حساب کاربری.");
        }

        await _userManager.UpdateSecurityStampAsync(user);

        return Result<bool>.Success(true);
    }
}