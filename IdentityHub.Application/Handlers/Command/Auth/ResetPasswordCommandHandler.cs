using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Application.Handlers.Command.Auth;

public record ResetPasswordCommand(string PhoneNumber, string Code, string NewPassword) : IRequest<IdentityResult>;


public class ResetPasswordCommandHandler : IRequestHandler<ResetPasswordCommand, IdentityResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOtpService _otpService;

    public ResetPasswordCommandHandler(UserManager<ApplicationUser> userManager, IOtpService otpService)
    {
        _userManager = userManager;
        _otpService = otpService;
    }

    public async Task<IdentityResult> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var isValid = await _otpService.ValidateOtpAsync(request.PhoneNumber, request.Code);
        if (!isValid) return IdentityResult.Failed(new IdentityError { Description = "کد تایید معتبر نیست." });

        var user =  _userManager.Users.FirstOrDefault(u => u.PhoneNumber == request.PhoneNumber);
        if (user == null) return IdentityResult.Failed(new IdentityError { Description = "کاربر یافت نشد." });

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        return await _userManager.ResetPasswordAsync(user, token, request.NewPassword);
    }
}