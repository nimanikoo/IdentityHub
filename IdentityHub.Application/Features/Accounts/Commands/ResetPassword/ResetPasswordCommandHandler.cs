using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Application.Common.Models;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Application.Features.Accounts.Commands.ResetPassword;

public record ResetPasswordCommand(string PhoneNumber, string OtpCode, string NewPassword) : IRequest<Result<string>>;

public class ResetPasswordHandler : IRequestHandler<ResetPasswordCommand, Result<string>>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOtpService _otpService;

    public ResetPasswordHandler(UserManager<ApplicationUser> userManager, IOtpService otpService)
    {
        _userManager = userManager;
        _otpService = otpService;
    }

    public async Task<Result<string>> Handle(ResetPasswordCommand request, CancellationToken cancellationToken)
    {
        var isOtpValid = await _otpService.ValidateOtpAsync(request.PhoneNumber, request.OtpCode);
        if (!isOtpValid)
            return Result<string>.Failure("InvalidOtp", "کد تایید نامعتبر یا منقضی شده است.");

        var user =  _userManager.Users.FirstOrDefault(u => u.PhoneNumber == request.PhoneNumber);
        if (user == null)
            return Result<string>.Failure("UserNotFound", "کاربری با این شماره موبایل یافت نشد.");

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

        var result = await _userManager.ResetPasswordAsync(user, resetToken, request.NewPassword);

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return Result<string>.Failure("ResetFailed", errors);
        }

        await _userManager.UpdateSecurityStampAsync(user);
        return Result<string>.Success("رمز عبور با موفقیت تغییر کرد.");
    }
}