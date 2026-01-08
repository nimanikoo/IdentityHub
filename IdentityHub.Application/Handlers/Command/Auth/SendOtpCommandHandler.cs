using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Application.Common.Models;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Application.Handlers.Command.Auth;

public record SendOtpCommand(string PhoneNumber) : IRequest<Result<string>>;

public class SendOtpHandler : IRequestHandler<SendOtpCommand, Result<string>>
{
    private readonly IOtpService _otpService;
    private readonly UserManager<ApplicationUser> _userManager;

    public SendOtpHandler(IOtpService otpService, UserManager<ApplicationUser> userManager)
    {
        _otpService = otpService;
        _userManager = userManager;
    }

    public async Task<Result<string>> Handle(SendOtpCommand request, CancellationToken cancellationToken)
    {
        var user = _userManager.Users.FirstOrDefault(u => u.PhoneNumber == request.PhoneNumber);
        if (user == null)
            return Result<string>.Failure("UserNotFound", "کاربری با این شماره یافت نشد.");

        var code = await _otpService.GenerateOtpAsync(user.Id.ToString(), request.PhoneNumber);
        
        return Result<string>.Success("کد تایید ارسال شد (کنسول را چک کنید).");
    }
}