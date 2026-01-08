using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Application.Common.Models;
using IdentityHub.Application.DTOs;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;

namespace IdentityHub.Application.Handlers.Command.Auth;

public class LoginWithOtpCommandHandler : IRequestHandler<LoginWithOtpCommand, Result<AuthResponse>>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOtpService _otpService;
    private readonly ITokenService _tokenService;

    public LoginWithOtpCommandHandler(UserManager<ApplicationUser> userManager, IOtpService otpService,
        ITokenService tokenService)
    {
        _userManager = userManager;
        _otpService = otpService;
        _tokenService = tokenService;
    }

    public async Task<Result<AuthResponse>> Handle(LoginWithOtpCommand request, CancellationToken cancellationToken)
    {
        var user = _userManager.Users.FirstOrDefault(u => u.PhoneNumber == request.PhoneNumber);
        if (user == null)
            throw new Exception("کاربری با این شماره یافت نشد.");

        var isOtpValid = await _otpService.ValidateOtpAsync(request.PhoneNumber, request.OtpCode);
        if (!isOtpValid)
            return Result<AuthResponse>.Failure("InvalidCredentials", "نام کاربری یا رمز عبور اشتباه است.");

        var authResponse = await _tokenService.GenerateTokensAsync(user);

        return Result<AuthResponse>.Success(authResponse);
    }
}