using System.Security.Claims;
using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Application.Common.Models;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;

namespace IdentityHub.Application.Features.Auth.Commands;

public record ExchangeTokenCommand(
    OpenIddictRequest Request,
    ClaimsPrincipal? Principal = null) : IRequest<Result<ClaimsPrincipal>>;

public class ExchangeTokenHandler : IRequestHandler<ExchangeTokenCommand, Result<ClaimsPrincipal>>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOtpService _otpService;

    public ExchangeTokenHandler(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IOtpService otpService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _otpService = otpService;
    }

    public async Task<Result<ClaimsPrincipal>> Handle(ExchangeTokenCommand command, CancellationToken cancellationToken)
    {
        var request = command.Request;

        if (request.IsPasswordGrantType())
            return await HandlePasswordGrantAsync(request);

        if (request.GrantType == "otp")
            return await HandleOtpGrantAsync(request);

        if (request.IsRefreshTokenGrantType())
            return await HandleRefreshTokenGrantAsync(command.Principal);

        return Result<ClaimsPrincipal>.Failure("unsupported_grant_type", "نوع احراز هویت پشتیبانی نمی‌شود.");
    }
    
    private async Task<Result<ClaimsPrincipal>> HandlePasswordGrantAsync(OpenIddictRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username ?? string.Empty);

        if (user == null)
            return Result<ClaimsPrincipal>.Failure("invalid_grant", "نام کاربری یا رمز عبور اشتباه است.");

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password!, lockoutOnFailure: true);

        if (result.IsLockedOut)
            return Result<ClaimsPrincipal>.Failure("invalid_grant", "حساب کاربری موقتاً مسدود شده است.");

        if (!result.Succeeded)
            return Result<ClaimsPrincipal>.Failure("invalid_grant", "نام کاربری یا رمز عبور اشتباه است.");

        return Result<ClaimsPrincipal>.Success(await CreateClaimsPrincipalAsync(user, request.GetScopes()));
    }

    private async Task<Result<ClaimsPrincipal>> HandleOtpGrantAsync(OpenIddictRequest request)
    {
        var phoneNumber = request.GetParameter("phone_number")?.ToString();
        var code = request.GetParameter("otp_code")?.ToString();

        if (string.IsNullOrWhiteSpace(phoneNumber) || string.IsNullOrWhiteSpace(code))
            return Result<ClaimsPrincipal>.Failure("invalid_request", "شماره موبایل و کد تایید الزامی است.");

        var isValid = await _otpService.ValidateOtpAsync(phoneNumber, code);
        if (!isValid)
            return Result<ClaimsPrincipal>.Failure("invalid_grant", "کد تایید نامعتبر یا منقضی شده است.");

        var user = _userManager.Users.FirstOrDefault(u => u.PhoneNumber == phoneNumber);
        if (user == null)
            return Result<ClaimsPrincipal>.Failure("invalid_grant", "کاربری با این شماره موبایل یافت نشد.");

        return Result<ClaimsPrincipal>.Success(await CreateClaimsPrincipalAsync(user, request.GetScopes()));
    }

    private async Task<Result<ClaimsPrincipal>> HandleRefreshTokenGrantAsync(ClaimsPrincipal? principal)
    {
        if (principal == null)
            return Result<ClaimsPrincipal>.Failure("invalid_grant", "توکن رفرش نامعتبر است.");

        var user = await _userManager.GetUserAsync(principal);
        if (user == null || !await _signInManager.CanSignInAsync(user))
            return Result<ClaimsPrincipal>.Failure("invalid_grant", "کاربر دیگر فعال نیست.");

        return Result<ClaimsPrincipal>.Success(await CreateClaimsPrincipalAsync(user, principal.GetScopes()));
    }

    private async Task<ClaimsPrincipal> CreateClaimsPrincipalAsync(ApplicationUser user, IEnumerable<string> scopes)
    {
        var principal = await _signInManager.CreateUserPrincipalAsync(user);
        principal.SetScopes(scopes);

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim));
        }

        return principal;
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        return claim.Type switch
        {
            OpenIddictConstants.Claims.Name or
                OpenIddictConstants.Claims.Email or
                OpenIddictConstants.Claims.Role or
                "phone_number"
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],

            _ => [OpenIddictConstants.Destinations.AccessToken]
        };
    }
}