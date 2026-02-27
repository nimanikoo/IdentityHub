using IdentityHub.Domain.Entities;

namespace IdentityHub.Application.Common.Interfaces.Services;

public interface IOtpService
{
    Task<string> GenerateOtpAsync(ApplicationUser user, CancellationToken cancellationToken = default);
    Task<bool> VerifyOtpAsync(ApplicationUser user, string otpCode, CancellationToken cancellationToken = default);
    Task<bool> SendOtpAsync(ApplicationUser user, string otp, CancellationToken cancellationToken = default);
    Task<bool> IsOtpExpiredAsync(ApplicationUser user);
}