using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Domain.Entities;

namespace IdentityHub.Infrastructure.Services;

/// <summary>
/// OTP Service Implementation
/// Generates, stores, and validates One-Time Passwords for secure authentication
/// </summary>
public class OtpService : IOtpService
{
    private const int OtpLength = 6;
    private const int OtpExpirationMinutes = 5;
    private const int MaxOtpAttempts = 5;

    public async Task<string> GenerateOtpAsync(ApplicationUser user, CancellationToken cancellationToken = default)
    {
        // Generate random 6-digit OTP
        var otp = GenerateRandomOtp();
        
        // Set OTP on user
        user.OtpCode = otp;
        user.OtpExpiration = DateTime.UtcNow.AddMinutes(OtpExpirationMinutes);
        user.OtpAttempts = 0; // Reset attempts counter
        
        return await Task.FromResult(otp);
    }

    public async Task<bool> VerifyOtpAsync(ApplicationUser user, string otpCode, CancellationToken cancellationToken = default)
    {
        // Check if OTP is expired
        if (await IsOtpExpiredAsync(user))
        {
            return false;
        }

        // Check if max attempts exceeded
        if (user.OtpAttempts >= MaxOtpAttempts)
        {
            return false;
        }

        // Increment attempts
        user.OtpAttempts++;

        // Verify OTP code
        if (!user.OtpCode!.Equals(otpCode, StringComparison.Ordinal))
        {
            return false;
        }

        // Clear OTP on successful verification
        user.OtpCode = null;
        user.OtpExpiration = null;
        user.OtpAttempts = 0;

        return true;
    }

    public async Task<bool> SendOtpAsync(ApplicationUser user, string otp, CancellationToken cancellationToken = default)
    {
        // In production, implement actual OTP delivery
        // This could be: Email, SMS via Twilio, Firebase, etc.
        // For now, logging to console for development
        Console.WriteLine($"[OTP Service] Sending OTP {otp} to {user.Email}");
        return await Task.FromResult(true);
    }

    public async Task<bool> IsOtpExpiredAsync(ApplicationUser user)
    {
        if (user.OtpExpiration == null)
        {
            return true;
        }

        return await Task.FromResult(DateTime.UtcNow > user.OtpExpiration);
    }

    private static string GenerateRandomOtp()
    {
        var random = new Random();
        return random.Next(100000, 999999).ToString();
    }
}
