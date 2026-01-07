namespace IdentityHub.Application.Common.Interfaces;

public interface IOtpService
{
    Task<string> GenerateOtpAsync(string userId, string phoneNumber);
    Task<bool> ValidateOtpAsync(string phoneNumber, string code); 
}