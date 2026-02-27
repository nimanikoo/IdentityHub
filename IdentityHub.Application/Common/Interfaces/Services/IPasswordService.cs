namespace IdentityHub.Application.Common.Interfaces.Services;

public interface IPasswordService
{
    Task<bool> ValidatePasswordStrengthAsync(string password);
    Task<bool> IsPasswordReusedAsync(string userId, string newPassword, int passwordHistoryCount = 3);
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash);
}
