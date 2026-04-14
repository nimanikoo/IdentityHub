using IdentityHub.Application.Common.Interfaces.Services;
using Microsoft.AspNetCore.Identity;
using System.Text.RegularExpressions;

namespace IdentityHub.Infrastructure.Services;

/// <summary>
/// Password Service Implementation
/// Validates password strength and manages password history
/// </summary>
public class PasswordService : IPasswordService
{
    private const int MinimumPasswordLength = 12;
    private const int MinimumUppercaseLetters = 1;
    private const int MinimumLowercaseLetters = 1;
    private const int MinimumDigits = 1;
    private const int MinimumSpecialCharacters = 1;

    public Task<bool> ValidatePasswordStrengthAsync(string password)
    {
        var errors = new List<string>();

        // Length check
        if (password.Length < MinimumPasswordLength)
            errors.Add($"Password must be at least {MinimumPasswordLength} characters long");

        // Uppercase check
        if (Regex.Matches(password, "[A-Z]").Count < MinimumUppercaseLetters)
            errors.Add("Password must contain at least one uppercase letter");

        // Lowercase check
        if (Regex.Matches(password, "[a-z]").Count < MinimumLowercaseLetters)
            errors.Add("Password must contain at least one lowercase letter");

        // Digit check
        if (Regex.Matches(password, "[0-9]").Count < MinimumDigits)
            errors.Add("Password must contain at least one digit");

        // Special character check
        if (Regex.Matches(password, "[^a-zA-Z0-9]").Count < MinimumSpecialCharacters)
            errors.Add("Password must contain at least one special character");

        // Check for common patterns (sequential, repetitive)
        if (HasCommonPatterns(password))
            errors.Add("Password contains common patterns");

        return Task.FromResult(!errors.Any());
    }

    public Task<bool> IsPasswordReusedAsync(string userId, string newPassword, int passwordHistoryCount = 3)
    {
        // TODO: Implement password history check in database
        // For now, returning false (not reused)
        return Task.FromResult(false);
    }

    public string HashPassword(string password)
    {
        var hasher = new PasswordHasher<object>();
        return hasher.HashPassword(null, password);
    }

    public bool VerifyPassword(string password, string hash)
    {
        var hasher = new PasswordHasher<object>();
        var result = hasher.VerifyHashedPassword(null, hash, password);
        return result == PasswordVerificationResult.Success;
    }

    private static bool HasCommonPatterns(string password)
    {
        // Check for sequential characters
        for (int i = 0; i < password.Length - 2; i++)
        {
            if (password[i + 1] == password[i] + 1 &&
                password[i + 2] == password[i] + 2)
            {
                return true;
            }
        }

        // Check for repetitive characters
        for (int i = 0; i < password.Length - 2; i++)
        {
            if (password[i] == password[i + 1] &&
                password[i + 1] == password[i + 2])
            {
                return true;
            }
        }

        return false;
    }
}
