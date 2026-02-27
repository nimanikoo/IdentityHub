namespace IdentityHub.Application.Common.Interfaces.Services;

public interface IEmailService
{
    Task<bool> SendEmailAsync(string to, string subject, string body, CancellationToken cancellationToken = default);
    Task<bool> SendOtpEmailAsync(string to, string otp, CancellationToken cancellationToken = default);
    Task<bool> SendPasswordResetEmailAsync(string to, string resetLink, CancellationToken cancellationToken = default);
    Task<bool> SendWelcomeEmailAsync(string to, string username, CancellationToken cancellationToken = default);
}
