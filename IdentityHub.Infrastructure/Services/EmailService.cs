using IdentityHub.Application.Common.Interfaces.Services;
using Microsoft.Extensions.Logging;

namespace IdentityHub.Infrastructure.Services;

/// <summary>
/// Email Service Implementation
/// Sends transactional emails for authentication workflows
/// </summary>
public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;

    public EmailService(ILogger<EmailService> logger)
    {
        _logger = logger;
    }

    public async Task<bool> SendEmailAsync(string to, string subject, string body, CancellationToken cancellationToken = default)
    {
        try
        {
            // TODO: Integrate with email provider (SendGrid, AWS SES, SMTP, etc.)
            _logger.LogInformation($"[Email Service] Sending email to {to} with subject: {subject}");
            
            // For development, just log it
            Console.WriteLine($"[Email] To: {to}");
            Console.WriteLine($"[Email] Subject: {subject}");
            Console.WriteLine($"[Email] Body: {body}");
            
            return await Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email");
            return false;
        }
    }

    public async Task<bool> SendOtpEmailAsync(string to, string otp, CancellationToken cancellationToken = default)
    {
        var subject = "Your One-Time Password (OTP)";
        var body = $@"
Hello,

Your One-Time Password (OTP) is: <strong>{otp}</strong>

This OTP will expire in 5 minutes.

Do not share this code with anyone.

Best regards,
IdentityHub Security Team
";

        return await SendEmailAsync(to, subject, body, cancellationToken);
    }

    public async Task<bool> SendPasswordResetEmailAsync(string to, string resetLink, CancellationToken cancellationToken = default)
    {
        var subject = "Password Reset Request";
        var body = $@"
Hello,

We received a request to reset your password. Click the link below to proceed:

<a href='{resetLink}'>Reset Password</a>

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
IdentityHub Security Team
";

        return await SendEmailAsync(to, subject, body, cancellationToken);
    }

    public async Task<bool> SendWelcomeEmailAsync(string to, string username, CancellationToken cancellationToken = default)
    {
        var subject = "Welcome to IdentityHub";
        var body = $@"
Hello {username},

Welcome to IdentityHub! Your account has been successfully created.

You can now log in and start using our services.

Best regards,
IdentityHub Team
";

        return await SendEmailAsync(to, subject, body, cancellationToken);
    }
}
