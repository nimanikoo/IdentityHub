namespace IdentityHub.Application.Common.Interfaces.Services;

public interface ISecurityAuditService
{
    Task LogLoginAttemptAsync(string userId, bool success, string ipAddress, string userAgent, CancellationToken cancellationToken = default);
    Task LogPasswordChangeAsync(string userId, string ipAddress, CancellationToken cancellationToken = default);
    Task LogOtpAttemptAsync(string userId, bool success, CancellationToken cancellationToken = default);
    Task LogRegistrationAsync(string userId, string email, CancellationToken cancellationToken = default);
}
