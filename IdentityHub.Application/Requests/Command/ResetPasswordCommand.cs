using IdentityHub.Application.Common.Models;
using MediatR;

namespace IdentityHub.Application.Requests.Command;

public record ResetPasswordCommand(string PhoneNumber, string OtpCode, string NewPassword) : IRequest<Result<string>>;