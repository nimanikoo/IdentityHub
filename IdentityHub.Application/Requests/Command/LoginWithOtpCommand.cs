using IdentityHub.Application.Common.Models;
using IdentityHub.Application.DTOs;
using MediatR;

namespace IdentityHub.Application.Requests.Command;

public record LoginWithOtpCommand : IRequest<Result<AuthResponse>>
{
    public string PhoneNumber { get; set; }
    public string OtpCode { get; set; }
}