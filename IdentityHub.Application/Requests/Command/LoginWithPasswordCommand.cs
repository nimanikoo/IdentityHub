using IdentityHub.Application.Common.Models;
using IdentityHub.Application.DTOs;
using MediatR;

namespace IdentityHub.Application.Requests.Command;

public record LoginWithPasswordCommand : IRequest<Result<AuthResponse>>
{
    public string Username { get; set; } 
    public string Password { get; set; }
}