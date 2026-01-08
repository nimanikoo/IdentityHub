using IdentityHub.Application.Common.Models;
using MediatR;

namespace IdentityHub.Application.Requests.Command;

public record LogoutCommand(string UserId) : IRequest<Result<bool>>;
