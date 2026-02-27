using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Change Password Command
/// Changes user's password (requires current password)
/// </summary>
public record ChangePasswordCommand(
    string CurrentPassword,
    string NewPassword,
    string ConfirmPassword
) : IRequest<IActionResult>;
