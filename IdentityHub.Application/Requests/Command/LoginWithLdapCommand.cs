using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Application.Requests.Command;

/// <summary>
/// Login with LDAP Command
/// Authenticates user against LDAP/Active Directory
/// </summary>
public record LoginWithLdapCommand(
    string Username,
    string Password
) : IRequest<IActionResult>;
