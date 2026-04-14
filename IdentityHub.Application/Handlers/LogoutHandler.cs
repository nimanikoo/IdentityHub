using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace IdentityHub.Application.Handlers;

public class LogoutHandler : IRequestHandler<LogoutCommand, IActionResult>
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<LogoutHandler> _logger;

    public LogoutHandler(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IHttpContextAccessor httpContextAccessor,
        ILogger<LogoutHandler> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(LogoutCommand request, CancellationToken cancellationToken)
    {
        try
        {
            // Get current user
            var userId = _httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (!string.IsNullOrEmpty(userId))
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    _logger.LogInformation($"User logged out: {user.UserName}");
                }
            }

            // Sign out
            await _signInManager.SignOutAsync();

            return new OkObjectResult(
                ApiResponse<object>.SuccessResponse(
                    new { message = "Successfully logged out" },
                    "Logout successful"
                )
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout error");
            return new BadRequestObjectResult(
                ApiResponse<object>.ErrorResponse("An unexpected error occurred during logout")
            );
        }
    }
}
