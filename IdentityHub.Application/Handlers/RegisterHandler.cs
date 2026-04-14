using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Application.Common.Models.Responses;
using IdentityHub.Application.Requests.Command;
using IdentityHub.Domain.Entities;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace IdentityHub.Application.Handlers;

public class RegisterHandler : IRequestHandler<RegisterCommand, IActionResult>
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _emailService;
    private readonly IPasswordService _passwordService;
    private readonly ISecurityAuditService _auditService;
    private readonly ILogger<RegisterHandler> _logger;

    public RegisterHandler(
        UserManager<ApplicationUser> userManager,
        IEmailService emailService,
        IPasswordService passwordService,
        ISecurityAuditService auditService,
        ILogger<RegisterHandler> logger)
    {
        _userManager = userManager;
        _emailService = emailService;
        _passwordService = passwordService;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<IActionResult> Handle(RegisterCommand request, CancellationToken ct)
    {
        try
        {
            // Validate input
            var errors = ValidateInput(request);
            if (errors.Any())
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Validation failed", errors)
                );
            }

            // Check if user exists
            var existingUser = await _userManager.FindByNameAsync(request.Username);
            if (existingUser != null)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Username already exists")
                );
            }

            // Check if email exists
            var emailExists = await _userManager.FindByEmailAsync(request.Email);
            if (emailExists != null)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Email already registered")
                );
            }

            // Validate password strength
            var isPasswordStrong = await _passwordService.ValidatePasswordStrengthAsync(request.Password);
            if (!isPasswordStrong)
            {
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse(
                        "Password does not meet security requirements. " +
                        "Must be 12+ characters with uppercase, lowercase, digits, and special characters"
                    )
                );
            }

            // Create user
            var user = new ApplicationUser
            {
                UserName = request.Username,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                EmailConfirmed = false,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
            {
                var errorMessages = result.Errors.Select(e => e.Description).ToList();
                return new BadRequestObjectResult(
                    ApiResponse<object>.ErrorResponse("Registration failed", errorMessages)
                );
            }

            // Log registration
            await _auditService.LogRegistrationAsync(user.Id.ToString(), user.Email!, ct);

            // Send welcome email
            await _emailService.SendWelcomeEmailAsync(user.Email!, user.UserName!, ct);

            // Generate email confirmation token
            var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            _logger.LogInformation($"User registered successfully: {user.UserName}");

            var response = new UserResponse
            {
                Id = user.Id,
                Username = user.UserName!,
                Email = user.Email!,
                FirstName = user.FirstName,
                LastName = user.LastName,
                EmailConfirmed = user.EmailConfirmed,
                CreatedAt = user.CreatedAt
            };

            return new OkObjectResult(
                ApiResponse<UserResponse>.SuccessResponse(response, "User registered successfully. Please verify your email.")
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration error");
            return new BadRequestObjectResult(
                ApiResponse<object>.ErrorResponse("An unexpected error occurred during registration")
            );
        }
    }

    private List<string> ValidateInput(RegisterCommand request)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(request.Username) || request.Username.Length < 3)
            errors.Add("Username must be at least 3 characters");

        if (string.IsNullOrWhiteSpace(request.Email) || !request.Email.Contains("@"))
            errors.Add("Valid email is required");

        if (string.IsNullOrWhiteSpace(request.FirstName))
            errors.Add("First name is required");

        if (string.IsNullOrWhiteSpace(request.LastName))
            errors.Add("Last name is required");

        if (request.Password != request.ConfirmPassword)
            errors.Add("Passwords do not match");

        if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 8)
            errors.Add("Password must be at least 8 characters");

        return errors;
    }
}
