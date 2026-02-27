using IdentityHub.Application.Common.Interfaces.Authentication;
using IdentityHub.Application.Common.Interfaces.Services;
using IdentityHub.Infrastructure.Authentication;
using IdentityHub.Infrastructure.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityHub.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        // JWT Configuration
        services.Configure<JwtSettings>(configuration.GetSection(JwtSettings.SectionName));
        services.AddSingleton<IJwtTokenGenerator, JwtTokenGenerator>();
        
        // Authentication Services
        services.AddScoped<IOtpService, OtpService>();
        services.AddScoped<ILdapService, LdapService>();
        
        // Security Services
        services.AddScoped<IPasswordService, PasswordService>();
        services.AddScoped<IEmailService, EmailService>();
        services.AddScoped<ISecurityAuditService, SecurityAuditService>();
        
        return services;
    }
}