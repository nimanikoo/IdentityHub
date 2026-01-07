using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Domain.Entities;
using IdentityHub.Infrastructure.Persistence.Contexts;
using IdentityHub.Infrastructure.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace IdentityHub.Infrastructure.Extension;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddMemoryCache();
        services.AddScoped<IOtpService, CachedOtpService>();
        
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));
            options.UseOpenIddict<Guid>();
        });

        services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
            {
                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 6;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                options.SetTokenEndpointUris("/connect/token")
                       .SetLogoutEndpointUris("/connect/logout");

                options.AllowPasswordFlow()
                       .AllowRefreshTokenFlow()
                       .AllowCustomFlow("otp");

                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                options.UseAspNetCore()
                       .EnableTokenEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough();

                options.AddEventHandler<OpenIddictServerEvents.ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(async context =>
                    {
                        if (context.Principal == null) return;

                        var httpContext = context.Transaction.GetHttpRequest()?.HttpContext;
                        if (httpContext == null) return;

                        var userManager = httpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
                        
                        var user = await userManager.GetUserAsync(context.Principal);
                        if (user == null) return;

                        var roles = await userManager.GetRolesAsync(user);

                        if (roles.Contains("Admin"))
                        {
                            context.Principal.SetAccessTokenLifetime(TimeSpan.FromDays(1));
                        }
                        else
                        {
                            context.Principal.SetAccessTokenLifetime(TimeSpan.FromMinutes(15));
                        }
                        
                        context.Principal.SetRefreshTokenLifetime(TimeSpan.FromDays(30));
                    });
                });
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        return services;
    }
}