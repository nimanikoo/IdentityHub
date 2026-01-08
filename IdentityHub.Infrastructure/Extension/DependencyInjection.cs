using System.Security.Claims;
using System.Text;
using IdentityHub.Application.Common.Interfaces;
using IdentityHub.Domain.Entities;
using IdentityHub.Infrastructure.Authentication;
using IdentityHub.Infrastructure.Persistence.Contexts;
using IdentityHub.Infrastructure.Services;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace IdentityHub.Infrastructure.Extension;

public static class DependencyInjection
{
    public static void AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddMemoryCache();
        services.AddScoped<IOtpService, CachedOtpService>();
        services.AddScoped<ITokenService, TokenService>();
        services.Configure<JwtSettings>(configuration.GetSection("JwtSettings"));

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
                options.User.AllowedUserNameCharacters =
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
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

                        var userManager =
                            httpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();

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

        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidAudience = jwtSettings.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret))
                };

                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var userManager = context.HttpContext.RequestServices
                            .GetRequiredService<UserManager<ApplicationUser>>();
                        var claimsIdentity = context.Principal!.Identity as ClaimsIdentity;

                        var userId = claimsIdentity?.FindFirst("user_name")?.Value
                                     ?? claimsIdentity?.FindFirst("sub")?.Value;

                        if (string.IsNullOrEmpty(userId))
                        {
                            context.Fail("Unauthorized");
                            return;
                        }

                        var tokenSecurityStamp = claimsIdentity?.FindFirst("security_stamp")?.Value;

                        if (string.IsNullOrEmpty(tokenSecurityStamp))
                        {
                            context.Fail("Unauthorized - No Security Stamp");
                            return;
                        }

                        var user = await userManager.FindByIdAsync(userId);
                        if (user == null)
                        {
                            context.Fail("User not found");
                            return;
                        }

                        var dbSecurityStamp = await userManager.GetSecurityStampAsync(user);

                        if (dbSecurityStamp != tokenSecurityStamp)
                        {
                            context.Fail("Token is invalid (User logged out or changed password)");
                        }
                    }
                };
            });
    }
}