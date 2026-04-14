# IdentityHub - Quick Reference Card

## Installation Checklist

```bash
# 1. Add new packages (if needed)
dotnet add package BCrypt.Net-Next
dotnet add package OpenIddict
dotnet add package Novell.Directory.Ldap.NETStandard

# 2. Database migration
cd IdentityHub.Infrastructure
dotnet ef migrations add AddSecurityFields
dotnet ef database update

# 3. Run application
cd IdentityHub.Api
dotnet run --configuration Development
```

## Configuration Quick Setup

### appsettings.Development.json
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=IdentityHubDb;Username=postgres;Password=password"
  },
  "AppSettings": {
    "AppUrl": "https://localhost:7001"
  }
}
```

### appsettings.Production.json
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=prod-server;Database=IdentityHubDb;Username=user;Password=secure_password"
  },
  "AppSettings": {
    "AppUrl": "https://your-domain.com",
    "JwtSecret": "min-32-chars-very-secure-secret-key-here"
  },
  "Email": {
    "Provider": "SendGrid",
    "SendGrid": {
      "ApiKey": "sg_live_xxxxxxxxxxxxx"
    }
  }
}
```

## API Quick Reference

### Register User
```bash
curl -X POST https://localhost:7001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "email": "john@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "password": "SecureP@ss123!",
    "confirmPassword": "SecureP@ss123!"
  }'
```

### Login
```bash
curl -X POST https://localhost:7001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "password": "SecureP@ss123!"
  }'
```

### Send OTP
```bash
curl -X POST https://localhost:7001/api/auth/send-otp \
  -H "Content-Type: application/json" \
  -d '{"username": "john"}'
```

### Verify OTP
```bash
curl -X POST https://localhost:7001/api/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john",
    "otpCode": "123456"
  }'
```

### Refresh Token
```bash
curl -X POST https://localhost:7001/api/auth/refresh-token \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "REFRESH_TOKEN_HERE"}'
```

### Change Password (Authenticated)
```bash
curl -X POST https://localhost:7001/api/auth/change-password \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "SecureP@ss123!",
    "newPassword": "NewSecureP@ss456!",
    "confirmPassword": "NewSecureP@ss456!"
  }'
```

### Logout (Authenticated)
```bash
curl -X POST https://localhost:7001/api/auth/logout \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Security Settings

### Password Policy
- Minimum length: 12 characters
- Requires uppercase (A-Z)
- Requires lowercase (a-z)
- Requires digits (0-9)
- Requires special char (!@#$%, etc)

### Account Lockout
- Failed attempts: 5
- Lockout duration: 15 minutes

### OTP Settings
- Length: 6 digits
- Expiration: 5 minutes
- Max attempts: 5

### Token Settings
- Access token expiration: 15 minutes (900 seconds)
- Refresh token expiration: 7 days

## Common Issues & Fixes

### Issue: "Invalid JWT secret"
**Fix**: Ensure JWT secret is minimum 32 characters
```json
"JwtSecret": "this-must-be-at-least-32-characters-long-for-security"
```

### Issue: "Email service not configured"
**Fix**: Update Email settings in appsettings
```json
"Email": {
  "Provider": "SendGrid",
  "SendGrid": {
    "ApiKey": "your-sendgrid-api-key"
  }
}
```

### Issue: "LDAP connection failed"
**Fix**: Verify LDAP configuration
```json
"Ldap": {
  "Enabled": true,
  "Server": "ldap://your-server.com",
  "Port": 389,
  "BaseDn": "dc=company,dc=com"
}
```

### Issue: "Database migration fails"
**Fix**: Ensure connection string is correct
```bash
dotnet ef database update -c ApplicationDbContext --verbose
```

### Issue: "OTP not sending"
**Fix**: Check email service configuration and API keys
```bash
# Test SendGrid API key
curl -X GET https://api.sendgrid.com/v3/user/profile \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## Development Commands

```bash
# Run application
dotnet run

# Run with watch (auto-reload)
dotnet watch run

# Build release
dotnet build -c Release

# Run tests
dotnet test

# Create migration
dotnet ef migrations add MigrationName

# Update database
dotnet ef database update

# Drop database
dotnet ef database drop

# View pending migrations
dotnet ef migrations list
```

## Project Files Overview

| File | Purpose |
|------|---------|
| `Program.cs` | OpenIddict configuration |
| `AuthController.cs` | API endpoints |
| `*Handler.cs` | Business logic (CQRS) |
| `*Service.cs` | External services |
| `ApplicationUser.cs` | User model |
| `appsettings.json` | Configuration |

## Testing Endpoints

```powershell
# PowerShell: Register
$body = @{
    username = "testuser"
    email = "test@example.com"
    firstName = "Test"
    lastName = "User"
    password = "SecureP@ss123!"
    confirmPassword = "SecureP@ss123!"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://localhost:7001/api/auth/register" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

## Environment Variables for Production

```bash
# Windows (PowerShell)
$env:ASPNETCORE_ENVIRONMENT = "Production"
$env:ConnectionStrings__DefaultConnection = "Host=...;Database=...;Username=...;Password=..."
$env:AppSettings__JwtSecret = "your-secret-key-min-32-chars"
$env:AppSettings__AppUrl = "https://your-domain.com"
$env:Email__SendGrid__ApiKey = "sg_live_xxxxx"

# Linux/Mac
export ASPNETCORE_ENVIRONMENT=Production
export ConnectionStrings__DefaultConnection="Host=...;Database=...;Username=...;Password=..."
export AppSettings__JwtSecret="your-secret-key-min-32-chars"
export AppSettings__AppUrl="https://your-domain.com"
export Email__SendGrid__ApiKey="sg_live_xxxxx"
```

## Database Indexes for Performance

```sql
-- Add these indexes to improve performance
CREATE INDEX idx_user_email ON AspNetUsers(Email);
CREATE INDEX idx_user_username ON AspNetUsers(UserName);
CREATE INDEX idx_user_active ON AspNetUsers(IsActive);
CREATE INDEX idx_user_ldapid ON AspNetUsers(LdapId);
CREATE INDEX idx_otp_expiration ON AspNetUsers(OtpExpiration);
CREATE INDEX idx_last_login ON AspNetUsers(LastLoginAt);
```

## Response Status Codes

| Code | Meaning | Common Cause |
|------|---------|---|
| 200 | OK | Success |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Wrong credentials |
| 403 | Forbidden | Token expired/invalid |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Server Error | Unexpected error |

## Key Classes to Remember

- `ApplicationUser` - User entity with security fields
- `RegisterHandler` - Handles registration
- `LoginWithPasswordHandler` - Password login
- `LoginWithOtpHandler` - OTP login
- `OtpService` - OTP generation/verification
- `PasswordService` - Password validation
- `EmailService` - Email sending
- `LdapService` - LDAP authentication

## Default Passwords (Development Only)

```
Database: postgres / password
Admin: admin / Admin123!@

⚠️ CHANGE THESE IMMEDIATELY IN PRODUCTION
```

## Useful Links

- [OpenIddict Documentation](https://documentation.openiddict.com/)
- [ASP.NET Core Security](https://docs.microsoft.com/en-us/aspnet/core/security/)
- [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

## Monitoring Points

Monitor these metrics in production:

```
✓ Login success/failure rate
✓ Account lockout events
✓ OTP generation/verification
✓ Password reset requests
✓ Failed authentication attempts
✓ API response times
✓ Error rates
✓ Database performance
```

## Notes for Team

1. **Never commit secrets** - Use environment variables
2. **Always use HTTPS** in production
3. **Rotate JWT secrets** periodically
4. **Review audit logs** weekly
5. **Update dependencies** monthly
6. **Test new features** before deployment
7. **Keep backups** of production database
8. **Monitor error rates** in real-time

## Quick Deploy (Docker)

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY ./publish .
ENTRYPOINT ["dotnet", "IdentityHub.Api.dll"]
```

```bash
docker build -t identityhub:latest .
docker run -e ASPNETCORE_ENVIRONMENT=Production \
           -e "ConnectionStrings__DefaultConnection=..." \
           -p 443:443 \
           identityhub:latest
```

---

**Last Updated**: February 27, 2026
**Version**: 1.0.0
**Status**: Ready for Production ✅
