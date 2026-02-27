# IdentityHub - Complete API Reference & Examples

## Base URL

**Development**: `https://localhost:7001`
**Production**: `https://your-domain.com`

## Authentication

Most endpoints use JWT Bearer tokens:

```bash
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Response Format

All responses follow a consistent format:

### Success Response
```json
{
  "success": true,
  "data": { /* response data */ },
  "message": "Operation successful"
}
```

### Error Response
```json
{
  "success": false,
  "data": null,
  "message": "Error description",
  "errors": ["Specific error 1", "Specific error 2"]
}
```

---

## Endpoints

### 1. User Registration

**Endpoint**: `POST /api/auth/register`

**Authentication**: None (Public)

**Request Body**:
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "password": "SecureP@ssw0rd123!",
  "confirmPassword": "SecureP@ssw0rd123!"
}
```

**Password Requirements**:
- Minimum 12 characters
- At least 1 uppercase letter (A-Z)
- At least 1 lowercase letter (a-z)
- At least 1 digit (0-9)
- At least 1 special character (!@#$%^&*, etc)

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "johndoe",
    "email": "john@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "emailConfirmed": false,
    "createdAt": "2026-02-27T10:30:00Z"
  },
  "message": "User registered successfully. Please verify your email."
}
```

**Error Response** (400 Bad Request):
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    "Password must be at least 12 characters long",
    "Email already registered"
  ]
}
```

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "password": "SecureP@ssw0rd123!",
    "confirmPassword": "SecureP@ssw0rd123!"
  }'
```

---

### 2. Login with Password

**Endpoint**: `POST /api/auth/login`

**Authentication**: None (Public)

**Request Body**:
```json
{
  "username": "johndoe",
  "password": "SecureP@ssw0rd123!"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQ1RjQ0MDkwNjAxRDhBMTYxRkNFRDQxQ0ZCQzI0NTUzIiwicC2t...",
    "refreshToken": "CfDJ8D_hf8gy4tJ...",
    "expiresIn": 900
  },
  "message": "Login successful"
}
```

**Error Responses**:

Invalid Credentials (401 Unauthorized):
```json
{
  "success": false,
  "message": "Invalid credentials"
}
```

Account Locked (401 Unauthorized):
```json
{
  "success": false,
  "message": "Account is temporarily locked. Please try again later."
}
```

Account Disabled (401 Unauthorized):
```json
{
  "success": false,
  "message": "Account is disabled."
}
```

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "SecureP@ssw0rd123!"
  }'
```

---

### 3. Send OTP (Request One-Time Password)

**Endpoint**: `POST /api/auth/send-otp`

**Authentication**: None (Public)

**Request Body**:
```json
{
  "username": "johndoe"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "message": "OTP sent to email"
  },
  "message": "OTP sent successfully. Check your email."
}
```

**Security Note**: The response doesn't reveal if the user exists (prevents user enumeration).

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/send-otp \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe"}'
```

---

### 4. Verify OTP (Complete OTP Login)

**Endpoint**: `POST /api/auth/verify-otp`

**Authentication**: None (Public)

**Request Body**:
```json
{
  "username": "johndoe",
  "otpCode": "123456"
}
```

**OTP Format**:
- 6-digit numeric code
- Expires after 5 minutes
- Maximum 5 verification attempts

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQ1RjQ0MDkwNjAxRDhBMTYxRkNFRDQxQ0ZCQzI0NTUzIiwicC2t...",
    "refreshToken": "CfDJ8D_hf8gy4tJ...",
    "expiresIn": 900
  },
  "message": "OTP verified. Login successful"
}
```

**Error Responses**:

Invalid OTP (400 Bad Request):
```json
{
  "success": false,
  "message": "Invalid OTP or too many attempts"
}
```

OTP Expired (400 Bad Request):
```json
{
  "success": false,
  "message": "OTP has expired. Please request a new one."
}
```

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "otpCode": "123456"
  }'
```

---

### 5. Login with LDAP

**Endpoint**: `POST /api/auth/login-ldap`

**Authentication**: None (Public)

**Request Body**:
```json
{
  "username": "johndoe",
  "password": "YourLdapPassword"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQ1RjQ0MDkwNjAxRDhBMTYxRkNFRDQxQ0ZCQzI0NTUzIiwicC2t...",
    "refreshToken": "CfDJ8D_hf8gy4tJ...",
    "expiresIn": 900
  },
  "message": "LDAP login successful"
}
```

**Features**:
- Validates against LDAP/Active Directory
- Auto-creates user in local database if new
- Syncs user attributes from directory
- Perfect for enterprise environments

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/login-ldap \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "YourLdapPassword"
  }'
```

---

### 6. Change Password

**Endpoint**: `POST /api/auth/change-password`

**Authentication**: Required (Bearer Token)

**Request Body**:
```json
{
  "currentPassword": "SecureP@ssw0rd123!",
  "newPassword": "NewSecureP@ssw0rd456!",
  "confirmPassword": "NewSecureP@ssw0rd456!"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "message": "Password changed successfully"
  },
  "message": "Your password has been updated"
}
```

**Error Responses**:

Unauthorized (401 Unauthorized):
```json
{
  "success": false,
  "message": "User not authenticated"
}
```

Wrong Current Password (400 Bad Request):
```json
{
  "success": false,
  "message": "Current password is incorrect"
}
```

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "currentPassword": "SecureP@ssw0rd123!",
    "newPassword": "NewSecureP@ssw0rd456!",
    "confirmPassword": "NewSecureP@ssw0rd456!"
  }'
```

---

### 7. Forgot Password

**Endpoint**: `POST /api/auth/forgot-password`

**Authentication**: None (Public)

**Request Body**:
```json
{
  "email": "john@example.com"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "message": "If the email exists, a password reset link has been sent."
  },
  "message": "Email sent"
}
```

**Security Note**: Response is the same whether email exists or not (prevents user enumeration).

**Email Sent**:
```
Subject: Password Reset Request

Hello,

We received a request to reset your password. Click the link below to proceed:

https://your-domain.com/reset-password?email=john@example.com&token=CfDJ8D_hf8gy4tJ...

This link will expire in 1 hour.

If you didn't request this, please ignore this email.

Best regards,
IdentityHub Security Team
```

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "john@example.com"}'
```

---

### 8. Reset Password

**Endpoint**: `POST /api/auth/reset-password`

**Authentication**: None (Public)

**Request Body**:
```json
{
  "email": "john@example.com",
  "resetToken": "CfDJ8D_hf8gy4tJ...",
  "newPassword": "NewSecureP@ssw0rd456!",
  "confirmPassword": "NewSecureP@ssw0rd456!"
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "message": "Password reset successfully"
  },
  "message": "Your password has been updated"
}
```

**Error Responses**:

Invalid Token (400 Bad Request):
```json
{
  "success": false,
  "message": "Invalid reset link or email"
}
```

Token Expired (400 Bad Request):
```json
{
  "success": false,
  "message": "Reset token has expired"
}
```

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "resetToken": "CfDJ8D_hf8gy4tJ...",
    "newPassword": "NewSecureP@ssw0rd456!",
    "confirmPassword": "NewSecureP@ssw0rd456!"
  }'
```

---

### 9. Refresh Token

**Endpoint**: `POST /api/auth/refresh-token`

**Authentication**: Bearer Token (Refresh Token)

**Request Body**:
```json
{
  "refreshToken": "CfDJ8D_hf8gy4tJ..."
}
```

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IkQ1RjQ0MDkwNjAxRDhBMTYxRkNFRDQxQ0ZCQzI0NTUzIiwicC2t...",
    "refreshToken": "CfDJ8D_hf8gy4tJNew...",
    "expiresIn": 900
  },
  "message": "Token refreshed"
}
```

**Token Lifetime**:
- Access Token: 15 minutes (900 seconds)
- Refresh Token: 7 days

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/refresh-token \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"refreshToken": "CfDJ8D_hf8gy4tJ..."}'
```

---

### 10. Logout

**Endpoint**: `POST /api/auth/logout`

**Authentication**: Required (Bearer Token)

**Request Body**: Empty

**Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "message": "Successfully logged out"
  },
  "message": "Logout successful"
}
```

**cURL Example**:
```bash
curl -X POST https://localhost:7001/api/auth/logout \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Error Codes & Status

| Status | Meaning | Common Causes |
|--------|---------|---------------|
| 200 | Success | Operation completed |
| 400 | Bad Request | Invalid input, validation failed |
| 401 | Unauthorized | Missing/invalid token, wrong credentials |
| 403 | Forbidden | Token expired, account disabled |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Server Error | Unexpected error |

---

## Common Flows

### Flow 1: Complete Login with Password
```
1. POST /api/auth/login (username, password)
   ↓ Returns: accessToken, refreshToken
2. Use accessToken in Authorization header for protected endpoints
3. When token expires, POST /api/auth/refresh-token to get new token
```

### Flow 2: Complete OTP Login
```
1. POST /api/auth/send-otp (username)
   ↓ Sends OTP to email
2. User receives OTP code
3. POST /api/auth/verify-otp (username, otpCode)
   ↓ Returns: accessToken, refreshToken
4. Use accessToken in Authorization header for protected endpoints
```

### Flow 3: Password Reset
```
1. POST /api/auth/forgot-password (email)
   ↓ Sends reset link to email
2. User clicks link with token
3. POST /api/auth/reset-password (email, resetToken, newPassword)
   ↓ Returns success
4. User can now login with new password
```

---

## Security Headers

All responses include:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

---

## Rate Limiting

- **Login endpoint**: 5 attempts per 15 minutes
- **Register endpoint**: 10 attempts per hour
- **Password reset**: 3 attempts per hour

---

## Testing Checklist

- [ ] Register with valid credentials
- [ ] Register with duplicate username
- [ ] Register with weak password
- [ ] Login with correct credentials
- [ ] Login with wrong password
- [ ] Attempt 5+ failed logins (should lockout)
- [ ] Send OTP
- [ ] Verify OTP with wrong code
- [ ] Verify OTP after expiration
- [ ] Change password while logged in
- [ ] Request password reset
- [ ] Reset password with token
- [ ] Refresh token
- [ ] Logout

---

**Last Updated**: February 2026
**API Version**: 1.0.0
**Status**: Production Ready ✅
