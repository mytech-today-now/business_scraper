# OAuth 2.0 Authentication System

## Overview

The Business Scraper application now includes a comprehensive OAuth 2.0 authentication and authorization system that provides secure, standards-compliant authentication for web applications, mobile apps, and API consumers.

## Features

### Core OAuth 2.0 Capabilities
- **Authorization Code Flow** with PKCE support
- **Refresh Token Flow** with token rotation
- **Client Credentials Flow** for server-to-server authentication
- **JWT-based Access Tokens** with configurable expiration
- **Token Introspection** (RFC 7662) for resource servers
- **Token Revocation** (RFC 7009) for security
- **Dynamic Client Registration** (RFC 7591) for self-service

### Security Features
- **PKCE (Proof Key for Code Exchange)** for enhanced mobile/SPA security
- **TLS/HTTPS enforcement** in production environments
- **Rate limiting** and brute-force protection
- **Token blacklisting** and revocation
- **Scope-based authorization** with fine-grained permissions
- **Secure credential storage** and validation

### Client Support
- **Public Clients** (Mobile apps, SPAs) with PKCE enforcement
- **Confidential Clients** (Server-side applications) with client secrets
- **API Clients** for machine-to-machine communication
- **Self-service registration** with validation

## API Endpoints

### Authorization Endpoint
```
GET /api/oauth/authorize
```

**Parameters:**
- `response_type=code` (required)
- `client_id` (required)
- `redirect_uri` (required)
- `scope` (optional, space-separated)
- `state` (recommended for CSRF protection)
- `code_challenge` (required for public clients)
- `code_challenge_method` (S256 or plain)

**Example:**
```
GET /api/oauth/authorize?response_type=code&client_id=my-app&redirect_uri=https://myapp.com/callback&scope=openid%20profile&state=xyz&code_challenge=abc123&code_challenge_method=S256
```

### Token Endpoint
```
POST /api/oauth/token
```

**Authorization Code Grant:**
```json
{
  "grant_type": "authorization_code",
  "client_id": "my-app",
  "client_secret": "secret", // Only for confidential clients
  "code": "auth_code_here",
  "redirect_uri": "https://myapp.com/callback",
  "code_verifier": "verifier_for_pkce" // Required if PKCE was used
}
```

**Refresh Token Grant:**
```json
{
  "grant_type": "refresh_token",
  "client_id": "my-app",
  "client_secret": "secret", // Only for confidential clients
  "refresh_token": "refresh_token_here"
}
```

**Client Credentials Grant:**
```json
{
  "grant_type": "client_credentials",
  "client_id": "my-api-client",
  "client_secret": "secret",
  "scope": "read write"
}
```

**Response:**
```json
{
  "access_token": "jwt_access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token", // Not included for client_credentials
  "scope": "openid profile read"
}
```

### UserInfo Endpoint
```
GET /api/oauth/userinfo
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "sub": "user_id",
  "name": "User Name",
  "email": "user@example.com",
  "roles": ["user"],
  "permissions": ["read"]
}
```

### Token Introspection Endpoint
```
POST /api/oauth/introspect
```

**Request:**
```json
{
  "token": "access_token_to_introspect",
  "client_id": "requesting_client",
  "client_secret": "client_secret"
}
```

**Response:**
```json
{
  "active": true,
  "scope": "openid profile read",
  "client_id": "my-app",
  "username": "user",
  "token_type": "Bearer",
  "exp": 1640995200,
  "iat": 1640991600,
  "sub": "user_id",
  "aud": "my-app",
  "iss": "https://api.businessscraper.com"
}
```

### Token Revocation Endpoint
```
POST /api/oauth/revoke
```

**Request:**
```json
{
  "token": "token_to_revoke",
  "client_id": "my-app",
  "client_secret": "secret"
}
```

### Discovery Endpoint
```
GET /api/oauth/.well-known/openid-configuration
```

**Response:**
```json
{
  "issuer": "https://api.businessscraper.com",
  "authorization_endpoint": "https://api.businessscraper.com/api/oauth/authorize",
  "token_endpoint": "https://api.businessscraper.com/api/oauth/token",
  "userinfo_endpoint": "https://api.businessscraper.com/api/oauth/userinfo",
  "introspection_endpoint": "https://api.businessscraper.com/api/oauth/introspect",
  "revocation_endpoint": "https://api.businessscraper.com/api/oauth/revoke",
  "registration_endpoint": "https://api.businessscraper.com/api/oauth/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "scopes_supported": ["openid", "profile", "email", "read", "write", "admin"]
}
```

### Client Registration Endpoint
```
POST /api/oauth/register
```

**Request:**
```json
{
  "client_name": "My Application",
  "client_type": "public", // or "confidential"
  "redirect_uris": ["https://myapp.com/callback"],
  "scope": "openid profile read",
  "grant_types": ["authorization_code", "refresh_token"],
  "contacts": ["admin@myapp.com"]
}
```

**Response:**
```json
{
  "client_id": "generated_client_id",
  "client_secret": "generated_secret", // Only for confidential clients
  "client_name": "My Application",
  "client_type": "public",
  "redirect_uris": ["https://myapp.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scope": "openid profile read",
  "client_id_issued_at": 1640991600
}
```

## Scopes

### Available Scopes
- `openid` - OpenID Connect authentication
- `profile` - Access to basic profile information
- `email` - Access to email address
- `read` - Read access to business data
- `write` - Write access to business data
- `admin` - Administrative access to all resources

### Scope Usage
Scopes define the permissions granted to access tokens. Clients must be configured with allowed scopes, and users may need to consent to requested scopes.

## PKCE Implementation

### Code Challenge Generation
```javascript
// Generate code verifier
const codeVerifier = crypto.randomBytes(32).toString('base64url')

// Generate code challenge (S256 method)
const codeChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url')
```

### Authorization Request with PKCE
```
GET /api/oauth/authorize?response_type=code&client_id=my-app&redirect_uri=https://myapp.com/callback&code_challenge=abc123&code_challenge_method=S256
```

### Token Request with PKCE
```json
{
  "grant_type": "authorization_code",
  "client_id": "my-app",
  "code": "auth_code",
  "redirect_uri": "https://myapp.com/callback",
  "code_verifier": "original_verifier"
}
```

## Client Types

### Public Clients
- **Use Case:** Mobile apps, Single Page Applications (SPAs)
- **Security:** PKCE required, no client secret
- **Example:** React SPA, mobile app

### Confidential Clients
- **Use Case:** Server-side web applications
- **Security:** Client secret required, PKCE optional
- **Example:** Next.js application, traditional web app

### API Clients
- **Use Case:** Server-to-server communication
- **Security:** Client credentials grant, client secret required
- **Example:** Microservice authentication, scheduled jobs

## Integration Examples

### Web Application (Authorization Code Flow)
```javascript
// 1. Redirect to authorization endpoint
const authUrl = new URL('/api/oauth/authorize', 'https://api.businessscraper.com')
authUrl.searchParams.set('response_type', 'code')
authUrl.searchParams.set('client_id', 'my-web-app')
authUrl.searchParams.set('redirect_uri', 'https://myapp.com/callback')
authUrl.searchParams.set('scope', 'openid profile read')
authUrl.searchParams.set('state', 'random-state-value')

window.location.href = authUrl.toString()

// 2. Handle callback and exchange code for tokens
const tokenResponse = await fetch('/api/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    client_id: 'my-web-app',
    client_secret: 'my-secret',
    code: authorizationCode,
    redirect_uri: 'https://myapp.com/callback'
  })
})

const tokens = await tokenResponse.json()
```

### Mobile App (Authorization Code Flow with PKCE)
```javascript
// 1. Generate PKCE challenge
const codeVerifier = generateCodeVerifier()
const codeChallenge = generateCodeChallenge(codeVerifier)

// 2. Redirect to authorization endpoint
const authUrl = new URL('/api/oauth/authorize', 'https://api.businessscraper.com')
authUrl.searchParams.set('response_type', 'code')
authUrl.searchParams.set('client_id', 'my-mobile-app')
authUrl.searchParams.set('redirect_uri', 'com.myapp://callback')
authUrl.searchParams.set('scope', 'openid profile read')
authUrl.searchParams.set('code_challenge', codeChallenge)
authUrl.searchParams.set('code_challenge_method', 'S256')

// 3. Exchange code for tokens with PKCE
const tokenResponse = await fetch('/api/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    client_id: 'my-mobile-app',
    code: authorizationCode,
    redirect_uri: 'com.myapp://callback',
    code_verifier: codeVerifier
  })
})
```

### API Client (Client Credentials Flow)
```javascript
// Server-to-server authentication
const tokenResponse = await fetch('/api/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'client_credentials',
    client_id: 'my-api-client',
    client_secret: 'api-secret',
    scope: 'read write'
  })
})

const { access_token } = await tokenResponse.json()

// Use access token for API requests
const apiResponse = await fetch('/api/businesses', {
  headers: {
    'Authorization': `Bearer ${access_token}`
  }
})
```

## Configuration

### Environment Variables
```bash
# OAuth Configuration
OAUTH_ISSUER=https://api.businessscraper.com
OAUTH_ACCESS_TOKEN_LIFETIME=3600
OAUTH_REFRESH_TOKEN_LIFETIME=2592000
OAUTH_AUTH_CODE_LIFETIME=600
OAUTH_REQUIRE_PKCE=true
OAUTH_ALLOW_PUBLIC_CLIENTS=true
OAUTH_ALLOW_DYNAMIC_REGISTRATION=false
OAUTH_ALLOWED_ORIGINS=https://myapp.com,https://admin.myapp.com

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Security
NODE_ENV=production
```

### Default Clients
The system includes three pre-configured clients:

1. **business-scraper-web** (Confidential)
   - Web application client
   - Scopes: openid, profile, email, read, write

2. **business-scraper-mobile** (Public)
   - Mobile/SPA client with PKCE
   - Scopes: openid, profile, email, read

3. **business-scraper-api** (Confidential)
   - API client for server-to-server
   - Scopes: read, write, admin

## Security Considerations

### Production Deployment
1. **Use HTTPS** - OAuth 2.0 requires TLS in production
2. **Secure JWT Secret** - Use a strong, random JWT signing key
3. **Rate Limiting** - Configure appropriate rate limits
4. **Token Expiration** - Set reasonable token lifetimes
5. **Scope Validation** - Implement proper scope checking
6. **Client Validation** - Validate redirect URIs and client credentials

### Best Practices
1. **PKCE for Public Clients** - Always use PKCE for mobile/SPA clients
2. **State Parameter** - Use state parameter for CSRF protection
3. **Token Storage** - Store tokens securely (secure cookies, keychain)
4. **Token Refresh** - Implement automatic token refresh
5. **Error Handling** - Handle OAuth errors gracefully
6. **Logging** - Log authentication events for monitoring

## Troubleshooting

### Common Issues

**Invalid Client Error**
- Verify client ID and secret
- Check client is active and not revoked
- Ensure client supports the requested grant type

**Invalid Grant Error**
- Check authorization code hasn't expired
- Verify redirect URI matches exactly
- Ensure PKCE code verifier is correct

**Invalid Scope Error**
- Verify requested scopes are allowed for the client
- Check scope format (space-separated)
- Ensure user has consented to scopes

**PKCE Verification Failed**
- Verify code verifier matches the challenge
- Check code challenge method (S256 vs plain)
- Ensure code verifier format is correct

### Debugging
Enable debug logging by setting the log level to debug in your environment configuration. This will provide detailed information about OAuth flows, token validation, and error conditions.

## Migration from Session-Based Auth

The OAuth 2.0 system is designed to work alongside the existing session-based authentication for backward compatibility. Existing endpoints will continue to work with session authentication while new integrations can use OAuth 2.0 tokens.

### Gradual Migration
1. **Phase 1:** Deploy OAuth 2.0 system alongside existing auth
2. **Phase 2:** Update client applications to use OAuth 2.0
3. **Phase 3:** Migrate API endpoints to OAuth middleware
4. **Phase 4:** Deprecate session-based authentication (optional)

## Support

For additional support or questions about the OAuth 2.0 implementation:
1. Check the troubleshooting section above
2. Review the API documentation
3. Examine the example integrations
4. Contact the development team for assistance
