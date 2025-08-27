# Security Implementation Guide

This document outlines the security measures implemented in the Business Scraper
application and provides guidance for secure deployment and operation.

## Overview

The Business Scraper application implements multiple layers of security
appropriate for a single-user application:

- **Authentication & Authorization** - Optional password-based access control
- **Input Validation & Sanitization** - Protection against injection attacks
- **Rate Limiting** - Prevention of abuse and DoS attacks
- **CSRF Protection** - Cross-site request forgery prevention
- **Security Headers** - Browser-level security enhancements
- **Secure Session Management** - Session-based authentication
- **API Key Protection** - Secure storage of sensitive credentials

## Security Features

### 1. Authentication System

#### Configuration

```env
# Enable/disable authentication
ENABLE_AUTH=true

# Session configuration
SESSION_TIMEOUT=3600000          # 1 hour in milliseconds
MAX_LOGIN_ATTEMPTS=5             # Maximum failed attempts before lockout
LOCKOUT_DURATION=900000          # 15 minutes lockout duration

# Single user credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password

# For production, use hashed passwords:
ADMIN_PASSWORD_HASH=your_password_hash
ADMIN_PASSWORD_SALT=your_password_salt
```

#### Password Security

- **Development**: Plain text passwords (for convenience)
- **Production**: PBKDF2-hashed passwords with salt
- **Strength Requirements**: Enforced through validation utility
- **Lockout Protection**: Temporary account lockout after failed attempts

#### Session Management

- **Secure Cookies**: HttpOnly, Secure, SameSite=Strict
- **Session Timeout**: Configurable timeout with automatic cleanup
- **CSRF Tokens**: Unique tokens for each session
- **Session Invalidation**: Proper cleanup on logout

### 2. Rate Limiting

#### Configuration

```env
RATE_LIMIT_WINDOW=60000          # 1 minute window
RATE_LIMIT_MAX=100               # Max requests per window
SCRAPING_RATE_LIMIT=10           # Max scraping requests per minute
```

#### Implementation

- **IP-based Limiting**: Tracks requests per IP address
- **Endpoint-specific Limits**: Different limits for different operations
- **Scraping Protection**: Special limits for resource-intensive operations
- **Automatic Reset**: Time-based window reset

### 3. Input Validation & Sanitization

#### Features

- **XSS Prevention**: Script tag removal and HTML escaping
- **SQL Injection Protection**: Pattern detection and blocking
- **Path Traversal Prevention**: Directory traversal pattern blocking
- **Command Injection Protection**: Dangerous character filtering
- **Data Type Validation**: Strict type checking for all inputs

#### Implementation

```typescript
// Automatic sanitization in API endpoints
const sanitizedInput = sanitizeInput(userInput)
const validation = validateInput(sanitizedInput)

if (!validation.isValid) {
  return error('Invalid input format')
}
```

### 4. Security Headers

#### Implemented Headers

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Strict-Transport-Security: max-age=31536000; includeSubDomains (production only)
```

#### Protection Against

- **Clickjacking**: X-Frame-Options prevents embedding
- **MIME Sniffing**: X-Content-Type-Options prevents content type confusion
- **XSS**: Content Security Policy restricts script execution
- **Information Leakage**: Referrer Policy controls referrer information

### 5. API Security

#### Endpoint Protection

- **Authentication Required**: Protected endpoints require valid session
- **CSRF Protection**: State-changing requests require CSRF tokens
- **Input Validation**: All inputs validated and sanitized
- **Error Handling**: Secure error messages without information disclosure

#### Logging & Monitoring

- **Security Events**: Failed login attempts, rate limit violations
- **Request Tracking**: IP addresses and request patterns
- **Error Logging**: Detailed logs for debugging without sensitive data exposure

## Setup Instructions

### 1. Basic Security Setup

For development with minimal security:

```env
ENABLE_AUTH=false
```

For production with full security:

```env
ENABLE_AUTH=true
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your_generated_hash
ADMIN_PASSWORD_SALT=your_generated_salt
```

### 2. Generate Secure Passwords

Use the provided utility to generate secure passwords:

```bash
# Interactive mode
node scripts/generate-password.js

# Generate random password
node scripts/generate-password.js --random --length 16

# Hash existing password
node scripts/generate-password.js --hash "your_password"
```

### 3. Environment Configuration

#### Development (.env.local)

```env
ENABLE_AUTH=false
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
RATE_LIMIT_MAX=1000
```

#### Production (.env)

```env
ENABLE_AUTH=true
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=your_secure_hash
ADMIN_PASSWORD_SALT=your_secure_salt
RATE_LIMIT_MAX=100
SCRAPING_RATE_LIMIT=10
SESSION_TIMEOUT=3600000
```

## Security Best Practices

### 1. Deployment Security

#### HTTPS Configuration

- **Always use HTTPS in production**
- **Configure SSL/TLS certificates properly**
- **Enable HSTS headers**
- **Use secure cookie settings**

#### Environment Variables

- **Never commit secrets to version control**
- **Use secure secret management systems**
- **Rotate API keys regularly**
- **Use different credentials for different environments**

#### Network Security

- **Restrict database access to application servers only**
- **Use firewalls to limit exposed ports**
- **Consider VPN access for administrative functions**
- **Monitor network traffic for anomalies**

### 2. Application Security

#### Regular Updates

- **Keep dependencies updated**
- **Monitor security advisories**
- **Apply security patches promptly**
- **Use automated vulnerability scanning**

#### Monitoring & Logging

- **Monitor failed login attempts**
- **Track rate limit violations**
- **Log security-relevant events**
- **Set up alerting for suspicious activity**

#### Backup & Recovery

- **Regular encrypted backups**
- **Test backup restoration procedures**
- **Secure backup storage**
- **Document recovery procedures**

### 3. Operational Security

#### Access Control

- **Limit administrative access**
- **Use strong, unique passwords**
- **Enable two-factor authentication where possible**
- **Regular access reviews**

#### Incident Response

- **Document security procedures**
- **Prepare incident response plan**
- **Regular security assessments**
- **Staff security training**

## Security Testing

### 1. Automated Testing

Run security tests as part of your CI/CD pipeline:

```bash
# Dependency vulnerability scanning
npm audit

# Static code analysis
npm run lint

# Security-focused tests
npm run test:security
```

### 2. Manual Testing

#### Authentication Testing

- Test login with invalid credentials
- Verify lockout after failed attempts
- Test session timeout behavior
- Verify logout functionality

#### Input Validation Testing

- Test XSS payloads in all input fields
- Test SQL injection patterns
- Test path traversal attempts
- Test command injection patterns

#### Rate Limiting Testing

- Test API rate limits
- Test scraping rate limits
- Verify proper error responses
- Test rate limit reset behavior

## Incident Response

### 1. Security Incident Detection

Monitor for these indicators:

- **Multiple failed login attempts**
- **Rate limit violations**
- **Unusual request patterns**
- **Error rate spikes**
- **Unexpected data access patterns**

### 2. Response Procedures

1. **Immediate Response**
   - Identify the scope of the incident
   - Isolate affected systems if necessary
   - Preserve logs and evidence

2. **Investigation**
   - Analyze logs for attack patterns
   - Identify compromised accounts or data
   - Determine attack vectors

3. **Remediation**
   - Patch vulnerabilities
   - Reset compromised credentials
   - Update security configurations
   - Restore from clean backups if necessary

4. **Recovery**
   - Verify system integrity
   - Monitor for continued attacks
   - Update security measures
   - Document lessons learned

## Compliance & Auditing

### 1. Security Auditing

Regular security audits should include:

- **Code review for security issues**
- **Dependency vulnerability assessment**
- **Configuration review**
- **Access control verification**
- **Log analysis**

### 2. Documentation

Maintain documentation for:

- **Security configurations**
- **Incident response procedures**
- **Access control policies**
- **Security training materials**
- **Audit findings and remediation**

## Support & Resources

### 1. Security Tools

Recommended tools for security testing:

- **OWASP ZAP** - Web application security scanner
- **npm audit** - Dependency vulnerability scanner
- **ESLint Security Plugin** - Static code analysis
- **Helmet.js** - Security headers middleware

### 2. Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Next.js Security Headers](https://nextjs.org/docs/advanced-features/security-headers)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

For security questions or to report vulnerabilities, please contact the
development team through secure channels.
