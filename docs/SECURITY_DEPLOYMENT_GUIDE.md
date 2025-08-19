# 🔐 Security Deployment Guide

## Overview

This guide provides comprehensive instructions for secure deployment of the Business Scraper application, focusing on proper secret management and security best practices.

## 🚨 Critical Security Requirements

### Before Deployment

1. **Never commit secrets to version control**
2. **Use strong, unique passwords for all environments**
3. **Enable authentication in production**
4. **Use encrypted connections (SSL/TLS)**
5. **Regularly rotate secrets and passwords**

## 📋 Environment Setup Checklist

### Development Environment

```bash
# 1. Copy template files
cp config/development.env.example config/development.env
cp .env.example .env.local

# 2. Generate development secrets
node scripts/generate-secrets.js --env development --output .env.dev.secrets

# 3. Update configuration files with generated secrets
# Edit config/development.env and replace CHANGE_ME/GENERATE_ values

# 4. Validate configuration
npm run config:validate
```

### Production Environment

```bash
# 1. Copy template files
cp config/production.env.example config/production.env

# 2. Generate production secrets (CRITICAL: Store securely)
node scripts/generate-secrets.js --env production --output .env.prod.secrets

# 3. Update configuration files with generated secrets
# Edit config/production.env and replace ALL placeholder values

# 4. Validate production configuration
NODE_ENV=production npm run config:validate

# 5. Remove secrets file after copying values
rm .env.prod.secrets  # After copying values to secure location
```

## 🔑 Secret Generation

### Automated Secret Generation

Use the provided script to generate cryptographically secure secrets:

```bash
# Generate all secrets for production
node scripts/generate-secrets.js --env production

# Generate secrets for specific environment
node scripts/generate-secrets.js --env development
node scripts/generate-secrets.js --env test

# Display secrets without saving to file
node scripts/generate-secrets.js --display-only
```

### Manual Secret Generation

If you need to generate secrets manually:

```bash
# Generate encryption key (32 bytes hex)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate JWT secret (64 bytes base64url)
node -e "console.log(require('crypto').randomBytes(64).toString('base64url'))"

# Generate secure password
node scripts/generate-password.js --random --length 24
```

## 🛡️ Security Configuration

### Required Security Variables

**Critical secrets that MUST be unique and secure:**

```env
# Database Security
DB_PASSWORD=<strong-unique-password>
POSTGRES_PASSWORD=<strong-unique-password>
REDIS_PASSWORD=<strong-unique-password>

# Application Security
ENCRYPTION_KEY=<32-byte-hex-key>
JWT_SECRET=<base64url-encoded-secret>
SESSION_SECRET=<random-string>

# Authentication
ADMIN_PASSWORD_HASH=<pbkdf2-hash>
ADMIN_PASSWORD_SALT=<random-salt>
```

### Production Security Settings

```env
# Enable authentication
ENABLE_AUTH=true

# Use hashed passwords (never plain text)
ADMIN_PASSWORD_HASH=<generated-hash>
ADMIN_PASSWORD_SALT=<generated-salt>
# Remove or comment out ADMIN_PASSWORD

# Enable SSL for database
DB_SSL=true

# Secure session settings
SESSION_TIMEOUT=3600000  # 1 hour
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=900000  # 15 minutes

# Rate limiting
RATE_LIMIT_MAX=100
SCRAPING_RATE_LIMIT=10
```

## 🔒 Secret Management Best Practices

### 1. Environment Separation

- **Development**: Use weak passwords for convenience, but still unique
- **Staging**: Use production-strength secrets, separate from production
- **Production**: Use maximum security, unique secrets

### 2. Secret Storage

**DO:**
- Use environment variables
- Use secret management services (AWS Secrets Manager, Azure Key Vault, etc.)
- Store secrets in encrypted files with restricted access
- Use different secrets for each environment

**DON'T:**
- Commit secrets to version control
- Share secrets via email or chat
- Use the same secrets across environments
- Store secrets in plain text files

### 3. Secret Rotation

- Rotate database passwords quarterly
- Rotate API keys when compromised
- Rotate encryption keys annually
- Update admin passwords regularly

## 🚀 Deployment Procedures

### Docker Deployment

1. **Create secure environment file:**
```bash
# Generate secrets
node scripts/generate-secrets.js --env production --output .env.production.secrets

# Copy values to docker environment file
cp .env.production.secrets .env.docker
# Edit .env.docker and add Docker-specific variables
```

2. **Deploy with Docker Compose:**
```bash
# Production deployment
docker-compose -f docker-compose.production.yml up -d

# Verify deployment
docker-compose -f docker-compose.production.yml logs app
```

### Manual Deployment

1. **Prepare environment:**
```bash
# Set NODE_ENV
export NODE_ENV=production

# Load configuration
npm run config:load production

# Validate configuration
npm run config:validate
```

2. **Build and start:**
```bash
# Build application
npm run build

# Start production server
npm start
```

## 🔍 Security Validation

### Configuration Validation

The application includes built-in security validation:

```bash
# Validate current configuration
npm run config:validate

# Load and validate specific environment
npm run config:load production
```

### Security Checklist

- [ ] All CHANGE_ME values replaced
- [ ] All GENERATE_ values replaced
- [ ] Strong passwords (12+ characters, mixed case, numbers, symbols)
- [ ] Unique secrets for each environment
- [ ] Authentication enabled in production
- [ ] SSL/TLS enabled for database connections
- [ ] No secrets committed to version control
- [ ] Configuration validation passes

## 🚨 Incident Response

### If Secrets Are Compromised

1. **Immediate Actions:**
   - Rotate all affected secrets immediately
   - Update all environment files
   - Restart all services
   - Review access logs

2. **Generate New Secrets:**
```bash
# Generate new secrets
node scripts/generate-secrets.js --env production

# Update configuration
# Restart services
```

3. **Audit and Monitor:**
   - Review who had access to compromised secrets
   - Monitor for unauthorized access
   - Update access controls

## 📞 Support

For security-related issues:
1. Check this documentation
2. Validate configuration with `npm run config:validate`
3. Generate new secrets with `node scripts/generate-secrets.js`
4. Review application logs for security warnings

## 🔗 Related Documentation

- [Configuration Guide](CONFIGURATION.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Security Overview](SECURITY.md)
