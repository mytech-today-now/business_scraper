# Configuration Management Guide

This document provides comprehensive information about the configuration management system for the Business Scraper application.

## Overview

The application uses a centralized configuration management system that:

- **Validates all environment variables** with type checking and constraints
- **Supports multiple environments** (development, production, test)
- **Provides feature flags** for enabling/disabling functionality
- **Includes health checks** for configuration validation
- **Offers flexible caching** with Redis and in-memory options
- **Configurable logging** with multiple formats and outputs

## Configuration Structure

### Application Configuration
```typescript
app: {
  name: string           // Application name
  version: string        // Application version
  environment: string    // Current environment (development/production/test)
  debug: boolean         // Debug mode flag
  port: number          // Server port
}
```

### Database Configuration
```typescript
database: {
  url?: string          // Full database URL (optional)
  host: string          // Database host
  port: number          // Database port
  name: string          // Database name
  user: string          // Database user
  password: string      // Database password
  poolMin: number       // Minimum pool connections
  poolMax: number       // Maximum pool connections
  idleTimeout: number   // Connection idle timeout
  connectionTimeout: number // Connection timeout
  ssl: boolean          // Enable SSL
}
```

### Security Configuration
```typescript
security: {
  enableAuth: boolean           // Enable authentication
  sessionTimeout: number        // Session timeout in ms
  maxLoginAttempts: number      // Max failed login attempts
  lockoutDuration: number       // Account lockout duration in ms
  rateLimitWindow: number       // Rate limit window in ms
  rateLimitMax: number          // Max requests per window
  scrapingRateLimit: number     // Max scraping requests per minute
  adminUsername: string         // Admin username
  adminPassword?: string        // Admin password (dev only)
  adminPasswordHash?: string    // Admin password hash (production)
  adminPasswordSalt?: string    // Admin password salt (production)
}
```

### Feature Flags
```typescript
features: {
  enableAuth: boolean                    // Authentication system
  enableCaching: boolean                 // Caching system
  enableRateLimiting: boolean           // Rate limiting
  enableMetrics: boolean                // Metrics collection
  enableDebugMode: boolean              // Debug mode
  enableExperimentalFeatures: boolean   // Experimental features
}
```

## Environment Files

### Development (`config/development.env`)
- **Authentication**: Disabled by default
- **Database**: Local PostgreSQL
- **Logging**: Debug level with file output
- **Rate Limiting**: Relaxed limits
- **Feature Flags**: Most features enabled for testing

### Production (`config/production.env`)
- **Authentication**: Enabled with secure credentials
- **Database**: Production database with SSL
- **Logging**: Info level with JSON format
- **Rate Limiting**: Strict limits
- **Feature Flags**: Stable features only

### Test (`config/test.env`)
- **Authentication**: Disabled for faster testing
- **Database**: Separate test database
- **Logging**: Minimal logging
- **Rate Limiting**: Very relaxed
- **Feature Flags**: Experimental features enabled

## Configuration Scripts

### Load Configuration
```bash
# Load and validate configuration for specific environment
npm run config:load development
npm run config:load production

# Validate current configuration
npm run config:validate

# Show configuration summary
npm run config:summary
```

### Generate Environment Files
```bash
# Generate .env files from templates
npm run config:dev      # Creates .env.development
npm run config:prod     # Creates .env.production
npm run config:test     # Creates .env.test

# Custom generation
npm run config:generate production .env.custom
```

## Environment Variables

### Required Variables
```env
NODE_ENV=development|production|test
NEXT_PUBLIC_APP_NAME=Business Scraper App
NEXT_PUBLIC_APP_VERSION=1.0.0
```

### Database Variables
```env
# Option 1: Full URL
DATABASE_URL=postgresql://user:pass@host:port/db

# Option 2: Individual settings
DB_HOST=localhost
DB_PORT=5432
DB_NAME=business_scraper_db
DB_USER=postgres
DB_PASSWORD=your_password
DB_SSL=false
```

### Security Variables
```env
# Authentication
ENABLE_AUTH=false
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123                    # Development only
ADMIN_PASSWORD_HASH=your_secure_hash       # Production
ADMIN_PASSWORD_SALT=your_secure_salt       # Production

# Rate Limiting
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX=100
SCRAPING_RATE_LIMIT=10
```

### Feature Flags
```env
FEATURE_ENABLE_CACHING=true
FEATURE_ENABLE_RATE_LIMITING=true
FEATURE_ENABLE_METRICS=false
FEATURE_ENABLE_EXPERIMENTAL=false
```

### Logging Configuration
```env
LOG_LEVEL=info                    # debug|info|warn|error
LOG_FORMAT=text                   # text|json
LOG_ENABLE_CONSOLE=true
LOG_ENABLE_FILE=false
LOG_FILE_PATH=./logs/app.log
```

### Cache Configuration
```env
# Memory Cache (default)
CACHE_TYPE=memory
CACHE_MAX_SIZE=1000
CACHE_TTL=3600000

# Redis Cache
CACHE_TYPE=redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=optional_password
REDIS_DB=0
```

## API Endpoints

### Configuration API
```
GET /api/config                    # Get public configuration
GET /api/config?section=health     # Configuration health check
GET /api/config?section=features   # Feature flags status
GET /api/config?section=validation # Configuration validation
GET /api/config?section=report     # Full configuration report
```

### Health Check API
```
GET /api/health                    # Application health including config
```

## Feature Flag System

### Available Features
- **AUTH**: Authentication and session management
- **CACHING**: Performance caching system
- **RATE_LIMITING**: API rate limiting protection
- **METRICS**: Application metrics collection
- **DEBUG_MODE**: Debug logging and tools
- **EXPERIMENTAL_FEATURES**: Beta and experimental features

### Usage in Code
```typescript
import { Features } from '@/lib/feature-flags'

// Check individual features
if (Features.isAuthEnabled()) {
  // Authentication logic
}

if (Features.isCachingEnabled()) {
  // Use caching
}

// With context
const context = { environment: 'production' }
if (Features.isMetricsEnabled(context)) {
  // Collect metrics
}
```

## Configuration Validation

### Automatic Validation
The system automatically validates:
- **Required variables** are present
- **Data types** are correct (string, number, boolean, URL, port)
- **Value ranges** are within acceptable limits
- **Dependencies** between configuration options
- **Security requirements** for production environments

### Manual Validation
```bash
# Validate current configuration
npm run config:validate

# Load and validate specific environment
npm run config:load production
```

### Health Checks
```bash
# Check configuration health via API
curl http://localhost:3000/api/config?section=health

# Check overall application health
curl http://localhost:3000/api/health
```

## Best Practices

### Development
1. **Use development template**: Start with `config/development.env`
2. **Override locally**: Use `.env.local` for personal settings
3. **Enable debug features**: Set `NEXT_PUBLIC_DEBUG=true`
4. **Use relaxed security**: Disable auth for easier development

### Production
1. **Generate secure credentials**: Use `scripts/generate-password.js`
2. **Enable all security features**: Authentication, rate limiting, SSL
3. **Use environment variables**: Never commit secrets to version control
4. **Monitor configuration**: Set up health check monitoring
5. **Use JSON logging**: Better for log aggregation systems

### Testing
1. **Use test database**: Separate from development data
2. **Disable unnecessary features**: Faster test execution
3. **Use minimal logging**: Reduce test output noise
4. **Enable experimental features**: Test new functionality

## Troubleshooting

### Common Issues

#### Configuration Not Loading
```bash
# Check if config files exist
ls -la config/

# Validate configuration
npm run config:validate

# Check environment variables
npm run config:summary
```

#### Database Connection Issues
```bash
# Check database configuration
npm run config:load | grep -i db

# Test database connection
npm run db:status
```

#### Feature Flags Not Working
```bash
# Check feature flag status
curl http://localhost:3000/api/config?section=features

# Validate feature dependencies
npm run config:validate
```

### Debug Mode
Enable debug mode for detailed logging:
```env
NEXT_PUBLIC_DEBUG=true
LOG_LEVEL=debug
```

### Configuration Report
Generate a comprehensive configuration report:
```bash
# Text report
npm run config:summary

# Markdown report
curl "http://localhost:3000/api/config?section=report&format=markdown" > config-report.md
```

## Security Considerations

### Production Security
1. **Use hashed passwords**: Never use plain text in production
2. **Secure API keys**: Store in secure environment variables
3. **Enable SSL**: For database and external API connections
4. **Rotate credentials**: Regularly update passwords and API keys
5. **Monitor access**: Log configuration access and changes

### Environment Separation
1. **Separate databases**: Different databases per environment
2. **Different API keys**: Use separate keys for dev/prod
3. **Isolated configurations**: No shared credentials between environments

### Secrets Management
1. **Environment variables**: Use secure environment variable systems
2. **Secret management**: Consider using dedicated secret management tools
3. **Access control**: Limit who can access production configurations
4. **Audit logging**: Track configuration changes and access

## Migration Guide

### From Environment Variables
If migrating from direct environment variable usage:

1. **Audit current variables**: List all environment variables in use
2. **Map to new structure**: Use the configuration schema
3. **Update code**: Replace `process.env` with `getConfig()`
4. **Test thoroughly**: Validate all functionality works
5. **Deploy gradually**: Use feature flags for gradual rollout

### Configuration Updates
When updating configuration:

1. **Update templates**: Modify files in `config/` directory
2. **Update validation**: Add new validation rules if needed
3. **Update documentation**: Keep this guide current
4. **Test all environments**: Validate dev, test, and production
5. **Communicate changes**: Inform team of configuration updates

## Support

For configuration-related issues:
1. Check this documentation
2. Run configuration validation: `npm run config:validate`
3. Check application health: `curl http://localhost:3000/api/health`
4. Review logs for configuration errors
5. Contact the development team with specific error messages
