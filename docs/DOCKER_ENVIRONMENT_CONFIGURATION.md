# Docker Environment Configuration Guide

## Overview

This guide explains how to configure the Business Scraper application for Docker production deployment. The environment configuration has been optimized for containerized production environments with proper security, networking, and resource management.

## Environment Files Structure

### 1. `.env` (Main Development/Docker Configuration)
- **Purpose**: Primary environment file optimized for Docker production deployment
- **Usage**: Used by default when running Docker containers
- **Configuration**: Production-ready with Docker service names and container networking

### 2. `.env.docker.production.template` (Production Template)
- **Purpose**: Template for production deployments with placeholder values
- **Usage**: Copy to `.env.production` and customize for your environment
- **Security**: Contains placeholder values that must be replaced with real production secrets

### 3. `config/production.env` (Legacy Production Config)
- **Purpose**: Legacy production configuration file
- **Status**: Maintained for backward compatibility
- **Recommendation**: Use `.env.docker.production.template` for new deployments

## Docker Production Deployment

### Quick Start

1. **Copy the production template:**
   ```bash
   cp .env.docker.production.template .env.production
   ```

2. **Update production values:**
   ```bash
   # Edit .env.production with your production secrets
   nano .env.production
   ```

3. **Deploy with Docker Compose:**
   ```bash
   docker-compose -f docker-compose.production.yml --env-file .env.production up -d
   ```

### Environment Variable Categories

#### Application Configuration
```bash
NEXT_PUBLIC_APP_NAME=Business Scraper App
NEXT_PUBLIC_APP_VERSION=1.3.0
NODE_ENV=production
NEXT_PUBLIC_DEBUG=false
PORT=3000
HOSTNAME=0.0.0.0
```

#### Docker Deployment Settings
```bash
DOCKER_DEPLOYMENT=true
CONTAINER_NAME_PREFIX=business-scraper
RESTART_POLICY=unless-stopped
DOCKER_BUILDKIT=1
COMPOSE_DOCKER_CLI_BUILD=1
```

#### Database Configuration (Docker Internal)
```bash
DB_TYPE=postgresql
DB_HOST=postgres                    # Docker service name
DB_PORT=5432
DB_NAME=business_scraper
DB_USER=postgres
DB_PASSWORD=YOUR_SECURE_PASSWORD    # Use Docker secrets
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable
```

#### Redis Cache Configuration (Docker Internal)
```bash
CACHE_TYPE=redis
REDIS_HOST=redis                    # Docker service name
REDIS_PORT=6379
REDIS_PASSWORD=YOUR_SECURE_PASSWORD # Use Docker secrets
REDIS_URL=redis://:${REDIS_PASSWORD}@${REDIS_HOST}:${REDIS_PORT}
```

#### Security & Authentication
```bash
ENABLE_AUTH=true
ADMIN_USERNAME=admin
ADMIN_PASSWORD=YOUR_SECURE_PASSWORD
ADMIN_PASSWORD_HASH=YOUR_GENERATED_HASH
ADMIN_PASSWORD_SALT=YOUR_GENERATED_SALT
ENCRYPTION_KEY=YOUR_32_BYTE_HEX_KEY
JWT_SECRET=YOUR_SECURE_JWT_SECRET
SESSION_SECRET=YOUR_SECURE_SESSION_SECRET
```

#### External API Keys
```bash
AZURE_AI_FOUNDRY_API_KEY=YOUR_PRODUCTION_KEY
GOOGLE_MAPS_API_KEY=YOUR_PRODUCTION_KEY
STRIPE_PUBLISHABLE_KEY=pk_live_YOUR_KEY
STRIPE_SECRET_KEY=sk_live_YOUR_KEY
```

#### Docker Container Configuration
```bash
CONTAINER_CPU_LIMIT=2.0
CONTAINER_MEMORY_LIMIT=4G
CONTAINER_CPU_RESERVATION=1.0
CONTAINER_MEMORY_RESERVATION=2G
```

#### Health Checks
```bash
HEALTH_CHECK_INTERVAL=30s
HEALTH_CHECK_TIMEOUT=10s
HEALTH_CHECK_RETRIES=3
HEALTH_CHECK_START_PERIOD=40s
HEALTH_CHECK_ENDPOINT=/api/health
```

#### Docker Networking
```bash
DOCKER_NETWORK_NAME=app-network
DOCKER_NETWORK_SUBNET=172.20.0.0/16
DOCKER_NETWORK_DRIVER=bridge
```

#### Docker Volumes
```bash
POSTGRES_DATA_VOLUME=postgres-data
REDIS_DATA_VOLUME=redis-data
APP_LOGS_VOLUME=app-logs
APP_UPLOADS_VOLUME=app-uploads
```

## Security Best Practices

### 1. Docker Secrets (Recommended for Production)

Instead of environment variables, use Docker secrets for sensitive data:

```yaml
# docker-compose.production.yml
secrets:
  postgres_password:
    external: true
  redis_password:
    external: true
  encryption_key:
    external: true
```

Create secrets:
```bash
echo "your_secure_password" | docker secret create postgres_password -
echo "your_redis_password" | docker secret create redis_password -
echo "your_encryption_key" | docker secret create encryption_key -
```

### 2. Environment Variable Override

Override sensitive values via environment variables:

```bash
# Set environment variables before deployment
export DB_PASSWORD="your_secure_db_password"
export REDIS_PASSWORD="your_secure_redis_password"
export ADMIN_PASSWORD="your_secure_admin_password"

# Deploy with overrides
docker-compose -f docker-compose.production.yml up -d
```

### 3. External Secret Management

Use external secret management systems:
- AWS Secrets Manager
- Azure Key Vault
- HashiCorp Vault
- Kubernetes Secrets

## Docker Compose Features

### Resource Management
- CPU and memory limits/reservations
- Automatic container restart policies
- Health check monitoring

### Networking
- Custom Docker network with subnet isolation
- Service-to-service communication via service names
- Port mapping for external access

### Data Persistence
- Named volumes for database data
- Application logs and uploads persistence
- Monitoring data retention

### Monitoring Integration
- Prometheus metrics collection
- Grafana dashboards
- Elasticsearch logging
- Health check endpoints

## Deployment Commands

### Development
```bash
# Use default .env file
docker-compose up -d
```

### Production
```bash
# Use production environment file
docker-compose -f docker-compose.production.yml --env-file .env.production up -d
```

### Monitoring
```bash
# View logs
docker-compose -f docker-compose.production.yml logs -f

# Check health
docker-compose -f docker-compose.production.yml ps

# Scale services
docker-compose -f docker-compose.production.yml up -d --scale app=3
```

### Maintenance
```bash
# Update containers
docker-compose -f docker-compose.production.yml pull
docker-compose -f docker-compose.production.yml up -d

# Backup data
docker-compose -f docker-compose.production.yml exec postgres pg_dump -U postgres business_scraper > backup.sql

# Clean up
docker-compose -f docker-compose.production.yml down
docker system prune -f
```

## Troubleshooting

### Common Issues

1. **Container fails to start**
   - Check environment variables are set correctly
   - Verify Docker secrets are created
   - Check container logs: `docker-compose logs app`

2. **Database connection issues**
   - Ensure PostgreSQL container is healthy
   - Verify database credentials
   - Check network connectivity between containers

3. **Redis connection issues**
   - Verify Redis container is running
   - Check Redis password configuration
   - Test connection: `docker-compose exec redis redis-cli ping`

4. **Health check failures**
   - Verify health check endpoint is accessible
   - Check application startup time
   - Review health check configuration

### Debug Commands

```bash
# Check container status
docker-compose -f docker-compose.production.yml ps

# View container logs
docker-compose -f docker-compose.production.yml logs app

# Execute commands in container
docker-compose -f docker-compose.production.yml exec app sh

# Check network connectivity
docker-compose -f docker-compose.production.yml exec app ping postgres

# Monitor resource usage
docker stats
```

## Migration from Development to Production

1. **Update environment variables** from development to production values
2. **Replace API keys** with production keys
3. **Configure external services** (database, Redis, monitoring)
4. **Set up SSL/TLS** for external access
5. **Configure backup strategies** for data persistence
6. **Set up monitoring and alerting**
7. **Test deployment** in staging environment first

## Conclusion

The Docker environment configuration provides a robust, secure, and scalable foundation for production deployment. Follow the security best practices and use the provided templates to ensure a successful production deployment.
