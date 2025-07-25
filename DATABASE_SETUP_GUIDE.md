# Database Setup Guide - Business Scraper Application

This guide provides step-by-step instructions for setting up the PostgreSQL database for the Business Scraper application.

## Overview

The application supports two database backends:
- **PostgreSQL** (recommended for production)
- **IndexedDB** (client-side storage, development/offline use)

## Prerequisites

### For PostgreSQL Setup
- PostgreSQL 12 or higher installed
- Node.js 16 or higher
- npm or yarn package manager

### Required PostgreSQL Extensions
- `uuid-ossp` (for UUID generation)
- `pg_trgm` (for full-text search optimization)

## Quick Start

### 1. Install Dependencies

The PostgreSQL client library has already been installed:
```bash
npm install pg @types/pg
```

### 2. Create Database

Connect to PostgreSQL as a superuser and create the database:

```sql
-- Connect to PostgreSQL
psql -U postgres

-- Create database
CREATE DATABASE business_scraper_db;

-- Create application user (optional, for production)
CREATE USER business_scraper_user WITH PASSWORD 'your_secure_password';

-- Grant permissions
GRANT CONNECT ON DATABASE business_scraper_db TO business_scraper_user;
GRANT USAGE ON SCHEMA public TO business_scraper_user;
GRANT CREATE ON SCHEMA public TO business_scraper_user;

-- Exit psql
\q
```

### 3. Configure Environment Variables

Copy the example environment file and update with your database credentials:

```bash
cp .env.example .env.local
```

Edit `.env.local` and uncomment/update the database configuration:

```env
# Database Configuration
DATABASE_URL=postgresql://business_scraper_user:your_secure_password@localhost:5432/business_scraper_db
DB_HOST=localhost
DB_PORT=5432
DB_NAME=business_scraper_db
DB_USER=business_scraper_user
DB_PASSWORD=your_secure_password

# Database Connection Pool Settings
DB_POOL_MIN=2
DB_POOL_MAX=10
DB_POOL_IDLE_TIMEOUT=30000
DB_CONNECTION_TIMEOUT=5000
```

### 4. Run Database Setup

Use the automated setup script:

```bash
# Option 1: Using npm script (requires psql in PATH)
npm run db:setup

# Option 2: Manual setup
psql -d business_scraper_db -f database/setup.sql
```

### 5. Verify Installation

Check migration status:

```bash
npm run db:status
```

You should see output showing the initial migration as applied.

### 6. Load Sample Data (Optional)

For development and testing:

```bash
npm run db:sample
```

## Manual Setup Steps

If you prefer to set up the database manually:

### 1. Initialize Migration Tracking

```bash
psql -d business_scraper_db -f database/migrations/migration_tracker.sql
```

### 2. Apply Initial Schema

```bash
psql -d business_scraper_db -f database/schema/001_initial_schema.sql
```

### 3. Record Migration

```sql
psql -d business_scraper_db -c "SELECT record_migration('001', 'initial_schema', 'manual', NULL);"
```

## Database Management

### Migration Commands

```bash
# Apply all pending migrations
npm run db:migrate

# Rollback to specific version
npm run db:migrate:down 000

# Check migration status
npm run db:status

# Reset database (WARNING: destroys all data)
npm run db:reset
```

### Alternative Migration Scripts

For different environments:

```bash
# Linux/macOS
./database/scripts/migrate.sh up

# Windows
database\scripts\migrate.bat up

# Node.js (cross-platform)
node database/scripts/migrate.js up
```

## Database Schema Overview

### Tables Created

1. **campaigns** - Scraping campaign configurations
2. **businesses** - Scraped business data
3. **scraping_sessions** - Session tracking and progress
4. **app_settings** - Application configuration and API keys
5. **schema_migrations** - Migration tracking

### Views Created

1. **campaign_summary** - Aggregated campaign statistics
2. **recent_scraping_activity** - Recent session activity
3. **business_search** - Full-text search optimized view

### Indexes

Comprehensive indexing for:
- Primary/foreign key relationships
- Status and date-based queries
- Full-text search (GIN indexes)
- JSON field queries

## Application Integration

### Using the Database

The application automatically detects the database type based on environment variables:

```typescript
import { getDatabase } from '@/lib/database'

// Get database instance (auto-detects PostgreSQL vs IndexedDB)
const db = await getDatabase()

// Use consistent API regardless of backend
const campaigns = await db.listCampaigns()
const businesses = await db.listBusinesses(campaignId)
```

### Environment-Based Configuration

- **Production**: Set `DATABASE_URL` to use PostgreSQL
- **Development**: Leave `DATABASE_URL` unset to use IndexedDB
- **Testing**: Use separate test database

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Verify PostgreSQL is running
   - Check host/port configuration
   - Ensure database exists

2. **Permission Denied**
   - Verify user has correct permissions
   - Check password in environment variables

3. **Extension Not Found**
   - Install required extensions as superuser:
     ```sql
     CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
     CREATE EXTENSION IF NOT EXISTS "pg_trgm";
     ```

4. **Migration Errors**
   - Check migration status: `npm run db:status`
   - Verify database schema manually
   - Check logs for specific error messages

### Debugging

Enable debug logging by setting:
```env
NEXT_PUBLIC_DEBUG=true
```

Check application logs for database connection and query information.

## Production Deployment

### Security Considerations

1. **Use Strong Passwords**
   - Generate secure passwords for database users
   - Store credentials securely (environment variables, secrets management)

2. **Network Security**
   - Use SSL connections in production
   - Restrict database access to application servers only
   - Configure firewall rules

3. **User Permissions**
   - Create dedicated application user with minimal required permissions
   - Avoid using superuser accounts for application connections

### Performance Optimization

1. **Connection Pooling**
   - Configure appropriate pool sizes based on load
   - Monitor connection usage

2. **Monitoring**
   - Set up database monitoring
   - Track query performance
   - Monitor disk usage and growth

3. **Backups**
   - Implement regular automated backups
   - Test backup restoration procedures
   - Consider point-in-time recovery

### Example Production Configuration

```env
# Production Database Configuration
DATABASE_URL=postgresql://app_user:secure_password@db.example.com:5432/business_scraper_prod?ssl=true
DB_POOL_MIN=5
DB_POOL_MAX=20
DB_POOL_IDLE_TIMEOUT=30000
DB_CONNECTION_TIMEOUT=5000
```

## Backup and Recovery

### Creating Backups

```bash
# Full database backup
pg_dump business_scraper_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Schema only
pg_dump --schema-only business_scraper_db > schema_backup.sql

# Data only
pg_dump --data-only business_scraper_db > data_backup.sql
```

### Restoring Backups

```bash
# Restore full backup
psql business_scraper_db < backup_file.sql

# Restore to new database
createdb business_scraper_restored
psql business_scraper_restored < backup_file.sql
```

## Support

For additional help:

1. Check the database README: `database/README.md`
2. Review migration files in `database/schema/`
3. Examine sample data in `database/sample_data.sql`
4. Check application logs for specific error messages

## Next Steps

After setting up the database:

1. Start the development server: `npm run dev`
2. Test database connectivity through the application
3. Create your first scraping campaign
4. Monitor database performance and optimize as needed
