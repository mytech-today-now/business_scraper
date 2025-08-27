# Business Scraper Database Schema

This directory contains the PostgreSQL database schema and migration files for
the Business Scraper application.

## Overview

The database is designed for a single-user business scraper application that
manages scraping campaigns, stores business data, tracks scraping sessions, and
maintains application settings.

## Database Structure

### Tables

#### 1. `campaigns`

Stores scraping campaign configurations and metadata.

**Key Fields:**

- `id` (UUID): Primary key
- `name` (VARCHAR): Campaign name
- `industry` (VARCHAR): Target industry
- `location` (VARCHAR): Geographic location
- `status` (VARCHAR): Campaign status (draft, active, paused, completed,
  cancelled)
- `parameters` (JSONB): Campaign-specific configuration
- `search_radius`, `search_depth`, `pages_per_site`: Scraping parameters

#### 2. `businesses`

Stores scraped business information and contact details.

**Key Fields:**

- `id` (UUID): Primary key
- `campaign_id` (UUID): Foreign key to campaigns
- `name` (VARCHAR): Business name
- `email` (TEXT[]): Array of email addresses
- `phone`, `website`: Contact information
- `address` (JSONB): Structured address data
- `confidence_score` (DECIMAL): Data quality score (0.00-1.00)
- `coordinates` (JSONB): Latitude/longitude coordinates

#### 3. `scraping_sessions`

Tracks individual scraping session progress and results.

**Key Fields:**

- `id` (UUID): Primary key
- `campaign_id` (UUID): Foreign key to campaigns
- `status` (VARCHAR): Session status (pending, running, completed, failed,
  cancelled)
- `total_urls`, `successful_scrapes`, `failed_scrapes`: Progress metrics
- `errors` (JSONB): Error details and debugging information
- `session_config` (JSONB): Session-specific configuration

#### 4. `app_settings`

Stores application configuration, API keys, and user preferences.

**Key Fields:**

- `id` (UUID): Primary key
- `key` (VARCHAR): Setting key (unique)
- `value` (TEXT): Setting value
- `value_type` (VARCHAR): Data type (string, number, boolean, json)
- `is_sensitive` (BOOLEAN): Flag for sensitive data like API keys
- `category` (VARCHAR): Setting category for organization

### Views

#### 1. `campaign_summary`

Provides aggregated campaign statistics including business counts and confidence
scores.

#### 2. `recent_scraping_activity`

Shows recent scraping sessions with duration and progress information.

#### 3. `business_search`

Optimized view for full-text search across business data.

### Indexes

The schema includes comprehensive indexes for:

- Primary and foreign key relationships
- Status and date-based queries
- Full-text search capabilities (using GIN indexes)
- JSON field queries

## Setup Instructions

### Prerequisites

- PostgreSQL 12 or higher
- Extensions: `uuid-ossp`, `pg_trgm`

### Installation

1. **Create Database:**

   ```sql
   CREATE DATABASE business_scraper_db;
   \c business_scraper_db;
   ```

2. **Run Setup Script:**
   ```bash
   psql -d business_scraper_db -f database/setup.sql
   ```

### Manual Migration

If you prefer to run migrations manually:

1. **Set up migration tracking:**

   ```bash
   psql -d business_scraper_db -f database/migrations/migration_tracker.sql
   ```

2. **Apply initial schema:**

   ```bash
   psql -d business_scraper_db -f database/schema/001_initial_schema.sql
   ```

3. **Record migration:**
   ```sql
   SELECT record_migration('001', 'initial_schema', 'manual', NULL);
   ```

## Migration Management

The database includes a migration tracking system:

- `schema_migrations` table tracks applied migrations
- Helper functions for migration management
- Rollback scripts for each migration

### Available Functions

- `is_migration_applied(version)`: Check if migration is applied
- `record_migration(version, name, checksum, exec_time)`: Record successful
  migration
- `remove_migration(version)`: Remove migration record (for rollbacks)

### Rollback

To rollback the initial schema:

```bash
psql -d business_scraper_db -f database/schema/001_initial_schema_rollback.sql
```

## Configuration

### Environment Variables

The application expects these database-related environment variables:

```env
# Database Connection
DATABASE_URL=postgresql://username:password@localhost:5432/business_scraper_db
DB_HOST=localhost
DB_PORT=5432
DB_NAME=business_scraper_db
DB_USER=business_scraper_user
DB_PASSWORD=your_secure_password

# Connection Pool Settings
DB_POOL_MIN=2
DB_POOL_MAX=10
DB_POOL_IDLE_TIMEOUT=30000
```

### Default Settings

The schema includes default application settings:

- Scraping timeouts and retry limits
- Search engine configurations
- API key placeholders
- Default search parameters

## Security Considerations

1. **Sensitive Data**: API keys and sensitive settings are flagged with
   `is_sensitive = TRUE`
2. **User Permissions**: Create dedicated database user with minimal required
   permissions
3. **Connection Security**: Use SSL connections in production
4. **Data Encryption**: Consider encrypting sensitive fields at application
   level

## Performance Optimization

The schema includes several performance optimizations:

1. **Indexes**: Comprehensive indexing strategy for common queries
2. **JSONB**: Efficient storage and querying of structured data
3. **Views**: Pre-optimized queries for common operations
4. **Triggers**: Automatic timestamp updates

## Monitoring and Maintenance

### Useful Queries

**Check migration status:**

```sql
SELECT * FROM migration_status;
```

**Campaign performance:**

```sql
SELECT * FROM campaign_summary;
```

**Recent activity:**

```sql
SELECT * FROM recent_scraping_activity LIMIT 10;
```

**Database statistics:**

```sql
SELECT
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes
FROM pg_stat_user_tables;
```

## Backup and Recovery

### Backup

```bash
pg_dump business_scraper_db > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Restore

```bash
psql business_scraper_db < backup_file.sql
```

## Future Migrations

When adding new migrations:

1. Create new migration file: `database/schema/002_migration_name.sql`
2. Create corresponding rollback:
   `database/schema/002_migration_name_rollback.sql`
3. Update version in migration tracker
4. Test thoroughly before applying to production

## Support

For issues or questions regarding the database schema:

1. Check the migration status and logs
2. Verify all required extensions are installed
3. Ensure proper permissions are set
4. Check the database schema documentation for expected data formats
