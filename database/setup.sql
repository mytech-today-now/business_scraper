-- Business Scraper Database Setup Script
-- This script sets up the complete database for the business scraper application
-- Run this script as a PostgreSQL superuser or database owner

-- Create the database (uncomment if creating a new database)
-- CREATE DATABASE business_scraper_db;
-- \c business_scraper_db;

-- Create a dedicated user for the application (optional, for production)
-- CREATE USER business_scraper_user WITH PASSWORD 'your_secure_password_here';

-- Grant necessary permissions
-- GRANT CONNECT ON DATABASE business_scraper_db TO business_scraper_user;
-- GRANT USAGE ON SCHEMA public TO business_scraper_user;
-- GRANT CREATE ON SCHEMA public TO business_scraper_user;

-- Set up migration tracking first
\i migration_tracker.sql

-- Apply the initial schema migration
\i schema/001_initial_schema.sql

-- Record the migration as applied
SELECT record_migration('001', 'initial_schema', 'manual_setup', NULL);

-- Grant permissions on all tables to the application user (uncomment for production)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO business_scraper_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO business_scraper_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO business_scraper_user;

-- Set default privileges for future tables
-- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO business_scraper_user;
-- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO business_scraper_user;
-- ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO business_scraper_user;

-- Display setup completion message
DO $$
BEGIN
    RAISE NOTICE 'Business Scraper database setup completed successfully!';
    RAISE NOTICE 'Database version: %', (SELECT value FROM app_settings WHERE key = 'app_version');
    RAISE NOTICE 'Tables created: campaigns, businesses, scraping_sessions, app_settings';
    RAISE NOTICE 'Migration tracking enabled';
END $$;
