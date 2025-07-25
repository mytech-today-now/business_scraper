-- Rollback script for initial schema migration
-- Version: 1.0.0
-- Description: Removes all tables, indexes, views, and functions created in 001_initial_schema.sql

-- Drop views first (they depend on tables)
DROP VIEW IF EXISTS business_search;
DROP VIEW IF EXISTS recent_scraping_activity;
DROP VIEW IF EXISTS campaign_summary;

-- Drop triggers
DROP TRIGGER IF EXISTS update_app_settings_updated_at ON app_settings;
DROP TRIGGER IF EXISTS update_scraping_sessions_updated_at ON scraping_sessions;
DROP TRIGGER IF EXISTS update_businesses_updated_at ON businesses;
DROP TRIGGER IF EXISTS update_campaigns_updated_at ON campaigns;

-- Drop the trigger function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes (they will be dropped automatically with tables, but explicit for clarity)
DROP INDEX IF EXISTS idx_app_settings_is_sensitive;
DROP INDEX IF EXISTS idx_app_settings_category;
DROP INDEX IF EXISTS idx_scraping_sessions_completed_at;
DROP INDEX IF EXISTS idx_scraping_sessions_started_at;
DROP INDEX IF EXISTS idx_scraping_sessions_status;
DROP INDEX IF EXISTS idx_scraping_sessions_campaign_id;
DROP INDEX IF EXISTS idx_businesses_coordinates_gin;
DROP INDEX IF EXISTS idx_businesses_address_gin;
DROP INDEX IF EXISTS idx_businesses_name_gin;
DROP INDEX IF EXISTS idx_businesses_email_gin;
DROP INDEX IF EXISTS idx_businesses_confidence_score;
DROP INDEX IF EXISTS idx_businesses_scraped_at;
DROP INDEX IF EXISTS idx_businesses_industry;
DROP INDEX IF EXISTS idx_businesses_name;
DROP INDEX IF EXISTS idx_businesses_campaign_id;
DROP INDEX IF EXISTS idx_campaigns_location_gin;
DROP INDEX IF EXISTS idx_campaigns_created_at;
DROP INDEX IF EXISTS idx_campaigns_industry;
DROP INDEX IF EXISTS idx_campaigns_status;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS app_settings;
DROP TABLE IF EXISTS scraping_sessions;
DROP TABLE IF EXISTS businesses;
DROP TABLE IF EXISTS campaigns;

-- Drop extensions (only if they were created by this migration and not used elsewhere)
-- Note: Be careful with dropping extensions as they might be used by other applications
-- DROP EXTENSION IF EXISTS "pg_trgm";
-- DROP EXTENSION IF EXISTS "uuid-ossp";

-- Note: Extensions are commented out because they might be used by other parts of the system
-- If you're certain they're only used by this application, you can uncomment the lines above
