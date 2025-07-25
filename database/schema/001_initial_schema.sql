-- Business Scraper Database Schema
-- Version: 1.0.0
-- Description: Initial schema for single-user business scraper application

-- Enable UUID extension for generating unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pg_trgm extension for text search optimization
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create campaigns table
CREATE TABLE campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100) NOT NULL,
    location VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'paused', 'completed', 'cancelled')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    parameters JSONB DEFAULT '{}',
    
    -- Additional campaign metadata
    description TEXT,
    search_radius INTEGER DEFAULT 25, -- in miles
    search_depth INTEGER DEFAULT 3,
    pages_per_site INTEGER DEFAULT 5,
    zip_code VARCHAR(10),
    
    -- Constraints
    CONSTRAINT campaigns_name_not_empty CHECK (LENGTH(TRIM(name)) > 0),
    CONSTRAINT campaigns_industry_not_empty CHECK (LENGTH(TRIM(industry)) > 0),
    CONSTRAINT campaigns_location_not_empty CHECK (LENGTH(TRIM(location)) > 0),
    CONSTRAINT campaigns_search_radius_positive CHECK (search_radius > 0),
    CONSTRAINT campaigns_search_depth_positive CHECK (search_depth > 0),
    CONSTRAINT campaigns_pages_per_site_positive CHECK (pages_per_site > 0)
);

-- Create businesses table
CREATE TABLE businesses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    email TEXT[], -- Array of email addresses
    phone VARCHAR(50),
    website VARCHAR(500),
    address JSONB NOT NULL DEFAULT '{}', -- Structured address data
    confidence_score DECIMAL(3,2) DEFAULT 0.00 CHECK (confidence_score >= 0.00 AND confidence_score <= 1.00),
    scraped_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Additional business data
    contact_person VARCHAR(255),
    coordinates JSONB, -- {lat: number, lng: number}
    industry VARCHAR(100),
    business_description TEXT,
    social_media JSONB DEFAULT '{}', -- Social media links
    business_hours JSONB DEFAULT '{}', -- Operating hours
    employee_count INTEGER,
    annual_revenue BIGINT,
    founded_year INTEGER,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT businesses_name_not_empty CHECK (LENGTH(TRIM(name)) > 0),
    CONSTRAINT businesses_website_format CHECK (website IS NULL OR website ~ '^https?://'),
    CONSTRAINT businesses_employee_count_positive CHECK (employee_count IS NULL OR employee_count >= 0),
    CONSTRAINT businesses_founded_year_reasonable CHECK (founded_year IS NULL OR (founded_year >= 1800 AND founded_year <= EXTRACT(YEAR FROM CURRENT_DATE)))
);

-- Create scraping_sessions table
CREATE TABLE scraping_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_urls INTEGER DEFAULT 0,
    successful_scrapes INTEGER DEFAULT 0,
    failed_scrapes INTEGER DEFAULT 0,
    errors JSONB DEFAULT '[]', -- Array of error objects
    
    -- Session configuration
    session_config JSONB DEFAULT '{}',
    user_agent VARCHAR(500),
    timeout_ms INTEGER DEFAULT 30000,
    max_retries INTEGER DEFAULT 3,
    delay_ms INTEGER DEFAULT 1000,
    
    -- Progress tracking
    current_url VARCHAR(500),
    progress_percentage DECIMAL(5,2) DEFAULT 0.00 CHECK (progress_percentage >= 0.00 AND progress_percentage <= 100.00),
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT scraping_sessions_total_urls_non_negative CHECK (total_urls >= 0),
    CONSTRAINT scraping_sessions_successful_scrapes_non_negative CHECK (successful_scrapes >= 0),
    CONSTRAINT scraping_sessions_failed_scrapes_non_negative CHECK (failed_scrapes >= 0),
    CONSTRAINT scraping_sessions_timeout_positive CHECK (timeout_ms > 0),
    CONSTRAINT scraping_sessions_max_retries_non_negative CHECK (max_retries >= 0),
    CONSTRAINT scraping_sessions_delay_non_negative CHECK (delay_ms >= 0),
    CONSTRAINT scraping_sessions_completed_after_started CHECK (completed_at IS NULL OR completed_at >= started_at)
);

-- Create app_settings table for storing API keys and configuration
CREATE TABLE app_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(100) NOT NULL UNIQUE,
    value TEXT,
    value_type VARCHAR(20) NOT NULL DEFAULT 'string' CHECK (value_type IN ('string', 'number', 'boolean', 'json')),
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE, -- For API keys and secrets
    category VARCHAR(50) DEFAULT 'general',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT app_settings_key_not_empty CHECK (LENGTH(TRIM(key)) > 0),
    CONSTRAINT app_settings_category_not_empty CHECK (LENGTH(TRIM(category)) > 0)
);

-- Create indexes for performance optimization

-- Campaigns indexes
CREATE INDEX idx_campaigns_status ON campaigns(status);
CREATE INDEX idx_campaigns_industry ON campaigns(industry);
CREATE INDEX idx_campaigns_created_at ON campaigns(created_at);
CREATE INDEX idx_campaigns_location_gin ON campaigns USING GIN (to_tsvector('english', location));

-- Businesses indexes
CREATE INDEX idx_businesses_campaign_id ON businesses(campaign_id);
CREATE INDEX idx_businesses_name ON businesses(name);
CREATE INDEX idx_businesses_industry ON businesses(industry);
CREATE INDEX idx_businesses_scraped_at ON businesses(scraped_at);
CREATE INDEX idx_businesses_confidence_score ON businesses(confidence_score);
CREATE INDEX idx_businesses_email_gin ON businesses USING GIN (email);
CREATE INDEX idx_businesses_name_gin ON businesses USING GIN (to_tsvector('english', name));
CREATE INDEX idx_businesses_address_gin ON businesses USING GIN (address);
CREATE INDEX idx_businesses_coordinates_gin ON businesses USING GIN (coordinates);

-- Scraping sessions indexes
CREATE INDEX idx_scraping_sessions_campaign_id ON scraping_sessions(campaign_id);
CREATE INDEX idx_scraping_sessions_status ON scraping_sessions(status);
CREATE INDEX idx_scraping_sessions_started_at ON scraping_sessions(started_at);
CREATE INDEX idx_scraping_sessions_completed_at ON scraping_sessions(completed_at);

-- App settings indexes
CREATE INDEX idx_app_settings_category ON app_settings(category);
CREATE INDEX idx_app_settings_is_sensitive ON app_settings(is_sensitive);

-- Create triggers for updating updated_at timestamps

-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to tables
CREATE TRIGGER update_campaigns_updated_at BEFORE UPDATE ON campaigns
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_businesses_updated_at BEFORE UPDATE ON businesses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scraping_sessions_updated_at BEFORE UPDATE ON scraping_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_app_settings_updated_at BEFORE UPDATE ON app_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default app settings
INSERT INTO app_settings (key, value, value_type, description, category, is_sensitive) VALUES
    ('app_version', '1.0.0', 'string', 'Application version', 'system', FALSE),
    ('scraping_timeout', '30000', 'number', 'Default scraping timeout in milliseconds', 'scraping', FALSE),
    ('scraping_max_retries', '3', 'number', 'Maximum number of retry attempts for failed scrapes', 'scraping', FALSE),
    ('scraping_delay_ms', '1000', 'number', 'Delay between scraping requests in milliseconds', 'scraping', FALSE),
    ('search_engine_timeout', '10000', 'number', 'Search engine API timeout in milliseconds', 'search', FALSE),
    ('max_search_results', '50', 'number', 'Maximum number of search results to process', 'search', FALSE),
    ('google_maps_api_key', '', 'string', 'Google Maps API key for geocoding', 'api_keys', TRUE),
    ('google_search_api_key', '', 'string', 'Google Custom Search API key', 'api_keys', TRUE),
    ('google_search_engine_id', '', 'string', 'Google Custom Search Engine ID', 'api_keys', TRUE),
    ('opencage_api_key', '', 'string', 'OpenCage API key for geocoding', 'api_keys', TRUE),
    ('bing_search_api_key', '', 'string', 'Bing Search API key', 'api_keys', TRUE),
    ('yandex_search_api_key', '', 'string', 'Yandex Search API key', 'api_keys', TRUE),
    ('default_search_radius', '25', 'number', 'Default search radius in miles', 'search', FALSE),
    ('default_search_depth', '3', 'number', 'Default search depth for web scraping', 'scraping', FALSE),
    ('default_pages_per_site', '5', 'number', 'Default number of pages to scrape per website', 'scraping', FALSE);

-- Create views for common queries

-- Campaign summary view
CREATE VIEW campaign_summary AS
SELECT 
    c.id,
    c.name,
    c.industry,
    c.location,
    c.status,
    c.created_at,
    COUNT(b.id) as total_businesses,
    COUNT(CASE WHEN b.confidence_score >= 0.7 THEN 1 END) as high_confidence_businesses,
    AVG(b.confidence_score) as avg_confidence_score,
    COUNT(ss.id) as total_sessions,
    COUNT(CASE WHEN ss.status = 'completed' THEN 1 END) as completed_sessions
FROM campaigns c
LEFT JOIN businesses b ON c.id = b.campaign_id
LEFT JOIN scraping_sessions ss ON c.id = ss.campaign_id
GROUP BY c.id, c.name, c.industry, c.location, c.status, c.created_at;

-- Recent scraping activity view
CREATE VIEW recent_scraping_activity AS
SELECT 
    ss.id,
    c.name as campaign_name,
    ss.status,
    ss.started_at,
    ss.completed_at,
    ss.total_urls,
    ss.successful_scrapes,
    ss.failed_scrapes,
    ss.progress_percentage,
    CASE 
        WHEN ss.completed_at IS NOT NULL THEN 
            EXTRACT(EPOCH FROM (ss.completed_at - ss.started_at)) / 60
        ELSE 
            EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - ss.started_at)) / 60
    END as duration_minutes
FROM scraping_sessions ss
JOIN campaigns c ON ss.campaign_id = c.id
ORDER BY ss.started_at DESC;

-- Business search view with full-text search capabilities
CREATE VIEW business_search AS
SELECT 
    b.id,
    b.campaign_id,
    c.name as campaign_name,
    b.name,
    b.email,
    b.phone,
    b.website,
    b.address,
    b.industry,
    b.confidence_score,
    b.scraped_at,
    to_tsvector('english', b.name || ' ' || COALESCE(b.industry, '') || ' ' || COALESCE(b.business_description, '')) as search_vector
FROM businesses b
JOIN campaigns c ON b.campaign_id = c.id;

-- Add comments for documentation
COMMENT ON TABLE campaigns IS 'Stores scraping campaign configurations and metadata';
COMMENT ON TABLE businesses IS 'Stores scraped business information and contact details';
COMMENT ON TABLE scraping_sessions IS 'Tracks individual scraping session progress and results';
COMMENT ON TABLE app_settings IS 'Stores application configuration, API keys, and user preferences';

COMMENT ON COLUMN campaigns.parameters IS 'JSON object containing campaign-specific configuration parameters';
COMMENT ON COLUMN businesses.address IS 'JSON object containing structured address information (street, city, state, zip, etc.)';
COMMENT ON COLUMN businesses.coordinates IS 'JSON object containing latitude and longitude coordinates';
COMMENT ON COLUMN businesses.confidence_score IS 'Confidence score (0.00-1.00) indicating data quality and accuracy';
COMMENT ON COLUMN scraping_sessions.errors IS 'JSON array containing error details and debugging information';
COMMENT ON COLUMN app_settings.is_sensitive IS 'Flag indicating if the setting contains sensitive data like API keys';
