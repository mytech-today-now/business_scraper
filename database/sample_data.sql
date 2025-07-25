-- Sample data for testing the business scraper database
-- This script inserts sample data for development and testing purposes

-- Insert sample campaigns
INSERT INTO campaigns (id, name, industry, location, status, description, search_radius, search_depth, pages_per_site, zip_code, parameters) VALUES
    (
        uuid_generate_v4(),
        'Downtown Restaurants Campaign',
        'Food & Beverage',
        'Downtown Seattle, WA',
        'active',
        'Scraping restaurants in downtown Seattle area',
        15,
        3,
        5,
        '98101',
        '{"keywords": ["restaurant", "cafe", "bistro"], "exclude_chains": true}'
    ),
    (
        uuid_generate_v4(),
        'Tech Startups Campaign',
        'Technology',
        'San Francisco Bay Area, CA',
        'completed',
        'Finding tech startups in the Bay Area',
        25,
        4,
        7,
        '94105',
        '{"keywords": ["startup", "software", "tech"], "min_employees": 10}'
    ),
    (
        uuid_generate_v4(),
        'Local Retail Stores',
        'Retail',
        'Austin, TX',
        'draft',
        'Local retail businesses in Austin',
        20,
        2,
        3,
        '73301',
        '{"keywords": ["retail", "store", "shop"], "exclude_online_only": true}'
    );

-- Get campaign IDs for foreign key references
DO $$
DECLARE
    restaurant_campaign_id UUID;
    tech_campaign_id UUID;
    retail_campaign_id UUID;
BEGIN
    -- Get campaign IDs
    SELECT id INTO restaurant_campaign_id FROM campaigns WHERE name = 'Downtown Restaurants Campaign';
    SELECT id INTO tech_campaign_id FROM campaigns WHERE name = 'Tech Startups Campaign';
    SELECT id INTO retail_campaign_id FROM campaigns WHERE name = 'Local Retail Stores';

    -- Insert sample businesses for restaurant campaign
    INSERT INTO businesses (campaign_id, name, email, phone, website, address, confidence_score, contact_person, coordinates, industry, business_description, social_media, business_hours) VALUES
        (
            restaurant_campaign_id,
            'The Gourmet Corner',
            ARRAY['info@gourmetcorner.com', 'orders@gourmetcorner.com'],
            '(206) 555-0123',
            'https://www.gourmetcorner.com',
            '{"street": "123 Pine Street", "city": "Seattle", "state": "WA", "zipCode": "98101", "suite": "Suite A"}',
            0.95,
            'Maria Rodriguez',
            '{"lat": 47.6097, "lng": -122.3331}',
            'Fine Dining',
            'Upscale restaurant featuring locally sourced ingredients and seasonal menus',
            '{"facebook": "https://facebook.com/gourmetcorner", "instagram": "@gourmetcorner"}',
            '{"monday": "5:00 PM - 10:00 PM", "tuesday": "5:00 PM - 10:00 PM", "wednesday": "5:00 PM - 10:00 PM", "thursday": "5:00 PM - 10:00 PM", "friday": "5:00 PM - 11:00 PM", "saturday": "5:00 PM - 11:00 PM", "sunday": "Closed"}'
        ),
        (
            restaurant_campaign_id,
            'Cafe Mocha',
            ARRAY['hello@cafemocha.com'],
            '(206) 555-0456',
            'https://www.cafemocha.com',
            '{"street": "456 1st Avenue", "city": "Seattle", "state": "WA", "zipCode": "98101"}',
            0.87,
            'John Smith',
            '{"lat": 47.6062, "lng": -122.3321}',
            'Coffee Shop',
            'Cozy coffee shop with artisanal coffee and fresh pastries',
            '{"instagram": "@cafemocha_seattle", "twitter": "@cafemocha"}',
            '{"monday": "6:00 AM - 6:00 PM", "tuesday": "6:00 AM - 6:00 PM", "wednesday": "6:00 AM - 6:00 PM", "thursday": "6:00 AM - 6:00 PM", "friday": "6:00 AM - 8:00 PM", "saturday": "7:00 AM - 8:00 PM", "sunday": "7:00 AM - 6:00 PM"}'
        );

    -- Insert sample businesses for tech campaign
    INSERT INTO businesses (campaign_id, name, email, phone, website, address, confidence_score, contact_person, coordinates, industry, business_description, employee_count, founded_year) VALUES
        (
            tech_campaign_id,
            'InnovateTech Solutions',
            ARRAY['contact@innovatetech.com', 'hr@innovatetech.com'],
            '(415) 555-0789',
            'https://www.innovatetech.com',
            '{"street": "789 Market Street", "city": "San Francisco", "state": "CA", "zipCode": "94105", "suite": "Floor 15"}',
            0.92,
            'Sarah Chen',
            '{"lat": 37.7749, "lng": -122.4194}',
            'Software Development',
            'AI-powered business automation solutions for enterprise clients',
            45,
            2019
        ),
        (
            tech_campaign_id,
            'DataFlow Analytics',
            ARRAY['info@dataflow.io'],
            '(415) 555-0321',
            'https://www.dataflow.io',
            '{"street": "321 Folsom Street", "city": "San Francisco", "state": "CA", "zipCode": "94107"}',
            0.89,
            'Michael Johnson',
            '{"lat": 37.7849, "lng": -122.4094}',
            'Data Analytics',
            'Real-time data analytics platform for e-commerce businesses',
            23,
            2020
        );

    -- Insert sample scraping sessions
    INSERT INTO scraping_sessions (campaign_id, status, started_at, completed_at, total_urls, successful_scrapes, failed_scrapes, progress_percentage, session_config, user_agent, timeout_ms, max_retries, delay_ms) VALUES
        (
            restaurant_campaign_id,
            'completed',
            CURRENT_TIMESTAMP - INTERVAL '2 hours',
            CURRENT_TIMESTAMP - INTERVAL '1 hour',
            25,
            23,
            2,
            100.00,
            '{"search_terms": ["restaurant", "cafe"], "location": "Seattle, WA"}',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            30000,
            3,
            1000
        ),
        (
            tech_campaign_id,
            'completed',
            CURRENT_TIMESTAMP - INTERVAL '1 day',
            CURRENT_TIMESTAMP - INTERVAL '23 hours',
            50,
            47,
            3,
            100.00,
            '{"search_terms": ["tech startup", "software company"], "location": "San Francisco, CA"}',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            30000,
            3,
            1500
        ),
        (
            retail_campaign_id,
            'running',
            CURRENT_TIMESTAMP - INTERVAL '30 minutes',
            NULL,
            30,
            15,
            1,
            53.33,
            '{"search_terms": ["retail store", "shop"], "location": "Austin, TX"}',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            30000,
            3,
            1200
        );

END $$;

-- Update some app settings with sample API keys (for testing - use fake keys)
UPDATE app_settings SET value = 'test_google_api_key_12345' WHERE key = 'google_maps_api_key';
UPDATE app_settings SET value = 'test_opencage_api_key_67890' WHERE key = 'opencage_api_key';

-- Display sample data summary
DO $$
DECLARE
    campaign_count INTEGER;
    business_count INTEGER;
    session_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO campaign_count FROM campaigns;
    SELECT COUNT(*) INTO business_count FROM businesses;
    SELECT COUNT(*) INTO session_count FROM scraping_sessions;
    
    RAISE NOTICE 'Sample data inserted successfully!';
    RAISE NOTICE 'Campaigns: %', campaign_count;
    RAISE NOTICE 'Businesses: %', business_count;
    RAISE NOTICE 'Scraping Sessions: %', session_count;
END $$;
