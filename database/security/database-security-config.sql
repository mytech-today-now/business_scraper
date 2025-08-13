-- Database Security Hardening Configuration
-- Business Scraper Application - PostgreSQL Security Setup
-- This script implements database-level security measures

-- ============================================================================
-- 1. CREATE DEDICATED APPLICATION USER WITH MINIMAL PRIVILEGES
-- ============================================================================

-- Create application user (if not exists)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'business_scraper_app') THEN
        CREATE ROLE business_scraper_app WITH LOGIN PASSWORD 'CHANGE_ME_SECURE_PASSWORD';
        RAISE NOTICE 'Created application user: business_scraper_app';
    ELSE
        RAISE NOTICE 'Application user already exists: business_scraper_app';
    END IF;
END
$$;

-- Create read-only user for reporting/analytics
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'business_scraper_readonly') THEN
        CREATE ROLE business_scraper_readonly WITH LOGIN PASSWORD 'CHANGE_ME_READONLY_PASSWORD';
        RAISE NOTICE 'Created read-only user: business_scraper_readonly';
    ELSE
        RAISE NOTICE 'Read-only user already exists: business_scraper_readonly';
    END IF;
END
$$;

-- ============================================================================
-- 2. REVOKE DEFAULT PERMISSIONS AND GRANT MINIMAL REQUIRED PERMISSIONS
-- ============================================================================

-- Revoke default permissions from public schema
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- Grant minimal permissions to application user
GRANT USAGE ON SCHEMA public TO business_scraper_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO business_scraper_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO business_scraper_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO business_scraper_app;

-- Grant read-only permissions to readonly user
GRANT USAGE ON SCHEMA public TO business_scraper_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO business_scraper_readonly;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO business_scraper_readonly;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO business_scraper_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO business_scraper_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO business_scraper_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO business_scraper_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON SEQUENCES TO business_scraper_readonly;

-- ============================================================================
-- 3. ENABLE ROW LEVEL SECURITY (RLS) FOR SENSITIVE TABLES
-- ============================================================================

-- Enable RLS on businesses table (contains sensitive contact information)
ALTER TABLE businesses ENABLE ROW LEVEL SECURITY;

-- Create policy for application user (full access)
CREATE POLICY businesses_app_policy ON businesses
    FOR ALL
    TO business_scraper_app
    USING (true)
    WITH CHECK (true);

-- Create policy for read-only user (read access only)
CREATE POLICY businesses_readonly_policy ON businesses
    FOR SELECT
    TO business_scraper_readonly
    USING (true);

-- Enable RLS on app_settings table (may contain sensitive configuration)
ALTER TABLE app_settings ENABLE ROW LEVEL SECURITY;

-- Create policy for app_settings
CREATE POLICY app_settings_app_policy ON app_settings
    FOR ALL
    TO business_scraper_app
    USING (true)
    WITH CHECK (true);

CREATE POLICY app_settings_readonly_policy ON app_settings
    FOR SELECT
    TO business_scraper_readonly
    USING (is_sensitive = false); -- Only non-sensitive settings

-- ============================================================================
-- 4. CREATE SECURITY AUDIT FUNCTIONS
-- ============================================================================

-- Function to log security events
CREATE OR REPLACE FUNCTION log_security_event(
    event_type TEXT,
    event_description TEXT,
    user_name TEXT DEFAULT current_user,
    client_ip INET DEFAULT inet_client_addr()
) RETURNS VOID AS $$
BEGIN
    INSERT INTO security_audit_log (
        event_type,
        event_description,
        user_name,
        client_ip,
        event_timestamp
    ) VALUES (
        event_type,
        event_description,
        user_name,
        client_ip,
        NOW()
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create security audit log table
CREATE TABLE IF NOT EXISTS security_audit_log (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    event_description TEXT NOT NULL,
    user_name VARCHAR(100) NOT NULL,
    client_ip INET,
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes for performance
    INDEX idx_security_audit_timestamp (event_timestamp),
    INDEX idx_security_audit_type (event_type),
    INDEX idx_security_audit_user (user_name)
);

-- Grant permissions on audit log
GRANT INSERT ON security_audit_log TO business_scraper_app;
GRANT SELECT ON security_audit_log TO business_scraper_readonly;

-- ============================================================================
-- 5. CREATE TRIGGERS FOR SENSITIVE DATA MONITORING
-- ============================================================================

-- Function to audit sensitive data access
CREATE OR REPLACE FUNCTION audit_sensitive_access() RETURNS TRIGGER AS $$
BEGIN
    -- Log access to sensitive fields
    IF TG_OP = 'SELECT' AND (
        NEW.email IS NOT NULL OR 
        NEW.phone IS NOT NULL OR 
        NEW.contact_person IS NOT NULL
    ) THEN
        PERFORM log_security_event(
            'SENSITIVE_DATA_ACCESS',
            'Access to sensitive business data: ' || NEW.id,
            current_user,
            inet_client_addr()
        );
    END IF;
    
    -- Log modifications to sensitive data
    IF TG_OP IN ('INSERT', 'UPDATE', 'DELETE') THEN
        PERFORM log_security_event(
            'SENSITIVE_DATA_MODIFICATION',
            TG_OP || ' operation on businesses table: ' || COALESCE(NEW.id, OLD.id),
            current_user,
            inet_client_addr()
        );
    END IF;
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create trigger for businesses table
DROP TRIGGER IF EXISTS audit_businesses_trigger ON businesses;
CREATE TRIGGER audit_businesses_trigger
    AFTER INSERT OR UPDATE OR DELETE ON businesses
    FOR EACH ROW EXECUTE FUNCTION audit_sensitive_access();

-- ============================================================================
-- 6. IMPLEMENT CONNECTION SECURITY SETTINGS
-- ============================================================================

-- Set secure connection parameters
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_prefer_server_ciphers = on;
ALTER SYSTEM SET ssl_ciphers = 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384';

-- Set connection limits
ALTER SYSTEM SET max_connections = 100;
ALTER SYSTEM SET superuser_reserved_connections = 3;

-- Set timeout settings
ALTER SYSTEM SET statement_timeout = '30s';
ALTER SYSTEM SET idle_in_transaction_session_timeout = '60s';
ALTER SYSTEM SET tcp_keepalives_idle = 600;
ALTER SYSTEM SET tcp_keepalives_interval = 30;
ALTER SYSTEM SET tcp_keepalives_count = 3;

-- ============================================================================
-- 7. CREATE SECURITY MONITORING VIEWS
-- ============================================================================

-- View for monitoring failed login attempts
CREATE OR REPLACE VIEW failed_login_attempts AS
SELECT 
    user_name,
    client_ip,
    COUNT(*) as attempt_count,
    MAX(event_timestamp) as last_attempt,
    MIN(event_timestamp) as first_attempt
FROM security_audit_log 
WHERE event_type = 'FAILED_LOGIN'
    AND event_timestamp > NOW() - INTERVAL '1 hour'
GROUP BY user_name, client_ip
HAVING COUNT(*) > 3;

-- View for monitoring suspicious query patterns
CREATE OR REPLACE VIEW suspicious_queries AS
SELECT 
    user_name,
    client_ip,
    event_description,
    event_timestamp
FROM security_audit_log 
WHERE event_type = 'SUSPICIOUS_QUERY'
    AND event_timestamp > NOW() - INTERVAL '24 hours'
ORDER BY event_timestamp DESC;

-- Grant access to monitoring views
GRANT SELECT ON failed_login_attempts TO business_scraper_readonly;
GRANT SELECT ON suspicious_queries TO business_scraper_readonly;

-- ============================================================================
-- 8. CREATE SECURITY MAINTENANCE PROCEDURES
-- ============================================================================

-- Procedure to rotate audit logs (keep last 90 days)
CREATE OR REPLACE FUNCTION cleanup_audit_logs() RETURNS VOID AS $$
BEGIN
    DELETE FROM security_audit_log 
    WHERE event_timestamp < NOW() - INTERVAL '90 days';
    
    PERFORM log_security_event(
        'MAINTENANCE',
        'Audit log cleanup completed',
        'system'
    );
END;
$$ LANGUAGE plpgsql;

-- Procedure to check for security violations
CREATE OR REPLACE FUNCTION check_security_violations() RETURNS TABLE(
    violation_type TEXT,
    violation_count BIGINT,
    last_occurrence TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        event_type::TEXT,
        COUNT(*)::BIGINT,
        MAX(event_timestamp)
    FROM security_audit_log 
    WHERE event_timestamp > NOW() - INTERVAL '24 hours'
        AND event_type IN ('FAILED_LOGIN', 'SUSPICIOUS_QUERY', 'UNAUTHORIZED_ACCESS')
    GROUP BY event_type
    HAVING COUNT(*) > 0;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 9. FINAL SECURITY VERIFICATION
-- ============================================================================

-- Log security configuration completion
SELECT log_security_event(
    'SECURITY_CONFIG',
    'Database security hardening configuration completed',
    'system'
);

-- Display security status
DO $$
BEGIN
    RAISE NOTICE '=== DATABASE SECURITY CONFIGURATION COMPLETED ===';
    RAISE NOTICE 'Application user: business_scraper_app (limited privileges)';
    RAISE NOTICE 'Read-only user: business_scraper_readonly (read access only)';
    RAISE NOTICE 'Row Level Security: ENABLED on sensitive tables';
    RAISE NOTICE 'Audit logging: ENABLED for sensitive operations';
    RAISE NOTICE 'Connection security: SSL and timeouts configured';
    RAISE NOTICE 'Monitoring views: Created for security analysis';
    RAISE NOTICE '';
    RAISE NOTICE 'IMPORTANT: Change default passwords before production use!';
    RAISE NOTICE 'IMPORTANT: Review and test all security policies!';
    RAISE NOTICE 'IMPORTANT: Configure SSL certificates for production!';
END
$$;
