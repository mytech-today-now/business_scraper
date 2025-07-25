-- Migration tracking table
-- This table keeps track of applied migrations to prevent duplicate applications

CREATE TABLE IF NOT EXISTS schema_migrations (
    id SERIAL PRIMARY KEY,
    version VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    checksum VARCHAR(64), -- MD5 or SHA256 hash of the migration file
    execution_time_ms INTEGER,
    
    CONSTRAINT schema_migrations_version_not_empty CHECK (LENGTH(TRIM(version)) > 0),
    CONSTRAINT schema_migrations_name_not_empty CHECK (LENGTH(TRIM(name)) > 0)
);

-- Index for quick version lookups
CREATE INDEX IF NOT EXISTS idx_schema_migrations_version ON schema_migrations(version);
CREATE INDEX IF NOT EXISTS idx_schema_migrations_applied_at ON schema_migrations(applied_at);

-- Insert the initial migration record
INSERT INTO schema_migrations (version, name, checksum) 
VALUES ('001', 'initial_schema', 'pending')
ON CONFLICT (version) DO NOTHING;

-- Function to check if a migration has been applied
CREATE OR REPLACE FUNCTION is_migration_applied(migration_version VARCHAR(50))
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM schema_migrations 
        WHERE version = migration_version
    );
END;
$$ LANGUAGE plpgsql;

-- Function to record a successful migration
CREATE OR REPLACE FUNCTION record_migration(
    migration_version VARCHAR(50),
    migration_name VARCHAR(255),
    file_checksum VARCHAR(64) DEFAULT NULL,
    exec_time_ms INTEGER DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO schema_migrations (version, name, checksum, execution_time_ms)
    VALUES (migration_version, migration_name, file_checksum, exec_time_ms)
    ON CONFLICT (version) 
    DO UPDATE SET 
        applied_at = CURRENT_TIMESTAMP,
        checksum = EXCLUDED.checksum,
        execution_time_ms = EXCLUDED.execution_time_ms;
END;
$$ LANGUAGE plpgsql;

-- Function to remove a migration record (for rollbacks)
CREATE OR REPLACE FUNCTION remove_migration(migration_version VARCHAR(50))
RETURNS VOID AS $$
BEGIN
    DELETE FROM schema_migrations WHERE version = migration_version;
END;
$$ LANGUAGE plpgsql;

-- View to show migration status
CREATE OR REPLACE VIEW migration_status AS
SELECT 
    version,
    name,
    applied_at,
    execution_time_ms,
    CASE 
        WHEN applied_at IS NOT NULL THEN 'Applied'
        ELSE 'Pending'
    END as status
FROM schema_migrations
ORDER BY version;
