#!/bin/bash

# Database Migration Script for Business Scraper
# Usage: ./migrate.sh [command] [options]
# Commands: up, down, status, reset

set -e

# Configuration
DB_NAME="${DB_NAME:-business_scraper_db}"
DB_USER="${DB_USER:-postgres}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATABASE_DIR="$(dirname "$SCRIPT_DIR")"
SCHEMA_DIR="$DATABASE_DIR/schema"
MIGRATIONS_DIR="$DATABASE_DIR/migrations"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Database connection function
psql_exec() {
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 "$@"
}

# Check if database exists
check_database() {
    if ! PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
        log_error "Database '$DB_NAME' does not exist. Please create it first."
        exit 1
    fi
}

# Initialize migration tracking
init_migration_tracking() {
    log_info "Initializing migration tracking..."
    if psql_exec -f "$MIGRATIONS_DIR/migration_tracker.sql" > /dev/null 2>&1; then
        log_success "Migration tracking initialized"
    else
        log_warning "Migration tracking may already be initialized"
    fi
}

# Check migration status
check_migration_status() {
    local version="$1"
    local result
    result=$(psql_exec -t -c "SELECT is_migration_applied('$version');" 2>/dev/null | tr -d ' \n')
    echo "$result"
}

# Apply migration
apply_migration() {
    local version="$1"
    local name="$2"
    local file="$3"
    
    log_info "Applying migration $version: $name"
    
    local start_time=$(date +%s%3N)
    
    if psql_exec -f "$file"; then
        local end_time=$(date +%s%3N)
        local duration=$((end_time - start_time))
        
        # Calculate checksum
        local checksum
        if command -v md5sum >/dev/null 2>&1; then
            checksum=$(md5sum "$file" | cut -d' ' -f1)
        elif command -v md5 >/dev/null 2>&1; then
            checksum=$(md5 -q "$file")
        else
            checksum="unknown"
        fi
        
        # Record migration
        psql_exec -c "SELECT record_migration('$version', '$name', '$checksum', $duration);"
        
        log_success "Migration $version applied successfully (${duration}ms)"
    else
        log_error "Failed to apply migration $version"
        exit 1
    fi
}

# Rollback migration
rollback_migration() {
    local version="$1"
    local name="$2"
    local file="$3"
    
    log_info "Rolling back migration $version: $name"
    
    if psql_exec -f "$file"; then
        # Remove migration record
        psql_exec -c "SELECT remove_migration('$version');"
        log_success "Migration $version rolled back successfully"
    else
        log_error "Failed to rollback migration $version"
        exit 1
    fi
}

# Show migration status
show_status() {
    log_info "Migration Status:"
    echo
    psql_exec -c "SELECT version, name, status, applied_at, execution_time_ms FROM migration_status ORDER BY version;"
}

# Migrate up
migrate_up() {
    local target_version="$1"
    
    check_database
    init_migration_tracking
    
    log_info "Running migrations..."
    
    # Find all migration files
    local migrations=()
    while IFS= read -r -d '' file; do
        if [[ "$file" =~ ([0-9]+)_([^_]+)\.sql$ ]] && [[ ! "$file" =~ _rollback\.sql$ ]]; then
            local version="${BASH_REMATCH[1]}"
            local name="${BASH_REMATCH[2]}"
            migrations+=("$version:$name:$file")
        fi
    done < <(find "$SCHEMA_DIR" -name "*.sql" -print0 | sort -z)
    
    if [ ${#migrations[@]} -eq 0 ]; then
        log_warning "No migration files found"
        return
    fi
    
    # Apply migrations
    for migration in "${migrations[@]}"; do
        IFS=':' read -r version name file <<< "$migration"
        
        # Skip if target version specified and this version is higher
        if [ -n "$target_version" ] && [ "$version" -gt "$target_version" ]; then
            continue
        fi
        
        # Check if already applied
        if [ "$(check_migration_status "$version")" = "t" ]; then
            log_info "Migration $version already applied, skipping"
            continue
        fi
        
        apply_migration "$version" "$name" "$file"
    done
    
    log_success "All migrations completed"
}

# Migrate down
migrate_down() {
    local target_version="$1"
    
    check_database
    
    if [ -z "$target_version" ]; then
        log_error "Target version required for rollback"
        exit 1
    fi
    
    log_info "Rolling back to version $target_version..."
    
    # Find rollback files
    local rollbacks=()
    while IFS= read -r -d '' file; do
        if [[ "$file" =~ ([0-9]+)_([^_]+)_rollback\.sql$ ]]; then
            local version="${BASH_REMATCH[1]}"
            local name="${BASH_REMATCH[2]}"
            rollbacks+=("$version:$name:$file")
        fi
    done < <(find "$SCHEMA_DIR" -name "*_rollback.sql" -print0 | sort -rz)
    
    # Apply rollbacks in reverse order
    for rollback in "${rollbacks[@]}"; do
        IFS=':' read -r version name file <<< "$rollback"
        
        # Skip if version is target or lower
        if [ "$version" -le "$target_version" ]; then
            continue
        fi
        
        # Check if migration is applied
        if [ "$(check_migration_status "$version")" = "f" ]; then
            log_info "Migration $version not applied, skipping rollback"
            continue
        fi
        
        rollback_migration "$version" "$name" "$file"
    done
    
    log_success "Rollback completed"
}

# Reset database
reset_database() {
    log_warning "This will drop all tables and reset the database. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        log_info "Resetting database..."
        
        # Drop all tables
        psql_exec -c "
            DROP SCHEMA public CASCADE;
            CREATE SCHEMA public;
            GRANT ALL ON SCHEMA public TO $DB_USER;
            GRANT ALL ON SCHEMA public TO public;
        "
        
        log_success "Database reset completed"
        
        # Re-run migrations
        migrate_up
    else
        log_info "Reset cancelled"
    fi
}

# Show help
show_help() {
    echo "Database Migration Script for Business Scraper"
    echo
    echo "Usage: $0 [command] [options]"
    echo
    echo "Commands:"
    echo "  up [version]     Apply migrations up to specified version (or all if no version)"
    echo "  down <version>   Rollback migrations to specified version"
    echo "  status           Show current migration status"
    echo "  reset            Reset database and re-apply all migrations"
    echo "  help             Show this help message"
    echo
    echo "Environment Variables:"
    echo "  DB_NAME          Database name (default: business_scraper_db)"
    echo "  DB_USER          Database user (default: postgres)"
    echo "  DB_PASSWORD      Database password"
    echo "  DB_HOST          Database host (default: localhost)"
    echo "  DB_PORT          Database port (default: 5432)"
    echo
    echo "Examples:"
    echo "  $0 up            # Apply all pending migrations"
    echo "  $0 up 001        # Apply migrations up to version 001"
    echo "  $0 down 000      # Rollback all migrations"
    echo "  $0 status        # Show migration status"
}

# Main script logic
case "${1:-help}" in
    up)
        migrate_up "$2"
        ;;
    down)
        migrate_down "$2"
        ;;
    status)
        show_status
        ;;
    reset)
        reset_database
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        echo
        show_help
        exit 1
        ;;
esac
