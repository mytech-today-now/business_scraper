#!/bin/bash

# Production Database Backup Script
# This script creates backups of the PostgreSQL database

set -e

# Configuration
BACKUP_DIR="./database/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="business_scraper_backup_${TIMESTAMP}.sql"
CONTAINER_NAME="business-scraper-db"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

echo "Starting database backup at $(date)"

# Create backup using docker exec
docker exec "$CONTAINER_NAME" pg_dump -U postgres business_scraper > "$BACKUP_DIR/$BACKUP_FILE"

# Compress the backup
gzip "$BACKUP_DIR/$BACKUP_FILE"

echo "Backup completed: $BACKUP_DIR/${BACKUP_FILE}.gz"

# Clean up old backups (keep last 7 days)
find "$BACKUP_DIR" -name "*.gz" -mtime +7 -delete

echo "Backup process completed at $(date)"
