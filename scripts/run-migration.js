#!/usr/bin/env node

/**
 * Database Migration Runner
 * Handles running and rolling back database migrations for multi-user collaboration
 */

const { Pool } = require('pg')
const fs = require('fs')
const path = require('path')

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'business_scraper',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
}

const pool = new Pool(dbConfig)

// Migration files
const migrations = {
  '001': {
    name: '001_initial_schema',
    file: 'database/schema/001_initial_schema.sql',
    description: 'Initial database schema',
  },
  '002': {
    name: '002_multi_user_collaboration',
    file: 'database/schema/002_multi_user_collaboration.sql',
    description: 'Multi-user collaboration schema',
  },
  '003': {
    name: '003_multi_user_data_migration',
    file: 'database/migrations/003_multi_user_data_migration.sql',
    description: 'Multi-user data migration',
  },
}

const rollbacks = {
  '003': {
    name: 'rollback_003_multi_user_data_migration',
    file: 'database/migrations/rollback_003_multi_user_data_migration.sql',
    description: 'Rollback multi-user data migration',
  },
}

/**
 * Display usage information
 */
function showUsage() {
  console.log(`
Database Migration Runner

Usage:
  node scripts/run-migration.js <command> [options]

Commands:
  migrate [version]     Run migrations (all or specific version)
  rollback <version>    Rollback specific migration
  status               Show migration status
  reset                Reset database (WARNING: destroys all data)
  help                 Show this help message

Examples:
  node scripts/run-migration.js migrate          # Run all migrations
  node scripts/run-migration.js migrate 003      # Run migration 003
  node scripts/run-migration.js rollback 003     # Rollback migration 003
  node scripts/run-migration.js status           # Show current status
  node scripts/run-migration.js reset            # Reset database

Environment Variables:
  DB_HOST              Database host (default: localhost)
  DB_PORT              Database port (default: 5432)
  DB_NAME              Database name (default: business_scraper)
  DB_USER              Database user (default: postgres)
  DB_PASSWORD          Database password (default: password)
  DB_SSL               Use SSL connection (default: false)
`)
}

/**
 * Execute SQL file
 */
async function executeSqlFile(filePath) {
  try {
    const fullPath = path.resolve(filePath)

    if (!fs.existsSync(fullPath)) {
      throw new Error(`Migration file not found: ${fullPath}`)
    }

    const sql = fs.readFileSync(fullPath, 'utf8')
    console.log(`Executing: ${filePath}`)

    const result = await pool.query(sql)
    console.log(`✓ Successfully executed: ${filePath}`)

    return result
  } catch (error) {
    console.error(`✗ Error executing ${filePath}:`, error.message)
    throw error
  }
}

/**
 * Check if migration logs table exists
 */
async function ensureMigrationLogsTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS migration_logs (
        id SERIAL PRIMARY KEY,
        migration_name VARCHAR(255) NOT NULL,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        status VARCHAR(50) DEFAULT 'running',
        error_message TEXT,
        affected_rows INTEGER DEFAULT 0
      )
    `)
  } catch (error) {
    console.error('Error creating migration_logs table:', error.message)
    throw error
  }
}

/**
 * Get migration status
 */
async function getMigrationStatus() {
  try {
    await ensureMigrationLogsTable()

    const result = await pool.query(`
      SELECT 
        migration_name,
        status,
        started_at,
        completed_at,
        affected_rows,
        error_message
      FROM migration_logs 
      ORDER BY started_at DESC
    `)

    return result.rows
  } catch (error) {
    console.error('Error getting migration status:', error.message)
    return []
  }
}

/**
 * Run specific migration
 */
async function runMigration(version) {
  const migration = migrations[version]

  if (!migration) {
    throw new Error(`Migration ${version} not found`)
  }

  console.log(`\nRunning migration ${version}: ${migration.description}`)
  console.log(`File: ${migration.file}`)

  await executeSqlFile(migration.file)

  console.log(`✓ Migration ${version} completed successfully`)
}

/**
 * Run all migrations
 */
async function runAllMigrations() {
  console.log('\nRunning all migrations...')

  const versions = Object.keys(migrations).sort()

  for (const version of versions) {
    await runMigration(version)
  }

  console.log('\n✓ All migrations completed successfully')
}

/**
 * Rollback specific migration
 */
async function rollbackMigration(version) {
  const rollback = rollbacks[version]

  if (!rollback) {
    throw new Error(`Rollback for migration ${version} not found`)
  }

  console.log(`\nRolling back migration ${version}`)
  console.log(`File: ${rollback.file}`)

  const confirm = process.env.FORCE_ROLLBACK === 'true' || process.argv.includes('--force')

  if (!confirm) {
    console.log('\n⚠️  WARNING: This will rollback the migration and may result in data loss!')
    console.log('To proceed, run with --force flag or set FORCE_ROLLBACK=true')
    return
  }

  await executeSqlFile(rollback.file)

  console.log(`✓ Migration ${version} rolled back successfully`)
}

/**
 * Reset database
 */
async function resetDatabase() {
  const confirm = process.env.FORCE_RESET === 'true' || process.argv.includes('--force')

  if (!confirm) {
    console.log('\n⚠️  WARNING: This will destroy ALL data in the database!')
    console.log('To proceed, run with --force flag or set FORCE_RESET=true')
    return
  }

  console.log('\nResetting database...')

  try {
    // Drop all tables
    await pool.query(`
      DROP SCHEMA public CASCADE;
      CREATE SCHEMA public;
      GRANT ALL ON SCHEMA public TO postgres;
      GRANT ALL ON SCHEMA public TO public;
    `)

    console.log('✓ Database reset successfully')
  } catch (error) {
    console.error('✗ Error resetting database:', error.message)
    throw error
  }
}

/**
 * Show migration status
 */
async function showStatus() {
  console.log('\nMigration Status:')
  console.log('================')

  const status = await getMigrationStatus()

  if (status.length === 0) {
    console.log('No migrations have been run yet.')
    return
  }

  status.forEach(migration => {
    const duration =
      migration.completed_at && migration.started_at
        ? `${Math.round((new Date(migration.completed_at) - new Date(migration.started_at)) / 1000)}s`
        : 'N/A'

    console.log(`
Migration: ${migration.migration_name}
Status: ${migration.status}
Started: ${migration.started_at}
Completed: ${migration.completed_at || 'N/A'}
Duration: ${duration}
Affected Rows: ${migration.affected_rows || 0}
${migration.error_message ? `Error: ${migration.error_message}` : ''}
${'─'.repeat(50)}`)
  })
}

/**
 * Main function
 */
async function main() {
  const command = process.argv[2]
  const version = process.argv[3]

  if (!command || command === 'help') {
    showUsage()
    return
  }

  try {
    console.log('Database Migration Runner')
    console.log('========================')
    console.log(`Database: ${dbConfig.database}@${dbConfig.host}:${dbConfig.port}`)

    switch (command) {
      case 'migrate':
        if (version) {
          await runMigration(version)
        } else {
          await runAllMigrations()
        }
        break

      case 'rollback':
        if (!version) {
          throw new Error('Version is required for rollback command')
        }
        await rollbackMigration(version)
        break

      case 'status':
        await showStatus()
        break

      case 'reset':
        await resetDatabase()
        break

      default:
        throw new Error(`Unknown command: ${command}`)
    }
  } catch (error) {
    console.error('\n✗ Migration failed:', error.message)
    process.exit(1)
  } finally {
    await pool.end()
  }
}

// Run if called directly
if (require.main === module) {
  main()
}

module.exports = {
  runMigration,
  runAllMigrations,
  rollbackMigration,
  resetDatabase,
  getMigrationStatus,
}
