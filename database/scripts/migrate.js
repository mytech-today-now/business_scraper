#!/usr/bin/env node

/**
 * Database Migration Script for Business Scraper
 * Node.js implementation for better integration with the application
 */

const fs = require('fs').promises
const path = require('path')
const { execSync } = require('child_process')
const crypto = require('crypto')

// Configuration
const config = {
  dbName: process.env.DB_NAME || 'business_scraper_db',
  dbUser: process.env.DB_USER || 'postgres',
  dbPassword: process.env.DB_PASSWORD || '',
  dbHost: process.env.DB_HOST || 'localhost',
  dbPort: process.env.DB_PORT || '5432',
}

const scriptDir = __dirname
const databaseDir = path.dirname(scriptDir)
const schemaDir = path.join(databaseDir, 'schema')
const migrationsDir = path.join(databaseDir, 'migrations')

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
}

// Logging functions
const log = {
  info: msg => console.log(`${colors.blue}[INFO]${colors.reset} ${msg}`),
  success: msg => console.log(`${colors.green}[SUCCESS]${colors.reset} ${msg}`),
  warning: msg => console.log(`${colors.yellow}[WARNING]${colors.reset} ${msg}`),
  error: msg => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
}

// Database connection helper
function psqlExec(query, options = {}) {
  const env = {
    ...process.env,
    PGPASSWORD: config.dbPassword,
  }

  const baseCmd = `psql -h ${config.dbHost} -p ${config.dbPort} -U ${config.dbUser} -d ${config.dbName} -v ON_ERROR_STOP=1`

  let cmd
  if (options.file) {
    cmd = `${baseCmd} -f "${options.file}"`
  } else {
    cmd = `${baseCmd} -c "${query}"`
  }

  if (options.silent) {
    cmd += ' > /dev/null 2>&1'
  }

  try {
    const result = execSync(cmd, {
      env,
      encoding: 'utf8',
      stdio: options.silent ? 'pipe' : 'inherit',
    })
    return { success: true, output: result }
  } catch (error) {
    return { success: false, error: error.message }
  }
}

// Check if database exists
function checkDatabase() {
  const env = {
    ...process.env,
    PGPASSWORD: config.dbPassword,
  }

  try {
    const result = execSync(
      `psql -h ${config.dbHost} -p ${config.dbPort} -U ${config.dbUser} -lqt`,
      { env, encoding: 'utf8' }
    )

    if (!result.includes(config.dbName)) {
      log.error(`Database '${config.dbName}' does not exist. Please create it first.`)
      process.exit(1)
    }
  } catch (error) {
    log.error(`Failed to check database: ${error.message}`)
    process.exit(1)
  }
}

// Initialize migration tracking
function initMigrationTracking() {
  log.info('Initializing migration tracking...')
  const trackerFile = path.join(migrationsDir, 'migration_tracker.sql')
  const result = psqlExec(null, { file: trackerFile, silent: true })

  if (result.success) {
    log.success('Migration tracking initialized')
  } else {
    log.warning('Migration tracking may already be initialized')
  }
}

// Check if migration is applied
function isMigrationApplied(version) {
  const result = psqlExec(`SELECT is_migration_applied('${version}');`, { silent: true })
  if (result.success) {
    return result.output.trim().includes('t')
  }
  return false
}

// Calculate file checksum
async function calculateChecksum(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf8')
    return crypto.createHash('md5').update(content).digest('hex')
  } catch (error) {
    return 'unknown'
  }
}

// Apply migration
async function applyMigration(version, name, filePath) {
  log.info(`Applying migration ${version}: ${name}`)

  const startTime = Date.now()
  const result = psqlExec(null, { file: filePath })

  if (result.success) {
    const duration = Date.now() - startTime
    const checksum = await calculateChecksum(filePath)

    // Record migration
    const recordResult = psqlExec(
      `SELECT record_migration('${version}', '${name}', '${checksum}', ${duration});`
    )

    if (recordResult.success) {
      log.success(`Migration ${version} applied successfully (${duration}ms)`)
    } else {
      log.error(`Failed to record migration ${version}`)
      process.exit(1)
    }
  } else {
    log.error(`Failed to apply migration ${version}: ${result.error}`)
    process.exit(1)
  }
}

// Rollback migration
function rollbackMigration(version, name, filePath) {
  log.info(`Rolling back migration ${version}: ${name}`)

  const result = psqlExec(null, { file: filePath })

  if (result.success) {
    // Remove migration record
    const removeResult = psqlExec(`SELECT remove_migration('${version}');`)

    if (removeResult.success) {
      log.success(`Migration ${version} rolled back successfully`)
    } else {
      log.error(`Failed to remove migration record ${version}`)
      process.exit(1)
    }
  } else {
    log.error(`Failed to rollback migration ${version}: ${result.error}`)
    process.exit(1)
  }
}

// Get migration files
async function getMigrationFiles() {
  try {
    const files = await fs.readdir(schemaDir)
    const migrations = []

    for (const file of files) {
      const match = file.match(/^(\d+)_([^_]+)\.sql$/)
      if (match && !file.includes('_rollback')) {
        const version = match[1]
        const name = match[2]
        const filePath = path.join(schemaDir, file)
        migrations.push({ version, name, filePath })
      }
    }

    return migrations.sort((a, b) => parseInt(a.version) - parseInt(b.version))
  } catch (error) {
    log.error(`Failed to read migration files: ${error.message}`)
    return []
  }
}

// Get rollback files
async function getRollbackFiles() {
  try {
    const files = await fs.readdir(schemaDir)
    const rollbacks = []

    for (const file of files) {
      const match = file.match(/^(\d+)_([^_]+)_rollback\.sql$/)
      if (match) {
        const version = match[1]
        const name = match[2]
        const filePath = path.join(schemaDir, file)
        rollbacks.push({ version, name, filePath })
      }
    }

    return rollbacks.sort((a, b) => parseInt(b.version) - parseInt(a.version))
  } catch (error) {
    log.error(`Failed to read rollback files: ${error.message}`)
    return []
  }
}

// Show migration status
function showStatus() {
  log.info('Migration Status:')
  console.log()
  const result = psqlExec(
    'SELECT version, name, status, applied_at, execution_time_ms FROM migration_status ORDER BY version;'
  )

  if (!result.success) {
    log.error('Failed to get migration status')
    process.exit(1)
  }
}

// Migrate up
async function migrateUp(targetVersion) {
  checkDatabase()
  initMigrationTracking()

  log.info('Running migrations...')

  const migrations = await getMigrationFiles()

  if (migrations.length === 0) {
    log.warning('No migration files found')
    return
  }

  for (const migration of migrations) {
    // Skip if target version specified and this version is higher
    if (targetVersion && parseInt(migration.version) > parseInt(targetVersion)) {
      continue
    }

    // Check if already applied
    if (isMigrationApplied(migration.version)) {
      log.info(`Migration ${migration.version} already applied, skipping`)
      continue
    }

    await applyMigration(migration.version, migration.name, migration.filePath)
  }

  log.success('All migrations completed')
}

// Migrate down
async function migrateDown(targetVersion) {
  if (!targetVersion) {
    log.error('Target version required for rollback')
    process.exit(1)
  }

  checkDatabase()

  log.info(`Rolling back to version ${targetVersion}...`)

  const rollbacks = await getRollbackFiles()

  for (const rollback of rollbacks) {
    // Skip if version is target or lower
    if (parseInt(rollback.version) <= parseInt(targetVersion)) {
      continue
    }

    // Check if migration is applied
    if (!isMigrationApplied(rollback.version)) {
      log.info(`Migration ${rollback.version} not applied, skipping rollback`)
      continue
    }

    rollbackMigration(rollback.version, rollback.name, rollback.filePath)
  }

  log.success('Rollback completed')
}

// Reset database
async function resetDatabase() {
  const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout,
  })

  return new Promise(resolve => {
    readline.question(
      'This will drop all tables and reset the database. Are you sure? (y/N) ',
      answer => {
        readline.close()

        if (answer.toLowerCase() === 'y') {
          log.info('Resetting database...')

          const result = psqlExec(`
                    DROP SCHEMA public CASCADE;
                    CREATE SCHEMA public;
                    GRANT ALL ON SCHEMA public TO ${config.dbUser};
                    GRANT ALL ON SCHEMA public TO public;
                `)

          if (result.success) {
            log.success('Database reset completed')
            migrateUp().then(resolve)
          } else {
            log.error('Failed to reset database')
            process.exit(1)
          }
        } else {
          log.info('Reset cancelled')
          resolve()
        }
      }
    )
  })
}

// Show help
function showHelp() {
  console.log('Database Migration Script for Business Scraper')
  console.log()
  console.log('Usage: node migrate.js [command] [options]')
  console.log()
  console.log('Commands:')
  console.log('  up [version]     Apply migrations up to specified version (or all if no version)')
  console.log('  down <version>   Rollback migrations to specified version')
  console.log('  status           Show current migration status')
  console.log('  reset            Reset database and re-apply all migrations')
  console.log('  help             Show this help message')
  console.log()
  console.log('Environment Variables:')
  console.log('  DB_NAME          Database name (default: business_scraper_db)')
  console.log('  DB_USER          Database user (default: postgres)')
  console.log('  DB_PASSWORD      Database password')
  console.log('  DB_HOST          Database host (default: localhost)')
  console.log('  DB_PORT          Database port (default: 5432)')
  console.log()
  console.log('Examples:')
  console.log('  node migrate.js up            # Apply all pending migrations')
  console.log('  node migrate.js up 001        # Apply migrations up to version 001')
  console.log('  node migrate.js down 000      # Rollback all migrations')
  console.log('  node migrate.js status        # Show migration status')
}

// Main execution
async function main() {
  const command = process.argv[2] || 'help'
  const version = process.argv[3]

  switch (command) {
    case 'up':
      await migrateUp(version)
      break
    case 'down':
      await migrateDown(version)
      break
    case 'status':
      showStatus()
      break
    case 'reset':
      await resetDatabase()
      break
    case 'help':
    case '--help':
    case '-h':
      showHelp()
      break
    default:
      log.error(`Unknown command: ${command}`)
      console.log()
      showHelp()
      process.exit(1)
  }
}

// Run the script
if (require.main === module) {
  main().catch(error => {
    log.error(`Migration failed: ${error.message}`)
    process.exit(1)
  })
}

module.exports = {
  migrateUp,
  migrateDown,
  showStatus,
  resetDatabase,
  isMigrationApplied,
}
