#!/usr/bin/env node

/**
 * Database Security Validation CLI Tool
 * Business Scraper Application - Security Compliance Checker
 * Enhanced with P0 Critical Security Constraints Validation
 */

const { execSync } = require('child_process')
const fs = require('fs')
const path = require('path')

// ANSI color codes for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
}

/**
 * Print colored console output
 */
function colorLog(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`)
}

/**
 * Print section header
 */
function printHeader(title) {
  console.log('\n' + '='.repeat(60))
  colorLog(title, 'cyan')
  console.log('='.repeat(60))
}

/**
 * Print status with appropriate color
 */
function printStatus(status, message) {
  const statusColors = {
    PASS: 'green',
    FAIL: 'red',
    WARNING: 'yellow',
    INFO: 'blue',
  }

  const color = statusColors[status] || 'reset'
  const icon =
    status === 'PASS' ? '✅' : status === 'FAIL' ? '❌' : status === 'WARNING' ? '⚠️' : 'ℹ️'

  colorLog(`${icon} [${status}] ${message}`, color)
}

/**
 * Check if required dependencies are installed
 */
function checkDependencies() {
  printHeader('CHECKING DEPENDENCIES')

  const requiredPackages = ['pg', 'dotenv']
  let allDependenciesOk = true

  for (const pkg of requiredPackages) {
    try {
      require.resolve(pkg)
      printStatus('PASS', `Package ${pkg} is installed`)
    } catch (error) {
      printStatus('FAIL', `Package ${pkg} is missing`)
      allDependenciesOk = false
    }
  }

  return allDependenciesOk
}

/**
 * Check environment configuration
 */
function checkEnvironmentConfig() {
  printHeader('CHECKING ENVIRONMENT CONFIGURATION')

  // Load environment variables
  require('dotenv').config()

  const requiredEnvVars = ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD']

  const optionalEnvVars = ['DB_SSL', 'DB_POOL_MIN', 'DB_POOL_MAX', 'DATABASE_URL']

  let configOk = true

  // Check required variables
  for (const envVar of requiredEnvVars) {
    if (process.env[envVar]) {
      printStatus('PASS', `${envVar} is configured`)
    } else {
      printStatus('FAIL', `${envVar} is missing`)
      configOk = false
    }
  }

  // Check optional variables
  for (const envVar of optionalEnvVars) {
    if (process.env[envVar]) {
      printStatus('INFO', `${envVar} is configured`)
    } else {
      printStatus('WARNING', `${envVar} is not configured (optional)`)
    }
  }

  // Check for weak passwords
  if (process.env.DB_PASSWORD) {
    const password = process.env.DB_PASSWORD
    if (password.length < 12) {
      printStatus('WARNING', 'Database password is shorter than 12 characters')
      configOk = false
    } else if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
      printStatus('WARNING', 'Database password should contain uppercase, lowercase, and numbers')
    } else {
      printStatus('PASS', 'Database password meets complexity requirements')
    }
  }

  // Check SSL configuration
  if (process.env.NODE_ENV === 'production' && process.env.DB_SSL !== 'true') {
    printStatus('WARNING', 'SSL is not enabled in production environment')
  }

  return configOk
}

/**
 * Test database connection
 */
async function testDatabaseConnection() {
  printHeader('TESTING DATABASE CONNECTION')

  try {
    const postgres = require('postgres')

    const connectionString = `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT || 5432}/${process.env.DB_NAME}`

    const sql = postgres(connectionString, {
      ssl: false, // Explicitly disable SSL to solve persistent SSL issues
      max: 1,
      idle_timeout: 30,
      connect_timeout: 5,
    })

    // Test basic connection and query
    const result = await sql`SELECT version()`
    printStatus('PASS', 'Database connection successful')
    printStatus('PASS', `PostgreSQL version: ${result[0].version.split(' ')[1]}`)

    // Check current user
    const userResult = await client.query('SELECT current_user, session_user')
    printStatus('INFO', `Connected as: ${userResult.rows[0].current_user}`)

    // Check if user has superuser privileges
    const superuserResult = await client.query(
      'SELECT usesuper FROM pg_user WHERE usename = current_user'
    )
    if (superuserResult.rows[0]?.usesuper) {
      printStatus(
        'WARNING',
        'Connected user has superuser privileges - consider using dedicated app user'
      )
    } else {
      printStatus('PASS', 'Connected user does not have superuser privileges')
    }

    await sql.end()

    return true
  } catch (error) {
    printStatus('FAIL', `Database connection failed: ${error.message}`)
    return false
  }
}

/**
 * Run database security validation
 */
async function runSecurityValidation() {
  printHeader('RUNNING SECURITY VALIDATION')

  try {
    // Import the validation module
    const validatorPath = path.join(__dirname, '../src/lib/databaseSecurityValidator.ts')

    if (!fs.existsSync(validatorPath)) {
      printStatus('FAIL', 'Database security validator not found')
      return false
    }

    // Since we can't directly import TypeScript in Node.js, we'll run a simplified validation
    printStatus('INFO', 'Running simplified security checks...')

    const { Pool } = require('pg')
    const pool = new Pool({
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      ssl: process.env.DB_SSL === 'true',
    })

    const client = await pool.connect()

    // Check SSL status
    try {
      const sslResult = await client.query('SHOW ssl')
      if (sslResult.rows[0]?.ssl === 'on') {
        printStatus('PASS', 'SSL is enabled')
      } else {
        printStatus('WARNING', 'SSL is not enabled')
      }
    } catch (error) {
      printStatus('WARNING', 'Could not check SSL status')
    }

    // Check for security audit table
    try {
      const auditResult = await client.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
            AND table_name = 'security_audit_log'
        ) as exists
      `)

      if (auditResult.rows[0]?.exists) {
        printStatus('PASS', 'Security audit logging table exists')
      } else {
        printStatus('WARNING', 'Security audit logging table not found')
      }
    } catch (error) {
      printStatus('WARNING', 'Could not check audit logging configuration')
    }

    // Check for RLS on sensitive tables
    try {
      const rlsResult = await client.query(`
        SELECT tablename, rowsecurity 
        FROM pg_tables 
        WHERE schemaname = 'public' 
          AND tablename IN ('businesses', 'app_settings')
      `)

      const tablesWithRLS = rlsResult.rows.filter(row => row.rowsecurity).length
      const totalTables = rlsResult.rows.length

      if (totalTables === 0) {
        printStatus('INFO', 'No sensitive tables found to check RLS')
      } else if (tablesWithRLS === totalTables) {
        printStatus('PASS', 'Row Level Security enabled on all sensitive tables')
      } else {
        printStatus('WARNING', `RLS enabled on ${tablesWithRLS}/${totalTables} sensitive tables`)
      }
    } catch (error) {
      printStatus('WARNING', 'Could not check Row Level Security configuration')
    }

    // Check connection limits
    try {
      const limitsResult = await client.query(`
        SELECT name, setting 
        FROM pg_settings 
        WHERE name IN ('max_connections', 'statement_timeout')
      `)

      const settings = limitsResult.rows.reduce((acc, row) => {
        acc[row.name] = row.setting
        return acc
      }, {})

      const maxConnections = parseInt(settings.max_connections || '0')
      if (maxConnections > 0 && maxConnections <= 200) {
        printStatus('PASS', `Connection limit appropriately set: ${maxConnections}`)
      } else {
        printStatus('WARNING', `Connection limit may be too high: ${maxConnections}`)
      }

      if (settings.statement_timeout && settings.statement_timeout !== '0') {
        printStatus('PASS', `Statement timeout configured: ${settings.statement_timeout}`)
      } else {
        printStatus('WARNING', 'Statement timeout not configured')
      }
    } catch (error) {
      printStatus('WARNING', 'Could not check connection limits')
    }

    await sql.end()

    return true
  } catch (error) {
    printStatus('FAIL', `Security validation failed: ${error.message}`)
    return false
  }
}

/**
 * Check for security configuration files
 */
function checkSecurityFiles() {
  printHeader('CHECKING SECURITY CONFIGURATION FILES')

  const securityFiles = [
    'database/security/database-security-config.sql',
    'src/lib/databaseSecurity.ts',
    'src/lib/secureDatabase.ts',
    'src/lib/databaseSecurityValidator.ts',
  ]

  let allFilesExist = true

  for (const file of securityFiles) {
    const filePath = path.join(__dirname, '..', file)
    if (fs.existsSync(filePath)) {
      printStatus('PASS', `Security file exists: ${file}`)
    } else {
      printStatus('FAIL', `Security file missing: ${file}`)
      allFilesExist = false
    }
  }

  return allFilesExist
}

/**
 * Generate security recommendations
 */
function generateRecommendations() {
  printHeader('SECURITY RECOMMENDATIONS')

  colorLog('📋 Database Security Checklist:', 'bright')
  console.log('')

  const recommendations = [
    '1. Use dedicated application user with minimal privileges',
    '2. Enable SSL/TLS encryption for all connections',
    '3. Set strong, unique passwords for all database accounts',
    '4. Enable Row Level Security (RLS) on sensitive tables',
    '5. Implement audit logging for sensitive operations',
    '6. Configure appropriate connection limits and timeouts',
    '7. Regularly update PostgreSQL to latest stable version',
    '8. Use parameterized queries to prevent SQL injection',
    '9. Implement database backup and recovery procedures',
    '10. Monitor database logs for suspicious activity',
  ]

  recommendations.forEach(rec => {
    colorLog(`   ${rec}`, 'yellow')
  })

  console.log('')
  colorLog('🔧 Next Steps:', 'bright')
  colorLog('   • Run: npm run db:security-setup (to apply security configuration)', 'cyan')
  colorLog('   • Run: npm test -- databaseSecurity.test.ts (to run security tests)', 'cyan')
  colorLog('   • Review: database/security/database-security-config.sql', 'cyan')
  colorLog('   • Monitor: Check security audit logs regularly', 'cyan')
}

/**
 * Main execution function
 */
async function main() {
  colorLog('🔒 Database Security Validation Tool', 'bright')
  colorLog('Business Scraper Application', 'blue')

  let overallStatus = true

  // Run all checks
  overallStatus &= checkDependencies()
  overallStatus &= checkEnvironmentConfig()
  overallStatus &= checkSecurityFiles()
  overallStatus &= await testDatabaseConnection()
  overallStatus &= await runSecurityValidation()

  // Generate final report
  printHeader('VALIDATION SUMMARY')

  if (overallStatus) {
    printStatus('PASS', 'All critical security checks passed')
    colorLog('🎉 Database security validation completed successfully!', 'green')
  } else {
    printStatus('WARNING', 'Some security issues were found')
    colorLog('⚠️  Please review and address the issues above', 'yellow')
  }

  generateRecommendations()

  process.exit(overallStatus ? 0 : 1)
}

// Run the validation
if (require.main === module) {
  main().catch(error => {
    colorLog(`❌ Validation failed: ${error.message}`, 'red')
    process.exit(1)
  })
}

module.exports = {
  checkDependencies,
  checkEnvironmentConfig,
  testDatabaseConnection,
  runSecurityValidation,
  checkSecurityFiles,
}
