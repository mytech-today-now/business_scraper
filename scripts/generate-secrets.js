#!/usr/bin/env node

/**
 * Comprehensive secrets generation utility for the business scraper application
 * Generates all required secrets for secure production deployment
 */

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

/**
 * Generate a cryptographically secure random string
 */
function generateSecureRandom(
  length = 32,
  charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
) {
  let result = ''
  const bytes = crypto.randomBytes(length * 2) // Generate extra bytes for better randomness

  for (let i = 0; i < length; i++) {
    result += charset.charAt(bytes[i] % charset.length)
  }

  return result
}

/**
 * Generate a secure password with mixed character types
 */
function generateSecurePassword(length = 24) {
  const lowercase = 'abcdefghijklmnopqrstuvwxyz'
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const numbers = '0123456789'
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'

  // Ensure at least one character from each type
  let password = ''
  password += lowercase[crypto.randomInt(lowercase.length)]
  password += uppercase[crypto.randomInt(uppercase.length)]
  password += numbers[crypto.randomInt(numbers.length)]
  password += symbols[crypto.randomInt(symbols.length)]

  // Fill the rest with random characters from all sets
  const allChars = lowercase + uppercase + numbers + symbols
  for (let i = 4; i < length; i++) {
    password += allChars[crypto.randomInt(allChars.length)]
  }

  // Shuffle the password
  return password
    .split('')
    .sort(() => crypto.randomInt(3) - 1)
    .join('')
}

/**
 * Generate a hex-encoded encryption key
 */
function generateEncryptionKey(length = 32) {
  return crypto.randomBytes(length).toString('hex')
}

/**
 * Generate JWT secret
 */
function generateJWTSecret(length = 64) {
  return crypto.randomBytes(length).toString('base64url')
}

/**
 * Hash a password using PBKDF2
 */
function hashPassword(password, salt) {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512').toString('hex')
  return { hash, salt: actualSalt }
}

/**
 * Generate all required secrets for an environment
 */
function generateAllSecrets(environment = 'production') {
  console.log(`🔐 Generating secrets for ${environment} environment...`)

  const secrets = {
    // Database credentials
    dbPassword: generateSecurePassword(32),
    postgresPassword: generateSecurePassword(32),
    redisPassword: generateSecurePassword(24),

    // Application secrets
    encryptionKey: generateEncryptionKey(32),
    jwtSecret: generateJWTSecret(64),
    sessionSecret: generateSecureRandom(64),

    // Admin credentials
    adminPassword: generateSecurePassword(20),

    // Monitoring
    grafanaPassword: generateSecurePassword(16),

    // CSP Nonce (for development, production should use dynamic generation)
    cspNonce: generateSecureRandom(16),
  }

  // Hash the admin password
  const adminHash = hashPassword(secrets.adminPassword)
  secrets.adminPasswordHash = adminHash.hash
  secrets.adminPasswordSalt = adminHash.salt

  return secrets
}

/**
 * Display secrets in environment variable format
 */
function displaySecrets(secrets, environment) {
  console.log(`\n📋 Environment Variables for ${environment.toUpperCase()}:`)
  console.log('='.repeat(50))

  console.log('\n# Database Configuration')
  console.log(`DB_PASSWORD=${secrets.dbPassword}`)
  console.log(`POSTGRES_PASSWORD=${secrets.postgresPassword}`)
  console.log(`REDIS_PASSWORD=${secrets.redisPassword}`)

  console.log('\n# Security Configuration')
  console.log(`ENCRYPTION_KEY=${secrets.encryptionKey}`)
  console.log(`JWT_SECRET=${secrets.jwtSecret}`)
  console.log(`SESSION_SECRET=${secrets.sessionSecret}`)

  console.log('\n# Authentication (Use hashed password for production)')
  console.log(`ADMIN_PASSWORD=${secrets.adminPassword}`)
  console.log(`ADMIN_PASSWORD_HASH=${secrets.adminPasswordHash}`)
  console.log(`ADMIN_PASSWORD_SALT=${secrets.adminPasswordSalt}`)

  console.log('\n# Monitoring')
  console.log(`GRAFANA_PASSWORD=${secrets.grafanaPassword}`)

  console.log('\n# Security Headers')
  console.log(`NEXT_PUBLIC_CSP_NONCE=${secrets.cspNonce}`)
}

/**
 * Save secrets to a file
 */
function saveSecretsToFile(secrets, environment, outputPath) {
  const envContent = `# ${environment.toUpperCase()} Environment Secrets
# Generated on: ${new Date().toISOString()}
# 
# ⚠️  CRITICAL SECURITY NOTICE:
# - Store this file securely and never commit to version control
# - Use a proper secret management system in production
# - Rotate these secrets regularly
#

# Database Configuration
DB_PASSWORD=${secrets.dbPassword}
POSTGRES_PASSWORD=${secrets.postgresPassword}
REDIS_PASSWORD=${secrets.redisPassword}

# Security Configuration
ENCRYPTION_KEY=${secrets.encryptionKey}
JWT_SECRET=${secrets.jwtSecret}
SESSION_SECRET=${secrets.sessionSecret}

# Authentication
ADMIN_PASSWORD=${secrets.adminPassword}
ADMIN_PASSWORD_HASH=${secrets.adminPasswordHash}
ADMIN_PASSWORD_SALT=${secrets.adminPasswordSalt}

# Monitoring
GRAFANA_PASSWORD=${secrets.grafanaPassword}

# Security Headers
NEXT_PUBLIC_CSP_NONCE=${secrets.cspNonce}

# Additional Configuration (update as needed)
NODE_ENV=${environment}
ENABLE_AUTH=true
RATE_LIMIT_MAX=100
SCRAPING_RATE_LIMIT=10
`

  fs.writeFileSync(outputPath, envContent)
  console.log(`\n💾 Secrets saved to: ${outputPath}`)
  console.log(`\n⚠️  IMPORTANT SECURITY REMINDERS:`)
  console.log(`   - Never commit this file to version control`)
  console.log(`   - Store securely and restrict access`)
  console.log(`   - Use proper secret management in production`)
  console.log(`   - Rotate secrets regularly`)
}

/**
 * Main function
 */
function main() {
  const args = process.argv.slice(2)

  if (args.includes('--help') || args.includes('-h')) {
    console.log('Business Scraper Secrets Generator')
    console.log('')
    console.log('Usage:')
    console.log('  node scripts/generate-secrets.js [options]')
    console.log('')
    console.log('Options:')
    console.log('  --env <environment>    Environment (development, production, test)')
    console.log('  --output <file>        Output file path')
    console.log("  --display-only         Only display secrets, don't save to file")
    console.log('  --help, -h             Show this help message')
    console.log('')
    console.log('Examples:')
    console.log('  node scripts/generate-secrets.js --env production')
    console.log('  node scripts/generate-secrets.js --env development --output .env.dev.secrets')
    console.log('  node scripts/generate-secrets.js --display-only')
    return
  }

  const envIndex = args.indexOf('--env')
  const environment = envIndex !== -1 ? args[envIndex + 1] : 'production'

  const outputIndex = args.indexOf('--output')
  const outputFile = outputIndex !== -1 ? args[outputIndex + 1] : `.env.${environment}.secrets`

  const displayOnly = args.includes('--display-only')

  console.log('🔐 Business Scraper Secrets Generator')
  console.log('=====================================')

  const secrets = generateAllSecrets(environment)
  displaySecrets(secrets, environment)

  if (!displayOnly) {
    saveSecretsToFile(secrets, environment, outputFile)
  }

  console.log('\n✅ Secret generation complete!')
}

// Run the script
main()
