#!/usr/bin/env node

/**
 * Direct authentication test - bypassing middleware
 */

const dotenv = require('dotenv')
const crypto = require('crypto')

// Load environment variables
dotenv.config({ path: '.env.local' })

// Test credentials
const testUsername = 'admin'
const testPassword = 'Wq+D%xj]O5$$yjVAy4fT'

// Environment variables
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin'
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || ''
const ADMIN_PASSWORD_SALT = process.env.ADMIN_PASSWORD_SALT || ''
const DEFAULT_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'

console.log('=== Direct Authentication Test ===')
console.log('Test Username:', testUsername)
console.log('Test Password:', testPassword)
console.log('')
console.log('Environment Variables:')
console.log('ADMIN_USERNAME:', ADMIN_USERNAME)
console.log('ADMIN_PASSWORD:', DEFAULT_PASSWORD)
console.log('ADMIN_PASSWORD_HASH:', ADMIN_PASSWORD_HASH ? `set (length: ${ADMIN_PASSWORD_HASH.length})` : 'not set')
console.log('ADMIN_PASSWORD_SALT:', ADMIN_PASSWORD_SALT ? `set (length: ${ADMIN_PASSWORD_SALT.length})` : 'not set')
console.log('Actual Hash:', ADMIN_PASSWORD_HASH)
console.log('Actual Salt:', ADMIN_PASSWORD_SALT)
console.log('')

/**
 * Hash a password using PBKDF2 (same as in the application)
 */
function hashPassword(password, salt) {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512').toString('hex')
  return { hash, salt: actualSalt }
}

/**
 * Verify password using PBKDF2 (same as in the application)
 */
function verifyPassword(password, hash, salt) {
  try {
    const { hash: computedHash } = hashPassword(password, salt)
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'))
  } catch (error) {
    console.error('Password verification error:', error)
    return false
  }
}

// Generate a fresh hash for testing
console.log('=== Generating Fresh Hash ===')
const { hash: freshHash, salt: freshSalt } = hashPassword(testPassword)
console.log('Fresh Hash:', freshHash)
console.log('Fresh Hash Length:', freshHash.length)
console.log('Fresh Salt:', freshSalt)
console.log('Fresh Salt Length:', freshSalt.length)
console.log('')

// Test authentication logic (same as in the application)
let isValidCredentials = false

console.log('=== Authentication Logic Test ===')
console.log('Username match:', testUsername === ADMIN_USERNAME)

if (ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT) {
  console.log('Using hashed password verification')
  const hashVerificationResult = verifyPassword(testPassword, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT)
  console.log('Hash verification result:', hashVerificationResult)
  
  isValidCredentials = testUsername === ADMIN_USERNAME && hashVerificationResult
} else {
  console.log('Using plain text password verification')
  isValidCredentials = testUsername === ADMIN_USERNAME && testPassword === DEFAULT_PASSWORD
}

console.log('')
console.log('Final authentication result:', isValidCredentials)

if (isValidCredentials) {
  console.log('✅ Authentication successful!')
} else {
  console.log('❌ Authentication failed!')
}
