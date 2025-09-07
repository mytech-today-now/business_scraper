#!/usr/bin/env node

/**
 * Test password verification for debugging authentication issues
 */

const crypto = require('crypto')
const dotenv = require('dotenv')

// Load environment variables from .env.local
dotenv.config({ path: '.env.local' })

// Test password and credentials
const testPassword = 'Wq+D%xj]O5$$yjVAy4fT'

// Generate a fresh hash and salt
console.log('=== Generating Fresh Hash ===')
const { hash: freshHash, salt: freshSalt } = hashPassword(testPassword)
console.log('Fresh Hash:', freshHash)
console.log('Fresh Salt:', freshSalt)
console.log('')

// Use environment variables if available, otherwise use fresh values
const testHash = process.env.ADMIN_PASSWORD_HASH || freshHash
const testSalt = process.env.ADMIN_PASSWORD_SALT || freshSalt

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

console.log('=== Password Verification Test ===')
console.log('Test Password:', testPassword)
console.log('Expected Hash:', testHash)
console.log('Expected Hash Length:', testHash.length)
console.log('Salt:', testSalt)
console.log('Salt Length:', testSalt.length)
console.log('')

// Test verification
const isValid = verifyPassword(testPassword, testHash, testSalt)
console.log('Verification Result:', isValid)

if (isValid) {
  console.log('✅ Password verification successful!')
} else {
  console.log('❌ Password verification failed!')
  
  // Generate new hash for comparison
  const { hash: newHash } = hashPassword(testPassword, testSalt)
  console.log('Generated Hash:', newHash)
  console.log('Generated Hash Length:', newHash.length)
  console.log('Hashes match:', newHash === testHash)
}

// Test environment variables
console.log('\n=== Environment Variables ===')
console.log('ADMIN_USERNAME:', process.env.ADMIN_USERNAME || 'not set')
console.log('ADMIN_PASSWORD:', process.env.ADMIN_PASSWORD || 'not set')
console.log('ADMIN_PASSWORD_HASH:', process.env.ADMIN_PASSWORD_HASH ? 'set' : 'not set')
console.log('ADMIN_PASSWORD_SALT:', process.env.ADMIN_PASSWORD_SALT ? 'set' : 'not set')
console.log('NODE_ENV:', process.env.NODE_ENV || 'not set')
