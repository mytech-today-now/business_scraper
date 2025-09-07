#!/usr/bin/env node

/**
 * Test password verification for the admin credentials
 * This script helps debug login authentication issues
 */

const crypto = require('crypto')

/**
 * Verify a password against a hash using PBKDF2
 */
function verifyPassword(password, hash, salt) {
  const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
  return computedHash === hash
}

/**
 * Hash a password using PBKDF2
 */
function hashPassword(password, salt) {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512').toString('hex')
  return { hash, salt: actualSalt }
}

// Test credentials from environment
const password = 'Wq+D%xj]O5$$yjVAy4fT'
const hash = '50ea037a8c1f7365ce632efae5ff87e53010d9dbfa756c785cd33573994f7095fa07d4006dee2bb281aa727f7455f0c48d9e1d87c6262dd5bcc5b03004c8168c'
const salt = '5acf2b02b38f79fe378864ea702d1fa6'

console.log('=== Password Verification Test ===')
console.log('Password:', password)
console.log('Salt:', salt)
console.log('Expected Hash:', hash)
console.log('')

// Test verification
const isValid = verifyPassword(password, hash, salt)
console.log('Verification Result:', isValid)

if (!isValid) {
  console.log('')
  console.log('=== Generating Correct Hash ===')
  const correctHash = hashPassword(password, salt)
  console.log('Computed Hash:', correctHash.hash)
  console.log('Expected Hash:', hash)
  console.log('Hashes Match:', correctHash.hash === hash)
  
  if (correctHash.hash !== hash) {
    console.log('')
    console.log('=== Suggested Fix ===')
    console.log('Update your .env file with:')
    console.log(`ADMIN_PASSWORD_HASH=${correctHash.hash}`)
    console.log(`ADMIN_PASSWORD_SALT=${correctHash.salt}`)
  }
}

console.log('')
console.log('=== Testing Alternative Password Formats ===')

// Test with different password formats that might be causing issues
const testPasswords = [
  'Wq+D%xj]O5$$yjVAy4fT',  // Original
  'Wq+D%xj]O5$yjVAy4fT',   // Single $
  'Wq+D%xj]O5\\$\\$yjVAy4fT', // Escaped $
]

testPasswords.forEach((testPwd, index) => {
  const result = verifyPassword(testPwd, hash, salt)
  console.log(`Test ${index + 1} (${testPwd}): ${result}`)
})
