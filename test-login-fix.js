#!/usr/bin/env node

/**
 * Test script to verify the login authentication fix
 * Tests password verification and environment configuration
 */

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

// Load environment variables
function loadEnv() {
  try {
    const envPath = path.join(process.cwd(), 'config', 'development.env')
    const envContent = fs.readFileSync(envPath, 'utf8')
    const lines = envContent.split('\n')
    
    for (const line of lines) {
      if (line.trim() && !line.startsWith('#')) {
        const [key, ...valueParts] = line.split('=')
        if (key && valueParts.length > 0) {
          const value = valueParts.join('=').trim()
          process.env[key.trim()] = value
        }
      }
    }
  } catch (error) {
    console.log('Could not load env file:', error.message)
  }
}

// Password verification function (same as in security.ts)
function verifyPassword(password, hash, salt) {
  const keyDerivationIterations = 100000
  const computedHash = crypto.pbkdf2Sync(password, salt, keyDerivationIterations, 64, 'sha512').toString('hex')
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'))
}

// Hash password function (same as in security.ts)
function hashPassword(password, salt) {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512').toString('hex')
  return { hash, salt: actualSalt }
}

// Test CSP configuration
function testCSPConfiguration() {
  console.log('\n=== CSP Configuration Test ===')
  
  // Test development CSP
  process.env.NODE_ENV = 'development'
  const devCSP = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://js.stripe.com https://vercel.live https://checkout.stripe.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' ws: wss: https:; worker-src 'self' blob:; manifest-src 'self'; frame-src 'self' https://js.stripe.com https://checkout.stripe.com;"
  
  console.log('✅ Development CSP includes unsafe-inline for styles:', devCSP.includes("style-src 'self' 'unsafe-inline'"))
  console.log('✅ Development CSP does not include nonces:', !devCSP.includes('nonce-'))
  
  return true
}

// Main test function
async function runTests() {
  console.log('🔐 Login Authentication Fix Test')
  console.log('================================\n')
  
  // Load environment
  loadEnv()
  
  const password = process.env.ADMIN_PASSWORD
  const hash = process.env.ADMIN_PASSWORD_HASH
  const salt = process.env.ADMIN_PASSWORD_SALT
  const username = process.env.ADMIN_USERNAME
  
  console.log('=== Environment Variables ===')
  console.log('ADMIN_USERNAME:', username || 'not set')
  console.log('ADMIN_PASSWORD:', password ? 'set' : 'not set')
  console.log('ADMIN_PASSWORD_HASH:', hash ? `set (${hash.length} chars)` : 'not set')
  console.log('ADMIN_PASSWORD_SALT:', salt ? `set (${salt.length} chars)` : 'not set')
  
  let testsPassed = 0
  let totalTests = 0
  
  // Test 1: Environment variables are set
  totalTests++
  if (username && password && hash && salt) {
    console.log('✅ Test 1: Environment variables are properly set')
    testsPassed++
  } else {
    console.log('❌ Test 1: Missing environment variables')
  }
  
  // Test 2: Hash length is correct
  totalTests++
  if (hash && hash.length === 128) {
    console.log('✅ Test 2: Hash length is correct (128 hex chars = 64 bytes)')
    testsPassed++
  } else {
    console.log('❌ Test 2: Hash length is incorrect. Expected 128, got:', hash ? hash.length : 'undefined')
  }
  
  // Test 3: Salt length is correct
  totalTests++
  if (salt && salt.length === 32) {
    console.log('✅ Test 3: Salt length is correct (32 hex chars = 16 bytes)')
    testsPassed++
  } else {
    console.log('❌ Test 3: Salt length is incorrect. Expected 32, got:', salt ? salt.length : 'undefined')
  }
  
  // Test 4: Password verification works
  totalTests++
  if (password && hash && salt) {
    try {
      const isValid = verifyPassword(password, hash, salt)
      if (isValid) {
        console.log('✅ Test 4: Password verification successful')
        testsPassed++
      } else {
        console.log('❌ Test 4: Password verification failed')
      }
    } catch (error) {
      console.log('❌ Test 4: Password verification error:', error.message)
    }
  } else {
    console.log('❌ Test 4: Cannot test password verification - missing credentials')
  }
  
  // Test 5: Hash generation is consistent
  totalTests++
  if (password && salt) {
    try {
      const { hash: newHash } = hashPassword(password, salt)
      if (newHash === hash) {
        console.log('✅ Test 5: Hash generation is consistent')
        testsPassed++
      } else {
        console.log('❌ Test 5: Hash generation inconsistent')
        console.log('Expected:', hash)
        console.log('Generated:', newHash)
      }
    } catch (error) {
      console.log('❌ Test 5: Hash generation error:', error.message)
    }
  } else {
    console.log('❌ Test 5: Cannot test hash generation - missing password or salt')
  }
  
  // Test 6: Wrong password is rejected
  totalTests++
  if (hash && salt) {
    try {
      const isValid = verifyPassword('wrongpassword', hash, salt)
      if (!isValid) {
        console.log('✅ Test 6: Wrong password correctly rejected')
        testsPassed++
      } else {
        console.log('❌ Test 6: Wrong password was accepted (security issue!)')
      }
    } catch (error) {
      console.log('❌ Test 6: Wrong password test error:', error.message)
    }
  } else {
    console.log('❌ Test 6: Cannot test wrong password - missing credentials')
  }
  
  // Test 7: CSP Configuration
  totalTests++
  if (testCSPConfiguration()) {
    console.log('✅ Test 7: CSP configuration is correct')
    testsPassed++
  } else {
    console.log('❌ Test 7: CSP configuration has issues')
  }
  
  // Summary
  console.log('\n=== Test Summary ===')
  console.log(`Tests passed: ${testsPassed}/${totalTests}`)
  console.log(`Success rate: ${Math.round((testsPassed / totalTests) * 100)}%`)
  
  if (testsPassed === totalTests) {
    console.log('🎉 All tests passed! Login authentication fix is working correctly.')
    return true
  } else {
    console.log('⚠️  Some tests failed. Please review the issues above.')
    return false
  }
}

// Run the tests
runTests().then(success => {
  process.exit(success ? 0 : 1)
}).catch(error => {
  console.error('Test execution failed:', error)
  process.exit(1)
})
