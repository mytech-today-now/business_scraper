#!/usr/bin/env node

/**
 * Password generation utility for the business scraper application
 * Generates secure password hashes for production deployment
 */

const crypto = require('crypto')
const readline = require('readline')

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
})

/**
 * Hash a password using PBKDF2
 */
function hashPassword(password, salt) {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex')
  const hash = crypto.pbkdf2Sync(password, actualSalt, 100000, 64, 'sha512').toString('hex')
  return { hash, salt: actualSalt }
}

/**
 * Generate a secure random password
 */
function generateRandomPassword(length = 16) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
  let password = ''

  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length))
  }

  return password
}

/**
 * Validate password strength
 */
function validatePasswordStrength(password) {
  const minLength = 8
  const hasUpperCase = /[A-Z]/.test(password)
  const hasLowerCase = /[a-z]/.test(password)
  const hasNumbers = /\d/.test(password)
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password)

  const issues = []

  if (password.length < minLength) {
    issues.push(`Password must be at least ${minLength} characters long`)
  }

  if (!hasUpperCase) {
    issues.push('Password must contain at least one uppercase letter')
  }

  if (!hasLowerCase) {
    issues.push('Password must contain at least one lowercase letter')
  }

  if (!hasNumbers) {
    issues.push('Password must contain at least one number')
  }

  if (!hasSpecialChar) {
    issues.push('Password must contain at least one special character')
  }

  return {
    isStrong: issues.length === 0,
    issues,
  }
}

/**
 * Main interactive function
 */
async function main() {
  console.log('🔐 Business Scraper Password Generator')
  console.log('=====================================\n')

  const action = await new Promise(resolve => {
    rl.question(
      'Choose an option:\n1. Generate random password\n2. Hash existing password\n\nEnter choice (1 or 2): ',
      resolve
    )
  })

  if (action === '1') {
    // Generate random password
    const lengthInput = await new Promise(resolve => {
      rl.question('Password length (default: 16): ', resolve)
    })

    const length = parseInt(lengthInput) || 16
    const password = generateRandomPassword(length)

    console.log(`\n✅ Generated password: ${password}`)

    const strength = validatePasswordStrength(password)
    if (strength.isStrong) {
      console.log('✅ Password strength: Strong')
    } else {
      console.log('⚠️  Password strength issues:')
      strength.issues.forEach(issue => console.log(`   - ${issue}`))
    }

    // Hash the generated password
    const { hash, salt } = hashPassword(password)

    console.log('\n📋 Environment Variables for Production:')
    console.log('=======================================')
    console.log(`ADMIN_PASSWORD_HASH=${hash}`)
    console.log(`ADMIN_PASSWORD_SALT=${salt}`)
    console.log('\n⚠️  Store the plain password securely and remove it after setup!')
  } else if (action === '2') {
    // Hash existing password
    const password = await new Promise(resolve => {
      rl.question('Enter password to hash: ', resolve)
    })

    if (!password) {
      console.log('❌ Password cannot be empty')
      rl.close()
      return
    }

    const strength = validatePasswordStrength(password)
    if (!strength.isStrong) {
      console.log('\n⚠️  Password strength issues:')
      strength.issues.forEach(issue => console.log(`   - ${issue}`))

      const proceed = await new Promise(resolve => {
        rl.question('\nProceed anyway? (y/N): ', resolve)
      })

      if (proceed.toLowerCase() !== 'y') {
        console.log('❌ Aborted')
        rl.close()
        return
      }
    } else {
      console.log('✅ Password strength: Strong')
    }

    const { hash, salt } = hashPassword(password)

    console.log('\n📋 Environment Variables for Production:')
    console.log('=======================================')
    console.log(`ADMIN_PASSWORD_HASH=${hash}`)
    console.log(`ADMIN_PASSWORD_SALT=${salt}`)
  } else {
    console.log('❌ Invalid choice')
  }

  console.log('\n📝 Usage Instructions:')
  console.log('======================')
  console.log('1. Add the environment variables to your production .env file')
  console.log('2. Remove or comment out ADMIN_PASSWORD')
  console.log('3. Set ENABLE_AUTH=true to enable authentication')
  console.log('4. Restart your application')

  rl.close()
}

// Handle command line arguments
const args = process.argv.slice(2)

if (args.includes('--help') || args.includes('-h')) {
  console.log('Business Scraper Password Generator')
  console.log('')
  console.log('Usage:')
  console.log('  node scripts/generate-password.js          # Interactive mode')
  console.log('  node scripts/generate-password.js --random # Generate random password')
  console.log('  node scripts/generate-password.js --hash <password> # Hash specific password')
  console.log('')
  console.log('Options:')
  console.log('  --random              Generate a random secure password')
  console.log('  --hash <password>     Hash a specific password')
  console.log('  --length <number>     Password length for random generation (default: 16)')
  console.log('  --help, -h            Show this help message')
  process.exit(0)
}

if (args.includes('--random')) {
  const lengthIndex = args.indexOf('--length')
  const length = lengthIndex !== -1 ? parseInt(args[lengthIndex + 1]) || 16 : 16

  const password = generateRandomPassword(length)
  const { hash, salt } = hashPassword(password)

  console.log('Generated Password:', password)
  console.log('Hash:', hash)
  console.log('Salt:', salt)
  console.log('')
  console.log('Environment Variables:')
  console.log(`ADMIN_PASSWORD_HASH=${hash}`)
  console.log(`ADMIN_PASSWORD_SALT=${salt}`)
} else if (args.includes('--hash')) {
  const hashIndex = args.indexOf('--hash')
  const password = args[hashIndex + 1]

  if (!password) {
    console.error('Error: Password required after --hash')
    process.exit(1)
  }

  const { hash, salt } = hashPassword(password)

  console.log('Hash:', hash)
  console.log('Salt:', salt)
  console.log('')
  console.log('Environment Variables:')
  console.log(`ADMIN_PASSWORD_HASH=${hash}`)
  console.log(`ADMIN_PASSWORD_SALT=${salt}`)
} else {
  // Interactive mode
  main().catch(console.error)
}
