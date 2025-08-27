/**
 * Demo script to show email validation functionality
 * Run with: node demo-email-validation.js
 */

// Simple demonstration of the email validation logic without DNS calls
class EmailValidationDemo {
  constructor() {
    // Common disposable email domains
    this.disposableDomains = new Set([
      'tempmail.org',
      '10minutemail.com',
      'guerrillamail.com',
      'mailinator.com',
      'throwaway.email',
      'yopmail.com',
      'maildrop.cc',
      'sharklasers.com',
    ])

    // Role-based email patterns
    this.roleBasedPatterns = [
      /^(info|contact|sales|support|admin|office|hello|inquiries|service|help|team|general)@/i,
      /^(marketing|hr|careers|jobs|billing|finance|accounting|legal|compliance)@/i,
      /^(webmaster|postmaster|hostmaster|abuse|security|privacy|noreply|no-reply)@/i,
      /^(orders|shipping|returns|customer|clients|partners|vendors|suppliers)@/i,
    ]

    // Enhanced email regex
    this.emailRegex =
      /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  }

  validateSyntax(email) {
    if (!email || email.length > 254) return false

    // Check for basic format
    if (!this.emailRegex.test(email)) return false

    // Additional checks
    const [localPart, domainPart] = email.split('@')

    // Local part checks
    if (localPart.length > 64) return false
    if (localPart.startsWith('.') || localPart.endsWith('.')) return false
    if (localPart.includes('..')) return false

    // Domain part checks
    if (domainPart.length > 253) return false
    if (domainPart.startsWith('-') || domainPart.endsWith('-')) return false

    return true
  }

  isDisposableEmail(domain) {
    return this.disposableDomains.has(domain.toLowerCase())
  }

  isRoleBasedEmail(email) {
    return this.roleBasedPatterns.some(pattern => pattern.test(email))
  }

  extractDomain(email) {
    const parts = email.split('@')
    return parts.length === 2 ? parts[1].toLowerCase() : ''
  }

  calculateDeliverabilityScore(syntaxValid, mxRecords, isDisposable, isRoleBased) {
    let score = 0

    if (syntaxValid) score += 30
    if (mxRecords) score += 40
    if (!isDisposable) score += 20
    if (!isRoleBased) score += 10

    return Math.min(100, Math.max(0, score))
  }

  calculateConfidence(syntaxValid, mxRecords, deliverabilityScore, isDisposable, isRoleBased) {
    // If syntax is invalid, confidence should be 0
    if (!syntaxValid) return 0

    let confidence = deliverabilityScore

    // Adjust confidence based on additional factors
    if (isDisposable) confidence *= 0.3 // Heavily penalize disposable emails
    if (isRoleBased) confidence *= 0.8 // Slightly penalize role-based emails
    if (!mxRecords) confidence *= 0.5 // Penalize no MX records

    return Math.round(Math.min(100, Math.max(0, confidence)))
  }

  validateEmail(email, hasMxRecords = true) {
    const normalizedEmail = email.toLowerCase().trim()
    const domain = this.extractDomain(normalizedEmail)
    const validationTimestamp = new Date().toISOString()
    const errors = []

    // 1. Syntax validation
    const syntaxValid = this.validateSyntax(normalizedEmail)
    if (!syntaxValid) {
      errors.push('Invalid email syntax')
    }

    // 2. Domain validation (simulated)
    const mxRecords = hasMxRecords && syntaxValid
    if (!mxRecords && syntaxValid) {
      errors.push('Domain has no valid MX records')
    }

    // 3. Disposable email detection
    const isDisposable = this.isDisposableEmail(domain)
    if (isDisposable) {
      errors.push('Disposable email domain detected')
    }

    // 4. Role-based email detection
    const isRoleBased = this.isRoleBasedEmail(normalizedEmail)

    // 5. Calculate deliverability score
    const deliverabilityScore = this.calculateDeliverabilityScore(
      syntaxValid,
      mxRecords,
      isDisposable,
      isRoleBased
    )

    // 6. Calculate overall confidence
    const confidence = this.calculateConfidence(
      syntaxValid,
      mxRecords,
      deliverabilityScore,
      isDisposable,
      isRoleBased
    )

    return {
      email: email, // Preserve original case
      isValid: syntaxValid && mxRecords && !isDisposable,
      deliverabilityScore,
      isDisposable,
      isRoleBased,
      domain,
      mxRecords,
      confidence,
      validationTimestamp,
      errors: errors.length > 0 ? errors : undefined,
    }
  }

  demonstrateValidation() {
    console.log('=== Email Validation Service Demo ===\n')

    const testEmails = [
      'john.doe@example.com', // Good personal email
      'info@company.com', // Role-based email
      'sales@business.org', // Role-based email
      'temp@tempmail.org', // Disposable email
      'user@10minutemail.com', // Disposable email
      'invalid-email', // Invalid syntax
      '', // Empty email
      'test@nonexistent.xyz', // No MX records (simulated)
    ]

    testEmails.forEach((email, index) => {
      const hasMxRecords = !email.includes('nonexistent.xyz') && email.includes('@')
      const result = this.validateEmail(email, hasMxRecords)

      console.log(`${index + 1}. Email: "${email}"`)
      console.log(`   Valid: ${result.isValid}`)
      console.log(`   Confidence: ${result.confidence}%`)
      console.log(`   Deliverability Score: ${result.deliverabilityScore}%`)
      console.log(`   Role-based: ${result.isRoleBased}`)
      console.log(`   Disposable: ${result.isDisposable}`)
      console.log(`   MX Records: ${result.mxRecords}`)
      if (result.errors) {
        console.log(`   Errors: ${result.errors.join(', ')}`)
      }
      console.log('')
    })

    // Demonstrate best email selection
    console.log('=== Best Email Selection Demo ===\n')

    const businessEmails = [
      'info@company.com',
      'sales@company.com',
      'john.doe@company.com',
      'temp@tempmail.org',
      'invalid-email',
    ]

    const validationResults = businessEmails.map(email => {
      const hasMxRecords =
        !email.includes('tempmail.org') && email.includes('@') && email !== 'invalid-email'
      return this.validateEmail(email, hasMxRecords)
    })

    console.log('Business Email Validation Results:')
    validationResults.forEach((result, index) => {
      console.log(
        `${index + 1}. ${result.email} - Valid: ${result.isValid}, Confidence: ${result.confidence}%, Role-based: ${result.isRoleBased}, Disposable: ${result.isDisposable}`
      )
    })

    // Find best email
    const validEmails = validationResults.filter(result => result.isValid && !result.isDisposable)

    if (validEmails.length > 0) {
      const bestEmail = validEmails.sort((a, b) => {
        // Prefer non-role-based emails
        if (!a.isRoleBased && b.isRoleBased) return -1
        if (a.isRoleBased && !b.isRoleBased) return 1

        // Then by confidence
        return b.confidence - a.confidence
      })[0]

      console.log(`\nBest Email: ${bestEmail.email} (Confidence: ${bestEmail.confidence}%)`)
    } else {
      console.log('\nNo valid emails found')
    }

    console.log('\n=== Summary ===')
    console.log('✅ Syntax validation with enhanced regex patterns')
    console.log('✅ Disposable email domain detection')
    console.log('✅ Role-based email identification')
    console.log('✅ Confidence scoring (0-100)')
    console.log('✅ Deliverability scoring')
    console.log('✅ Best email selection algorithm')
    console.log('✅ Error reporting and validation metadata')
    console.log('\nSection 2.1.1 implementation is complete! 🎉')
  }
}

// Run the demonstration
const demo = new EmailValidationDemo()
demo.demonstrateValidation()
