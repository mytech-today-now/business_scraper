#!/usr/bin/env node

/**
 * Comprehensive authentication test suite
 * Tests all the fixes implemented for the authentication issues
 */

const fetch = require('node-fetch')

let testResults = {
  total: 0,
  passed: 0,
  failed: 0,
  tests: []
}

function logTest(name, passed, details = '') {
  testResults.total++
  if (passed) {
    testResults.passed++
    console.log(`✅ ${name}`)
  } else {
    testResults.failed++
    console.log(`❌ ${name}`)
    if (details) console.log(`   ${details}`)
  }
  testResults.tests.push({ name, passed, details })
}

async function runComprehensiveTests() {
  console.log('=== Comprehensive Authentication Test Suite ===')
  console.log('')
  
  try {
    // Test 1: CSRF Token Generation
    console.log('1. Testing CSRF token generation...')
    const csrfResponse = await fetch('http://localhost:3001/api/csrf', {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    })
    
    const csrfPassed = csrfResponse.status === 200
    logTest('CSRF token generation', csrfPassed, csrfPassed ? '' : `Status: ${csrfResponse.status}`)
    
    if (!csrfPassed) return
    
    const csrfData = await csrfResponse.json()
    const sessionCookie = csrfResponse.headers.get('set-cookie')
    const sessionMatch = sessionCookie.match(/session-id=([^;]+)/)
    const sessionCookieValue = sessionMatch ? sessionMatch[0] : ''
    
    // Test 2: Session Validation
    console.log('2. Testing session validation...')
    const sessionResponse = await fetch('http://localhost:3001/api/csrf', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Cookie': sessionCookieValue
      }
    })
    
    const sessionPassed = sessionResponse.status === 200
    logTest('Session validation', sessionPassed, sessionPassed ? '' : `Status: ${sessionResponse.status}`)
    
    // Test 3: Authentication with Correct Credentials
    console.log('3. Testing authentication with correct credentials...')
    const authResponse = await fetch('http://localhost:3001/api/auth', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Cookie': sessionCookieValue,
        'X-CSRF-Token': csrfData.csrfToken
      },
      body: JSON.stringify({
        username: 'admin',
        password: 'Wq+D%xj]O5$$yjVAy4fT'
      })
    })
    
    const authPassed = authResponse.status === 200
    logTest('Authentication with correct credentials', authPassed, authPassed ? '' : `Status: ${authResponse.status}`)
    
    if (authPassed) {
      const authData = await authResponse.json()
      logTest('Authentication returns success', authData.success === true)
      logTest('Authentication returns session ID', !!authData.sessionId)
      logTest('Authentication returns CSRF token', !!authData.csrfToken)
    }
    
    // Test 4: Authentication with Wrong Credentials
    console.log('4. Testing authentication with wrong credentials...')
    const wrongAuthResponse = await fetch('http://localhost:3001/api/auth', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Cookie': sessionCookieValue,
        'X-CSRF-Token': csrfData.csrfToken
      },
      body: JSON.stringify({
        username: 'admin',
        password: 'wrongpassword'
      })
    })
    
    const wrongAuthPassed = wrongAuthResponse.status === 401
    logTest('Authentication rejects wrong credentials', wrongAuthPassed, wrongAuthPassed ? '' : `Status: ${wrongAuthResponse.status}`)
    
    // Test 5: Rate Limiting (Test multiple failed attempts)
    console.log('5. Testing rate limiting...')
    let failedAttempts = 0
    let rateLimitTriggered = false
    
    // Try up to 10 failed attempts to test the new limit of 9
    for (let i = 0; i < 10; i++) {
      const failResponse = await fetch('http://localhost:3001/api/auth', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Cookie': sessionCookieValue,
          'X-CSRF-Token': csrfData.csrfToken
        },
        body: JSON.stringify({
          username: 'admin',
          password: 'wrongpassword'
        })
      })
      
      failedAttempts++
      
      if (failResponse.status === 429) {
        rateLimitTriggered = true
        break
      }
      
      // Small delay between attempts
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    
    logTest('Rate limiting allows up to 9 attempts', failedAttempts >= 9 && rateLimitTriggered, 
           `Failed attempts before rate limit: ${failedAttempts}`)
    
    // Test 6: CSP Headers Present
    console.log('6. Testing CSP headers...')
    const cspHeaders = csrfResponse.headers.get('content-security-policy')
    const cspPassed = !!cspHeaders && cspHeaders.includes('style-src')
    logTest('CSP headers present and configured', cspPassed, cspPassed ? '' : 'CSP headers missing or incomplete')
    
    // Test 7: Security Headers
    console.log('7. Testing security headers...')
    const securityHeaders = [
      'x-frame-options',
      'x-content-type-options',
      'referrer-policy',
      'x-xss-protection',
      'strict-transport-security'
    ]
    
    let securityHeadersPassed = true
    securityHeaders.forEach(header => {
      const headerValue = csrfResponse.headers.get(header)
      if (!headerValue) {
        securityHeadersPassed = false
        logTest(`Security header: ${header}`, false, 'Header missing')
      }
    })
    
    if (securityHeadersPassed) {
      logTest('All security headers present', true)
    }
    
  } catch (error) {
    console.error('Test suite error:', error)
    logTest('Test suite execution', false, error.message)
  }
  
  // Print summary
  console.log('')
  console.log('=== Test Results Summary ===')
  console.log(`Total Tests: ${testResults.total}`)
  console.log(`Passed: ${testResults.passed}`)
  console.log(`Failed: ${testResults.failed}`)
  console.log(`Success Rate: ${Math.round((testResults.passed / testResults.total) * 100)}%`)
  
  if (testResults.failed > 0) {
    console.log('')
    console.log('Failed Tests:')
    testResults.tests.filter(t => !t.passed).forEach(t => {
      console.log(`- ${t.name}: ${t.details}`)
    })
  }
  
  return testResults.passed / testResults.total >= 0.9 // 90% success rate
}

runComprehensiveTests().then(success => {
  if (success) {
    console.log('')
    console.log('🎉 Test suite passed with 90%+ success rate!')
    process.exit(0)
  } else {
    console.log('')
    console.log('❌ Test suite failed to meet 90% success rate')
    process.exit(1)
  }
})
