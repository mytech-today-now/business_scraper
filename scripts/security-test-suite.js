#!/usr/bin/env node

/**
 * Comprehensive Security Test Suite
 * P0 - Critical Security Testing and Validation
 * 
 * This script runs comprehensive security tests including:
 * - Input validation testing
 * - SQL injection testing
 * - XSS testing
 * - CSRF testing
 * - Authentication testing
 * - Session security testing
 * - Rate limiting testing
 * - CSP validation
 */

const { execSync } = require('child_process')
const fs = require('fs')
const path = require('path')
const https = require('https')
const http = require('http')

// Test configuration
const config = {
  baseUrl: process.env.TEST_BASE_URL || 'http://localhost:3000',
  testTimeout: 30000,
  maxRetries: 3
}

// ANSI colors for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
}

function colorLog(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`)
}

/**
 * Security test cases
 */
const securityTests = [
  {
    name: 'SQL Injection Protection',
    category: 'Input Validation',
    test: async () => {
      const sqlPayloads = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "UNION SELECT * FROM users",
        "admin'--",
        "' OR 1=1 --"
      ]

      for (const payload of sqlPayloads) {
        const response = await makeRequest('/api/search', 'POST', {
          query: payload
        })

        if (response.status === 200 && !response.body.includes('error')) {
          throw new Error(`SQL injection payload not blocked: ${payload}`)
        }
      }

      return { passed: true, message: 'All SQL injection payloads blocked' }
    }
  },

  {
    name: 'XSS Protection',
    category: 'Input Validation',
    test: async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert(1)',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<object data="javascript:alert(1)"></object>'
      ]

      for (const payload of xssPayloads) {
        const response = await makeRequest('/api/search', 'POST', {
          query: payload
        })

        if (response.body.includes(payload) && !response.body.includes('sanitized')) {
          throw new Error(`XSS payload not sanitized: ${payload}`)
        }
      }

      return { passed: true, message: 'All XSS payloads sanitized' }
    }
  },

  {
    name: 'CSRF Protection',
    category: 'Authentication',
    test: async () => {
      // Test POST request without CSRF token
      const response = await makeRequest('/api/auth', 'POST', {
        email: 'test@example.com',
        password: 'password'
      }, {}, false) // Don't include CSRF token

      if (response.status !== 403) {
        throw new Error('CSRF protection not working - request should be blocked')
      }

      return { passed: true, message: 'CSRF protection working correctly' }
    }
  },

  {
    name: 'Rate Limiting',
    category: 'API Security',
    test: async () => {
      const requests = []
      
      // Make multiple rapid requests
      for (let i = 0; i < 150; i++) {
        requests.push(makeRequest('/api/health', 'GET'))
      }

      const responses = await Promise.all(requests)
      const rateLimitedResponses = responses.filter(r => r.status === 429)

      if (rateLimitedResponses.length === 0) {
        throw new Error('Rate limiting not working - no 429 responses received')
      }

      return { passed: true, message: `Rate limiting working - ${rateLimitedResponses.length} requests blocked` }
    }
  },

  {
    name: 'Security Headers',
    category: 'HTTP Security',
    test: async () => {
      const response = await makeRequest('/', 'GET')
      const headers = response.headers

      const requiredHeaders = [
        'x-frame-options',
        'x-content-type-options',
        'referrer-policy',
        'content-security-policy',
        'strict-transport-security'
      ]

      const missingHeaders = requiredHeaders.filter(header => !headers[header])

      if (missingHeaders.length > 0) {
        throw new Error(`Missing security headers: ${missingHeaders.join(', ')}`)
      }

      return { passed: true, message: 'All required security headers present' }
    }
  },

  {
    name: 'CSP Configuration',
    category: 'Content Security',
    test: async () => {
      const response = await makeRequest('/', 'GET')
      const csp = response.headers['content-security-policy']

      if (!csp) {
        throw new Error('Content Security Policy header missing')
      }

      const requiredDirectives = [
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ]

      const missingDirectives = requiredDirectives.filter(directive => !csp.includes(directive))

      if (missingDirectives.length > 0) {
        throw new Error(`Missing CSP directives: ${missingDirectives.join(', ')}`)
      }

      return { passed: true, message: 'CSP configuration is secure' }
    }
  },

  {
    name: 'Session Security',
    category: 'Authentication',
    test: async () => {
      const response = await makeRequest('/api/auth', 'POST', {
        email: 'admin@example.com',
        password: 'correct_password'
      })

      const setCookieHeader = response.headers['set-cookie']
      if (!setCookieHeader) {
        throw new Error('No session cookie set')
      }

      const sessionCookie = setCookieHeader.find(cookie => cookie.includes('session'))
      if (!sessionCookie) {
        throw new Error('Session cookie not found')
      }

      if (!sessionCookie.includes('HttpOnly')) {
        throw new Error('Session cookie missing HttpOnly flag')
      }

      if (!sessionCookie.includes('SameSite=Strict')) {
        throw new Error('Session cookie missing SameSite=Strict')
      }

      return { passed: true, message: 'Session security configuration is correct' }
    }
  },

  {
    name: 'Input Length Validation',
    category: 'Input Validation',
    test: async () => {
      const longInput = 'a'.repeat(20000) // 20KB input

      const response = await makeRequest('/api/search', 'POST', {
        query: longInput
      })

      if (response.status !== 400 && response.status !== 413) {
        throw new Error('Long input not rejected')
      }

      return { passed: true, message: 'Input length validation working' }
    }
  }
]

/**
 * Make HTTP request with error handling
 */
async function makeRequest(path, method = 'GET', body = null, headers = {}, includeCSRF = true) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, config.baseUrl)
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'SecurityTestSuite/1.0',
        ...headers
      }
    }

    if (includeCSRF) {
      options.headers['X-CSRF-Token'] = 'test-token'
    }

    const client = url.protocol === 'https:' ? https : http
    
    const req = client.request(url, options, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: data
        })
      })
    })

    req.on('error', reject)
    req.setTimeout(config.testTimeout, () => {
      req.destroy()
      reject(new Error('Request timeout'))
    })

    if (body) {
      req.write(JSON.stringify(body))
    }

    req.end()
  })
}

/**
 * Run all security tests
 */
async function runSecurityTests() {
  colorLog('🔒 Starting Comprehensive Security Test Suite\n', 'cyan')

  let passedTests = 0
  let totalTests = securityTests.length
  const results = []

  for (const test of securityTests) {
    colorLog(`Testing: ${test.name} (${test.category})`, 'blue')
    
    try {
      const result = await test.test()
      
      if (result.passed) {
        colorLog(`✅ PASSED: ${result.message}`, 'green')
        passedTests++
      } else {
        colorLog(`❌ FAILED: ${result.message}`, 'red')
      }
      
      results.push({
        name: test.name,
        category: test.category,
        passed: result.passed,
        message: result.message
      })
      
    } catch (error) {
      colorLog(`❌ ERROR: ${error.message}`, 'red')
      results.push({
        name: test.name,
        category: test.category,
        passed: false,
        message: error.message
      })
    }
    
    console.log('') // Empty line for readability
  }

  // Generate summary report
  colorLog('📊 Security Test Summary:', 'cyan')
  console.log(`Total Tests: ${totalTests}`)
  console.log(`Passed: ${passedTests}`)
  console.log(`Failed: ${totalTests - passedTests}`)
  console.log(`Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`)

  // Save detailed report
  const reportPath = path.join(__dirname, '..', 'logs', `security-test-${Date.now()}.json`)
  const report = {
    timestamp: new Date().toISOString(),
    summary: {
      totalTests,
      passedTests,
      failedTests: totalTests - passedTests,
      successRate: ((passedTests / totalTests) * 100).toFixed(1)
    },
    results
  }

  // Ensure logs directory exists
  const logsDir = path.dirname(reportPath)
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true })
  }

  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2))
  colorLog(`\n📄 Detailed report saved to: ${reportPath}`, 'blue')

  return passedTests === totalTests
}

/**
 * Main execution
 */
async function main() {
  try {
    const allTestsPassed = await runSecurityTests()

    if (allTestsPassed) {
      colorLog('\n🎉 All security tests passed!', 'green')
      process.exit(0)
    } else {
      colorLog('\n⚠️  Some security tests failed. Please review the results.', 'yellow')
      process.exit(1)
    }

  } catch (error) {
    colorLog(`❌ Security test suite failed: ${error.message}`, 'red')
    process.exit(1)
  }
}

// Run if called directly
if (require.main === module) {
  main()
}

module.exports = { runSecurityTests }
