#!/usr/bin/env node

/**
 * Test login API endpoint
 * This script tests the authentication flow to verify the fixes
 */

const https = require('https')
const http = require('http')

async function testLoginAPI() {
  console.log('=== Testing Login API ===')
  
  try {
    // First, get CSRF token
    console.log('1. Getting CSRF token...')
    const csrfResponse = await makeRequest('GET', '/api/csrf')
    console.log('CSRF Response Status:', csrfResponse.statusCode)
    console.log('CSRF Response Headers:', csrfResponse.headers)
    
    if (csrfResponse.statusCode !== 200) {
      console.error('Failed to get CSRF token')
      return
    }
    
    const csrfData = JSON.parse(csrfResponse.body)
    console.log('CSRF Data:', csrfData)
    
    // Extract CSRF token and session cookie
    const csrfToken = csrfData.csrfToken
    const sessionCookie = csrfResponse.headers['set-cookie']?.find(cookie => 
      cookie.startsWith('session-id=')
    )
    
    console.log('CSRF Token:', csrfToken)
    console.log('Session Cookie:', sessionCookie)
    
    // Now test login
    console.log('\n2. Testing login...')
    const loginData = {
      username: 'admin',
      password: 'Wq+D%xj]O5$$yjVAy4fT'
    }
    
    const loginHeaders = {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken
    }
    
    if (sessionCookie) {
      loginHeaders['Cookie'] = sessionCookie
    }
    
    const loginResponse = await makeRequest('POST', '/api/auth', loginData, loginHeaders)
    console.log('Login Response Status:', loginResponse.statusCode)
    console.log('Login Response Headers:', loginResponse.headers)
    console.log('Login Response Body:', loginResponse.body)
    
    if (loginResponse.statusCode === 200) {
      console.log('\n✅ Login successful!')
    } else {
      console.log('\n❌ Login failed!')
    }
    
  } catch (error) {
    console.error('Error testing login API:', error)
  }
}

function makeRequest(method, path, data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: method,
      headers: {
        'User-Agent': 'Node.js Test Script',
        ...headers
      }
    }
    
    if (data && method !== 'GET') {
      const jsonData = JSON.stringify(data)
      options.headers['Content-Length'] = Buffer.byteLength(jsonData)
    }
    
    const req = http.request(options, (res) => {
      let body = ''
      
      res.on('data', (chunk) => {
        body += chunk
      })
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body
        })
      })
    })
    
    req.on('error', (error) => {
      reject(error)
    })
    
    if (data && method !== 'GET') {
      req.write(JSON.stringify(data))
    }
    
    req.end()
  })
}

// Run the test
testLoginAPI()
