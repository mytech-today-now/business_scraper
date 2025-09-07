#!/usr/bin/env node

/**
 * Test session validation directly
 */

const fetch = require('node-fetch')

async function testSessionValidation() {
  console.log('=== Session Validation Test ===')
  
  try {
    // Step 1: Get CSRF token and session
    console.log('1. Getting CSRF token and session...')
    const csrfResponse = await fetch('http://localhost:3001/api/csrf', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'test-session-validation'
      }
    })
    
    console.log('CSRF Response Status:', csrfResponse.status)
    
    if (csrfResponse.status !== 200) {
      console.log('❌ Failed to get CSRF token')
      return
    }
    
    const csrfData = await csrfResponse.json()
    const sessionCookie = csrfResponse.headers.get('set-cookie')
    const sessionId = csrfData.sessionId
    
    console.log('Session ID:', sessionId)
    console.log('Session Cookie:', sessionCookie)
    console.log('')
    
    // Step 2: Test session validation by making a simple request
    console.log('2. Testing session validation...')
    
    // Extract just the session-id cookie value
    const sessionCookieMatch = sessionCookie.match(/session-id=([^;]+)/)
    const sessionCookieValue = sessionCookieMatch ? sessionCookieMatch[0] : ''
    
    console.log('Extracted Session Cookie:', sessionCookieValue)
    
    // Make a request to the same endpoint to see if session is recognized
    const validateResponse = await fetch('http://localhost:3001/api/csrf', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'test-session-validation',
        'Cookie': sessionCookieValue
      }
    })
    
    console.log('Validation Response Status:', validateResponse.status)
    
    if (validateResponse.status === 200) {
      const validateData = await validateResponse.json()
      console.log('Validation Data:', validateData)
      
      if (validateData.sessionId === sessionId) {
        console.log('✅ Session validation successful - same session ID')
      } else {
        console.log('⚠️  Session validation returned different session ID')
        console.log('Original:', sessionId)
        console.log('Returned:', validateData.sessionId)
      }
    } else {
      console.log('❌ Session validation failed')
      const errorData = await validateResponse.text()
      console.log('Error:', errorData)
    }

    // Step 3: Test POST request to /api/auth specifically
    console.log('')
    console.log('3. Testing POST request to /api/auth...')

    const authResponse = await fetch('http://localhost:3001/api/auth', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'test-session-validation',
        'Cookie': sessionCookieValue,
        'X-CSRF-Token': csrfData.csrfToken
      },
      body: JSON.stringify({
        username: 'admin',
        password: 'Wq+D%xj]O5$$yjVAy4fT'
      })
    })

    console.log('Auth POST Response Status:', authResponse.status)

    if (authResponse.status === 200) {
      const authData = await authResponse.json()
      console.log('✅ Auth POST successful')
      console.log('Auth Data:', authData)
    } else {
      console.log('❌ Auth POST failed')
      const authError = await authResponse.text()
      console.log('Auth Error:', authError)
    }

  } catch (error) {
    console.error('Test error:', error)
  }
}

testSessionValidation()
