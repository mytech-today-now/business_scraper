#!/usr/bin/env node

/**
 * Test Valid Login with Real Credentials
 * Business Scraper Application - Issue #165 Validation
 */

const http = require('http');

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000';

/**
 * Make HTTP request with promise
 */
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data,
          response: res
        });
      });
    });

    req.on('error', reject);
    
    if (options.body) {
      req.write(options.body);
    }
    
    req.end();
  });
}

/**
 * Test login with valid credentials
 */
async function testValidLogin() {
  console.log('🔐 Testing login with valid credentials...');
  
  try {
    // First get a session and CSRF token
    const sessionResponse = await makeRequest(`${BASE_URL}/api/auth`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (sessionResponse.statusCode !== 200) {
      console.log(`❌ Failed to get session: ${sessionResponse.statusCode}`);
      return;
    }

    const sessionData = JSON.parse(sessionResponse.body);
    console.log(`📋 Session ID: ${sessionData.sessionId}`);
    console.log(`🛡️  CSRF Token: ${sessionData.csrfToken}`);

    // Try login with credentials from development.env
    const loginData = {
      username: 'admin',
      password: 'Wq+D%xj]O5$$yjVAy4fT' // From development.env
    };

    const loginResponse = await makeRequest(`${BASE_URL}/api/auth`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-CSRF-Token': sessionData.csrfToken,
        'Cookie': sessionResponse.headers['set-cookie'] ? sessionResponse.headers['set-cookie'].join('; ') : ''
      },
      body: JSON.stringify(loginData)
    });
    
    console.log(`📊 Login Response Status: ${loginResponse.statusCode}`);
    
    if (loginResponse.statusCode === 200) {
      console.log('✅ Login successful!');
      const loginResult = JSON.parse(loginResponse.body);
      console.log(`   Session ID: ${loginResult.sessionId}`);
      console.log(`   Success: ${loginResult.success}`);
    } else if (loginResponse.statusCode === 401) {
      console.log('❌ Login failed: Invalid credentials');
      console.log(`   Response: ${loginResponse.body}`);
    } else if (loginResponse.statusCode === 403) {
      console.log('❌ Login failed: CSRF validation failed');
      console.log(`   Response: ${loginResponse.body}`);
    } else if (loginResponse.statusCode === 500) {
      console.log('❌ Login failed: Internal server error (500)');
      console.log(`   Response: ${loginResponse.body}`);
    } else {
      console.log(`⚠️  Unexpected response: ${loginResponse.statusCode}`);
      console.log(`   Response: ${loginResponse.body}`);
    }

  } catch (error) {
    console.log(`❌ Login test error: ${error.message}`);
  }
}

// Run test
testValidLogin().catch(console.error);
