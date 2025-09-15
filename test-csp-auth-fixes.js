#!/usr/bin/env node

/**
 * Test Script for CSP and Authentication Fixes
 * Business Scraper Application - Issue #165 Validation
 */

const http = require('http');
const https = require('https');

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000';

/**
 * Make HTTP request with promise
 */
function makeRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const protocol = url.startsWith('https:') ? https : http;
    const req = protocol.request(url, options, (res) => {
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
 * Test ping endpoint
 */
async function testPingEndpoint() {
  console.log('\n🏓 Testing /api/ping endpoint...');
  
  try {
    // Test GET request
    const getResponse = await makeRequest(`${BASE_URL}/api/ping`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (getResponse.statusCode === 200) {
      console.log('  ✅ GET /api/ping: OK');
      const data = JSON.parse(getResponse.body);
      console.log(`     Status: ${data.status}, Server: ${data.server}`);
    } else {
      console.log(`  ❌ GET /api/ping: ${getResponse.statusCode}`);
    }

    // Test HEAD request
    const headResponse = await makeRequest(`${BASE_URL}/api/ping`, {
      method: 'HEAD',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (headResponse.statusCode === 200) {
      console.log('  ✅ HEAD /api/ping: OK');
    } else {
      console.log(`  ❌ HEAD /api/ping: ${headResponse.statusCode}`);
    }

  } catch (error) {
    console.log(`  ❌ Ping endpoint error: ${error.message}`);
  }
}

/**
 * Test authentication endpoint
 */
async function testAuthEndpoint() {
  console.log('\n🔐 Testing /api/auth endpoint...');
  
  try {
    // Test GET request (session check)
    const getResponse = await makeRequest(`${BASE_URL}/api/auth`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (getResponse.statusCode === 200) {
      console.log('  ✅ GET /api/auth: OK');
      const data = JSON.parse(getResponse.body);
      console.log(`     Authenticated: ${data.authenticated}, Session ID: ${data.sessionId}`);
    } else {
      console.log(`  ❌ GET /api/auth: ${getResponse.statusCode}`);
    }

    // Test POST request (login attempt)
    const loginData = {
      username: 'admin',
      password: 'test123' // This should fail, but shouldn't cause 500 error
    };

    const postResponse = await makeRequest(`${BASE_URL}/api/auth`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'test-token' // Mock CSRF token
      },
      body: JSON.stringify(loginData)
    });
    
    if (postResponse.statusCode === 401) {
      console.log('  ✅ POST /api/auth: Correctly rejected invalid credentials (401)');
    } else if (postResponse.statusCode === 200) {
      console.log('  ✅ POST /api/auth: Login successful (200)');
    } else if (postResponse.statusCode === 500) {
      console.log('  ❌ POST /api/auth: Internal server error (500) - Fix needed');
      console.log(`     Response: ${postResponse.body}`);
    } else {
      console.log(`  ⚠️  POST /api/auth: Unexpected status ${postResponse.statusCode}`);
      console.log(`     Response: ${postResponse.body}`);
    }

  } catch (error) {
    console.log(`  ❌ Auth endpoint error: ${error.message}`);
  }
}

/**
 * Test CSP reporting endpoint
 */
async function testCSPReportEndpoint() {
  console.log('\n🛡️  Testing /api/csp-report endpoint...');
  
  try {
    // Test OPTIONS request (CORS preflight)
    const optionsResponse = await makeRequest(`${BASE_URL}/api/csp-report`, {
      method: 'OPTIONS',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (optionsResponse.statusCode === 200) {
      console.log('  ✅ OPTIONS /api/csp-report: OK');
    } else {
      console.log(`  ❌ OPTIONS /api/csp-report: ${optionsResponse.statusCode}`);
    }

    // Test POST request (CSP violation report)
    const cspReport = {
      'csp-report': {
        'document-uri': 'http://localhost:3000/',
        'referrer': '',
        'violated-directive': 'style-src',
        'effective-directive': 'style-src',
        'original-policy': "default-src 'self'",
        'blocked-uri': 'inline',
        'status-code': 200
      }
    };

    const postResponse = await makeRequest(`${BASE_URL}/api/csp-report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cspReport)
    });
    
    if (postResponse.statusCode === 200) {
      console.log('  ✅ POST /api/csp-report: OK');
    } else if (postResponse.statusCode === 403) {
      console.log('  ❌ POST /api/csp-report: Forbidden (403) - Access denied');
    } else {
      console.log(`  ⚠️  POST /api/csp-report: ${postResponse.statusCode}`);
      console.log(`     Response: ${postResponse.body}`);
    }

  } catch (error) {
    console.log(`  ❌ CSP report endpoint error: ${error.message}`);
  }
}

/**
 * Test health endpoint
 */
async function testHealthEndpoint() {
  console.log('\n🏥 Testing /api/health endpoint...');
  
  try {
    const response = await makeRequest(`${BASE_URL}/api/health`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.statusCode === 200) {
      console.log('  ✅ GET /api/health: OK');
      const data = JSON.parse(response.body);
      console.log(`     Status: ${data.status}, Environment: ${data.environment}`);
    } else {
      console.log(`  ❌ GET /api/health: ${response.statusCode}`);
    }

  } catch (error) {
    console.log(`  ❌ Health endpoint error: ${error.message}`);
  }
}

/**
 * Main test function
 */
async function runTests() {
  console.log('🧪 Running CSP and Authentication Fixes Validation Tests');
  console.log(`📍 Testing against: ${BASE_URL}`);
  console.log('=' .repeat(60));

  await testPingEndpoint();
  await testAuthEndpoint();
  await testCSPReportEndpoint();
  await testHealthEndpoint();

  console.log('\n' + '=' .repeat(60));
  console.log('✨ Test validation complete!');
  console.log('\n📋 Summary:');
  console.log('   - /api/ping endpoint should be accessible');
  console.log('   - /api/auth should not return 500 errors');
  console.log('   - /api/csp-report should not return 403 errors');
  console.log('   - All endpoints should respond appropriately');
  console.log('\n🔧 If any tests fail, check the application logs for details.');
}

// Run tests if this script is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { runTests, testPingEndpoint, testAuthEndpoint, testCSPReportEndpoint, testHealthEndpoint };
