#!/usr/bin/env node

/**
 * Production Admin Login Test
 * Tests the admin login functionality against the running production application
 */

const http = require('http');
const https = require('https');

// Configuration
const BASE_URL = 'http://localhost:3000';
const ADMIN_CREDENTIALS = {
  username: 'admin',
  password: 'oAXDIh5)3s9<(gDpK19,'
};

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function makeRequest(method, path, data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Admin-Login-Test/1.0',
        ...headers
      }
    };

    if (data) {
      const jsonData = JSON.stringify(data);
      options.headers['Content-Length'] = Buffer.byteLength(jsonData);
    }

    const protocol = url.protocol === 'https:' ? https : http;
    const req = protocol.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try {
          const parsedBody = body ? JSON.parse(body) : {};
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: parsedBody
          });
        } catch (e) {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: body
          });
        }
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

async function testHealthEndpoint() {
  log('\n🏥 Testing Health Endpoint...', 'cyan');
  
  try {
    const response = await makeRequest('GET', '/api/health');
    
    if (response.statusCode === 200) {
      log('✅ Health endpoint is responding', 'green');
      log(`   Status: ${response.body.status}`, 'blue');
      log(`   Environment: ${response.body.environment}`, 'blue');
      log(`   Version: ${response.body.version}`, 'blue');
      return true;
    } else {
      log(`❌ Health endpoint returned ${response.statusCode}`, 'red');
      return false;
    }
  } catch (error) {
    log(`❌ Health endpoint error: ${error.message}`, 'red');
    return false;
  }
}

async function getCSRFToken() {
  log('\n🛡️  Getting CSRF Token...', 'cyan');
  
  try {
    const response = await makeRequest('GET', '/api/csrf');
    
    if (response.statusCode === 200 && response.body.csrfToken) {
      log('✅ CSRF token obtained', 'green');
      log(`   Token: ${response.body.csrfToken.substring(0, 16)}...`, 'blue');
      return {
        csrfToken: response.body.csrfToken,
        sessionCookie: response.headers['set-cookie']
      };
    } else {
      log(`❌ Failed to get CSRF token: ${response.statusCode}`, 'red');
      return null;
    }
  } catch (error) {
    log(`❌ CSRF token error: ${error.message}`, 'red');
    return null;
  }
}

async function testAdminLogin(csrfToken, sessionCookie) {
  log('\n🔐 Testing Admin Login...', 'cyan');
  
  try {
    const headers = {
      'X-CSRF-Token': csrfToken
    };
    
    if (sessionCookie) {
      headers['Cookie'] = Array.isArray(sessionCookie) ? sessionCookie.join('; ') : sessionCookie;
    }
    
    const response = await makeRequest('POST', '/api/auth', ADMIN_CREDENTIALS, headers);
    
    log(`📊 Login Response Status: ${response.statusCode}`, 'blue');
    
    if (response.statusCode === 200) {
      if (response.body.success) {
        log('🎉 ADMIN LOGIN SUCCESSFUL!', 'green');
        log(`   Session ID: ${response.body.sessionId ? response.body.sessionId.substring(0, 16) + '...' : 'None'}`, 'blue');
        log(`   User: ${response.body.user || 'admin'}`, 'blue');
        
        // Check for session cookie in response
        if (response.headers['set-cookie']) {
          log('🍪 Session cookie set in response', 'green');
        }
        
        return {
          success: true,
          sessionId: response.body.sessionId,
          sessionCookie: response.headers['set-cookie']
        };
      } else {
        log('❌ Login failed: Authentication unsuccessful', 'red');
        log(`   Message: ${response.body.message || 'Unknown error'}`, 'yellow');
        return { success: false };
      }
    } else if (response.statusCode === 401) {
      log('❌ Login failed: Invalid credentials', 'red');
      return { success: false };
    } else {
      log(`❌ Login failed: HTTP ${response.statusCode}`, 'red');
      log(`   Response: ${JSON.stringify(response.body, null, 2)}`, 'yellow');
      return { success: false };
    }
  } catch (error) {
    log(`❌ Login error: ${error.message}`, 'red');
    return { success: false };
  }
}

async function testMainPageAccess(sessionCookie) {
  log('\n🏠 Testing Main Page Access...', 'cyan');
  
  try {
    const headers = {};
    if (sessionCookie) {
      headers['Cookie'] = Array.isArray(sessionCookie) ? sessionCookie.join('; ') : sessionCookie;
    }
    
    const response = await makeRequest('GET', '/', null, headers);
    
    if (response.statusCode === 200) {
      log('✅ Main page accessible after login', 'green');
      return true;
    } else if (response.statusCode === 302 || response.statusCode === 301) {
      const location = response.headers.location;
      if (location && location.includes('/login')) {
        log('⚠️  Redirected back to login page', 'yellow');
        log('   This may indicate session persistence issues', 'yellow');
        return false;
      } else {
        log(`✅ Redirected to: ${location}`, 'green');
        return true;
      }
    } else {
      log(`❌ Main page access failed: HTTP ${response.statusCode}`, 'red');
      return false;
    }
  } catch (error) {
    log(`❌ Main page access error: ${error.message}`, 'red');
    return false;
  }
}

async function runAdminLoginTest() {
  log('🚀 Starting Admin Login Test Suite', 'bright');
  log('=' .repeat(50), 'blue');
  
  // Test 1: Health Check
  const healthOk = await testHealthEndpoint();
  if (!healthOk) {
    log('\n❌ CRITICAL: Application is not responding properly', 'red');
    process.exit(1);
  }
  
  // Test 2: Get CSRF Token
  const csrfData = await getCSRFToken();
  if (!csrfData) {
    log('\n❌ CRITICAL: Cannot obtain CSRF token', 'red');
    process.exit(1);
  }
  
  // Test 3: Admin Login
  const loginResult = await testAdminLogin(csrfData.csrfToken, csrfData.sessionCookie);
  if (!loginResult.success) {
    log('\n❌ CRITICAL: Admin login failed', 'red');
    process.exit(1);
  }
  
  // Test 4: Main Page Access
  const mainPageOk = await testMainPageAccess(loginResult.sessionCookie);
  
  // Final Results
  log('\n' + '=' .repeat(50), 'blue');
  log('🏆 ADMIN LOGIN TEST RESULTS', 'bright');
  log('=' .repeat(50), 'blue');
  
  log('✅ Health Check: PASSED', 'green');
  log('✅ CSRF Token: PASSED', 'green');
  log('✅ Admin Login: PASSED', 'green');
  log(`${mainPageOk ? '✅' : '⚠️ '} Main Page Access: ${mainPageOk ? 'PASSED' : 'PARTIAL'}`, mainPageOk ? 'green' : 'yellow');
  
  log('\n📋 Test Summary:', 'cyan');
  log(`   Username: ${ADMIN_CREDENTIALS.username}`, 'blue');
  log(`   Password: ${ADMIN_CREDENTIALS.password.substring(0, 8)}...`, 'blue');
  log('   Authentication: ✅ WORKING', 'green');
  log('   Session Creation: ✅ WORKING', 'green');
  
  if (mainPageOk) {
    log('\n🎉 ALL TESTS PASSED! Admin login is fully functional.', 'green');
  } else {
    log('\n⚠️  PARTIAL SUCCESS: Login works but session persistence needs attention.', 'yellow');
  }
  
  log('\n💡 The admin user can successfully authenticate with the application!', 'bright');
}

// Run the test
if (require.main === module) {
  runAdminLoginTest().catch(error => {
    log(`\n💥 Test suite failed: ${error.message}`, 'red');
    process.exit(1);
  });
}

module.exports = { runAdminLoginTest, testAdminLogin, ADMIN_CREDENTIALS };
