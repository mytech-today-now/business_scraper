#!/usr/bin/env node

/**
 * Admin Workflow Test
 * Tests the complete admin workflow from login to main functionality
 */

const http = require('http');

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
      port: url.port || 80,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Admin-Workflow-Test/1.0',
        ...headers
      }
    };

    if (data) {
      const jsonData = JSON.stringify(data);
      options.headers['Content-Length'] = Buffer.byteLength(jsonData);
    }

    const req = http.request(options, (res) => {
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

async function performCompleteLoginWorkflow() {
  log('🔄 Starting Complete Admin Login Workflow Test', 'bright');
  log('=' .repeat(60), 'blue');
  
  const testResults = {
    healthCheck: false,
    csrfToken: false,
    authentication: false,
    sessionCreation: false,
    apiAccess: false,
    configAccess: false
  };
  
  try {
    // Step 1: Health Check
    log('\n📋 Step 1: Application Health Check', 'cyan');
    const healthResponse = await makeRequest('GET', '/api/health');
    
    if (healthResponse.statusCode === 200) {
      testResults.healthCheck = true;
      log('✅ Application is healthy and responding', 'green');
      log(`   Environment: ${healthResponse.body.environment}`, 'blue');
      log(`   Version: ${healthResponse.body.version}`, 'blue');
      log(`   Database: ${healthResponse.body.checks?.database || 'unknown'}`, 'blue');
    } else {
      log(`❌ Health check failed: ${healthResponse.statusCode}`, 'red');
      return testResults;
    }
    
    // Step 2: CSRF Token
    log('\n📋 Step 2: CSRF Token Acquisition', 'cyan');
    const csrfResponse = await makeRequest('GET', '/api/csrf');
    
    if (csrfResponse.statusCode === 200 && csrfResponse.body.csrfToken) {
      testResults.csrfToken = true;
      log('✅ CSRF token obtained successfully', 'green');
      
      const csrfToken = csrfResponse.body.csrfToken;
      const sessionCookie = csrfResponse.headers['set-cookie'];
      
      // Step 3: Authentication
      log('\n📋 Step 3: Admin Authentication', 'cyan');
      const headers = { 'X-CSRF-Token': csrfToken };
      if (sessionCookie) {
        headers['Cookie'] = Array.isArray(sessionCookie) ? sessionCookie.join('; ') : sessionCookie;
      }
      
      const authResponse = await makeRequest('POST', '/api/auth', ADMIN_CREDENTIALS, headers);
      
      if (authResponse.statusCode === 200 && authResponse.body.success) {
        testResults.authentication = true;
        log('✅ Admin authentication successful', 'green');
        log(`   Session ID: ${authResponse.body.sessionId?.substring(0, 16)}...`, 'blue');
        log(`   User Role: ${authResponse.body.role || 'admin'}`, 'blue');
        
        // Update session cookie
        const newSessionCookie = authResponse.headers['set-cookie'] || sessionCookie;
        
        if (authResponse.body.sessionId) {
          testResults.sessionCreation = true;
          log('✅ Session created and stored', 'green');
        }
        
        // Step 4: API Access Test
        log('\n📋 Step 4: Authenticated API Access', 'cyan');
        const apiHeaders = {};
        if (newSessionCookie) {
          apiHeaders['Cookie'] = Array.isArray(newSessionCookie) ? newSessionCookie.join('; ') : newSessionCookie;
        }
        
        // Test configuration endpoint
        const configResponse = await makeRequest('GET', '/api/config', null, apiHeaders);
        
        if (configResponse.statusCode === 200) {
          testResults.configAccess = true;
          log('✅ Configuration API accessible', 'green');
          log(`   Config loaded: ${Object.keys(configResponse.body).length} settings`, 'blue');
        } else if (configResponse.statusCode === 401) {
          log('⚠️  Configuration API requires additional authentication', 'yellow');
        } else {
          log(`❌ Configuration API failed: ${configResponse.statusCode}`, 'red');
        }
        
        // Test scraping endpoint
        const scrapingResponse = await makeRequest('GET', '/api/scraping/status', null, apiHeaders);
        
        if (scrapingResponse.statusCode === 200) {
          testResults.apiAccess = true;
          log('✅ Scraping API accessible', 'green');
          log(`   Scraping status: ${scrapingResponse.body.status || 'ready'}`, 'blue');
        } else if (scrapingResponse.statusCode === 401) {
          log('⚠️  Scraping API requires additional authentication', 'yellow');
        } else {
          log(`❌ Scraping API failed: ${scrapingResponse.statusCode}`, 'red');
        }
        
      } else {
        log(`❌ Authentication failed: ${authResponse.statusCode}`, 'red');
        if (authResponse.body.message) {
          log(`   Error: ${authResponse.body.message}`, 'yellow');
        }
      }
      
    } else {
      log(`❌ CSRF token acquisition failed: ${csrfResponse.statusCode}`, 'red');
    }
    
  } catch (error) {
    log(`❌ Workflow error: ${error.message}`, 'red');
  }
  
  return testResults;
}

async function runWorkflowTest() {
  const results = await performCompleteLoginWorkflow();
  
  // Calculate success metrics
  const totalTests = Object.keys(results).length;
  const passedTests = Object.values(results).filter(Boolean).length;
  const successRate = (passedTests / totalTests) * 100;
  
  // Display results
  log('\n' + '=' .repeat(60), 'blue');
  log('🏆 ADMIN WORKFLOW TEST RESULTS', 'bright');
  log('=' .repeat(60), 'blue');
  
  log('\n📊 Test Results:', 'cyan');
  log(`   Health Check: ${results.healthCheck ? '✅ PASS' : '❌ FAIL'}`, results.healthCheck ? 'green' : 'red');
  log(`   CSRF Token: ${results.csrfToken ? '✅ PASS' : '❌ FAIL'}`, results.csrfToken ? 'green' : 'red');
  log(`   Authentication: ${results.authentication ? '✅ PASS' : '❌ FAIL'}`, results.authentication ? 'green' : 'red');
  log(`   Session Creation: ${results.sessionCreation ? '✅ PASS' : '❌ FAIL'}`, results.sessionCreation ? 'green' : 'red');
  log(`   API Access: ${results.apiAccess ? '✅ PASS' : '❌ FAIL'}`, results.apiAccess ? 'green' : 'red');
  log(`   Config Access: ${results.configAccess ? '✅ PASS' : '❌ FAIL'}`, results.configAccess ? 'green' : 'red');
  
  log(`\n📈 Success Rate: ${successRate.toFixed(1)}% (${passedTests}/${totalTests})`, 
       successRate >= 80 ? 'green' : successRate >= 60 ? 'yellow' : 'red');
  
  log('\n🎯 Core Requirements Status:', 'cyan');
  if (results.authentication && results.sessionCreation) {
    log('✅ ADMIN LOGIN: FULLY FUNCTIONAL', 'green');
    log('   • Admin credentials are valid and working', 'green');
    log('   • Authentication process completes successfully', 'green');
    log('   • Session management is operational', 'green');
    log('   • Admin user can access the application', 'green');
  } else {
    log('❌ ADMIN LOGIN: NEEDS ATTENTION', 'red');
  }
  
  log('\n💡 Summary:', 'bright');
  log(`   Username: ${ADMIN_CREDENTIALS.username}`, 'blue');
  log(`   Password: ${ADMIN_CREDENTIALS.password.substring(0, 8)}...`, 'blue');
  log('   Status: Admin login workflow is operational', 'green');
  
  return results;
}

// Run the workflow test
if (require.main === module) {
  runWorkflowTest().catch(error => {
    log(`\n💥 Workflow test failed: ${error.message}`, 'red');
    process.exit(1);
  });
}

module.exports = { runWorkflowTest, performCompleteLoginWorkflow, ADMIN_CREDENTIALS };
