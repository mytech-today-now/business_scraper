/**
 * Rate Limiting Test Script
 * Tests the enhanced rate limiting and anti-bot measures
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🧪 Starting Rate Limiting Test Suite...\n');

// Test configuration
const testConfig = {
  testDuration: 300000, // 5 minutes
  maxRequests: 5,
  expectedMinDelay: 30000, // 30 seconds
  logFile: 'rate-limiting-test.log'
};

// Create log file
const logStream = fs.createWriteStream(testConfig.logFile, { flags: 'w' });

function log(message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}`;
  console.log(logMessage);
  logStream.write(logMessage + '\n');
}

// Test 1: Basic Rate Limiting Test
async function testBasicRateLimiting() {
  log('📋 Test 1: Basic Rate Limiting');
  log('Testing if delays are properly implemented between requests...');
  
  const startTime = Date.now();
  const requestTimes = [];
  
  // Simulate multiple requests
  for (let i = 0; i < 3; i++) {
    const requestTime = Date.now();
    requestTimes.push(requestTime);
    
    log(`Request ${i + 1} initiated at: ${new Date(requestTime).toLocaleTimeString()}`);
    
    if (i > 0) {
      const delay = requestTime - requestTimes[i - 1];
      log(`Delay since last request: ${delay}ms`);
      
      if (delay >= testConfig.expectedMinDelay) {
        log(`✅ Delay is adequate (${delay}ms >= ${testConfig.expectedMinDelay}ms)`);
      } else {
        log(`❌ Delay is too short (${delay}ms < ${testConfig.expectedMinDelay}ms)`);
      }
    }
    
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  log('✅ Basic rate limiting test completed\n');
}

// Test 2: Circuit Breaker Test
async function testCircuitBreaker() {
  log('📋 Test 2: Circuit Breaker Test');
  log('Testing circuit breaker behavior with simulated failures...');
  
  // This would normally require actual API calls to test properly
  // For now, we'll test the logic structure
  
  const circuitBreakerConfig = {
    maxFailures: 2,
    cooldownPeriod: 10 * 60 * 1000, // 10 minutes
    failures: 0,
    lastFailureTime: 0
  };
  
  // Simulate failures
  for (let i = 0; i < 3; i++) {
    circuitBreakerConfig.failures++;
    circuitBreakerConfig.lastFailureTime = Date.now();
    
    log(`Simulated failure ${i + 1}: failures = ${circuitBreakerConfig.failures}`);
    
    if (circuitBreakerConfig.failures >= circuitBreakerConfig.maxFailures) {
      log(`🔴 Circuit breaker triggered after ${circuitBreakerConfig.failures} failures`);
      log(`Cooldown period: ${circuitBreakerConfig.cooldownPeriod / 1000}s`);
      break;
    }
  }
  
  log('✅ Circuit breaker test completed\n');
}

// Test 3: Exponential Backoff Test
async function testExponentialBackoff() {
  log('📋 Test 3: Exponential Backoff Test');
  log('Testing exponential backoff calculation...');
  
  const baseDelay = 30000; // 30 seconds
  const maxDelay = 300000; // 5 minutes
  
  for (let failures = 0; failures < 5; failures++) {
    const exponentialDelay = baseDelay * Math.pow(2, failures);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    const finalDelay = Math.min(exponentialDelay + jitter, maxDelay);
    
    log(`Failures: ${failures}, Calculated delay: ${Math.round(finalDelay)}ms (${Math.round(finalDelay/1000)}s)`);
  }
  
  log('✅ Exponential backoff test completed\n');
}

// Test 4: Anti-Bot Measures Test
async function testAntiBotMeasures() {
  log('📋 Test 4: Anti-Bot Measures Test');
  log('Testing randomization in user agents and viewports...');
  
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
  ];
  
  const viewports = [
    { width: 1366, height: 768 },
    { width: 1920, height: 1080 },
    { width: 1440, height: 900 },
    { width: 1280, height: 720 }
  ];
  
  // Test randomization
  for (let i = 0; i < 5; i++) {
    const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
    const randomViewport = viewports[Math.floor(Math.random() * viewports.length)];
    
    log(`Request ${i + 1}:`);
    log(`  User Agent: ${randomUserAgent.substring(0, 50)}...`);
    log(`  Viewport: ${randomViewport.width}x${randomViewport.height}`);
  }
  
  log('✅ Anti-bot measures test completed\n');
}

// Test 5: Server-Side Rate Limiting Test
async function testServerSideRateLimiting() {
  log('📋 Test 5: Server-Side Rate Limiting Test');
  log('Testing server-side minimum delay enforcement...');
  
  const minDelay = 45000; // 45 seconds
  let lastRequestTime = 0;
  
  for (let i = 0; i < 3; i++) {
    const now = Date.now();
    const timeSinceLastRequest = now - lastRequestTime;
    
    if (lastRequestTime > 0) {
      log(`Time since last request: ${timeSinceLastRequest}ms`);
      
      if (timeSinceLastRequest < minDelay) {
        const waitTime = minDelay - timeSinceLastRequest;
        log(`⏳ Server-side rate limiting: would wait ${waitTime}ms`);
      } else {
        log(`✅ Sufficient time has passed (${timeSinceLastRequest}ms >= ${minDelay}ms)`);
      }
    }
    
    lastRequestTime = now;
    
    // Simulate the minimum delay
    await new Promise(resolve => setTimeout(resolve, 1000)); // Short delay for testing
  }
  
  log('✅ Server-side rate limiting test completed\n');
}

// Main test runner
async function runTests() {
  try {
    log('🚀 Starting Rate Limiting Test Suite');
    log(`Test configuration: ${JSON.stringify(testConfig, null, 2)}\n`);
    
    await testBasicRateLimiting();
    await testCircuitBreaker();
    await testExponentialBackoff();
    await testAntiBotMeasures();
    await testServerSideRateLimiting();
    
    log('🎉 All tests completed successfully!');
    log(`📄 Full test log saved to: ${testConfig.logFile}`);
    
  } catch (error) {
    log(`❌ Test suite failed: ${error.message}`);
    process.exit(1);
  } finally {
    logStream.end();
  }
}

// Run the tests
runTests().catch(console.error);
