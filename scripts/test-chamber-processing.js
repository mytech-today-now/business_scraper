#!/usr/bin/env node

/**
 * Test script for Chamber of Commerce processing
 * Usage: node scripts/test-chamber-processing.js
 */

const { spawn } = require('child_process');
const path = require('path');

console.log('🔍 Testing Chamber of Commerce Processing...\n');

// Test URL from the error logs
const testUrl = 'https://www.chamberofcommerce.com/business-directory/illinois/barrington/pet-groomer/2005503583-the-grooming-lodge';

async function testHealthCheck() {
  console.log('1. Testing health check endpoint...');
  
  try {
    const response = await fetch('http://localhost:3000/api/health/chamber');
    const data = await response.json();
    
    console.log(`   Status: ${response.status}`);
    console.log(`   Overall: ${data.overall}`);
    
    if (data.healthCheck) {
      console.log(`   Browser: ${data.healthCheck.healthy ? 'OK' : 'FAILED'}`);
      if (data.healthCheck.browserVersion) {
        console.log(`   Version: ${data.healthCheck.browserVersion}`);
      }
      if (data.healthCheck.error) {
        console.log(`   Error: ${data.healthCheck.error}`);
      }
    }
    
    return data.overall === 'healthy';
  } catch (error) {
    console.log(`   ❌ Health check failed: ${error.message}`);
    return false;
  }
}

async function testChamberProcessing() {
  console.log('\n2. Testing Chamber of Commerce processing...');
  
  try {
    const response = await fetch('http://localhost:3000/api/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'chamber-of-commerce',
        url: testUrl,
        maxResults: 5,
        maxPagesPerSite: 20
      })
    });
    
    const data = await response.json();
    
    console.log(`   Status: ${response.status}`);
    console.log(`   Success: ${data.success}`);
    console.log(`   Results: ${data.count || 0} businesses found`);
    
    if (!data.success) {
      console.log(`   Error: ${data.errorMessage || data.error}`);
    }
    
    if (data.results && data.results.length > 0) {
      console.log('\n   Sample results:');
      data.results.slice(0, 2).forEach((result, index) => {
        console.log(`   ${index + 1}. ${result.title}`);
        console.log(`      URL: ${result.url}`);
        console.log(`      Domain: ${result.domain}`);
      });
    }
    
    return data.success;
  } catch (error) {
    console.log(`   ❌ Processing failed: ${error.message}`);
    return false;
  }
}

async function checkServerStatus() {
  console.log('0. Checking if server is running...');
  
  try {
    const response = await fetch('http://localhost:3000/api/health');
    console.log(`   ✅ Server is running (status: ${response.status})`);
    return true;
  } catch (error) {
    console.log(`   ❌ Server not accessible: ${error.message}`);
    console.log('   Please make sure the development server is running with: npm run dev');
    return false;
  }
}

async function runTests() {
  console.log('Chamber of Commerce Processing Diagnostic\n');
  console.log('=========================================\n');
  
  const serverRunning = await checkServerStatus();
  if (!serverRunning) {
    process.exit(1);
  }
  
  const healthOk = await testHealthCheck();
  const processingOk = await testChamberProcessing();
  
  console.log('\n📊 Test Summary:');
  console.log('================');
  console.log(`Server Status: ${serverRunning ? '✅ OK' : '❌ FAILED'}`);
  console.log(`Health Check: ${healthOk ? '✅ OK' : '❌ FAILED'}`);
  console.log(`Processing: ${processingOk ? '✅ OK' : '❌ FAILED'}`);
  
  if (healthOk && processingOk) {
    console.log('\n🎉 All tests passed! Chamber of Commerce processing is working.');
  } else {
    console.log('\n⚠️  Some tests failed. Check the logs above for details.');
    console.log('\nTroubleshooting tips:');
    console.log('- Ensure Puppeteer dependencies are installed');
    console.log('- Check if the server has sufficient memory');
    console.log('- Verify network connectivity to Chamber of Commerce website');
    console.log('- Check server logs for detailed error messages');
  }
}

// Run the tests
runTests().catch(error => {
  console.error('Test runner failed:', error);
  process.exit(1);
});
