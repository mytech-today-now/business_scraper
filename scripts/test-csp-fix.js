#!/usr/bin/env node

/**
 * CSP Fix Validation Script
 * Tests the CSP configuration to ensure the white screen issue is resolved
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 Testing CSP Configuration Fix...\n');

// Test 1: Check environment configuration
console.log('1. Checking environment configuration...');
const envPath = path.join(process.cwd(), '.env');
const envLocalPath = path.join(process.cwd(), '.env.local');

try {
  const envContent = fs.readFileSync(envPath, 'utf8');
  const envLocalContent = fs.readFileSync(envLocalPath, 'utf8');
  
  const envNodeEnv = envContent.match(/NODE_ENV=(.+)/)?.[1];
  const envLocalNodeEnv = envLocalContent.match(/NODE_ENV=(.+)/)?.[1];
  
  console.log(`   .env NODE_ENV: ${envNodeEnv}`);
  console.log(`   .env.local NODE_ENV: ${envLocalNodeEnv}`);
  
  if (envLocalNodeEnv === 'development') {
    console.log('   ✅ Environment configuration is correct');
  } else {
    console.log('   ❌ Environment configuration issue detected');
  }
} catch (error) {
  console.log('   ❌ Error reading environment files:', error.message);
}

// Test 2: Check CSP configuration
console.log('\n2. Checking CSP configuration...');
try {
  const cspConfigPath = path.join(process.cwd(), 'src/lib/cspConfig.ts');
  const cspContent = fs.readFileSync(cspConfigPath, 'utf8');
  
  // Check for missing hashes that were causing violations
  const missingHashes = [
    'sha256-2lt0bFJlc5Kaphf4LkrOMIrdaHAEYNx8N9WCufhBrCo=',
    'sha256-oolAXs2Cdo3WdBhu4uUyDkOe8GFEQ1wq7uqTsMiKW9U=',
    'sha256-z05Y9BUQz7PEpWh9sitkqC+x0N4+SQix0AsyRlpYy7Q=',
    'sha256-JM7ucALGjjhHJ6z0bfjR6Dx5+OvnghD+JZoXdsywlzM=',
    'sha256-VySdMvYwvSwI5wjrw1P0Bfo7JRandOP0fPX3lt9vjaI='
  ];
  
  let allHashesPresent = true;
  missingHashes.forEach(hash => {
    if (!cspContent.includes(hash)) {
      console.log(`   ❌ Missing hash: ${hash}`);
      allHashesPresent = false;
    }
  });
  
  if (allHashesPresent) {
    console.log('   ✅ All required script hashes are present');
  }
  
  // Check for development CSP configuration
  if (cspContent.includes("'unsafe-inline'") && cspContent.includes("'unsafe-eval'")) {
    console.log('   ✅ Development CSP allows unsafe-inline and unsafe-eval');
  } else {
    console.log('   ❌ Development CSP configuration issue');
  }
} catch (error) {
  console.log('   ❌ Error reading CSP configuration:', error.message);
}

// Test 3: Check middleware configuration
console.log('\n3. Checking middleware configuration...');
try {
  const middlewarePath = path.join(process.cwd(), 'src/middleware.ts');
  const middlewareContent = fs.readFileSync(middlewarePath, 'utf8');
  
  if (middlewareContent.includes('isDevelopment && process.env.ENABLE_CSP_IN_DEV !== \'true\'')) {
    console.log('   ✅ Middleware prioritizes development CSP correctly');
  } else {
    console.log('   ❌ Middleware configuration issue');
  }
  
  if (middlewareContent.includes('unsafe-inline')) {
    console.log('   ✅ Development CSP includes unsafe-inline');
  } else {
    console.log('   ❌ Development CSP missing unsafe-inline');
  }
} catch (error) {
  console.log('   ❌ Error reading middleware configuration:', error.message);
}

// Test 4: Check layout nonce injection
console.log('\n4. Checking layout nonce injection...');
try {
  const layoutPath = path.join(process.cwd(), 'src/app/layout.tsx');
  const layoutContent = fs.readFileSync(layoutPath, 'utf8');
  
  if (layoutContent.includes('getCSPNonce()')) {
    console.log('   ✅ Layout imports CSP nonce function');
  } else {
    console.log('   ❌ Layout missing CSP nonce import');
  }
  
  if (layoutContent.includes('meta name="csp-nonce"')) {
    console.log('   ✅ Layout includes CSP nonce meta tag');
  } else {
    console.log('   ❌ Layout missing CSP nonce meta tag');
  }
  
  if (layoutContent.includes('window.__CSP_NONCE__')) {
    console.log('   ✅ Layout sets global CSP nonce variable');
  } else {
    console.log('   ❌ Layout missing global CSP nonce variable');
  }
} catch (error) {
  console.log('   ❌ Error reading layout configuration:', error.message);
}

console.log('\n🎯 CSP Fix Validation Complete!');
console.log('\nNext steps:');
console.log('1. Start the development server: npm run dev');
console.log('2. Open http://localhost:3001 in your browser');
console.log('3. Check browser console for CSP violations');
console.log('4. Verify the application loads without white screen');
