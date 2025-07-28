#!/usr/bin/env node

/**
 * Test script to generate console output for testing the copy functionality
 * This script will generate various types of console logs to test the copy feature
 */

console.log('🧪 Testing Console Copy Functionality');
console.log('=====================================');

// Generate different types of logs
console.info('ℹ️  This is an info message');
console.warn('⚠️  This is a warning message');
console.error('❌ This is an error message');
console.debug('🐛 This is a debug message');

// Generate some structured data
console.log('📊 Sample data:', {
  timestamp: new Date().toISOString(),
  user: 'test-user',
  action: 'console-test',
  data: {
    items: [1, 2, 3, 4, 5],
    status: 'active',
    config: {
      enabled: true,
      timeout: 5000
    }
  }
});

// Generate a series of logs to test buffer
for (let i = 1; i <= 20; i++) {
  console.log(`📝 Log entry ${i}: This is a test message to fill the console buffer`);
  
  if (i % 5 === 0) {
    console.info(`✅ Checkpoint ${i/5}: Generated ${i} log entries`);
  }
}

// Generate some longer messages
console.log('📄 Long message test: ' + 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(10));

// Generate error with stack trace
try {
  throw new Error('Test error for console copy functionality');
} catch (error) {
  console.error('🔥 Caught test error:', error.message);
}

// Final summary
console.log('✨ Console copy test completed!');
console.log('📋 Instructions:');
console.log('   1. Open the application in your browser');
console.log('   2. Open the Processing Window');
console.log('   3. Show the Console Output section');
console.log('   4. Click the "Copy" button to copy all logs to clipboard');
console.log('   5. Paste the clipboard content to verify it works');
console.log('');
console.log('🎯 Expected behavior:');
console.log('   - Copy button should show "Copying..." then "Copied!"');
console.log('   - Clipboard should contain all console logs from newest to oldest');
console.log('   - Large amounts of data should be truncated to fit clipboard limits');
console.log('   - Copy should work even with 10,000+ log entries in buffer');

console.log('🏁 Test script finished. Check the console output in the browser!');
