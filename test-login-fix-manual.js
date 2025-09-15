/**
 * Manual test script to verify the login fix
 * Tests that the infinite render loop issue is resolved
 */

const puppeteer = require('puppeteer');

async function testLoginFix() {
  console.log('🚀 Starting manual login fix test...');
  
  let browser;
  let page;
  
  try {
    // Launch browser
    browser = await puppeteer.launch({
      headless: false, // Set to true for headless testing
      devtools: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    page = await browser.newPage();
    
    // Enable console logging
    page.on('console', msg => {
      const type = msg.type();
      const text = msg.text();
      
      // Log console messages but filter out noise
      if (type === 'error' || type === 'warn') {
        console.log(`[BROWSER ${type.toUpperCase()}]: ${text}`);
      } else if (text.includes('Login') || text.includes('CSRF') || text.includes('Maximum update depth')) {
        console.log(`[BROWSER ${type.toUpperCase()}]: ${text}`);
      }
    });
    
    // Navigate to login page
    console.log('📄 Navigating to login page...');
    await page.goto('http://localhost:3003/login', { 
      waitUntil: 'networkidle2',
      timeout: 30000 
    });
    
    // Wait for page to load
    await page.waitForSelector('input[name="username"]', { timeout: 10000 });
    console.log('✅ Login page loaded successfully');
    
    // Check for infinite render loop warnings
    let hasInfiniteLoopWarning = false;
    page.on('console', msg => {
      if (msg.text().includes('Maximum update depth exceeded')) {
        hasInfiniteLoopWarning = true;
        console.log('❌ INFINITE LOOP DETECTED:', msg.text());
      }
    });
    
    // Wait a bit to see if infinite loops occur
    console.log('⏳ Waiting 5 seconds to check for infinite render loops...');
    await page.waitForTimeout(5000);
    
    if (!hasInfiniteLoopWarning) {
      console.log('✅ No infinite render loop warnings detected');
    }
    
    // Fill in login form
    console.log('📝 Filling in login form...');
    await page.type('input[name="username"]', 'admin');
    await page.type('input[name="password"]', 'Wq+D%xj]O5$$yjVAy4fT');
    
    // Wait for CSRF token to load
    console.log('🔐 Waiting for CSRF token...');
    await page.waitForFunction(() => {
      const csrfInput = document.querySelector('input[name="csrf_token"]');
      return csrfInput && csrfInput.value;
    }, { timeout: 10000 });
    console.log('✅ CSRF token loaded');
    
    // Click submit button
    console.log('🔘 Clicking submit button...');
    const submitButton = await page.waitForSelector('button[type="submit"]');
    await submitButton.click();
    
    // Wait for either redirect or error
    console.log('⏳ Waiting for login response...');
    
    try {
      // Wait for either redirect to dashboard or error message
      await Promise.race([
        page.waitForNavigation({ timeout: 10000 }),
        page.waitForSelector('.text-red-700', { timeout: 10000 })
      ]);
      
      const currentUrl = page.url();
      console.log('📍 Current URL:', currentUrl);
      
      if (currentUrl.includes('/login')) {
        // Still on login page, check for error
        const errorElement = await page.$('.text-red-700');
        if (errorElement) {
          const errorText = await page.evaluate(el => el.textContent, errorElement);
          console.log('⚠️ Login error:', errorText);
        } else {
          console.log('❌ Login failed - still on login page with no error message');
        }
      } else {
        console.log('✅ Login successful - redirected to:', currentUrl);
      }
      
    } catch (error) {
      console.log('⏳ Login response timeout - checking current state...');
      
      // Check if we're still on login page
      const currentUrl = page.url();
      if (currentUrl.includes('/login')) {
        console.log('❌ Login appears to have failed - still on login page');
        
        // Check for any error messages
        const errorElement = await page.$('.text-red-700');
        if (errorElement) {
          const errorText = await page.evaluate(el => el.textContent, errorElement);
          console.log('Error message:', errorText);
        }
      }
    }
    
    // Final check for infinite loops
    if (hasInfiniteLoopWarning) {
      console.log('❌ TEST FAILED: Infinite render loops detected');
      return false;
    } else {
      console.log('✅ TEST PASSED: No infinite render loops detected');
      return true;
    }
    
  } catch (error) {
    console.error('❌ Test failed with error:', error.message);
    return false;
  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

// Run the test
if (require.main === module) {
  testLoginFix().then(success => {
    console.log('\n=== TEST SUMMARY ===');
    if (success) {
      console.log('🎉 Login fix test PASSED');
      process.exit(0);
    } else {
      console.log('💥 Login fix test FAILED');
      process.exit(1);
    }
  }).catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });
}

module.exports = { testLoginFix };
