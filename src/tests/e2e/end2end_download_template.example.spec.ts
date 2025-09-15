/**
 * End-to-End Download Test Template - EXAMPLE FILE
 * 
 * This is a template for creating end-to-end download tests.
 * Copy this file and replace the placeholder values with real credentials
 * for your local testing environment.
 * 
 * IMPORTANT: Never commit files with real API keys or credentials!
 * Files matching *end2end*.spec.ts are automatically ignored by .gitignore
 */

import { test, expect, Page } from '@playwright/test'

// Test configuration - REPLACE WITH REAL VALUES
const TEST_TIMEOUT = 60000
const ADMIN_CREDENTIALS = {
  username: 'REPLACE_WITH_REAL_USERNAME',
  password: 'REPLACE_WITH_REAL_PASSWORD'
}

// Test parameters for scraping - REPLACE WITH REAL VALUES
const SCRAPING_PARAMS = {
  zipCode: 'REPLACE_WITH_TEST_ZIP',
  radius: 'REPLACE_WITH_TEST_RADIUS',
  industry: 'REPLACE_WITH_TEST_INDUSTRY'
}

// Base URL - REPLACE WITH YOUR TEST ENVIRONMENT
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000'

test.describe('End-to-End Download Test Template', () => {
  test.beforeEach(async ({ page }) => {
    // Set longer timeout for E2E tests
    test.setTimeout(TEST_TIMEOUT)
  })

  test('should login with admin credentials', async ({ page }) => {
    console.log('Testing login with admin credentials...')
    
    // Navigate to login page
    await page.goto(`${BASE_URL}/login`)
    await page.waitForLoadState('networkidle')
    
    // Fill credentials - THESE SHOULD BE REAL VALUES IN YOUR LOCAL COPY
    await page.fill('input[name="username"], input[name="email"]', ADMIN_CREDENTIALS.username)
    await page.fill('input[name="password"]', ADMIN_CREDENTIALS.password)
    
    // Submit login form
    await page.click('button[type="submit"]')
    
    // Wait for redirect and verify login success
    await page.waitForLoadState('networkidle')
    expect(page.url()).not.toContain('/login')
    
    console.log('Login test completed successfully!')
  })

  test('should configure scraping parameters', async ({ page }) => {
    console.log('Testing scraping configuration...')
    
    // First login
    await page.goto(`${BASE_URL}/login`)
    await page.fill('input[name="username"], input[name="email"]', ADMIN_CREDENTIALS.username)
    await page.fill('input[name="password"]', ADMIN_CREDENTIALS.password)
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')
    
    // Navigate to configuration
    await page.goto(`${BASE_URL}/config`)
    await page.waitForLoadState('networkidle')
    
    // Set scraping parameters - THESE SHOULD BE REAL VALUES IN YOUR LOCAL COPY
    await page.fill('input[name="zipCode"]', SCRAPING_PARAMS.zipCode)
    await page.fill('input[name="radius"]', SCRAPING_PARAMS.radius)
    await page.fill('input[name="industry"]', SCRAPING_PARAMS.industry)
    
    // Save configuration
    await page.click('button:has-text("Save")')
    
    console.log('Configuration test completed successfully!')
  })

  test('should perform scraping and download results', async ({ page }) => {
    console.log('Testing scraping and download...')
    
    // Login and configure (reuse previous steps)
    await page.goto(`${BASE_URL}/login`)
    await page.fill('input[name="username"], input[name="email"]', ADMIN_CREDENTIALS.username)
    await page.fill('input[name="password"]', ADMIN_CREDENTIALS.password)
    await page.click('button[type="submit"]')
    await page.waitForLoadState('networkidle')
    
    // Start scraping
    await page.goto(`${BASE_URL}/scraping`)
    await page.waitForLoadState('networkidle')
    
    // Click start scraping button
    await page.click('button:has-text("Start Scraping")')
    
    // Wait for results (with extended timeout)
    await page.waitForSelector('table, .results', { timeout: 120000 })
    
    // Look for download button
    const downloadButton = page.locator('button:has-text("Download"), button:has-text("Export")')
    await expect(downloadButton).toBeVisible()
    
    // Click download (actual download testing would require additional setup)
    await downloadButton.click()
    
    console.log('Scraping and download test completed successfully!')
  })
})

/**
 * Helper functions for E2E tests
 */

async function waitForPageLoad(page: Page, timeout = 15000): Promise<void> {
  await page.waitForLoadState('networkidle', { timeout })
  await page.waitForLoadState('domcontentloaded', { timeout })
}

async function takeDebugScreenshot(page: Page, name: string): Promise<string> {
  const screenshotPath = `test-results/debug-${name}-${Date.now()}.png`
  await page.screenshot({ path: screenshotPath, fullPage: true })
  console.log(`Debug screenshot saved: ${screenshotPath}`)
  return screenshotPath
}

/**
 * SECURITY NOTES:
 * 
 * 1. This template file is safe to commit because it contains no real credentials
 * 2. When creating actual test files, copy this template and replace placeholders
 * 3. Real test files will be automatically ignored by .gitignore patterns
 * 4. Never commit files containing:
 *    - Real API keys
 *    - Real passwords
 *    - Real user credentials
 *    - Production URLs with sensitive data
 * 
 * USAGE:
 * 
 * 1. Copy this file to: end2end_download_local.spec.ts
 * 2. Replace all REPLACE_WITH_* placeholders with real values
 * 3. Run tests locally: npm run test:e2e
 * 4. The real test file will be automatically ignored by git
 */
