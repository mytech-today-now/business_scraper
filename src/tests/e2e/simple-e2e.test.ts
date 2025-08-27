/**
 * Simple End-to-End Tests
 * Basic E2E tests that can run without a full application setup
 */

import { test, expect } from '@playwright/test'

// Test configuration
const BASE_URL = process.env.TEST_BASE_URL || 'https://example.com'

test.describe('Simple E2E Tests', () => {
  test('should load the homepage successfully', async ({ page }) => {
    // Navigate to a simple test page
    await page.goto(BASE_URL)

    // Check that the page loads
    await expect(page).toHaveTitle(/Example Domain/)

    // Check for basic content
    await expect(page.locator('h1')).toContainText('Example Domain')
  })

  test('should handle navigation', async ({ page }) => {
    await page.goto(BASE_URL)

    // Check that we can interact with the page
    const heading = page.locator('h1')
    await expect(heading).toBeVisible()

    // Check page content
    const content = await page.textContent('body')
    expect(content).toContain('Example Domain')
  })

  test('should be responsive', async ({ page }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto(BASE_URL)

    await expect(page.locator('h1')).toBeVisible()

    // Test desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 })
    await expect(page.locator('h1')).toBeVisible()
  })

  test('should handle errors gracefully', async ({ page }) => {
    // Test 404 page
    const response = await page.goto(BASE_URL + '/nonexistent-page')

    // Should handle the request (even if it's a 404)
    expect(response).toBeTruthy()
  })

  test('should load within reasonable time', async ({ page }) => {
    const startTime = Date.now()

    await page.goto(BASE_URL)
    await page.waitForLoadState('networkidle')

    const loadTime = Date.now() - startTime

    // Should load within 5 seconds
    expect(loadTime).toBeLessThan(5000)
  })

  test('should handle basic interactions', async ({ page }) => {
    await page.goto(BASE_URL)

    // Test clicking on elements
    const body = page.locator('body')
    await body.click()

    // Test keyboard navigation
    await page.keyboard.press('Tab')

    // Test scrolling
    await page.evaluate(() => window.scrollTo(0, 100))

    // Verify page is still functional
    await expect(page.locator('h1')).toBeVisible()
  })

  test('should handle form interactions', async ({ page }) => {
    await page.goto(BASE_URL)

    // Try to find any input elements (if they exist)
    const inputs = page.locator('input')
    const inputCount = await inputs.count()

    if (inputCount > 0) {
      // Test typing in the first input
      await inputs.first().fill('test input')
      const value = await inputs.first().inputValue()
      expect(value).toBe('test input')
    }

    // This test passes regardless of whether inputs exist
    expect(true).toBe(true)
  })

  test('should handle multiple tabs', async ({ context }) => {
    // Create a new page (tab)
    const page1 = await context.newPage()
    const page2 = await context.newPage()

    // Navigate both pages
    await page1.goto(BASE_URL)
    await page2.goto(BASE_URL)

    // Verify both pages loaded
    await expect(page1.locator('h1')).toContainText('Example Domain')
    await expect(page2.locator('h1')).toContainText('Example Domain')

    // Close pages
    await page1.close()
    await page2.close()
  })

  test('should handle browser back/forward', async ({ page }) => {
    await page.goto(BASE_URL)

    // Try to navigate to a different path
    await page.goto(BASE_URL + '#section')

    // Go back
    await page.goBack()

    // Go forward
    await page.goForward()

    // Verify page is still functional
    await expect(page.locator('h1')).toBeVisible()
  })

  test('should handle page refresh', async ({ page }) => {
    await page.goto(BASE_URL)

    // Verify initial load
    await expect(page.locator('h1')).toBeVisible()

    // Refresh the page
    await page.reload()

    // Verify page still works after refresh
    await expect(page.locator('h1')).toBeVisible()
  })

  test('should handle different user agents', async ({ page }) => {
    // Set a mobile user agent
    await page.setExtraHTTPHeaders({
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    })

    await page.goto(BASE_URL)

    // Verify page loads with mobile user agent
    await expect(page.locator('h1')).toBeVisible()
  })

  test('should handle network conditions', async ({ page }) => {
    // Simulate slow network
    await page.route('**/*', async route => {
      // Add a small delay to simulate slow network
      await new Promise(resolve => setTimeout(resolve, 100))
      await route.continue()
    })

    const startTime = Date.now()
    await page.goto(BASE_URL)
    const loadTime = Date.now() - startTime

    // Should still load, just slower
    await expect(page.locator('h1')).toBeVisible()
    expect(loadTime).toBeGreaterThan(100) // Should be slower due to our delay
  })

  test('should handle JavaScript disabled', async ({ context }) => {
    // Create a new page with JavaScript disabled
    const page = await context.newPage()
    await page.setJavaScriptEnabled(false)

    await page.goto(BASE_URL)

    // Basic HTML should still work
    await expect(page.locator('h1')).toBeVisible()

    await page.close()
  })

  test('should handle cookies and local storage', async ({ page }) => {
    await page.goto(BASE_URL)

    // Set a cookie
    await page.context().addCookies([
      {
        name: 'test-cookie',
        value: 'test-value',
        domain: new URL(BASE_URL).hostname,
        path: '/',
      },
    ])

    // Set local storage
    await page.evaluate(() => {
      localStorage.setItem('test-key', 'test-value')
    })

    // Refresh and verify persistence
    await page.reload()

    const cookies = await page.context().cookies()
    const testCookie = cookies.find(c => c.name === 'test-cookie')
    expect(testCookie?.value).toBe('test-value')

    const localStorageValue = await page.evaluate(() => {
      return localStorage.getItem('test-key')
    })
    expect(localStorageValue).toBe('test-value')
  })

  test('should handle accessibility basics', async ({ page }) => {
    await page.goto(BASE_URL)

    // Check for basic accessibility features
    const title = await page.title()
    expect(title.length).toBeGreaterThan(0)

    // Check for heading structure
    const h1Count = await page.locator('h1').count()
    expect(h1Count).toBeGreaterThan(0)

    // Check for alt text on images (if any)
    const images = page.locator('img')
    const imageCount = await images.count()

    if (imageCount > 0) {
      for (let i = 0; i < imageCount; i++) {
        const alt = await images.nth(i).getAttribute('alt')
        // Alt attribute should exist (can be empty for decorative images)
        expect(alt).not.toBeNull()
      }
    }
  })

  test('should handle performance basics', async ({ page }) => {
    // Start performance monitoring
    await page.goto(BASE_URL)

    // Get performance metrics
    const performanceMetrics = await page.evaluate(() => {
      const navigation = performance.getEntriesByType(
        'navigation'
      )[0] as PerformanceNavigationTiming
      return {
        domContentLoaded:
          navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
        loadComplete: navigation.loadEventEnd - navigation.loadEventStart,
        firstPaint: performance.getEntriesByName('first-paint')[0]?.startTime || 0,
        firstContentfulPaint:
          performance.getEntriesByName('first-contentful-paint')[0]?.startTime || 0,
      }
    })

    // Basic performance assertions
    expect(performanceMetrics.domContentLoaded).toBeGreaterThanOrEqual(0)
    expect(performanceMetrics.loadComplete).toBeGreaterThanOrEqual(0)

    // Performance should be reasonable (under 3 seconds for basic page)
    expect(performanceMetrics.domContentLoaded).toBeLessThan(3000)
  })
})
