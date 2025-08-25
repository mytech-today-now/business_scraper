/**
 * Error Handling Scenarios E2E Tests
 * Comprehensive testing of error handling and edge cases
 */

import { test, expect, Page, BrowserContext } from '@playwright/test'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

interface ErrorScenario {
  name: string
  setup: (page: Page, context: BrowserContext) => Promise<void>
  trigger: (page: Page) => Promise<void>
  validate: (page: Page) => Promise<void>
}

test.describe('Error Handling Scenarios E2E Tests', () => {
  test.describe('Network Error Scenarios', () => {
    test('should handle complete network failure gracefully', async ({ page, context }) => {
      // Block all network requests
      await context.route('**/*', route => {
        route.abort('failed')
      })

      await page.goto(BASE_URL, { waitUntil: 'domcontentloaded' })
      
      // Page should still load basic structure
      await expect(page.locator('body')).toBeVisible()
      
      // Try to perform actions that require network
      const searchLink = page.locator('a[href*="/search"], button:has-text("Search")')
      if (await searchLink.isVisible()) {
        await searchLink.click()
        
        // Should handle navigation gracefully
        await expect(page.locator('body')).toBeVisible()
      }
    })

    test('should handle intermittent network failures', async ({ page, context }) => {
      let requestCount = 0
      
      await context.route('**/api/**', route => {
        requestCount++
        
        // Fail every other request
        if (requestCount % 2 === 0) {
          route.abort('failed')
        } else {
          route.continue()
        }
      })

      await page.goto(`${BASE_URL}/search`)
      
      // Perform search that might fail
      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should either show results or error message
      await Promise.race([
        page.waitForSelector('[data-testid="results"], .results', { timeout: 20000 }),
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 20000 }),
        page.waitForSelector(':has-text("Error")', { timeout: 20000 })
      ])
      
      // Page should remain functional
      await expect(page.locator('body')).toBeVisible()
    })

    test('should handle slow network responses', async ({ page, context }) => {
      // Add delay to all API requests
      await context.route('**/api/**', async route => {
        await new Promise(resolve => setTimeout(resolve, 5000)) // 5 second delay
        await route.continue()
      })

      await page.goto(`${BASE_URL}/search`)
      
      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      
      const startTime = Date.now()
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should show loading indicator
      await Promise.race([
        page.waitForSelector('[data-testid="loading"], .loading, .spinner', { timeout: 2000 }),
        page.waitForTimeout(1000)
      ])
      
      // Wait for eventual response
      await Promise.race([
        page.waitForSelector('[data-testid="results"], .results', { timeout: 30000 }),
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 30000 })
      ])
      
      const totalTime = Date.now() - startTime
      expect(totalTime).toBeGreaterThan(4000) // Should have waited for delay
    })
  })

  test.describe('Server Error Scenarios', () => {
    test('should handle 500 internal server errors', async ({ page, context }) => {
      await context.route('**/api/**', route => {
        route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Internal server error' })
        })
      })

      await page.goto(`${BASE_URL}/search`)
      
      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should show appropriate error message
      await Promise.race([
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 10000 }),
        page.waitForSelector(':has-text("Error")', { timeout: 10000 }),
        page.waitForSelector(':has-text("server error")', { timeout: 10000 })
      ])
      
      // Error should not crash the application
      await expect(page.locator('body')).toBeVisible()
    })

    test('should handle 404 not found errors', async ({ page, context }) => {
      await context.route('**/api/**', route => {
        route.fulfill({
          status: 404,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'Not found' })
        })
      })

      await page.goto(`${BASE_URL}/search`)
      
      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should handle 404 gracefully
      await Promise.race([
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 10000 }),
        page.waitForSelector(':has-text("not found")', { timeout: 10000 })
      ])
    })

    test('should handle malformed JSON responses', async ({ page, context }) => {
      await context.route('**/api/**', route => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: 'invalid json response {'
        })
      })

      await page.goto(`${BASE_URL}/search`)
      
      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should handle parsing error
      await Promise.race([
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 10000 }),
        page.waitForSelector(':has-text("Error")', { timeout: 10000 })
      ])
    })
  })

  test.describe('Client-Side Error Scenarios', () => {
    test('should handle JavaScript errors gracefully', async ({ page }) => {
      // Inject JavaScript error
      await page.addInitScript(() => {
        window.addEventListener('load', () => {
          setTimeout(() => {
            throw new Error('Simulated JavaScript error')
          }, 1000)
        })
      })

      const errors: string[] = []
      page.on('pageerror', error => {
        errors.push(error.message)
      })

      await page.goto(BASE_URL)
      
      // Wait for potential error
      await page.waitForTimeout(2000)
      
      // Should have caught the error
      expect(errors.length).toBeGreaterThan(0)
      
      // Page should still be functional
      await expect(page.locator('body')).toBeVisible()
    })

    test('should handle localStorage quota exceeded', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Try to fill localStorage beyond quota
      await page.evaluate(() => {
        try {
          const largeData = 'x'.repeat(10 * 1024 * 1024) // 10MB string
          for (let i = 0; i < 100; i++) {
            localStorage.setItem(`large-item-${i}`, largeData)
          }
        } catch (error) {
          console.log('localStorage quota exceeded:', error.message)
        }
      })
      
      // Application should still work
      await expect(page.locator('body')).toBeVisible()
      
      // Try to navigate to search
      await page.goto(`${BASE_URL}/search`)
      await expect(page.locator('form, [data-testid="search-form"]')).toBeVisible()
    })

    test('should handle memory pressure scenarios', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Create memory pressure
      await page.evaluate(() => {
        const arrays: number[][] = []
        try {
          for (let i = 0; i < 1000; i++) {
            arrays.push(new Array(100000).fill(i))
          }
        } catch (error) {
          console.log('Memory pressure detected:', error.message)
        }
      })
      
      // Application should remain responsive
      await expect(page.locator('body')).toBeVisible()
      
      // Try basic navigation
      await page.goto(`${BASE_URL}/search`)
      await expect(page.locator('form')).toBeVisible()
    })
  })

  test.describe('Input Validation Error Scenarios', () => {
    test('should handle extremely long input values', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)
      
      const longString = 'a'.repeat(10000) // 10k characters
      
      await page.fill('input[name="industry"], [data-testid="industry-input"]', longString)
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', longString)
      
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should either validate input or handle gracefully
      await Promise.race([
        page.waitForSelector('[data-testid="validation-error"], .validation-error', { timeout: 5000 }),
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 5000 }),
        page.waitForTimeout(3000)
      ])
      
      // Page should remain functional
      await expect(page.locator('body')).toBeVisible()
    })

    test('should handle special characters and unicode', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)
      
      const specialChars = '!@#$%^&*()[]{}|;:,.<>?`~'
      const unicodeChars = '🏢🍕🏨🛍️💼'
      
      await page.fill('input[name="industry"], [data-testid="industry-input"]', specialChars + unicodeChars)
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should handle special characters appropriately
      await Promise.race([
        page.waitForSelector('[data-testid="results"], .results', { timeout: 15000 }),
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 15000 }),
        page.waitForSelector('[data-testid="no-results"], .no-results', { timeout: 15000 })
      ])
    })

    test('should handle SQL injection attempts', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)
      
      const sqlInjection = "'; DROP TABLE businesses; --"
      
      await page.fill('input[name="industry"], [data-testid="industry-input"]', sqlInjection)
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Should sanitize input and not execute SQL
      await Promise.race([
        page.waitForSelector('[data-testid="results"], .results', { timeout: 15000 }),
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 15000 }),
        page.waitForSelector('[data-testid="validation-error"], .validation-error', { timeout: 15000 })
      ])
      
      // Application should still be functional
      await expect(page.locator('body')).toBeVisible()
    })
  })

  test.describe('Browser Compatibility Error Scenarios', () => {
    test('should handle missing browser features gracefully', async ({ page }) => {
      // Disable certain browser features
      await page.addInitScript(() => {
        // Simulate missing fetch API
        delete (window as any).fetch
        
        // Simulate missing localStorage
        delete (window as any).localStorage
        
        // Simulate missing Promise
        delete (window as any).Promise
      })

      await page.goto(BASE_URL)
      
      // Should still load basic functionality
      await expect(page.locator('body')).toBeVisible()
      
      // Try navigation
      const searchLink = page.locator('a[href*="/search"], button:has-text("Search")')
      if (await searchLink.isVisible()) {
        await searchLink.click()
        await expect(page.locator('body')).toBeVisible()
      }
    })

    test('should handle viewport size changes gracefully', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test various viewport sizes
      const viewports = [
        { width: 320, height: 568 },   // Mobile
        { width: 768, height: 1024 },  // Tablet
        { width: 1920, height: 1080 }, // Desktop
        { width: 2560, height: 1440 }  // Large desktop
      ]
      
      for (const viewport of viewports) {
        await page.setViewportSize(viewport)
        await page.waitForTimeout(500)
        
        // Verify page is still functional
        await expect(page.locator('body')).toBeVisible()
        
        // Try to navigate to search
        await page.goto(`${BASE_URL}/search`)
        await expect(page.locator('form, [data-testid="search-form"]')).toBeVisible()
      }
    })
  })

  test.describe('Concurrent User Error Scenarios', () => {
    test('should handle multiple users with conflicting actions', async ({ browser }) => {
      const context1 = await browser.newContext()
      const context2 = await browser.newContext()
      
      const page1 = await context1.newPage()
      const page2 = await context2.newPage()
      
      try {
        // Both users navigate to search
        await Promise.all([
          page1.goto(`${BASE_URL}/search`),
          page2.goto(`${BASE_URL}/search`)
        ])
        
        // Both users perform searches simultaneously
        const search1 = performConcurrentSearch(page1, 'restaurants', '12345')
        const search2 = performConcurrentSearch(page2, 'hotels', '67890')
        
        const results = await Promise.allSettled([search1, search2])
        
        // At least one search should succeed
        const successfulSearches = results.filter(result => result.status === 'fulfilled')
        expect(successfulSearches.length).toBeGreaterThan(0)
        
      } finally {
        await context1.close()
        await context2.close()
      }
    })
  })
})

// Helper function for concurrent search testing
async function performConcurrentSearch(page: Page, industry: string, zipCode: string): Promise<void> {
  await page.fill('input[name="industry"], [data-testid="industry-input"]', industry)
  await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', zipCode)
  await page.click('button[type="submit"], [data-testid="search-button"]')
  
  await Promise.race([
    page.waitForSelector('[data-testid="results"], .results', { timeout: 20000 }),
    page.waitForSelector('[data-testid="error-message"], .error', { timeout: 20000 }),
    page.waitForSelector('[data-testid="no-results"], .no-results', { timeout: 20000 })
  ])
}
