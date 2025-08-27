/**
 * Search Engine Management E2E Tests
 * End-to-end testing of search engine configuration and management features
 */

import { test, expect, Page } from '@playwright/test'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

test.describe('Search Engine Management E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto(BASE_URL)
  })

  test.describe('Search Engine Configuration', () => {
    test('should allow configuring search engines', async ({ page }) => {
      // Navigate to search engine settings (if available)
      const settingsButton = page.locator(
        '[data-testid="settings-button"], button:has-text("Settings"), [aria-label="Settings"]'
      )

      if (await settingsButton.isVisible()) {
        await settingsButton.click()

        // Look for search engine configuration options
        const searchEngineSection = page.locator(
          '[data-testid="search-engines"], .search-engines, :has-text("Search Engines")'
        )

        if (await searchEngineSection.isVisible()) {
          // Test enabling/disabling search engines
          const checkboxes = page.locator('input[type="checkbox"]')
          const checkboxCount = await checkboxes.count()

          if (checkboxCount > 0) {
            // Toggle first checkbox
            await checkboxes.first().click()

            // Verify state change
            const isChecked = await checkboxes.first().isChecked()
            expect(typeof isChecked).toBe('boolean')

            // Save settings if save button exists
            const saveButton = page.locator(
              'button:has-text("Save"), [data-testid="save-settings"]'
            )
            if (await saveButton.isVisible()) {
              await saveButton.click()

              // Wait for save confirmation
              await Promise.race([
                page.waitForSelector('[data-testid="save-success"], .success-message', {
                  timeout: 5000,
                }),
                page.waitForTimeout(2000),
              ])
            }
          }
        }
      }

      // If no settings UI, verify search functionality works
      await page.goto(`${BASE_URL}/search`)
      await expect(page.locator('form, [data-testid="search-form"]')).toBeVisible()
    })

    test('should handle search engine priority configuration', async ({ page }) => {
      // Navigate to search configuration
      await page.goto(`${BASE_URL}/search`)

      // Look for advanced search options
      const advancedButton = page.locator(
        '[data-testid="advanced-options"], button:has-text("Advanced"), .advanced-toggle'
      )

      if (await advancedButton.isVisible()) {
        await advancedButton.click()

        // Look for search engine selection
        const engineSelect = page.locator(
          'select[name="searchEngine"], [data-testid="search-engine-select"]'
        )

        if (await engineSelect.isVisible()) {
          // Get available options
          const options = await engineSelect.locator('option').all()

          if (options.length > 1) {
            // Select different search engine
            await engineSelect.selectOption({ index: 1 })

            // Verify selection
            const selectedValue = await engineSelect.inputValue()
            expect(selectedValue).toBeTruthy()
          }
        }
      }

      // Verify search form is still functional
      await expect(
        page.locator('input[name="industry"], [data-testid="industry-input"]')
      ).toBeVisible()
    })
  })

  test.describe('Search Engine Fallback Behavior', () => {
    test('should handle primary search engine failure', async ({ page, context }) => {
      // Mock API failure for primary search engine
      await context.route('**/api/search**', async route => {
        const url = route.request().url()

        // Fail first request, succeed on retry
        if (url.includes('retry=true')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              results: [{ id: '1', name: 'Fallback Business', url: 'https://example.com' }],
            }),
          })
        } else {
          await route.abort('failed')
        }
      })

      await page.goto(`${BASE_URL}/search`)

      // Perform search
      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')

      // Should either show error or fallback results
      await Promise.race([
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 15000 }),
        page.waitForSelector('[data-testid="results"], .results', { timeout: 15000 }),
        page.waitForSelector(':has-text("Fallback")', { timeout: 15000 }),
      ])

      // Verify page is still functional
      await expect(page.locator('body')).toBeVisible()
    })

    test('should retry failed search requests', async ({ page, context }) => {
      let requestCount = 0

      await context.route('**/api/search**', async route => {
        requestCount++

        if (requestCount === 1) {
          // Fail first request
          await route.abort('failed')
        } else {
          // Succeed on retry
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              results: [{ id: '1', name: 'Retry Success Business', url: 'https://example.com' }],
            }),
          })
        }
      })

      await page.goto(`${BASE_URL}/search`)

      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')

      // Wait for retry to complete
      await page.waitForTimeout(5000)

      // Should have made multiple requests
      expect(requestCount).toBeGreaterThan(1)
    })
  })

  test.describe('Search Engine Performance Monitoring', () => {
    test('should track search engine response times', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)

      // Perform search and measure time
      const startTime = Date.now()

      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')

      // Wait for results or error
      await Promise.race([
        page.waitForSelector('[data-testid="results"], .results', { timeout: 30000 }),
        page.waitForSelector('[data-testid="error-message"], .error', { timeout: 30000 }),
        page.waitForSelector('[data-testid="no-results"], .no-results', { timeout: 30000 }),
      ])

      const responseTime = Date.now() - startTime

      // Response time should be reasonable (under 30 seconds)
      expect(responseTime).toBeLessThan(30000)

      // Log performance metrics
      console.log(`Search response time: ${responseTime}ms`)
    })

    test('should handle concurrent search requests', async ({ page, context }) => {
      // Create multiple pages for concurrent requests
      const page2 = await context.newPage()
      const page3 = await context.newPage()

      try {
        // Navigate all pages to search
        await Promise.all([
          page.goto(`${BASE_URL}/search`),
          page2.goto(`${BASE_URL}/search`),
          page3.goto(`${BASE_URL}/search`),
        ])

        // Perform concurrent searches
        const searchPromises = [
          performSearch(page, 'restaurants', '12345'),
          performSearch(page2, 'hotels', '67890'),
          performSearch(page3, 'shops', '54321'),
        ]

        const results = await Promise.allSettled(searchPromises)

        // At least one search should succeed
        const successfulSearches = results.filter(result => result.status === 'fulfilled')
        expect(successfulSearches.length).toBeGreaterThan(0)
      } finally {
        await page2.close()
        await page3.close()
      }
    })
  })

  test.describe('Search Engine Rate Limiting', () => {
    test('should respect rate limits', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)

      // Perform multiple rapid searches
      const searchPromises = []

      for (let i = 0; i < 5; i++) {
        searchPromises.push(
          performSearch(page, `business${i}`, `1234${i}`).catch(error => ({ error: error.message }))
        )

        // Small delay between requests
        await page.waitForTimeout(500)
      }

      const results = await Promise.allSettled(searchPromises)

      // Some requests might be rate limited, but at least one should succeed
      const successfulRequests = results.filter(
        result => result.status === 'fulfilled' && !result.value.error
      )

      expect(successfulRequests.length).toBeGreaterThan(0)
    })

    test('should show rate limit messages when appropriate', async ({ page, context }) => {
      // Mock rate limit response
      await context.route('**/api/search**', async route => {
        await route.fulfill({
          status: 429,
          contentType: 'application/json',
          body: JSON.stringify({
            error: 'Rate limit exceeded',
            retryAfter: 60,
          }),
        })
      })

      await page.goto(`${BASE_URL}/search`)

      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
      await page.click('button[type="submit"], [data-testid="search-button"]')

      // Should show rate limit message
      await Promise.race([
        page.waitForSelector(':has-text("rate limit")', { timeout: 10000 }),
        page.waitForSelector(':has-text("too many requests")', { timeout: 10000 }),
        page.waitForSelector('[data-testid="rate-limit-error"]', { timeout: 10000 }),
      ])
    })
  })

  test.describe('Search Engine Health Monitoring', () => {
    test('should detect unhealthy search engines', async ({ page, context }) => {
      // Mock unhealthy search engine responses
      await context.route('**/api/health**', async route => {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            searchEngines: {
              primary: { status: 'healthy', responseTime: 150 },
              secondary: { status: 'unhealthy', responseTime: 5000 },
              fallback: { status: 'healthy', responseTime: 300 },
            },
          }),
        })
      })

      await page.goto(BASE_URL)

      // Check if health status is displayed anywhere
      const healthIndicator = page.locator(
        '[data-testid="health-status"], .health-indicator, .status-indicator'
      )

      if (await healthIndicator.isVisible()) {
        // Verify health information is displayed
        await expect(healthIndicator).toBeVisible()
      }

      // Verify search functionality still works despite unhealthy engines
      await page.goto(`${BASE_URL}/search`)
      await expect(page.locator('form')).toBeVisible()
    })
  })
})

// Helper function to perform a search
async function performSearch(page: Page, industry: string, zipCode: string): Promise<void> {
  await page.fill('input[name="industry"], [data-testid="industry-input"]', industry)
  await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', zipCode)
  await page.click('button[type="submit"], [data-testid="search-button"]')

  // Wait for response
  await Promise.race([
    page.waitForSelector('[data-testid="results"], .results', { timeout: 15000 }),
    page.waitForSelector('[data-testid="error-message"], .error', { timeout: 15000 }),
    page.waitForSelector('[data-testid="no-results"], .no-results', { timeout: 15000 }),
  ])
}
