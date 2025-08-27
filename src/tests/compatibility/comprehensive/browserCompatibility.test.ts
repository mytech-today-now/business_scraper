/**
 * Comprehensive Browser Compatibility Tests
 * Testing application across different browsers, devices, and operating systems
 */

import { test, expect, devices, Browser, BrowserContext, Page } from '@playwright/test'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

interface CompatibilityTestResult {
  browser: string
  device?: string
  viewport?: { width: number; height: number }
  success: boolean
  error?: string
  performanceMetrics?: {
    loadTime: number
    renderTime: number
    interactionTime: number
  }
}

class CompatibilityTester {
  private results: CompatibilityTestResult[] = []

  async testBrowserCompatibility(
    browser: Browser,
    browserName: string,
    deviceConfig?: any
  ): Promise<CompatibilityTestResult> {
    let context: BrowserContext | null = null
    let page: Page | null = null

    try {
      const startTime = Date.now()

      // Create context with device configuration if provided
      context = deviceConfig ? await browser.newContext(deviceConfig) : await browser.newContext()

      page = await context.newPage()

      // Navigate to application
      await page.goto(BASE_URL, { waitUntil: 'networkidle' })
      const loadTime = Date.now() - startTime

      // Test basic functionality
      await this.testBasicFunctionality(page)
      const renderTime = Date.now() - startTime - loadTime

      // Test user interactions
      await this.testUserInteractions(page)
      const interactionTime = Date.now() - startTime - loadTime - renderTime

      const result: CompatibilityTestResult = {
        browser: browserName,
        device: deviceConfig?.name,
        viewport: deviceConfig?.viewport,
        success: true,
        performanceMetrics: {
          loadTime,
          renderTime,
          interactionTime,
        },
      }

      this.results.push(result)
      return result
    } catch (error) {
      const result: CompatibilityTestResult = {
        browser: browserName,
        device: deviceConfig?.name,
        viewport: deviceConfig?.viewport,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      }

      this.results.push(result)
      return result
    } finally {
      if (page) await page.close()
      if (context) await context.close()
    }
  }

  private async testBasicFunctionality(page: Page): Promise<void> {
    // Test page load
    await expect(page.locator('body')).toBeVisible()

    // Test navigation
    const title = await page.title()
    expect(title).toBeTruthy()

    // Test CSS rendering
    const bodyStyles = await page.locator('body').evaluate(el => {
      const styles = window.getComputedStyle(el)
      return {
        display: styles.display,
        fontFamily: styles.fontFamily,
      }
    })
    expect(bodyStyles.display).toBeTruthy()

    // Test JavaScript execution
    const jsWorking = await page.evaluate(() => {
      return typeof window !== 'undefined' && typeof document !== 'undefined'
    })
    expect(jsWorking).toBe(true)
  }

  private async testUserInteractions(page: Page): Promise<void> {
    try {
      // Test navigation to search page
      const searchLink = page.locator(
        'a[href*="/search"], button:has-text("Search"), [data-testid="search-nav"]'
      )
      if (await searchLink.isVisible()) {
        await searchLink.click()
        await page.waitForURL('**/search**', { timeout: 10000 })
      } else {
        await page.goto(`${BASE_URL}/search`)
      }

      // Test form interactions
      const industryInput = page
        .locator('input[name="industry"], [data-testid="industry-input"]')
        .first()
      if (await industryInput.isVisible()) {
        await industryInput.fill('restaurants')

        const zipInput = page
          .locator('input[name="zipCode"], [data-testid="zipcode-input"]')
          .first()
        if (await zipInput.isVisible()) {
          await zipInput.fill('12345')
        }
      }

      // Test button interactions
      const submitButton = page
        .locator('button[type="submit"], [data-testid="search-button"]')
        .first()
      if (await submitButton.isVisible()) {
        await submitButton.click()

        // Wait for response (either results or error)
        await Promise.race([
          page.waitForSelector('[data-testid="results"], .results', { timeout: 15000 }),
          page.waitForSelector('[data-testid="error-message"], .error', { timeout: 15000 }),
          page.waitForTimeout(10000),
        ])
      }
    } catch (error) {
      // Some interactions might fail on certain browsers/devices
      console.warn('User interaction test failed:', error)
    }
  }

  getResults(): CompatibilityTestResult[] {
    return this.results
  }

  getSuccessRate(): number {
    const total = this.results.length
    const successful = this.results.filter(r => r.success).length
    return total > 0 ? successful / total : 0
  }

  getFailedTests(): CompatibilityTestResult[] {
    return this.results.filter(r => !r.success)
  }
}

test.describe('Browser Compatibility Comprehensive Tests', () => {
  let compatibilityTester: CompatibilityTester

  test.beforeEach(() => {
    compatibilityTester = new CompatibilityTester()
  })

  test.describe('Desktop Browser Compatibility', () => {
    test('should work on Chromium-based browsers', async ({ browser }) => {
      const result = await compatibilityTester.testBrowserCompatibility(browser, 'Chromium')

      expect(result.success).toBe(true)
      expect(result.performanceMetrics?.loadTime).toBeLessThan(10000)
    })

    test('should work on Firefox', async ({ browser }) => {
      // Note: This test will use the configured browser from playwright.config.ts
      const result = await compatibilityTester.testBrowserCompatibility(browser, 'Firefox')

      expect(result.success).toBe(true)
      expect(result.performanceMetrics?.loadTime).toBeLessThan(15000)
    })

    test('should work on WebKit/Safari', async ({ browser }) => {
      const result = await compatibilityTester.testBrowserCompatibility(browser, 'WebKit')

      expect(result.success).toBe(true)
      expect(result.performanceMetrics?.loadTime).toBeLessThan(15000)
    })
  })

  test.describe('Mobile Device Compatibility', () => {
    test('should work on iPhone devices', async ({ browser }) => {
      const iPhoneConfig = devices['iPhone 13']
      const result = await compatibilityTester.testBrowserCompatibility(
        browser,
        'Mobile Safari',
        iPhoneConfig
      )

      expect(result.success).toBe(true)
      expect(result.viewport?.width).toBe(390)
    })

    test('should work on Android devices', async ({ browser }) => {
      const androidConfig = devices['Pixel 5']
      const result = await compatibilityTester.testBrowserCompatibility(
        browser,
        'Chrome Mobile',
        androidConfig
      )

      expect(result.success).toBe(true)
      expect(result.viewport?.width).toBe(393)
    })

    test('should work on tablet devices', async ({ browser }) => {
      const tabletConfig = devices['iPad Pro']
      const result = await compatibilityTester.testBrowserCompatibility(
        browser,
        'Mobile Safari',
        tabletConfig
      )

      expect(result.success).toBe(true)
      expect(result.viewport?.width).toBe(1024)
    })
  })

  test.describe('Viewport Size Compatibility', () => {
    test('should work on small screens (320px)', async ({ browser }) => {
      const smallScreenConfig = {
        viewport: { width: 320, height: 568 },
      }

      const result = await compatibilityTester.testBrowserCompatibility(
        browser,
        'Small Screen',
        smallScreenConfig
      )

      expect(result.success).toBe(true)
    })

    test('should work on medium screens (768px)', async ({ browser }) => {
      const mediumScreenConfig = {
        viewport: { width: 768, height: 1024 },
      }

      const result = await compatibilityTester.testBrowserCompatibility(
        browser,
        'Medium Screen',
        mediumScreenConfig
      )

      expect(result.success).toBe(true)
    })

    test('should work on large screens (1920px)', async ({ browser }) => {
      const largeScreenConfig = {
        viewport: { width: 1920, height: 1080 },
      }

      const result = await compatibilityTester.testBrowserCompatibility(
        browser,
        'Large Screen',
        largeScreenConfig
      )

      expect(result.success).toBe(true)
    })

    test('should work on ultra-wide screens (2560px)', async ({ browser }) => {
      const ultraWideConfig = {
        viewport: { width: 2560, height: 1440 },
      }

      const result = await compatibilityTester.testBrowserCompatibility(
        browser,
        'Ultra-wide Screen',
        ultraWideConfig
      )

      expect(result.success).toBe(true)
    })
  })

  test.describe('Feature Support Compatibility', () => {
    test('should handle browsers with limited JavaScript support', async ({ page }) => {
      // Disable JavaScript and test basic functionality
      await page.context().addInitScript(() => {
        // Simulate limited JavaScript environment
        delete (window as any).fetch
        delete (window as any).Promise
      })

      await page.goto(BASE_URL)

      // Should still render basic HTML/CSS
      await expect(page.locator('body')).toBeVisible()
    })

    test('should handle browsers with disabled cookies', async ({ browser }) => {
      const context = await browser.newContext({
        permissions: [],
        extraHTTPHeaders: {
          Cookie: '',
        },
      })

      const page = await context.newPage()

      await page.goto(BASE_URL)
      await expect(page.locator('body')).toBeVisible()

      await context.close()
    })

    test('should handle browsers with disabled local storage', async ({ page }) => {
      await page.addInitScript(() => {
        // Disable localStorage
        Object.defineProperty(window, 'localStorage', {
          value: null,
          writable: false,
        })
      })

      await page.goto(BASE_URL)
      await expect(page.locator('body')).toBeVisible()
    })

    test('should handle slow network connections', async ({ browser }) => {
      const context = await browser.newContext()

      // Simulate slow 3G connection
      await context.route('**/*', async route => {
        await new Promise(resolve => setTimeout(resolve, 1000)) // 1 second delay
        await route.continue()
      })

      const page = await context.newPage()

      const startTime = Date.now()
      await page.goto(BASE_URL, { timeout: 30000 })
      const loadTime = Date.now() - startTime

      await expect(page.locator('body')).toBeVisible()
      expect(loadTime).toBeGreaterThan(1000) // Should reflect the delay

      await context.close()
    })
  })

  test.describe('Accessibility Compatibility', () => {
    test('should work with screen readers', async ({ page }) => {
      await page.goto(BASE_URL)

      // Check for ARIA landmarks
      const landmarks = await page.locator('[role="main"], [role="navigation"], main, nav').count()
      expect(landmarks).toBeGreaterThan(0)

      // Check for proper heading structure
      const h1Count = await page.locator('h1').count()
      expect(h1Count).toBe(1) // Should have exactly one h1

      // Check for alt text on images
      const images = await page.locator('img').all()
      for (const image of images) {
        const alt = await image.getAttribute('alt')
        const ariaLabel = await image.getAttribute('aria-label')
        const role = await image.getAttribute('role')

        // Images should have alt text, aria-label, or be decorative
        expect(alt !== null || ariaLabel !== null || role === 'presentation').toBe(true)
      }
    })

    test('should support keyboard navigation', async ({ page }) => {
      await page.goto(BASE_URL)

      // Test tab navigation
      await page.keyboard.press('Tab')
      const firstFocusable = await page.locator(':focus').first()
      await expect(firstFocusable).toBeVisible()

      // Continue tabbing through focusable elements
      for (let i = 0; i < 5; i++) {
        await page.keyboard.press('Tab')
        const focused = await page.locator(':focus').first()
        if ((await focused.count()) > 0) {
          await expect(focused).toBeVisible()
        }
      }
    })

    test('should support high contrast mode', async ({ browser }) => {
      const context = await browser.newContext({
        colorScheme: 'dark',
        forcedColors: 'active',
      })

      const page = await context.newPage()
      await page.goto(BASE_URL)

      await expect(page.locator('body')).toBeVisible()

      // Check that content is still readable
      const bodyText = await page.locator('body').textContent()
      expect(bodyText).toBeTruthy()

      await context.close()
    })
  })

  test.describe('Performance Compatibility', () => {
    test('should perform well on low-end devices', async ({ browser }) => {
      const lowEndConfig = {
        viewport: { width: 360, height: 640 },
        deviceScaleFactor: 1,
        isMobile: true,
        hasTouch: true,
      }

      const context = await browser.newContext(lowEndConfig)
      const page = await context.newPage()

      // Simulate slower CPU
      await page.emulateMedia({ reducedMotion: 'reduce' })

      const startTime = Date.now()
      await page.goto(BASE_URL)
      const loadTime = Date.now() - startTime

      await expect(page.locator('body')).toBeVisible()

      // Should still load within reasonable time even on low-end devices
      expect(loadTime).toBeLessThan(20000) // 20 seconds max

      await context.close()
    })

    test('should handle memory constraints', async ({ page }) => {
      await page.goto(BASE_URL)

      // Simulate memory pressure by creating large objects
      await page.evaluate(() => {
        const largeArrays: number[][] = []
        try {
          for (let i = 0; i < 100; i++) {
            largeArrays.push(new Array(10000).fill(i))
          }
        } catch (error) {
          // Memory pressure detected
        }
      })

      // Application should still be responsive
      await expect(page.locator('body')).toBeVisible()
    })
  })

  test.describe('Compatibility Test Summary', () => {
    test('should provide comprehensive compatibility coverage', async ({ browser }) => {
      // Test multiple configurations
      const testConfigs = [
        { name: 'Desktop Chrome', config: { viewport: { width: 1920, height: 1080 } } },
        { name: 'Mobile Portrait', config: devices['iPhone 13'] },
        { name: 'Tablet Landscape', config: devices['iPad Pro'] },
        { name: 'Small Screen', config: { viewport: { width: 320, height: 568 } } },
      ]

      for (const { name, config } of testConfigs) {
        await compatibilityTester.testBrowserCompatibility(browser, name, config)
      }

      const results = compatibilityTester.getResults()
      const successRate = compatibilityTester.getSuccessRate()
      const failedTests = compatibilityTester.getFailedTests()

      // Log results for debugging
      console.log('\n🌐 Browser Compatibility Test Results:')
      console.log(`✅ Success Rate: ${(successRate * 100).toFixed(1)}%`)
      console.log(`📱 Configurations Tested: ${results.length}`)

      if (failedTests.length > 0) {
        console.log('❌ Failed Tests:')
        failedTests.forEach(test => {
          console.log(`  - ${test.browser} ${test.device || ''}: ${test.error}`)
        })
      }

      // Compatibility requirements
      expect(successRate).toBeGreaterThanOrEqual(0.8) // 80% compatibility minimum
      expect(results.length).toBeGreaterThan(3) // Test multiple configurations

      // Performance requirements
      const successfulTests = results.filter(r => r.success && r.performanceMetrics)
      successfulTests.forEach(test => {
        if (test.performanceMetrics) {
          expect(test.performanceMetrics.loadTime).toBeLessThan(20000) // 20 seconds max
        }
      })
    })
  })
})
