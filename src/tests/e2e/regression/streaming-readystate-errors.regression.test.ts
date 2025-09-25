/**
 * Regression Tests for Streaming ReadyState 2 Errors
 * Ensures that GitHub Issue #201 - streaming connection errors are handled properly
 */

import { test, expect } from '@playwright/test'

test.describe('Streaming ReadyState Error Regression Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')
  })

  test('REG-STREAM-001: ReadyState 2 errors should not cause excessive logging', async ({ page }) => {
    const errorLogs: string[] = []
    const warnLogs: string[] = []
    
    page.on('console', msg => {
      const text = msg.text()
      if (msg.type() === 'error' || text.includes('ERROR')) {
        errorLogs.push(text)
      }
      if (msg.type() === 'warn' || text.includes('WARN')) {
        warnLogs.push(text)
      }
    })

    // Navigate to scraping page
    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    // Fill in search parameters
    await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', 'Insurance Agencies, Financial Advisory Services')
    await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', '60047')

    // Start streaming search
    await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')

    // Wait for potential streaming errors
    await page.waitForTimeout(10000)

    // Count readyState 2 error messages
    const readyState2Errors = [...errorLogs, ...warnLogs].filter(log => 
      log.includes('readyState') && log.includes('2')
    )

    // Should not have excessive readyState 2 error logs
    expect(readyState2Errors.length).toBeLessThan(10)
  })

  test('REG-STREAM-002: Streaming should fallback gracefully when service unavailable', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })

    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', 'test query')
    await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', 'test location')

    await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')

    // Wait for fallback to occur
    await page.waitForTimeout(15000)

    // Should eventually show fallback or circuit breaker message
    const fallbackMessages = consoleLogs.filter(log => 
      log.includes('falling back') || 
      log.includes('batch search') || 
      log.includes('circuit breaker') ||
      log.includes('Service temporarily unavailable')
    )

    expect(fallbackMessages.length).toBeGreaterThan(0)
  })

  test('REG-STREAM-003: Circuit breaker should prevent infinite retry loops', async ({ page }) => {
    const errorLogs: string[] = []
    
    page.on('console', msg => {
      if (msg.type() === 'error' || msg.text().includes('ERROR') || msg.text().includes('WARN')) {
        errorLogs.push(msg.text())
      }
    })

    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', 'test query')
    await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', 'test location')

    // Start search and let it fail multiple times
    await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')

    // Wait for circuit breaker to activate
    await page.waitForTimeout(20000)

    // Count total retry attempts
    const retryMessages = errorLogs.filter(log => 
      log.includes('Retrying connection') || log.includes('retry')
    )

    // Should not have excessive retries due to circuit breaker
    expect(retryMessages.length).toBeLessThan(20)

    // Should have circuit breaker activation
    const circuitBreakerMessages = errorLogs.filter(log => 
      log.includes('circuit breaker') || log.includes('Service temporarily unavailable')
    )

    expect(circuitBreakerMessages.length).toBeGreaterThan(0)
  })

  test('REG-STREAM-004: Network offline should be handled gracefully', async ({ page, context }) => {
    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', 'test query')
    await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', 'test location')

    // Go offline
    await context.setOffline(true)

    await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')

    // Should detect offline status
    await expect(page.locator('text=Network connection lost')).toBeVisible({ timeout: 10000 })

    // Go back online
    await context.setOffline(false)

    // Should recover
    await page.waitForTimeout(3000)
    
    // Network error should disappear or retry should be possible
    const networkErrorVisible = await page.locator('text=Network connection lost').isVisible()
    const retryButtonEnabled = await page.locator('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")').isEnabled()

    expect(!networkErrorVisible || retryButtonEnabled).toBe(true)
  })

  test('REG-STREAM-005: Streaming logs should not contain ANSI color codes', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })

    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', 'test query')
    await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', 'test location')

    await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')

    await page.waitForTimeout(5000)

    // Check for ANSI escape sequences in streaming-related logs
    const ansiPattern = /\x1b\[[0-9;]*[a-zA-Z]|\[2;38;2;124;124;124m|\[0m/
    const streamingLogs = consoleLogs.filter(log => 
      log.includes('useSearchStreaming') || log.includes('stream-search')
    )
    const logsWithAnsi = streamingLogs.filter(log => ansiPattern.test(log))

    expect(logsWithAnsi).toHaveLength(0)
  })

  test('REG-STREAM-006: Duplicate streaming error logs should be minimized', async ({ page }) => {
    const errorLogs: string[] = []
    
    page.on('console', msg => {
      if (msg.type() === 'error' || msg.text().includes('ERROR') || msg.text().includes('WARN')) {
        errorLogs.push(msg.text())
      }
    })

    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', 'test query')
    await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', 'test location')

    await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')

    await page.waitForTimeout(10000)

    // Count consecutive duplicate error entries
    let consecutiveDuplicates = 0
    let maxConsecutiveDuplicates = 0

    for (let i = 1; i < errorLogs.length; i++) {
      if (errorLogs[i] === errorLogs[i - 1]) {
        consecutiveDuplicates++
      } else {
        maxConsecutiveDuplicates = Math.max(maxConsecutiveDuplicates, consecutiveDuplicates)
        consecutiveDuplicates = 0
      }
    }

    // Should not have more than 2 consecutive identical error entries
    expect(maxConsecutiveDuplicates).toBeLessThanOrEqual(2)
  })

  test('REG-STREAM-007: Health check should prevent streaming when service unhealthy', async ({ page, request }) => {
    // Check health endpoint
    const healthResponse = await request.get('/api/stream-health')
    expect(healthResponse.status()).toBe(200)

    const health = await healthResponse.json()

    if (health.status === 'unhealthy') {
      await page.click('text=Scraping')
      await page.waitForLoadState('networkidle')

      await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', 'test query')
      await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', 'test location')

      await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')

      // Should show service unavailable message
      await expect(page.locator('text=Service temporarily unavailable')).toBeVisible({ timeout: 10000 })
    }
  })

  test('REG-STREAM-008: Rate limiting should not interfere with normal usage', async ({ request }) => {
    // Normal request should work
    const normalResponse = await request.get('/api/stream-search?q=test&location=test')
    expect([200, 503]).toContain(normalResponse.status())

    if (normalResponse.status() === 200) {
      // Verify SSE headers
      expect(normalResponse.headers()['content-type']).toBe('text/event-stream')
      expect(normalResponse.headers()['cache-control']).toBe('no-cache, no-transform')
    }
  })
})

test.describe('Streaming Performance Tests', () => {
  test('REG-STREAM-009: Connection establishment should be reasonably fast', async ({ request }) => {
    const start = Date.now()
    const response = await request.get('/api/stream-search?q=test&location=test')
    const duration = Date.now() - start

    // Connection should establish quickly
    expect(duration).toBeLessThan(5000)
    expect([200, 429, 503]).toContain(response.status())
  })

  test('REG-STREAM-010: Memory usage should not grow excessively during streaming errors', async ({ page }) => {
    // Basic memory test - in real environment you'd use performance monitoring
    const initialMemory = await page.evaluate(() => (performance as any).memory?.usedJSHeapSize || 0)

    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    // Trigger multiple failed streaming attempts
    for (let i = 0; i < 3; i++) {
      await page.fill('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]', `test query ${i}`)
      await page.fill('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]', `test location ${i}`)
      await page.click('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")')
      await page.waitForTimeout(3000)

      // Clear if possible
      const clearButton = page.locator('[data-testid="clear-results-button"], button:has-text("Clear")')
      if (await clearButton.isVisible()) {
        await clearButton.click()
      }
    }

    const finalMemory = await page.evaluate(() => (performance as any).memory?.usedJSHeapSize || 0)

    if (initialMemory > 0 && finalMemory > 0) {
      const memoryIncrease = finalMemory - initialMemory
      const memoryIncreasePercent = (memoryIncrease / initialMemory) * 100

      // Memory should not increase excessively
      expect(memoryIncreasePercent).toBeLessThan(50)
    }
  })
})
