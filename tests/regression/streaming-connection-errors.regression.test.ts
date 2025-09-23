/**
 * Regression Tests for Streaming Connection Errors
 * Ensures that GitHub Issue #192 and related streaming issues don't regress
 */

import { test, expect } from '@playwright/test'

test.describe('Streaming Connection Error Regression Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')
  })

  test('REG-001: EventSource readyState 2 error should not cause infinite retry loops', async ({ page }) => {
    const consoleLogs: string[] = []
    const errorLogs: string[] = []
    
    page.on('console', msg => {
      const text = msg.text()
      consoleLogs.push(text)
      if (msg.type() === 'error' || text.includes('ERROR') || text.includes('WARN')) {
        errorLogs.push(text)
      }
    })
    
    // Navigate to scraping page
    await page.click('text=Scraping')
    
    // Fill in search parameters
    await page.fill('[data-testid="search-input"]', 'Insurance Agencies, Financial Advisory Services')
    await page.fill('[data-testid="location-input"]', '60047')
    
    // Start streaming search
    await page.click('[data-testid="start-search-button"]')
    
    // Wait for potential retry attempts
    await page.waitForTimeout(15000)
    
    // Count streaming connection error messages
    const connectionErrors = errorLogs.filter(log => 
      log.includes('Streaming connection error') && log.includes('readyState')
    )
    
    // Should not have excessive retry attempts (max 3 retries per attempt)
    expect(connectionErrors.length).toBeLessThan(20)
    
    // Should eventually stop retrying or fallback
    const recentErrors = errorLogs.slice(-5)
    const hasCircuitBreakerMessage = recentErrors.some(log => 
      log.includes('circuit breaker') || log.includes('Service temporarily unavailable')
    )
    const hasFallbackMessage = recentErrors.some(log => 
      log.includes('falling back') || log.includes('batch search')
    )
    
    expect(hasCircuitBreakerMessage || hasFallbackMessage).toBe(true)
  })

  test('REG-002: ANSI color codes should not appear in console output', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })
    
    await page.click('text=Scraping')
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    await page.click('[data-testid="start-search-button"]')
    
    await page.waitForTimeout(5000)
    
    // Check for ANSI escape sequences
    const ansiPattern = /\x1b\[[0-9;]*[a-zA-Z]|\[2;38;2;124;124;124m|\[0m/
    const logsWithAnsi = consoleLogs.filter(log => ansiPattern.test(log))
    
    expect(logsWithAnsi).toHaveLength(0)
  })

  test('REG-003: Duplicate log entries should be minimized', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })
    
    await page.click('text=Scraping')
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    await page.click('[data-testid="start-search-button"]')
    
    await page.waitForTimeout(5000)
    
    // Count consecutive duplicate entries
    let consecutiveDuplicates = 0
    let maxConsecutiveDuplicates = 0
    
    for (let i = 1; i < consoleLogs.length; i++) {
      if (consoleLogs[i] === consoleLogs[i - 1]) {
        consecutiveDuplicates++
      } else {
        maxConsecutiveDuplicates = Math.max(maxConsecutiveDuplicates, consecutiveDuplicates)
        consecutiveDuplicates = 0
      }
    }
    
    // Should not have more than 2 consecutive identical log entries
    expect(maxConsecutiveDuplicates).toBeLessThanOrEqual(2)
  })

  test('REG-004: Health check should prevent streaming when service is unhealthy', async ({ page, request }) => {
    // First verify health check endpoint works
    const healthResponse = await request.get('/api/stream-health')
    expect(healthResponse.status()).toBe(200)
    
    const health = await healthResponse.json()
    
    if (health.status === 'unhealthy') {
      // If service is unhealthy, streaming should not start
      await page.click('text=Scraping')
      await page.fill('[data-testid="search-input"]', 'test query')
      await page.fill('[data-testid="location-input"]', 'test location')
      await page.click('[data-testid="start-search-button"]')
      
      // Should show service unavailable message
      await expect(page.locator('text=Service temporarily unavailable')).toBeVisible({ timeout: 10000 })
    }
  })

  test('REG-005: Rate limiting should prevent abuse while allowing normal usage', async ({ request }) => {
    // Normal usage should work
    const normalResponse = await request.get('/api/stream-search?q=test&location=test')
    expect([200, 503]).toContain(normalResponse.status()) // 200 for success, 503 for service unavailable
    
    // Excessive requests should be rate limited
    const rapidRequests = []
    for (let i = 0; i < 35; i++) {
      rapidRequests.push(request.get('/api/stream-search?q=test&location=test'))
    }
    
    const responses = await Promise.all(rapidRequests)
    const rateLimitedCount = responses.filter(r => r.status() === 429).length
    
    expect(rateLimitedCount).toBeGreaterThan(0)
  })

  test('REG-006: Middleware should not interfere with SSE connections', async ({ request }) => {
    const response = await request.get('/api/stream-search?q=test&location=test')
    
    if (response.status() === 200) {
      // Verify SSE-specific headers are set correctly
      expect(response.headers()['content-type']).toBe('text/event-stream')
      expect(response.headers()['cache-control']).toBe('no-cache, no-transform')
      expect(response.headers()['connection']).toBe('keep-alive')
      
      // Verify restrictive cache headers are NOT set for SSE
      expect(response.headers()['pragma']).not.toBe('no-cache')
      expect(response.headers()['expires']).not.toBe('0')
    }
  })

  test('REG-007: Circuit breaker should open after repeated failures', async ({ page }) => {
    const errorLogs: string[] = []
    
    page.on('console', msg => {
      if (msg.type() === 'error' || msg.text().includes('ERROR') || msg.text().includes('WARN')) {
        errorLogs.push(msg.text())
      }
    })
    
    await page.click('text=Scraping')
    
    // Attempt multiple searches to trigger circuit breaker
    for (let i = 0; i < 3; i++) {
      await page.fill('[data-testid="search-input"]', `test query ${i}`)
      await page.fill('[data-testid="location-input"]', `test location ${i}`)
      await page.click('[data-testid="start-search-button"]')
      
      // Wait for failure
      await page.waitForTimeout(5000)
      
      // Clear results if possible
      const clearButton = page.locator('[data-testid="clear-results-button"]')
      if (await clearButton.isVisible()) {
        await clearButton.click()
      }
    }
    
    // Circuit breaker should eventually open
    const circuitBreakerMessages = errorLogs.filter(log => 
      log.includes('circuit breaker') || log.includes('Service temporarily unavailable')
    )
    
    expect(circuitBreakerMessages.length).toBeGreaterThan(0)
  })

  test('REG-008: Network connectivity changes should be handled gracefully', async ({ page, context }) => {
    await page.click('text=Scraping')
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    
    // Start with network offline
    await context.setOffline(true)
    await page.click('[data-testid="start-search-button"]')
    
    // Should detect offline status
    await expect(page.locator('text=Network connection lost')).toBeVisible({ timeout: 10000 })
    
    // Restore network
    await context.setOffline(false)
    
    // Should recover automatically or allow retry
    await page.waitForTimeout(2000)
    
    // Network error message should disappear or retry should be possible
    const networkErrorVisible = await page.locator('text=Network connection lost').isVisible()
    const retryButtonVisible = await page.locator('[data-testid="start-search-button"]').isEnabled()
    
    expect(!networkErrorVisible || retryButtonVisible).toBe(true)
  })

  test('REG-009: Service initialization errors should be handled properly', async ({ request }) => {
    // Test the health check endpoint for service status
    const healthResponse = await request.get('/api/stream-health')
    expect(healthResponse.status()).toBe(200)
    
    const health = await healthResponse.json()
    expect(health.diagnostics).toBeDefined()
    expect(health.diagnostics.serverInfo).toBeDefined()
    
    // If services are not initialized, should be reported in health check
    if (health.status === 'unhealthy') {
      expect(health.error || health.details).toBeDefined()
    }
  })

  test('REG-010: Error recovery should work after temporary failures', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })
    
    await page.click('text=Scraping')
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    
    // Start search
    await page.click('[data-testid="start-search-button"]')
    
    // Wait for initial attempt and potential retries
    await page.waitForTimeout(10000)
    
    // Clear any errors and try again
    const clearButton = page.locator('[data-testid="clear-results-button"]')
    if (await clearButton.isVisible()) {
      await clearButton.click()
    }
    
    // Second attempt should not be blocked by previous failures
    await page.click('[data-testid="start-search-button"]')
    
    // Should be able to attempt again (not permanently blocked)
    const isButtonDisabled = await page.locator('[data-testid="start-search-button"]').isDisabled()
    expect(isButtonDisabled).toBe(false)
  })
})

test.describe('Streaming Performance Regression Tests', () => {
  test('REG-011: Memory usage should not grow excessively during streaming', async ({ page }) => {
    // This is a basic test - in a real environment you'd use performance monitoring
    const initialMemory = await page.evaluate(() => (performance as any).memory?.usedJSHeapSize || 0)
    
    await page.click('text=Scraping')
    
    // Perform multiple search operations
    for (let i = 0; i < 3; i++) {
      await page.fill('[data-testid="search-input"]', `test query ${i}`)
      await page.fill('[data-testid="location-input"]', `test location ${i}`)
      await page.click('[data-testid="start-search-button"]')
      await page.waitForTimeout(3000)
      
      const clearButton = page.locator('[data-testid="clear-results-button"]')
      if (await clearButton.isVisible()) {
        await clearButton.click()
      }
    }
    
    const finalMemory = await page.evaluate(() => (performance as any).memory?.usedJSHeapSize || 0)
    
    if (initialMemory > 0 && finalMemory > 0) {
      const memoryIncrease = finalMemory - initialMemory
      const memoryIncreasePercent = (memoryIncrease / initialMemory) * 100
      
      // Memory should not increase by more than 50% during normal operations
      expect(memoryIncreasePercent).toBeLessThan(50)
    }
  })

  test('REG-012: Response times should remain reasonable', async ({ request }) => {
    const start = Date.now()
    const response = await request.get('/api/stream-search?q=test&location=test')
    const duration = Date.now() - start
    
    // Initial response should be fast (connection establishment)
    expect(duration).toBeLessThan(5000)
    
    // Status should be reasonable
    expect([200, 429, 503]).toContain(response.status())
  })
})
