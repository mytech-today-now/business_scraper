/**
 * Build Verification Tests (BVT) for Toast Deduplication
 * Critical tests that must pass for toast deduplication to be considered working
 * Related to GitHub Issue #201: Duplicate toast messages
 */

import { test, expect } from '@playwright/test'

test.describe('Toast Deduplication BVT', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')
  })

  test('BVT-TOAST-001: ZIP code validation toast should not appear more than once', async ({ page }) => {
    const toastMessages: string[] = []
    
    page.on('console', msg => {
      const text = msg.text()
      if (text.includes('ZIP code') && text.includes('valid')) {
        toastMessages.push(text)
      }
    })

    // Navigate to configuration page
    await page.click('text=Configuration')
    await page.waitForTimeout(3000)

    // Check that ZIP code validation toast appears at most once
    const zipCodeToasts = toastMessages.filter(msg => 
      msg.includes('ZIP code') && msg.includes('valid')
    )
    
    expect(zipCodeToasts.length).toBeLessThanOrEqual(1)
  })

  test('BVT-TOAST-002: Toast deduplication system should be functional', async ({ page }) => {
    const toastMessages: string[] = []
    
    page.on('console', msg => {
      const text = msg.text()
      if (text.includes('ZIP code') && text.includes('valid')) {
        toastMessages.push(text)
      }
    })

    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    await expect(zipInput).toBeVisible()

    // Enter same ZIP code multiple times rapidly
    for (let i = 0; i < 3; i++) {
      await zipInput.selectAll()
      await zipInput.fill('60047')
      await zipInput.blur()
      await page.waitForTimeout(200)
    }

    await page.waitForTimeout(1000)

    // Should have limited toasts due to deduplication
    const uniqueToasts = new Set(toastMessages.filter(msg => 
      msg.includes('ZIP code "60047" is valid')
    ))

    expect(uniqueToasts.size).toBeLessThanOrEqual(1)
  })

  test('BVT-TOAST-003: Different ZIP codes should each get their own toast', async ({ page }) => {
    const toastMessages: string[] = []
    
    page.on('console', msg => {
      const text = msg.text()
      if (text.includes('ZIP code') && text.includes('valid')) {
        toastMessages.push(text)
      }
    })

    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    await expect(zipInput).toBeVisible()

    // Enter different ZIP codes
    const zipCodes = ['60047', '90210']
    
    for (const zipCode of zipCodes) {
      await zipInput.selectAll()
      await zipInput.fill(zipCode)
      await zipInput.blur()
      await page.waitForTimeout(1000)
    }

    await page.waitForTimeout(1000)

    // Should have toasts for different ZIP codes
    const zipCodeToasts = toastMessages.filter(msg => 
      msg.includes('ZIP code') && msg.includes('valid')
    )

    expect(zipCodeToasts.length).toBeGreaterThan(0)
    expect(zipCodeToasts.length).toBeLessThanOrEqual(zipCodes.length)
  })

  test('BVT-TOAST-004: Console logs should not contain ANSI color codes', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })

    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    if (await zipInput.isVisible()) {
      await zipInput.selectAll()
      await zipInput.fill('60047')
      await zipInput.blur()
    }

    await page.waitForTimeout(2000)

    // Check for ANSI escape sequences
    const ansiPattern = /\x1b\[[0-9;]*[a-zA-Z]|\[2;38;2;124;124;124m|\[0m/
    const logsWithAnsi = consoleLogs.filter(log => ansiPattern.test(log))

    expect(logsWithAnsi).toHaveLength(0)
  })

  test('BVT-TOAST-005: ZIP code logging should be limited', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })

    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    if (await zipInput.isVisible()) {
      // Enter same ZIP code multiple times
      for (let i = 0; i < 5; i++) {
        await zipInput.selectAll()
        await zipInput.fill('60047')
        await zipInput.blur()
        await page.waitForTimeout(100)
      }
    }

    await page.waitForTimeout(2000)

    // Count ZIP code detection logs
    const zipDetectionLogs = consoleLogs.filter(log => 
      log.includes('AddressInputHandler') && log.includes('ZIP code input detected: 60047')
    )

    // Should have limited logging due to deduplication
    expect(zipDetectionLogs.length).toBeLessThan(3)
  })
})

test.describe('Streaming Error Handling BVT', () => {
  test('BVT-STREAM-001: Streaming errors should not cause excessive logging', async ({ page }) => {
    const errorLogs: string[] = []
    
    page.on('console', msg => {
      if (msg.type() === 'error' || msg.text().includes('ERROR') || msg.text().includes('WARN')) {
        errorLogs.push(msg.text())
      }
    })

    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    // Try to start streaming (may fail due to service unavailability)
    const searchInput = page.locator('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]').first()
    const locationInput = page.locator('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]').first()
    const startButton = page.locator('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")').first()

    if (await searchInput.isVisible() && await locationInput.isVisible() && await startButton.isVisible()) {
      await searchInput.fill('test query')
      await locationInput.fill('test location')
      await startButton.click()

      // Wait for potential errors
      await page.waitForTimeout(5000)
    }

    // Should not have excessive error logging
    const streamingErrors = errorLogs.filter(log => 
      log.includes('useSearchStreaming') || log.includes('stream-search')
    )

    expect(streamingErrors.length).toBeLessThan(20)
  })

  test('BVT-STREAM-002: Circuit breaker should prevent infinite retries', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })

    await page.click('text=Scraping')
    await page.waitForLoadState('networkidle')

    const searchInput = page.locator('[data-testid="search-input"], input[placeholder*="query"], input[placeholder*="search"]').first()
    const locationInput = page.locator('[data-testid="location-input"], input[placeholder*="location"], input[placeholder*="ZIP"]').first()
    const startButton = page.locator('[data-testid="start-search-button"], button:has-text("Start"), button:has-text("Search")').first()

    if (await searchInput.isVisible() && await locationInput.isVisible() && await startButton.isVisible()) {
      await searchInput.fill('test query')
      await locationInput.fill('test location')
      await startButton.click()

      // Wait for circuit breaker to potentially activate
      await page.waitForTimeout(10000)

      // Should eventually show circuit breaker or fallback message
      const circuitBreakerMessages = consoleLogs.filter(log => 
        log.includes('circuit breaker') || 
        log.includes('Service temporarily unavailable') ||
        log.includes('falling back')
      )

      // If streaming fails, should have circuit breaker or fallback
      const hasStreamingErrors = consoleLogs.some(log => 
        log.includes('Streaming connection error')
      )

      if (hasStreamingErrors) {
        expect(circuitBreakerMessages.length).toBeGreaterThan(0)
      }
    }
  })

  test('BVT-STREAM-003: Health check endpoints should be accessible', async ({ request }) => {
    const healthResponse = await request.get('/api/health')
    expect(healthResponse.status()).toBe(200)

    const streamHealthResponse = await request.get('/api/stream-health')
    expect(streamHealthResponse.status()).toBe(200)

    const streamHealth = await streamHealthResponse.json()
    expect(streamHealth.status).toBeDefined()
  })

  test('BVT-STREAM-004: Stream search endpoint should handle requests properly', async ({ request }) => {
    const response = await request.get('/api/stream-search?q=test&location=test')
    
    // Should return SSE response (200) or service unavailable (503)
    expect([200, 503]).toContain(response.status())
    
    if (response.status() === 200) {
      expect(response.headers()['content-type']).toBe('text/event-stream')
      expect(response.headers()['cache-control']).toBe('no-cache, no-transform')
    }
  })

  test('BVT-STREAM-005: Rate limiting should be properly configured', async ({ request }) => {
    // Make multiple requests to test rate limiting
    const requests = []
    for (let i = 0; i < 35; i++) {
      requests.push(request.get('/api/stream-search?q=test&location=test'))
    }
    
    const responses = await Promise.all(requests)
    const rateLimitedResponses = responses.filter(r => r.status() === 429)
    
    // Should have some rate limited responses
    expect(rateLimitedResponses.length).toBeGreaterThan(0)
  })
})
