/**
 * Build Verification Tests (BVT) for Streaming Functionality
 * Critical tests that must pass for streaming features to be considered working
 * Related to GitHub Issue #192: EventSource connection errors
 */

import { test, expect } from '@playwright/test'

test.describe('Streaming Functionality BVT', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/')
    
    // Wait for the application to load
    await page.waitForLoadState('networkidle')
  })

  test('BVT-001: Health check endpoint should be accessible', async ({ request }) => {
    const response = await request.get('/api/health')
    expect(response.status()).toBe(200)
    
    const health = await response.json()
    expect(health.status).toBeDefined()
  })

  test('BVT-002: Stream health endpoint should be accessible', async ({ request }) => {
    const response = await request.get('/api/stream-health')
    expect(response.status()).toBe(200)
    
    const health = await response.json()
    expect(health.status).toBeDefined()
    expect(health.diagnostics).toBeDefined()
  })

  test('BVT-003: Stream search endpoint should accept valid requests', async ({ request }) => {
    const response = await request.get('/api/stream-search?q=test&location=test')
    
    // Should return SSE response (200) or service unavailable (503)
    expect([200, 503]).toContain(response.status())
    
    if (response.status() === 200) {
      expect(response.headers()['content-type']).toBe('text/event-stream')
    }
  })

  test('BVT-004: Stream search endpoint should reject invalid requests', async ({ request }) => {
    const response = await request.get('/api/stream-search') // Missing query
    expect(response.status()).toBe(400)
    
    const error = await response.json()
    expect(error.error).toContain('Query parameter "q" is required')
  })

  test('BVT-005: Streaming UI components should be present', async ({ page }) => {
    // Navigate to scraping page
    await page.click('text=Scraping')
    
    // Check for streaming-related UI elements
    await expect(page.locator('[data-testid="search-input"]')).toBeVisible()
    await expect(page.locator('[data-testid="location-input"]')).toBeVisible()
    await expect(page.locator('[data-testid="start-search-button"]')).toBeVisible()
  })

  test('BVT-006: Console should not show ANSI color codes', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })
    
    // Navigate to scraping page and trigger some activity
    await page.click('text=Scraping')
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    
    // Wait a bit for any console logs
    await page.waitForTimeout(2000)
    
    // Check that no console logs contain ANSI escape sequences
    const ansiPattern = /\x1b\[[0-9;]*[a-zA-Z]/
    const logsWithAnsi = consoleLogs.filter(log => ansiPattern.test(log))
    
    expect(logsWithAnsi).toHaveLength(0)
  })

  test('BVT-007: No duplicate log entries in console', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })
    
    // Navigate to scraping page and trigger some activity
    await page.click('text=Scraping')
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    
    // Wait for logs to accumulate
    await page.waitForTimeout(3000)
    
    // Check for duplicate consecutive log entries
    let duplicateCount = 0
    for (let i = 1; i < consoleLogs.length; i++) {
      if (consoleLogs[i] === consoleLogs[i - 1]) {
        duplicateCount++
      }
    }
    
    // Allow some duplicates but not excessive
    expect(duplicateCount).toBeLessThan(5)
  })

  test('BVT-008: Rate limiting should be properly configured', async ({ request }) => {
    // Make multiple rapid requests to test rate limiting
    const requests = []
    for (let i = 0; i < 35; i++) { // Exceed the limit of 30
      requests.push(request.get('/api/stream-search?q=test&location=test'))
    }
    
    const responses = await Promise.all(requests)
    const rateLimitedResponses = responses.filter(r => r.status() === 429)
    
    // Should have some rate limited responses
    expect(rateLimitedResponses.length).toBeGreaterThan(0)
  })

  test('BVT-009: CORS headers should be present', async ({ request }) => {
    const response = await request.get('/api/stream-search?q=test&location=test')
    
    expect(response.headers()['access-control-allow-origin']).toBe('*')
    expect(response.headers()['access-control-allow-methods']).toContain('GET')
  })

  test('BVT-010: Middleware should not interfere with SSE', async ({ request }) => {
    const response = await request.get('/api/stream-search?q=test&location=test')
    
    if (response.status() === 200) {
      // SSE endpoints should have specific cache control
      expect(response.headers()['cache-control']).toBe('no-cache, no-transform')
      expect(response.headers()['connection']).toBe('keep-alive')
      
      // Should not have restrictive cache headers
      expect(response.headers()['pragma']).not.toBe('no-cache')
      expect(response.headers()['expires']).not.toBe('0')
    }
  })
})

test.describe('Streaming Error Recovery BVT', () => {
  test('BVT-011: Application should handle network errors gracefully', async ({ page, context }) => {
    // Navigate to scraping page
    await page.goto('/')
    await page.click('text=Scraping')
    
    // Simulate network failure
    await context.setOffline(true)
    
    // Try to start streaming
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    await page.click('[data-testid="start-search-button"]')
    
    // Should show appropriate error message
    await expect(page.locator('text=Network connection lost')).toBeVisible({ timeout: 5000 })
    
    // Restore network
    await context.setOffline(false)
    
    // Should be able to retry
    await page.click('[data-testid="start-search-button"]')
    
    // Should not show network error anymore
    await expect(page.locator('text=Network connection lost')).not.toBeVisible({ timeout: 5000 })
  })

  test('BVT-012: Circuit breaker should prevent excessive retries', async ({ page }) => {
    // This test would require mocking the server to always fail
    // For BVT, we just verify the UI doesn't get stuck in infinite retry loops
    
    await page.goto('/')
    await page.click('text=Scraping')
    
    await page.fill('[data-testid="search-input"]', 'test query')
    await page.fill('[data-testid="location-input"]', 'test location')
    
    // Start search
    await page.click('[data-testid="start-search-button"]')
    
    // Wait for potential retries
    await page.waitForTimeout(10000)
    
    // UI should not be stuck in loading state indefinitely
    const isStillLoading = await page.locator('[data-testid="loading-indicator"]').isVisible()
    
    // After 10 seconds, should either be completed or show error, not still loading
    if (isStillLoading) {
      // Check if there's a reasonable error message
      await expect(page.locator('text=Service temporarily unavailable')).toBeVisible()
    }
  })
})

test.describe('Performance BVT', () => {
  test('BVT-013: Health check should respond quickly', async ({ request }) => {
    const start = Date.now()
    const response = await request.get('/api/health')
    const duration = Date.now() - start
    
    expect(response.status()).toBe(200)
    expect(duration).toBeLessThan(5000) // Should respond within 5 seconds
  })

  test('BVT-014: Stream health check should respond quickly', async ({ request }) => {
    const start = Date.now()
    const response = await request.get('/api/stream-health')
    const duration = Date.now() - start
    
    expect(response.status()).toBe(200)
    expect(duration).toBeLessThan(5000) // Should respond within 5 seconds
  })

  test('BVT-015: SSE connection should establish quickly', async ({ request }) => {
    const start = Date.now()
    const response = await request.get('/api/stream-search?q=test&location=test')
    const duration = Date.now() - start
    
    // Connection should be established quickly (even if service is unavailable)
    expect(duration).toBeLessThan(3000) // Should respond within 3 seconds
  })
})
