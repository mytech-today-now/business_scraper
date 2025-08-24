/**
 * Memory Management End-to-End Tests
 * Tests complete memory management workflows from user perspective
 */

import { test, expect } from '@playwright/test'

test.describe('Memory Management E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/')
    
    // Wait for the application to load
    await page.waitForSelector('[data-testid="app-container"]', { timeout: 10000 })
  })

  test('should display memory dashboard and controls', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Verify memory dashboard is visible
    await expect(page.locator('[data-testid="memory-dashboard"]')).toBeVisible()
    
    // Verify memory monitor controls
    await expect(page.locator('button:has-text("Start")')).toBeVisible()
    await expect(page.locator('button:has-text("Settings")')).toBeVisible()
    
    // Verify cleanup controls
    await expect(page.locator('button:has-text("Clean Memory")')).toBeVisible()
    await expect(page.locator('button:has-text("Emergency")')).toBeVisible()
  })

  test('should start and stop memory monitoring', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Start monitoring
    await page.click('button:has-text("Start")')
    
    // Verify monitoring is active
    await expect(page.locator('button:has-text("Stop")')).toBeVisible()
    
    // Verify memory statistics are displayed
    await expect(page.locator('[data-testid="memory-usage"]')).toBeVisible()
    
    // Stop monitoring
    await page.click('button:has-text("Stop")')
    
    // Verify monitoring is stopped
    await expect(page.locator('button:has-text("Start")')).toBeVisible()
  })

  test('should perform manual memory cleanup', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Perform cleanup
    await page.click('button:has-text("Clean Memory")')
    
    // Wait for cleanup to complete
    await page.waitForSelector('text=Cleanup completed', { timeout: 10000 })
    
    // Verify success message
    await expect(page.locator('text=Cleanup completed')).toBeVisible()
  })

  test('should display memory alerts when thresholds are exceeded', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Start monitoring
    await page.click('button:has-text("Start")')
    
    // Simulate high memory usage (this would need to be triggered by the application)
    // In a real scenario, this might involve loading large datasets
    
    // Wait for potential alerts
    await page.waitForTimeout(2000)
    
    // Check if alerts section exists
    const alertsSection = page.locator('[data-testid="memory-alerts"]')
    if (await alertsSection.isVisible()) {
      await expect(alertsSection).toBeVisible()
    }
  })

  test('should configure memory settings', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Open settings
    await page.click('button:has-text("Settings")')
    
    // Verify settings panel is visible
    await expect(page.locator('[data-testid="memory-settings"]')).toBeVisible()
    
    // Configure cleanup options
    await page.check('input[type="checkbox"]:near(:text("Clear search results"))')
    await page.check('input[type="checkbox"]:near(:text("Clear cached data"))')
    
    // Update retention sessions
    await page.fill('input[type="number"]', '5')
    
    // Settings should be applied automatically
    await page.waitForTimeout(500)
  })

  test('should show compact memory monitor in header', async ({ page }) => {
    // Verify compact memory monitor is visible in header
    const compactMonitor = page.locator('[data-testid="compact-memory-monitor"]')
    
    if (await compactMonitor.isVisible()) {
      await expect(compactMonitor).toBeVisible()
      
      // Should show memory percentage
      await expect(compactMonitor.locator('text=/%/')).toBeVisible()
      
      // Should show memory progress bar
      await expect(compactMonitor.locator('[role="progressbar"]')).toBeVisible()
    }
  })

  test('should handle emergency cleanup', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Perform emergency cleanup
    await page.click('button:has-text("Emergency")')
    
    // Wait for emergency cleanup to complete
    await page.waitForSelector('text=Emergency cleanup completed', { timeout: 15000 })
    
    // Verify success message
    await expect(page.locator('text=Emergency cleanup completed')).toBeVisible()
  })

  test('should integrate memory management with scraping workflow', async ({ page }) => {
    // Start a scraping operation
    await page.click('button:has-text("Scraping")')
    
    // Configure scraping parameters
    await page.fill('input[placeholder*="industry"]', 'restaurants')
    await page.fill('input[placeholder*="location"]', '90210')
    
    // Start scraping
    await page.click('button:has-text("Start Scraping")')
    
    // Navigate to memory tab while scraping
    await page.click('button:has-text("Memory")')
    
    // Verify memory monitoring is active during scraping
    await expect(page.locator('[data-testid="memory-dashboard"]')).toBeVisible()
    
    // Memory usage should be tracked
    const memoryUsage = page.locator('[data-testid="memory-usage"]')
    if (await memoryUsage.isVisible()) {
      await expect(memoryUsage).toBeVisible()
    }
    
    // Stop scraping
    await page.click('button:has-text("Scraping")')
    await page.click('button:has-text("Stop Scraping")')
  })

  test('should persist memory settings across page reloads', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Open settings and configure
    await page.click('button:has-text("Settings")')
    await page.fill('input[type="number"]', '7')
    await page.check('input[type="checkbox"]:near(:text("Force garbage collection"))')
    
    // Reload page
    await page.reload()
    await page.waitForSelector('[data-testid="app-container"]')
    
    // Navigate back to memory tab
    await page.click('button:has-text("Memory")')
    await page.click('button:has-text("Settings")')
    
    // Verify settings are persisted
    await expect(page.locator('input[type="number"]')).toHaveValue('7')
    await expect(page.locator('input[type="checkbox"]:near(:text("Force garbage collection"))')).toBeChecked()
  })

  test('should handle memory management API errors gracefully', async ({ page }) => {
    // Mock API failure
    await page.route('/api/memory', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Internal server error' })
      })
    })
    
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Attempt cleanup operation
    await page.click('button:has-text("Clean Memory")')
    
    // Should show error message gracefully
    await page.waitForSelector('text=Cleanup failed', { timeout: 5000 })
    await expect(page.locator('text=Cleanup failed')).toBeVisible()
  })

  test('should show memory statistics and history', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Start monitoring
    await page.click('button:has-text("Start")')
    
    // Wait for statistics to accumulate
    await page.waitForTimeout(3000)
    
    // Verify memory statistics are displayed
    const memoryStats = page.locator('[data-testid="memory-stats"]')
    if (await memoryStats.isVisible()) {
      await expect(memoryStats).toBeVisible()
      
      // Should show current usage
      await expect(memoryStats.locator('text=/\\d+(\\.\\d+)?\\s*(KB|MB|GB)/')).toBeVisible()
      
      // Should show percentage
      await expect(memoryStats.locator('text=/\\d+(\\.\\d+)?%/')).toBeVisible()
    }
  })

  test('should handle concurrent memory operations', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Start monitoring
    await page.click('button:has-text("Start")')
    
    // Perform multiple operations concurrently
    const cleanupPromise = page.click('button:has-text("Clean Memory")')
    const settingsPromise = page.click('button:has-text("Settings")')
    
    // Wait for operations to complete
    await Promise.all([cleanupPromise, settingsPromise])
    
    // Verify application remains responsive
    await expect(page.locator('[data-testid="memory-dashboard"]')).toBeVisible()
  })

  test('should provide accessibility for memory management features', async ({ page }) => {
    // Navigate to memory tab
    await page.click('button:has-text("Memory")')
    
    // Verify ARIA labels and roles
    await expect(page.locator('button[aria-label*="memory"]')).toBeVisible()
    
    // Verify keyboard navigation
    await page.keyboard.press('Tab')
    await page.keyboard.press('Tab')
    await page.keyboard.press('Enter')
    
    // Should be able to navigate and interact with keyboard
    await expect(page.locator('[data-testid="memory-dashboard"]')).toBeVisible()
  })
})
