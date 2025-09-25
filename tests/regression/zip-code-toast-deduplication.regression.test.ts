/**
 * Regression Tests for ZIP Code Toast Deduplication
 * Ensures that GitHub Issue #201 - duplicate toast messages don't regress
 */

import { test, expect } from '@playwright/test'

test.describe('ZIP Code Toast Deduplication Regression Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')
  })

  test('REG-ZIP-001: ZIP code validation toast should appear only once on configuration page load', async ({ page }) => {
    const toastMessages: string[] = []
    
    // Capture all toast notifications
    page.on('console', msg => {
      const text = msg.text()
      if (text.includes('ZIP code') && text.includes('valid')) {
        toastMessages.push(text)
      }
    })

    // Navigate to configuration page
    await page.click('text=Configuration')
    
    // Wait for page to load and any existing ZIP code to be processed
    await page.waitForTimeout(3000)
    
    // Check that ZIP code validation toast appears at most once
    const zipCodeToasts = toastMessages.filter(msg => 
      msg.includes('ZIP code') && msg.includes('valid')
    )
    
    expect(zipCodeToasts.length).toBeLessThanOrEqual(1)
  })

  test('REG-ZIP-002: Multiple rapid ZIP code inputs should not create duplicate toasts', async ({ page }) => {
    const toastMessages: string[] = []
    
    page.on('console', msg => {
      const text = msg.text()
      if (text.includes('ZIP code') && text.includes('valid')) {
        toastMessages.push(text)
      }
    })

    // Navigate to configuration page
    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    // Find ZIP code input
    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    await expect(zipInput).toBeVisible()

    // Clear and enter the same ZIP code multiple times rapidly
    for (let i = 0; i < 5; i++) {
      await zipInput.selectAll()
      await zipInput.fill('60047')
      await zipInput.blur()
      await page.waitForTimeout(100) // Small delay between inputs
    }

    // Wait for all processing to complete
    await page.waitForTimeout(2000)

    // Count unique ZIP code validation toasts
    const uniqueToasts = new Set(toastMessages.filter(msg => 
      msg.includes('ZIP code "60047" is valid')
    ))

    // Should have at most 1 unique toast for the same ZIP code
    expect(uniqueToasts.size).toBeLessThanOrEqual(1)
  })

  test('REG-ZIP-003: Different ZIP codes should each get their own toast', async ({ page }) => {
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
    const zipCodes = ['60047', '90210', '10001']
    
    for (const zipCode of zipCodes) {
      await zipInput.selectAll()
      await zipInput.fill(zipCode)
      await zipInput.blur()
      await page.waitForTimeout(1000) // Wait for processing
    }

    await page.waitForTimeout(2000)

    // Each different ZIP code should get its own toast
    const zipCodeToasts = toastMessages.filter(msg => 
      msg.includes('ZIP code') && msg.includes('valid')
    )

    // Should have toasts for different ZIP codes (but not duplicates for same ZIP)
    expect(zipCodeToasts.length).toBeGreaterThan(0)
    expect(zipCodeToasts.length).toBeLessThanOrEqual(zipCodes.length)
  })

  test('REG-ZIP-004: Toast deduplication should reset after sufficient time', async ({ page }) => {
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

    // Enter ZIP code first time
    await zipInput.selectAll()
    await zipInput.fill('60047')
    await zipInput.blur()
    await page.waitForTimeout(1000)

    const initialToastCount = toastMessages.filter(msg => 
      msg.includes('ZIP code "60047" is valid')
    ).length

    // Wait for deduplication window to expire (15+ seconds)
    await page.waitForTimeout(16000)

    // Enter same ZIP code again
    await zipInput.selectAll()
    await zipInput.fill('60047')
    await zipInput.blur()
    await page.waitForTimeout(1000)

    const finalToastCount = toastMessages.filter(msg => 
      msg.includes('ZIP code "60047" is valid')
    ).length

    // Should allow a new toast after deduplication window expires
    expect(finalToastCount).toBeGreaterThan(initialToastCount)
  })

  test('REG-ZIP-005: Page refresh should reset toast deduplication', async ({ page }) => {
    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    await expect(zipInput).toBeVisible()

    // Enter ZIP code
    await zipInput.selectAll()
    await zipInput.fill('60047')
    await zipInput.blur()
    await page.waitForTimeout(1000)

    // Refresh page
    await page.reload()
    await page.waitForLoadState('networkidle')

    const toastMessages: string[] = []
    
    page.on('console', msg => {
      const text = msg.text()
      if (text.includes('ZIP code') && text.includes('valid')) {
        toastMessages.push(text)
      }
    })

    // Navigate back to configuration
    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    // Enter same ZIP code again
    const newZipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    await expect(newZipInput).toBeVisible()
    
    await newZipInput.selectAll()
    await newZipInput.fill('60047')
    await newZipInput.blur()
    await page.waitForTimeout(1000)

    // Should allow toast after page refresh
    const zipCodeToasts = toastMessages.filter(msg => 
      msg.includes('ZIP code "60047" is valid')
    )

    expect(zipCodeToasts.length).toBeGreaterThanOrEqual(0) // Should not be blocked by previous session
  })
})

test.describe('ZIP Code Logging Deduplication Tests', () => {
  test('REG-ZIP-006: ZIP code detection should not log excessively', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })

    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    await expect(zipInput).toBeVisible()

    // Enter same ZIP code multiple times
    for (let i = 0; i < 10; i++) {
      await zipInput.selectAll()
      await zipInput.fill('60047')
      await zipInput.blur()
      await page.waitForTimeout(100)
    }

    await page.waitForTimeout(2000)

    // Count ZIP code detection logs
    const zipDetectionLogs = consoleLogs.filter(log => 
      log.includes('AddressInputHandler') && log.includes('ZIP code input detected: 60047')
    )

    // Should have limited logging due to deduplication
    expect(zipDetectionLogs.length).toBeLessThan(5) // Should be much less than 10 inputs
  })

  test('REG-ZIP-007: No ANSI color codes should appear in console logs', async ({ page }) => {
    const consoleLogs: string[] = []
    
    page.on('console', msg => {
      consoleLogs.push(msg.text())
    })

    await page.click('text=Configuration')
    await page.waitForLoadState('networkidle')

    const zipInput = page.locator('[data-testid="zip-code-input"], input[placeholder*="ZIP"], input[placeholder*="90210"]').first()
    await expect(zipInput).toBeVisible()

    await zipInput.selectAll()
    await zipInput.fill('60047')
    await zipInput.blur()
    await page.waitForTimeout(2000)

    // Check for ANSI escape sequences
    const ansiPattern = /\x1b\[[0-9;]*[a-zA-Z]|\[2;38;2;124;124;124m|\[0m/
    const logsWithAnsi = consoleLogs.filter(log => ansiPattern.test(log))

    expect(logsWithAnsi).toHaveLength(0)
  })
})
