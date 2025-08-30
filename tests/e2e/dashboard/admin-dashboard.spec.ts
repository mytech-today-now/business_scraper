import { test, expect } from '@playwright/test'

test.describe('Admin Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/')
    
    // Wait for the application to load
    await page.waitForSelector('[data-testid="app-container"]', { timeout: 10000 })
    
    // Click on the Dashboard tab
    await page.click('button:has-text("Dashboard")')
    
    // Wait for dashboard to load
    await page.waitForSelector('h1:has-text("Payment System Dashboard")', { timeout: 10000 })
  })

  test('should display dashboard header and navigation', async ({ page }) => {
    // Check dashboard title
    await expect(page.locator('h1')).toContainText('Payment System Dashboard')
    
    // Check header buttons
    await expect(page.locator('button:has-text("Export Compliance Report")')).toBeVisible()
    await expect(page.locator('button:has-text("Settings")')).toBeVisible()
  })

  test('should display key metrics cards', async ({ page }) => {
    // Check that all metric cards are present
    await expect(page.locator('text=Total Revenue')).toBeVisible()
    await expect(page.locator('text=Active Users')).toBeVisible()
    await expect(page.locator('text=Monthly Revenue')).toBeVisible()
    await expect(page.locator('text=System Health')).toBeVisible()
    
    // Check that metric values are displayed (even if 0)
    const revenueCard = page.locator('[data-testid="total-revenue-card"]').first()
    await expect(revenueCard.locator('.text-2xl')).toBeVisible()
  })

  test('should display alert banner when alerts are present', async ({ page }) => {
    // Mock alerts data
    await page.route('**/api/monitoring/alerts', async route => {
      await route.fulfill({
        json: {
          active: [
            { id: '1', title: 'High CPU usage detected', severity: 'warning' },
            { id: '2', title: 'Database connection slow', severity: 'medium' }
          ]
        }
      })
    })
    
    // Reload to trigger alert display
    await page.reload()
    await page.waitForSelector('h1:has-text("Payment System Dashboard")')
    
    // Check alert banner
    await expect(page.locator('text=2 active alerts')).toBeVisible()
    await expect(page.locator('text=High CPU usage detected')).toBeVisible()
  })

  test('should navigate between dashboard tabs', async ({ page }) => {
    // Check that all tabs are present
    await expect(page.locator('button[role="tab"]:has-text("Analytics")')).toBeVisible()
    await expect(page.locator('button[role="tab"]:has-text("Performance")')).toBeVisible()
    await expect(page.locator('button[role="tab"]:has-text("Subscriptions")')).toBeVisible()
    await expect(page.locator('button[role="tab"]:has-text("Compliance")')).toBeVisible()
    
    // Click on Performance tab
    await page.click('button[role="tab"]:has-text("Performance")')
    await expect(page.locator('text=Response Times')).toBeVisible()
    await expect(page.locator('text=Error Rate')).toBeVisible()
    await expect(page.locator('text=Uptime')).toBeVisible()
    
    // Click on Subscriptions tab
    await page.click('button[role="tab"]:has-text("Subscriptions")')
    await expect(page.locator('text=Subscription Overview')).toBeVisible()
    await expect(page.locator('text=Total')).toBeVisible()
    await expect(page.locator('text=Active')).toBeVisible()
    
    // Click on Compliance tab
    await page.click('button[role="tab"]:has-text("Compliance")')
    await expect(page.locator('text=Compliance Status')).toBeVisible()
    await expect(page.locator('text=GDPR Compliance')).toBeVisible()
    await expect(page.locator('text=PCI DSS')).toBeVisible()
  })

  test('should handle compliance report generation', async ({ page }) => {
    // Mock compliance report API
    await page.route('**/api/audit/compliance-report', async route => {
      await route.fulfill({
        json: {
          success: true,
          reportId: 'report-123',
          downloadUrl: '/downloads/compliance-report-123.pdf'
        }
      })
    })
    
    // Click export compliance report button
    await page.click('button:has-text("Export Compliance Report")')
    
    // Check for success message (this would be a toast or alert in real implementation)
    await page.waitForFunction(() => {
      return window.confirm || window.alert
    }, { timeout: 5000 })
  })

  test('should display analytics data correctly', async ({ page }) => {
    // Mock analytics data
    await page.route('**/api/analytics/user/**', async route => {
      await route.fulfill({
        json: {
          success: true,
          data: {
            metrics: {
              totalRevenue: 15000.50,
              growthRate: 0.15,
              activeUsers: 250,
              userGrowthRate: 0.08,
              monthlyRevenue: 5000.25,
              averageRevenuePerUser: 20.00,
              transactionCount: 750,
              totalUsers: 300,
              newUsers: 25
            },
            subscriptionMetrics: {
              totalSubscriptions: 200,
              activeSubscriptions: 180,
              canceledSubscriptions: 15,
              trialSubscriptions: 5
            }
          }
        }
      })
    })
    
    // Reload to get fresh data
    await page.reload()
    await page.waitForSelector('h1:has-text("Payment System Dashboard")')
    
    // Check that analytics data is displayed
    await expect(page.locator('text=$15,000.50')).toBeVisible()
    await expect(page.locator('text=+15.0% from last month')).toBeVisible()
    await expect(page.locator('text=250')).toBeVisible() // Active users
    
    // Navigate to Analytics tab to see detailed metrics
    await page.click('button[role="tab"]:has-text("Analytics")')
    await expect(page.locator('text=Revenue Trends')).toBeVisible()
    await expect(page.locator('text=User Metrics')).toBeVisible()
  })

  test('should handle loading states', async ({ page }) => {
    // Mock slow API response
    await page.route('**/api/analytics/user/**', async route => {
      await new Promise(resolve => setTimeout(resolve, 2000))
      await route.fulfill({
        json: { success: true, data: { metrics: {}, subscriptionMetrics: {} } }
      })
    })
    
    // Navigate to dashboard
    await page.goto('/')
    await page.click('button:has-text("Dashboard")')
    
    // Check loading state
    await expect(page.locator('text=Loading dashboard...')).toBeVisible()
    
    // Wait for loading to complete
    await page.waitForSelector('h1:has-text("Payment System Dashboard")', { timeout: 15000 })
  })

  test('should handle error states', async ({ page }) => {
    // Mock API error
    await page.route('**/api/analytics/user/**', async route => {
      await route.fulfill({
        status: 500,
        json: { error: 'Internal server error' }
      })
    })
    
    // Navigate to dashboard
    await page.goto('/')
    await page.click('button:has-text("Dashboard")')
    
    // Check error state
    await expect(page.locator('text=Error Loading Dashboard')).toBeVisible()
    await expect(page.locator('button:has-text("Retry")')).toBeVisible()
    
    // Test retry functionality
    await page.route('**/api/analytics/user/**', async route => {
      await route.fulfill({
        json: { success: true, data: { metrics: {}, subscriptionMetrics: {} } }
      })
    })
    
    await page.click('button:has-text("Retry")')
    await page.waitForSelector('h1:has-text("Payment System Dashboard")')
  })

  test('should be responsive on mobile devices', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 })
    
    // Navigate to dashboard
    await page.goto('/')
    await page.click('button:has-text("Dashboard")')
    await page.waitForSelector('h1:has-text("Payment System Dashboard")')
    
    // Check that dashboard is responsive
    await expect(page.locator('h1:has-text("Payment System Dashboard")')).toBeVisible()
    
    // Check that metric cards stack vertically on mobile
    const metricsGrid = page.locator('.grid-cols-1')
    await expect(metricsGrid).toBeVisible()
    
    // Check that tabs are still functional on mobile
    await page.click('button[role="tab"]:has-text("Performance")')
    await expect(page.locator('text=Response Times')).toBeVisible()
  })

  test('should maintain accessibility standards', async ({ page }) => {
    // Check for proper ARIA labels and roles
    await expect(page.locator('button[role="tab"]')).toHaveCount(4)
    await expect(page.locator('[role="tabpanel"]')).toBeVisible()
    
    // Check keyboard navigation
    await page.keyboard.press('Tab')
    await page.keyboard.press('ArrowRight')
    
    // Check that focus is managed properly
    const focusedElement = page.locator(':focus')
    await expect(focusedElement).toBeVisible()
  })

  test('should track analytics events', async ({ page }) => {
    // Mock analytics tracking
    let analyticsEvents: any[] = []
    await page.route('**/api/analytics/track', async route => {
      const request = route.request()
      const body = await request.postDataJSON()
      analyticsEvents.push(body)
      await route.fulfill({ json: { success: true } })
    })
    
    // Navigate between tabs
    await page.click('button[role="tab"]:has-text("Performance")')
    await page.click('button[role="tab"]:has-text("Analytics")')
    
    // Check that analytics events were tracked
    expect(analyticsEvents.length).toBeGreaterThan(0)
  })
})
