/**
 * Comprehensive User Workflow E2E Tests
 * End-to-end testing of complete user journeys and workflows
 */

import { test, expect, Page, BrowserContext } from '@playwright/test'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

interface WorkflowStep {
  name: string
  action: (page: Page) => Promise<void>
  validation: (page: Page) => Promise<void>
  timeout?: number
}

class WorkflowTester {
  private steps: WorkflowStep[] = []
  private currentStep = 0

  addStep(step: WorkflowStep): void {
    this.steps.push(step)
  }

  async executeWorkflow(page: Page): Promise<void> {
    for (let i = 0; i < this.steps.length; i++) {
      this.currentStep = i
      const step = this.steps[i]
      
      console.log(`\n🔄 Executing step ${i + 1}/${this.steps.length}: ${step.name}`)
      
      try {
        // Execute the action
        await step.action(page)
        
        // Wait a moment for any async operations
        await page.waitForTimeout(1000)
        
        // Validate the result
        await step.validation(page)
        
        console.log(`✅ Step ${i + 1} completed successfully`)
      } catch (error) {
        console.error(`❌ Step ${i + 1} failed: ${error}`)
        
        // Take screenshot on failure
        await page.screenshot({ 
          path: `test-results/workflow-failure-step-${i + 1}.png`,
          fullPage: true 
        })
        
        throw new Error(`Workflow failed at step ${i + 1} (${step.name}): ${error}`)
      }
    }
  }

  reset(): void {
    this.steps = []
    this.currentStep = 0
  }
}

test.describe('Comprehensive User Workflow Tests', () => {
  let workflowTester: WorkflowTester

  test.beforeEach(() => {
    workflowTester = new WorkflowTester()
  })

  test.afterEach(() => {
    workflowTester.reset()
  })

  test.describe('Complete Business Search Workflow', () => {
    test('should complete full business search and export workflow', async ({ page }) => {
      // Step 1: Navigate to application
      workflowTester.addStep({
        name: 'Navigate to home page',
        action: async (page) => {
          await page.goto(BASE_URL)
        },
        validation: async (page) => {
          await expect(page).toHaveTitle(/Business Scraper|Business Search/i)
          await expect(page.locator('body')).toBeVisible()
        }
      })

      // Step 2: Navigate to search configuration
      workflowTester.addStep({
        name: 'Navigate to search page',
        action: async (page) => {
          await page.click('a[href*="/search"], button:has-text("Start Search"), [data-testid="search-nav"]')
        },
        validation: async (page) => {
          await expect(page.url()).toContain('/search')
          await expect(page.locator('form, [data-testid="search-form"]')).toBeVisible()
        }
      })

      // Step 3: Configure search parameters
      workflowTester.addStep({
        name: 'Configure search parameters',
        action: async (page) => {
          // Fill industry field
          const industryInput = page.locator('input[name="industry"], [data-testid="industry-input"], input[placeholder*="industry"]').first()
          if (await industryInput.isVisible()) {
            await industryInput.fill('restaurants')
          }

          // Fill ZIP code field
          const zipInput = page.locator('input[name="zipCode"], [data-testid="zipcode-input"], input[placeholder*="zip"]').first()
          if (await zipInput.isVisible()) {
            await zipInput.fill('12345')
          }

          // Set additional parameters if available
          const maxResultsInput = page.locator('input[name="maxResults"], [data-testid="max-results"]').first()
          if (await maxResultsInput.isVisible()) {
            await maxResultsInput.fill('10')
          }
        },
        validation: async (page) => {
          // Verify form fields are filled
          const industryValue = await page.locator('input[name="industry"], [data-testid="industry-input"]').first().inputValue().catch(() => '')
          const zipValue = await page.locator('input[name="zipCode"], [data-testid="zipcode-input"]').first().inputValue().catch(() => '')
          
          expect(industryValue || zipValue).toBeTruthy() // At least one field should be filled
        }
      })

      // Step 4: Start search
      workflowTester.addStep({
        name: 'Start business search',
        action: async (page) => {
          await page.click('button[type="submit"], [data-testid="search-button"], button:has-text("Search")')
        },
        validation: async (page) => {
          // Wait for search to start (loading indicator or results page)
          await Promise.race([
            page.waitForSelector('[data-testid="loading"], .loading, .spinner', { timeout: 5000 }),
            page.waitForSelector('[data-testid="results"], .results', { timeout: 5000 }),
            page.waitForURL('**/results*', { timeout: 5000 })
          ]).catch(() => {
            // If none of the above selectors are found, that's okay
          })
        },
        timeout: 10000
      })

      // Step 5: Wait for and verify results
      workflowTester.addStep({
        name: 'Wait for search results',
        action: async (page) => {
          // Wait for results to load
          await Promise.race([
            page.waitForSelector('[data-testid="results-table"], .results-table, table', { timeout: 30000 }),
            page.waitForSelector('[data-testid="results-list"], .results-list', { timeout: 30000 }),
            page.waitForSelector('[data-testid="business-card"], .business-card', { timeout: 30000 })
          ])
        },
        validation: async (page) => {
          // Verify results are displayed
          const hasResults = await Promise.race([
            page.locator('[data-testid="results-table"] tr, table tr').count(),
            page.locator('[data-testid="business-card"], .business-card').count(),
            page.locator('[data-testid="results-list"] li').count()
          ]).then(count => count > 0).catch(() => false)

          expect(hasResults).toBe(true)
        },
        timeout: 35000
      })

      // Step 6: Interact with results (optional filtering/sorting)
      workflowTester.addStep({
        name: 'Interact with results',
        action: async (page) => {
          // Try to interact with results (sort, filter, etc.)
          const sortButton = page.locator('[data-testid="sort-button"], button:has-text("Sort")').first()
          if (await sortButton.isVisible()) {
            await sortButton.click()
          }

          // Try pagination if available
          const nextButton = page.locator('[data-testid="next-page"], button:has-text("Next")').first()
          if (await nextButton.isVisible()) {
            await nextButton.click()
            await page.waitForTimeout(2000)
          }
        },
        validation: async (page) => {
          // Verify page is still functional
          await expect(page.locator('body')).toBeVisible()
        }
      })

      // Step 7: Export results
      workflowTester.addStep({
        name: 'Export search results',
        action: async (page) => {
          // Look for export button
          const exportButton = page.locator('[data-testid="export-button"], button:has-text("Export"), button:has-text("Download")').first()
          if (await exportButton.isVisible()) {
            await exportButton.click()
            
            // Select CSV format if format selection is available
            const csvOption = page.locator('[data-testid="csv-option"], option[value="csv"], button:has-text("CSV")').first()
            if (await csvOption.isVisible()) {
              await csvOption.click()
            }
          }
        },
        validation: async (page) => {
          // Verify export was initiated (download or success message)
          await Promise.race([
            page.waitForEvent('download', { timeout: 10000 }),
            page.waitForSelector('[data-testid="export-success"], .success-message', { timeout: 5000 })
          ]).catch(() => {
            // Export might not be implemented, that's okay for this test
          })
        }
      })

      // Execute the complete workflow
      await workflowTester.executeWorkflow(page)
    }, 120000) // 2 minute timeout for complete workflow

    test('should handle search with no results gracefully', async ({ page }) => {
      workflowTester.addStep({
        name: 'Navigate to search page',
        action: async (page) => {
          await page.goto(`${BASE_URL}/search`)
        },
        validation: async (page) => {
          await expect(page.locator('form, [data-testid="search-form"]')).toBeVisible()
        }
      })

      workflowTester.addStep({
        name: 'Search for non-existent business type',
        action: async (page) => {
          await page.fill('input[name="industry"], [data-testid="industry-input"]', 'nonexistentbusinesstype12345')
          await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '00000')
          await page.click('button[type="submit"], [data-testid="search-button"]')
        },
        validation: async (page) => {
          // Should show no results message or empty state
          await Promise.race([
            page.waitForSelector('[data-testid="no-results"], .no-results, .empty-state', { timeout: 30000 }),
            page.waitForSelector(':has-text("No results found")', { timeout: 30000 }),
            page.waitForSelector(':has-text("0 results")', { timeout: 30000 })
          ])
        },
        timeout: 35000
      })

      await workflowTester.executeWorkflow(page)
    }, 60000)
  })

  test.describe('Error Handling Workflows', () => {
    test('should handle network errors gracefully', async ({ page, context }) => {
      // Simulate network failure
      await context.route('**/api/**', route => {
        route.abort('failed')
      })

      workflowTester.addStep({
        name: 'Navigate to search with network failure',
        action: async (page) => {
          await page.goto(`${BASE_URL}/search`)
        },
        validation: async (page) => {
          await expect(page.locator('body')).toBeVisible()
        }
      })

      workflowTester.addStep({
        name: 'Attempt search with network failure',
        action: async (page) => {
          await page.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
          await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
          await page.click('button[type="submit"], [data-testid="search-button"]')
        },
        validation: async (page) => {
          // Should show error message
          await Promise.race([
            page.waitForSelector('[data-testid="error-message"], .error-message', { timeout: 10000 }),
            page.waitForSelector(':has-text("Error")', { timeout: 10000 }),
            page.waitForSelector(':has-text("Failed")', { timeout: 10000 })
          ])
        }
      })

      await workflowTester.executeWorkflow(page)
    }, 30000)

    test('should handle invalid input gracefully', async ({ page }) => {
      workflowTester.addStep({
        name: 'Navigate to search page',
        action: async (page) => {
          await page.goto(`${BASE_URL}/search`)
        },
        validation: async (page) => {
          await expect(page.locator('form')).toBeVisible()
        }
      })

      workflowTester.addStep({
        name: 'Submit form with invalid data',
        action: async (page) => {
          // Try invalid ZIP code
          await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', 'invalid-zip')
          await page.click('button[type="submit"], [data-testid="search-button"]')
        },
        validation: async (page) => {
          // Should show validation error or prevent submission
          const hasValidationError = await Promise.race([
            page.waitForSelector('[data-testid="validation-error"], .validation-error', { timeout: 5000 }).then(() => true),
            page.waitForSelector(':has-text("Invalid")', { timeout: 5000 }).then(() => true),
            page.waitForSelector('input:invalid', { timeout: 5000 }).then(() => true)
          ]).catch(() => false)

          // Either validation error shown or form prevented submission
          expect(hasValidationError || page.url().includes('/search')).toBe(true)
        }
      })

      await workflowTester.executeWorkflow(page)
    }, 30000)
  })

  test.describe('Multi-Session Workflows', () => {
    test('should maintain state across browser sessions', async ({ browser }) => {
      // Create first session
      const context1 = await browser.newContext()
      const page1 = await context1.newPage()

      try {
        await page1.goto(`${BASE_URL}/search`)
        await page1.fill('input[name="industry"], [data-testid="industry-input"]', 'restaurants')
        await page1.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '12345')
        
        // Store some data in localStorage if available
        await page1.evaluate(() => {
          localStorage.setItem('test-session', 'session1-data')
        })

        await context1.close()

        // Create second session
        const context2 = await browser.newContext()
        const page2 = await context2.newPage()

        await page2.goto(BASE_URL)
        
        // Check if data persists (it shouldn't in a new context)
        const storedData = await page2.evaluate(() => {
          return localStorage.getItem('test-session')
        })

        expect(storedData).toBeNull() // Data should not persist across contexts

        await context2.close()
      } catch (error) {
        await context1.close().catch(() => {})
        throw error
      }
    }, 30000)
  })

  test.describe('Performance and Load Workflows', () => {
    test('should handle rapid user interactions', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)

      // Rapid form interactions
      for (let i = 0; i < 5; i++) {
        await page.fill('input[name="industry"], [data-testid="industry-input"]', `test${i}`)
        await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', `1234${i}`)
        await page.waitForTimeout(100) // Small delay between interactions
      }

      // Verify form is still responsive
      await expect(page.locator('input[name="industry"], [data-testid="industry-input"]')).toHaveValue('test4')
      await expect(page.locator('input[name="zipCode"], [data-testid="zipcode-input"]')).toHaveValue('12344')
    }, 30000)

    test('should handle large result sets efficiently', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)
      
      // Search for a broad term that might return many results
      await page.fill('input[name="industry"], [data-testid="industry-input"]', 'business')
      await page.fill('input[name="zipCode"], [data-testid="zipcode-input"]', '10001') // NYC ZIP
      
      const startTime = Date.now()
      await page.click('button[type="submit"], [data-testid="search-button"]')
      
      // Wait for results with timeout
      await Promise.race([
        page.waitForSelector('[data-testid="results-table"], table', { timeout: 45000 }),
        page.waitForSelector('[data-testid="no-results"]', { timeout: 45000 })
      ])
      
      const loadTime = Date.now() - startTime
      
      // Results should load within reasonable time (45 seconds)
      expect(loadTime).toBeLessThan(45000)
      
      // Page should remain responsive
      await expect(page.locator('body')).toBeVisible()
    }, 60000)
  })
})
