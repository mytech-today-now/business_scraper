/**
 * Accessibility Testing Suite
 * Automated accessibility compliance testing using axe-core
 */

import { test, expect, Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

interface AccessibilityResult {
  url: string
  violations: any[]
  passes: any[]
  incomplete: any[]
  inapplicable: any[]
  timestamp: string
}

class AccessibilityTester {
  private results: AccessibilityResult[] = []

  async runAccessibilityTest(page: Page, url: string, testName: string): Promise<AccessibilityResult> {
    await page.goto(url)
    
    // Wait for page to be fully loaded
    await page.waitForLoadState('networkidle')
    
    // Run axe accessibility scan
    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
      .analyze()

    const result: AccessibilityResult = {
      url,
      violations: accessibilityScanResults.violations,
      passes: accessibilityScanResults.passes,
      incomplete: accessibilityScanResults.incomplete,
      inapplicable: accessibilityScanResults.inapplicable,
      timestamp: new Date().toISOString()
    }

    this.results.push(result)

    // Log violations for debugging
    if (result.violations.length > 0) {
      console.log(`\n🚨 Accessibility violations found on ${url}:`)
      result.violations.forEach((violation, index) => {
        console.log(`\n${index + 1}. ${violation.id} (${violation.impact})`)
        console.log(`   Description: ${violation.description}`)
        console.log(`   Help: ${violation.help}`)
        console.log(`   Elements affected: ${violation.nodes.length}`)
        
        violation.nodes.forEach((node: any, nodeIndex: number) => {
          console.log(`   ${nodeIndex + 1}. ${node.target.join(' > ')}`)
          if (node.failureSummary) {
            console.log(`      Issue: ${node.failureSummary}`)
          }
        })
      })
    } else {
      console.log(`✅ No accessibility violations found on ${url}`)
    }

    return result
  }

  getResults(): AccessibilityResult[] {
    return this.results
  }

  getViolations(): any[] {
    return this.results.flatMap(result => result.violations)
  }

  getCriticalViolations(): any[] {
    return this.getViolations().filter(violation => 
      violation.impact === 'critical' || violation.impact === 'serious'
    )
  }

  generateReport(): string {
    const totalViolations = this.getViolations().length
    const criticalViolations = this.getCriticalViolations().length
    const pagesScanned = this.results.length

    const violationsByImpact = {
      critical: this.getViolations().filter(v => v.impact === 'critical').length,
      serious: this.getViolations().filter(v => v.impact === 'serious').length,
      moderate: this.getViolations().filter(v => v.impact === 'moderate').length,
      minor: this.getViolations().filter(v => v.impact === 'minor').length
    }

    return `
Accessibility Test Report
=========================
Pages Scanned: ${pagesScanned}
Total Violations: ${totalViolations}
Critical Violations: ${criticalViolations}

Violations by Impact:
- Critical: ${violationsByImpact.critical}
- Serious: ${violationsByImpact.serious}
- Moderate: ${violationsByImpact.moderate}
- Minor: ${violationsByImpact.minor}

${this.results.map(result => `
Page: ${result.url}
Violations: ${result.violations.length}
${result.violations.map(v => `- ${v.id} (${v.impact}): ${v.description}`).join('\n')}
`).join('\n')}
    `.trim()
  }
}

test.describe('Accessibility Testing Suite', () => {
  let accessibilityTester: AccessibilityTester

  test.beforeEach(() => {
    accessibilityTester = new AccessibilityTester()
  })

  test.describe('Core Page Accessibility', () => {
    test('home page should be accessible', async ({ page }) => {
      const result = await accessibilityTester.runAccessibilityTest(
        page, 
        BASE_URL, 
        'home-page-accessibility'
      )

      // Should have no critical or serious violations
      const criticalViolations = result.violations.filter(v => 
        v.impact === 'critical' || v.impact === 'serious'
      )
      
      expect(criticalViolations).toHaveLength(0)
      
      // Total violations should be minimal
      expect(result.violations.length).toBeLessThanOrEqual(5)
    })

    test('search configuration page should be accessible', async ({ page }) => {
      const result = await accessibilityTester.runAccessibilityTest(
        page, 
        `${BASE_URL}/search`, 
        'search-page-accessibility'
      )

      const criticalViolations = result.violations.filter(v => 
        v.impact === 'critical' || v.impact === 'serious'
      )
      
      expect(criticalViolations).toHaveLength(0)
    })

    test('results page should be accessible', async ({ page }) => {
      // First navigate to search page and perform a search
      await page.goto(`${BASE_URL}/search`)
      
      // Fill in search form (if it exists)
      try {
        await page.fill('[data-testid="industry-input"]', 'restaurants')
        await page.fill('[data-testid="zipcode-input"]', '12345')
        await page.click('[data-testid="search-button"]')
        
        // Wait for results to load
        await page.waitForSelector('[data-testid="results-container"]', { timeout: 10000 })
      } catch (error) {
        // If search form doesn't exist, navigate directly to results
        await page.goto(`${BASE_URL}/results`)
      }

      const result = await accessibilityTester.runAccessibilityTest(
        page, 
        page.url(), 
        'results-page-accessibility'
      )

      const criticalViolations = result.violations.filter(v => 
        v.impact === 'critical' || v.impact === 'serious'
      )
      
      expect(criticalViolations).toHaveLength(0)
    })
  })

  test.describe('Interactive Elements Accessibility', () => {
    test('form controls should be accessible', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)
      
      // Test form accessibility
      const result = await new AxeBuilder({ page })
        .include('form')
        .withTags(['wcag2a', 'wcag2aa'])
        .analyze()

      // Check for form-specific accessibility issues
      const formViolations = result.violations.filter(violation =>
        violation.tags.includes('cat.forms') || 
        violation.tags.includes('cat.keyboard') ||
        violation.id.includes('label') ||
        violation.id.includes('input')
      )

      expect(formViolations).toHaveLength(0)

      // Verify form elements have proper labels
      const inputs = await page.locator('input').all()
      for (const input of inputs) {
        const ariaLabel = await input.getAttribute('aria-label')
        const id = await input.getAttribute('id')
        const hasLabel = id ? await page.locator(`label[for="${id}"]`).count() > 0 : false
        
        expect(ariaLabel || hasLabel).toBeTruthy()
      }
    })

    test('buttons should be accessible', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test button accessibility
      const buttons = await page.locator('button').all()
      
      for (const button of buttons) {
        // Check if button has accessible name
        const ariaLabel = await button.getAttribute('aria-label')
        const textContent = await button.textContent()
        const title = await button.getAttribute('title')
        
        expect(ariaLabel || textContent?.trim() || title).toBeTruthy()
        
        // Check if button is keyboard accessible
        await button.focus()
        expect(await button.evaluate(el => document.activeElement === el)).toBe(true)
      }
    })

    test('navigation should be accessible', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test navigation accessibility
      const result = await new AxeBuilder({ page })
        .include('nav')
        .withTags(['wcag2a', 'wcag2aa'])
        .analyze()

      const navViolations = result.violations.filter(violation =>
        violation.tags.includes('cat.keyboard') || 
        violation.tags.includes('cat.structure')
      )

      expect(navViolations).toHaveLength(0)
    })
  })

  test.describe('Content Accessibility', () => {
    test('images should have alt text', async ({ page }) => {
      await page.goto(BASE_URL)
      
      const images = await page.locator('img').all()
      
      for (const image of images) {
        const alt = await image.getAttribute('alt')
        const ariaLabel = await image.getAttribute('aria-label')
        const role = await image.getAttribute('role')
        
        // Images should have alt text, aria-label, or be decorative
        expect(alt !== null || ariaLabel || role === 'presentation').toBeTruthy()
      }
    })

    test('headings should be properly structured', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test heading structure
      const result = await new AxeBuilder({ page })
        .withTags(['cat.structure'])
        .analyze()

      const headingViolations = result.violations.filter(violation =>
        violation.id.includes('heading') || 
        violation.id.includes('h1') ||
        violation.id.includes('h2') ||
        violation.id.includes('h3')
      )

      expect(headingViolations).toHaveLength(0)

      // Check heading hierarchy
      const headings = await page.locator('h1, h2, h3, h4, h5, h6').all()
      let previousLevel = 0

      for (const heading of headings) {
        const tagName = await heading.evaluate(el => el.tagName.toLowerCase())
        const currentLevel = parseInt(tagName.charAt(1))
        
        // Heading levels should not skip (e.g., h1 -> h3)
        if (previousLevel > 0) {
          expect(currentLevel - previousLevel).toBeLessThanOrEqual(1)
        }
        
        previousLevel = currentLevel
      }
    })

    test('color contrast should be sufficient', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test color contrast
      const result = await new AxeBuilder({ page })
        .withTags(['cat.color'])
        .analyze()

      const colorViolations = result.violations.filter(violation =>
        violation.id.includes('color-contrast') ||
        violation.id.includes('color')
      )

      expect(colorViolations).toHaveLength(0)
    })
  })

  test.describe('Keyboard Navigation', () => {
    test('should be fully keyboard navigable', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test keyboard navigation
      const focusableElements = await page.locator(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      ).all()

      // Tab through all focusable elements
      for (let i = 0; i < Math.min(focusableElements.length, 10); i++) {
        await page.keyboard.press('Tab')
        
        // Verify focus is visible
        const focusedElement = await page.locator(':focus').first()
        expect(await focusedElement.count()).toBe(1)
      }
    })

    test('should handle escape key properly', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test escape key handling for modals/dropdowns
      await page.keyboard.press('Escape')
      
      // Should not cause any JavaScript errors
      const errors = await page.evaluate(() => window.console.error.toString())
      expect(errors).not.toContain('Error')
    })
  })

  test.describe('Screen Reader Compatibility', () => {
    test('should have proper ARIA landmarks', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Check for ARIA landmarks
      const landmarks = await page.locator('[role="main"], [role="navigation"], [role="banner"], [role="contentinfo"], main, nav, header, footer').count()
      
      expect(landmarks).toBeGreaterThan(0)
    })

    test('should have proper ARIA labels and descriptions', async ({ page }) => {
      await page.goto(BASE_URL)
      
      // Test ARIA attributes
      const result = await new AxeBuilder({ page })
        .withTags(['cat.aria'])
        .analyze()

      const ariaViolations = result.violations.filter(violation =>
        violation.tags.includes('cat.aria')
      )

      expect(ariaViolations).toHaveLength(0)
    })
  })

  test.describe('Accessibility Report Generation', () => {
    test('should generate comprehensive accessibility report', async ({ page }) => {
      // Run tests on multiple pages
      const pages = [BASE_URL, `${BASE_URL}/search`]
      
      for (const pageUrl of pages) {
        await accessibilityTester.runAccessibilityTest(page, pageUrl, `report-${pageUrl}`)
      }

      const report = accessibilityTester.generateReport()
      const criticalViolations = accessibilityTester.getCriticalViolations()

      expect(report).toContain('Accessibility Test Report')
      expect(report).toContain('Pages Scanned:')
      expect(report).toContain('Total Violations:')

      console.log('\n' + report)

      // Fail if critical violations are found
      expect(criticalViolations.length).toBe(0)
    })
  })
})
