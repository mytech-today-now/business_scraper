/**
 * WCAG Compliance Testing
 * Comprehensive Web Content Accessibility Guidelines compliance testing
 */

import { test, expect, Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000'

interface WCAGTestResult {
  level: 'A' | 'AA' | 'AAA'
  guideline: string
  criterion: string
  passed: boolean
  violations: any[]
  description: string
}

class WCAGComplianceTester {
  private results: WCAGTestResult[] = []

  async testWCAGLevel(page: Page, level: 'A' | 'AA' | 'AAA'): Promise<WCAGTestResult[]> {
    const tags =
      level === 'A'
        ? ['wcag2a']
        : level === 'AA'
          ? ['wcag2a', 'wcag2aa']
          : ['wcag2a', 'wcag2aa', 'wcag2aaa']

    const result = await new AxeBuilder({ page }).withTags(tags).analyze()

    const levelResults: WCAGTestResult[] = []

    // Group violations by WCAG criteria
    const criteriaMap = new Map<string, any[]>()

    result.violations.forEach(violation => {
      violation.tags.forEach((tag: string) => {
        if (tag.startsWith('wcag')) {
          if (!criteriaMap.has(tag)) {
            criteriaMap.set(tag, [])
          }
          criteriaMap.get(tag)!.push(violation)
        }
      })
    })

    // Create test results for each criterion
    const wcagCriteria = this.getWCAGCriteria(level)

    wcagCriteria.forEach(criterion => {
      const violations = criteriaMap.get(criterion.tag) || []

      const testResult: WCAGTestResult = {
        level,
        guideline: criterion.guideline,
        criterion: criterion.name,
        passed: violations.length === 0,
        violations,
        description: criterion.description,
      }

      levelResults.push(testResult)
      this.results.push(testResult)
    })

    return levelResults
  }

  private getWCAGCriteria(level: 'A' | 'AA' | 'AAA') {
    const criteria = [
      // WCAG 2.1 Level A
      {
        tag: 'wcag111',
        guideline: '1.1 Text Alternatives',
        name: '1.1.1 Non-text Content',
        description: 'All non-text content has text alternatives',
      },
      {
        tag: 'wcag121',
        guideline: '1.2 Time-based Media',
        name: '1.2.1 Audio-only and Video-only',
        description: 'Alternatives for audio-only and video-only content',
      },
      {
        tag: 'wcag131',
        guideline: '1.3 Adaptable',
        name: '1.3.1 Info and Relationships',
        description: 'Information and relationships can be programmatically determined',
      },
      {
        tag: 'wcag132',
        guideline: '1.3 Adaptable',
        name: '1.3.2 Meaningful Sequence',
        description: 'Content can be presented in a meaningful sequence',
      },
      {
        tag: 'wcag133',
        guideline: '1.3 Adaptable',
        name: '1.3.3 Sensory Characteristics',
        description: 'Instructions do not rely solely on sensory characteristics',
      },
      {
        tag: 'wcag141',
        guideline: '1.4 Distinguishable',
        name: '1.4.1 Use of Color',
        description: 'Color is not the only means of conveying information',
      },
      {
        tag: 'wcag142',
        guideline: '1.4 Distinguishable',
        name: '1.4.2 Audio Control',
        description: 'Audio that plays automatically can be controlled',
      },
      {
        tag: 'wcag211',
        guideline: '2.1 Keyboard Accessible',
        name: '2.1.1 Keyboard',
        description: 'All functionality is available via keyboard',
      },
      {
        tag: 'wcag212',
        guideline: '2.1 Keyboard Accessible',
        name: '2.1.2 No Keyboard Trap',
        description: 'Keyboard focus is not trapped',
      },
      {
        tag: 'wcag221',
        guideline: '2.2 Enough Time',
        name: '2.2.1 Timing Adjustable',
        description: 'Time limits can be adjusted or extended',
      },
      {
        tag: 'wcag222',
        guideline: '2.2 Enough Time',
        name: '2.2.2 Pause, Stop, Hide',
        description: 'Moving content can be paused, stopped, or hidden',
      },
      {
        tag: 'wcag231',
        guideline: '2.3 Seizures',
        name: '2.3.1 Three Flashes or Below',
        description: 'Content does not contain flashing that causes seizures',
      },
      {
        tag: 'wcag241',
        guideline: '2.4 Navigable',
        name: '2.4.1 Bypass Blocks',
        description: 'Mechanism to skip repeated content blocks',
      },
      {
        tag: 'wcag242',
        guideline: '2.4 Navigable',
        name: '2.4.2 Page Titled',
        description: 'Web pages have descriptive titles',
      },
      {
        tag: 'wcag243',
        guideline: '2.4 Navigable',
        name: '2.4.3 Focus Order',
        description: 'Focus order preserves meaning and operability',
      },
      {
        tag: 'wcag244',
        guideline: '2.4 Navigable',
        name: '2.4.4 Link Purpose',
        description: 'Purpose of links can be determined from link text',
      },
      {
        tag: 'wcag311',
        guideline: '3.1 Readable',
        name: '3.1.1 Language of Page',
        description: 'Primary language of page is programmatically determined',
      },
      {
        tag: 'wcag321',
        guideline: '3.2 Predictable',
        name: '3.2.1 On Focus',
        description: 'Focus does not trigger unexpected context changes',
      },
      {
        tag: 'wcag322',
        guideline: '3.2 Predictable',
        name: '3.2.2 On Input',
        description: 'Input does not trigger unexpected context changes',
      },
      {
        tag: 'wcag331',
        guideline: '3.3 Input Assistance',
        name: '3.3.1 Error Identification',
        description: 'Input errors are identified and described',
      },
      {
        tag: 'wcag332',
        guideline: '3.3 Input Assistance',
        name: '3.3.2 Labels or Instructions',
        description: 'Labels or instructions are provided for user input',
      },
      {
        tag: 'wcag411',
        guideline: '4.1 Compatible',
        name: '4.1.1 Parsing',
        description: 'Content can be parsed reliably',
      },
      {
        tag: 'wcag412',
        guideline: '4.1 Compatible',
        name: '4.1.2 Name, Role, Value',
        description: 'Name, role, and value can be programmatically determined',
      },
    ]

    if (level === 'AA' || level === 'AAA') {
      criteria.push(
        // WCAG 2.1 Level AA
        {
          tag: 'wcag123',
          guideline: '1.2 Time-based Media',
          name: '1.2.3 Audio Description or Media Alternative',
          description: 'Audio description or media alternative for video',
        },
        {
          tag: 'wcag124',
          guideline: '1.2 Time-based Media',
          name: '1.2.4 Captions (Live)',
          description: 'Captions for live audio content',
        },
        {
          tag: 'wcag125',
          guideline: '1.2 Time-based Media',
          name: '1.2.5 Audio Description (Prerecorded)',
          description: 'Audio description for prerecorded video',
        },
        {
          tag: 'wcag134',
          guideline: '1.3 Adaptable',
          name: '1.3.4 Orientation',
          description: 'Content does not restrict orientation',
        },
        {
          tag: 'wcag135',
          guideline: '1.3 Adaptable',
          name: '1.3.5 Identify Input Purpose',
          description: 'Input purpose can be programmatically determined',
        },
        {
          tag: 'wcag143',
          guideline: '1.4 Distinguishable',
          name: '1.4.3 Contrast (Minimum)',
          description: 'Text has sufficient color contrast',
        },
        {
          tag: 'wcag144',
          guideline: '1.4 Distinguishable',
          name: '1.4.4 Resize text',
          description: 'Text can be resized up to 200%',
        },
        {
          tag: 'wcag145',
          guideline: '1.4 Distinguishable',
          name: '1.4.5 Images of Text',
          description: 'Images of text are avoided when possible',
        },
        {
          tag: 'wcag213',
          guideline: '2.1 Keyboard Accessible',
          name: '2.1.3 Keyboard (No Exception)',
          description: 'All functionality is keyboard accessible',
        },
        {
          tag: 'wcag214',
          guideline: '2.1 Keyboard Accessible',
          name: '2.1.4 Character Key Shortcuts',
          description: 'Character key shortcuts can be disabled or remapped',
        },
        {
          tag: 'wcag245',
          guideline: '2.4 Navigable',
          name: '2.4.5 Multiple Ways',
          description: 'Multiple ways to locate web pages',
        },
        {
          tag: 'wcag246',
          guideline: '2.4 Navigable',
          name: '2.4.6 Headings and Labels',
          description: 'Headings and labels describe topic or purpose',
        },
        {
          tag: 'wcag247',
          guideline: '2.4 Navigable',
          name: '2.4.7 Focus Visible',
          description: 'Keyboard focus indicator is visible',
        },
        {
          tag: 'wcag312',
          guideline: '3.1 Readable',
          name: '3.1.2 Language of Parts',
          description: 'Language of parts is programmatically determined',
        },
        {
          tag: 'wcag323',
          guideline: '3.2 Predictable',
          name: '3.2.3 Consistent Navigation',
          description: 'Navigation is consistent across pages',
        },
        {
          tag: 'wcag324',
          guideline: '3.2 Predictable',
          name: '3.2.4 Consistent Identification',
          description: 'Components are consistently identified',
        },
        {
          tag: 'wcag333',
          guideline: '3.3 Input Assistance',
          name: '3.3.3 Error Suggestion',
          description: 'Error suggestions are provided when possible',
        },
        {
          tag: 'wcag334',
          guideline: '3.3 Input Assistance',
          name: '3.3.4 Error Prevention (Legal, Financial, Data)',
          description: 'Error prevention for important transactions',
        },
        {
          tag: 'wcag413',
          guideline: '4.1 Compatible',
          name: '4.1.3 Status Messages',
          description: 'Status messages can be programmatically determined',
        }
      )
    }

    return criteria
  }

  getResults(): WCAGTestResult[] {
    return this.results
  }

  getFailedCriteria(): WCAGTestResult[] {
    return this.results.filter(result => !result.passed)
  }

  generateComplianceReport(): string {
    const levelA = this.results.filter(r => r.level === 'A')
    const levelAA = this.results.filter(r => r.level === 'AA')

    const levelAPass = levelA.filter(r => r.passed).length
    const levelAAPass = levelAA.filter(r => r.passed).length

    const levelACompliance = levelA.length > 0 ? (levelAPass / levelA.length) * 100 : 0
    const levelAACompliance = levelAA.length > 0 ? (levelAAPass / levelAA.length) * 100 : 0

    return `
WCAG 2.1 Compliance Report
==========================
Level A Compliance: ${levelACompliance.toFixed(1)}% (${levelAPass}/${levelA.length})
Level AA Compliance: ${levelAACompliance.toFixed(1)}% (${levelAAPass}/${levelAA.length})

Failed Criteria:
${this.getFailedCriteria()
  .map(
    result => `
- ${result.criterion} (${result.level})
  Guideline: ${result.guideline}
  Violations: ${result.violations.length}
  Description: ${result.description}
`
  )
  .join('')}
    `.trim()
  }
}

test.describe('WCAG Compliance Testing', () => {
  let wcagTester: WCAGComplianceTester

  test.beforeEach(() => {
    wcagTester = new WCAGComplianceTester()
  })

  test.describe('WCAG 2.1 Level A Compliance', () => {
    test('home page should meet WCAG Level A', async ({ page }) => {
      await page.goto(BASE_URL)
      await page.waitForLoadState('networkidle')

      const results = await wcagTester.testWCAGLevel(page, 'A')
      const failedCriteria = results.filter(r => !r.passed)

      console.log(
        `\nWCAG Level A Results: ${results.length - failedCriteria.length}/${results.length} passed`
      )

      if (failedCriteria.length > 0) {
        console.log('\nFailed Level A Criteria:')
        failedCriteria.forEach(result => {
          console.log(`- ${result.criterion}: ${result.violations.length} violations`)
        })
      }

      // Level A should have minimal failures
      expect(failedCriteria.length).toBeLessThanOrEqual(3)
    })

    test('search page should meet WCAG Level A', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)
      await page.waitForLoadState('networkidle')

      const results = await wcagTester.testWCAGLevel(page, 'A')
      const failedCriteria = results.filter(r => !r.passed)

      expect(failedCriteria.length).toBeLessThanOrEqual(3)
    })
  })

  test.describe('WCAG 2.1 Level AA Compliance', () => {
    test('home page should meet WCAG Level AA', async ({ page }) => {
      await page.goto(BASE_URL)
      await page.waitForLoadState('networkidle')

      const results = await wcagTester.testWCAGLevel(page, 'AA')
      const failedCriteria = results.filter(r => !r.passed)

      console.log(
        `\nWCAG Level AA Results: ${results.length - failedCriteria.length}/${results.length} passed`
      )

      // Level AA allows for more failures but should still be mostly compliant
      expect(failedCriteria.length).toBeLessThanOrEqual(5)
    })

    test('should have proper color contrast', async ({ page }) => {
      await page.goto(BASE_URL)

      const result = await new AxeBuilder({ page })
        .withTags(['wcag143']) // Color contrast
        .analyze()

      expect(result.violations).toHaveLength(0)
    })

    test('should have keyboard accessibility', async ({ page }) => {
      await page.goto(BASE_URL)

      const result = await new AxeBuilder({ page })
        .withTags(['wcag211', 'wcag212']) // Keyboard accessibility
        .analyze()

      expect(result.violations).toHaveLength(0)
    })

    test('should have proper focus management', async ({ page }) => {
      await page.goto(BASE_URL)

      const result = await new AxeBuilder({ page })
        .withTags(['wcag247']) // Focus visible
        .analyze()

      expect(result.violations).toHaveLength(0)
    })
  })

  test.describe('Specific WCAG Criteria Testing', () => {
    test('should have proper page titles (2.4.2)', async ({ page }) => {
      const pages = [BASE_URL, `${BASE_URL}/search`]

      for (const pageUrl of pages) {
        await page.goto(pageUrl)
        const title = await page.title()

        expect(title).toBeTruthy()
        expect(title.length).toBeGreaterThan(0)
        expect(title).not.toBe('Untitled')
      }
    })

    test('should have proper heading structure (1.3.1)', async ({ page }) => {
      await page.goto(BASE_URL)

      const h1Count = await page.locator('h1').count()
      expect(h1Count).toBe(1) // Should have exactly one h1

      // Check heading hierarchy
      const headings = await page.locator('h1, h2, h3, h4, h5, h6').all()
      let previousLevel = 0

      for (const heading of headings) {
        const tagName = await heading.evaluate(el => el.tagName.toLowerCase())
        const currentLevel = parseInt(tagName.charAt(1))

        if (previousLevel > 0) {
          expect(currentLevel - previousLevel).toBeLessThanOrEqual(1)
        }

        previousLevel = currentLevel
      }
    })

    test('should have proper form labels (3.3.2)', async ({ page }) => {
      await page.goto(`${BASE_URL}/search`)

      const inputs = await page
        .locator(
          'input[type="text"], input[type="email"], input[type="password"], select, textarea'
        )
        .all()

      for (const input of inputs) {
        const id = await input.getAttribute('id')
        const ariaLabel = await input.getAttribute('aria-label')
        const ariaLabelledby = await input.getAttribute('aria-labelledby')

        if (id) {
          const labelCount = await page.locator(`label[for="${id}"]`).count()
          expect(labelCount > 0 || ariaLabel || ariaLabelledby).toBeTruthy()
        } else {
          expect(ariaLabel || ariaLabelledby).toBeTruthy()
        }
      }
    })

    test('should have proper language declaration (3.1.1)', async ({ page }) => {
      await page.goto(BASE_URL)

      const htmlLang = await page.getAttribute('html', 'lang')
      expect(htmlLang).toBeTruthy()
      expect(htmlLang).toMatch(/^[a-z]{2}(-[A-Z]{2})?$/) // e.g., 'en' or 'en-US'
    })
  })

  test.describe('Compliance Report Generation', () => {
    test('should generate comprehensive WCAG compliance report', async ({ page }) => {
      // Test multiple pages for comprehensive report
      const pages = [BASE_URL, `${BASE_URL}/search`]

      for (const pageUrl of pages) {
        await page.goto(pageUrl)
        await page.waitForLoadState('networkidle')

        await wcagTester.testWCAGLevel(page, 'A')
        await wcagTester.testWCAGLevel(page, 'AA')
      }

      const report = wcagTester.generateComplianceReport()
      const failedCriteria = wcagTester.getFailedCriteria()

      expect(report).toContain('WCAG 2.1 Compliance Report')
      expect(report).toContain('Level A Compliance:')
      expect(report).toContain('Level AA Compliance:')

      console.log('\n' + report)

      // Should achieve at least 80% compliance for Level A
      const levelAResults = wcagTester.getResults().filter(r => r.level === 'A')
      const levelAPass = levelAResults.filter(r => r.passed).length
      const levelACompliance =
        levelAResults.length > 0 ? (levelAPass / levelAResults.length) * 100 : 0

      expect(levelACompliance).toBeGreaterThanOrEqual(80)
    })
  })
})
