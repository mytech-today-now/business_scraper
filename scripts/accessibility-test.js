#!/usr/bin/env node
/**
 * Accessibility Testing Script
 * Runs automated accessibility checks using axe-core
 */

const { chromium } = require('playwright')
const { AxePuppeteer } = require('@axe-core/puppeteer')
const fs = require('fs')
const path = require('path')

const PAGES_TO_TEST = ['/', '/search', '/results', '/settings', '/export', '/help']

const ACCESSIBILITY_RULES = {
  // WCAG 2.1 AA compliance
  tags: ['wcag2a', 'wcag2aa', 'wcag21aa'],
  rules: {
    'color-contrast': { enabled: true },
    'keyboard-navigation': { enabled: true },
    'focus-management': { enabled: true },
    'aria-labels': { enabled: true },
    'heading-order': { enabled: true },
    'landmark-roles': { enabled: true },
    'alt-text': { enabled: true },
    'form-labels': { enabled: true },
  },
}

async function runAccessibilityTests() {
  console.log('🔍 Starting accessibility tests...')

  const browser = await chromium.launch({ headless: true })
  const context = await browser.newContext()
  const page = await context.newPage()

  const results = []
  const baseUrl = process.env.TEST_URL || 'http://localhost:3000'

  try {
    for (const pagePath of PAGES_TO_TEST) {
      console.log(`Testing ${pagePath}...`)

      const url = `${baseUrl}${pagePath}`
      await page.goto(url, { waitUntil: 'networkidle' })

      // Wait for page to be fully loaded
      await page.waitForTimeout(2000)

      // Run axe accessibility tests
      const axeResults = await page.evaluate(async () => {
        const axe = require('axe-core')
        return await axe.run(document, {
          tags: ['wcag2a', 'wcag2aa', 'wcag21aa'],
          rules: {
            'color-contrast': { enabled: true },
            'keyboard-navigation': { enabled: true },
            'focus-management': { enabled: true },
            'aria-labels': { enabled: true },
            'heading-order': { enabled: true },
            'landmark-roles': { enabled: true },
            'alt-text': { enabled: true },
            'form-labels': { enabled: true },
          },
        })
      })

      // Test keyboard navigation
      const keyboardResults = await testKeyboardNavigation(page)

      // Test screen reader compatibility
      const screenReaderResults = await testScreenReaderCompatibility(page)

      const pageResults = {
        url,
        axe: axeResults,
        keyboard: keyboardResults,
        screenReader: screenReaderResults,
        timestamp: new Date().toISOString(),
      }

      results.push(pageResults)

      // Log immediate results
      if (axeResults.violations.length > 0) {
        console.log(
          `❌ ${axeResults.violations.length} accessibility violations found on ${pagePath}`
        )
        axeResults.violations.forEach(violation => {
          console.log(`  - ${violation.id}: ${violation.description}`)
        })
      } else {
        console.log(`✅ No accessibility violations found on ${pagePath}`)
      }
    }

    // Generate comprehensive report
    await generateAccessibilityReport(results)

    // Check if any critical violations were found
    const totalViolations = results.reduce((sum, result) => sum + result.axe.violations.length, 0)
    const criticalViolations = results.reduce(
      (sum, result) =>
        sum +
        result.axe.violations.filter(v => v.impact === 'critical' || v.impact === 'serious').length,
      0
    )

    console.log(`\n📊 Accessibility Test Summary:`)
    console.log(`Total pages tested: ${results.length}`)
    console.log(`Total violations: ${totalViolations}`)
    console.log(`Critical/Serious violations: ${criticalViolations}`)

    if (criticalViolations > 0) {
      console.log('❌ Accessibility tests failed due to critical violations')
      process.exit(1)
    } else {
      console.log('✅ All accessibility tests passed')
      process.exit(0)
    }
  } catch (error) {
    console.error('❌ Accessibility testing failed:', error)
    process.exit(1)
  } finally {
    await browser.close()
  }
}

async function testKeyboardNavigation(page) {
  const results = {
    tabOrder: [],
    focusTraps: [],
    skipLinks: false,
    errors: [],
  }

  try {
    // Test tab order
    await page.keyboard.press('Tab')
    let tabCount = 0
    const maxTabs = 50 // Prevent infinite loops

    while (tabCount < maxTabs) {
      const focusedElement = await page.evaluate(() => {
        const element = document.activeElement
        return element
          ? {
              tagName: element.tagName,
              id: element.id,
              className: element.className,
              ariaLabel: element.getAttribute('aria-label'),
              role: element.getAttribute('role'),
            }
          : null
      })

      if (!focusedElement) break

      results.tabOrder.push(focusedElement)
      await page.keyboard.press('Tab')
      tabCount++
    }

    // Test for skip links
    await page.keyboard.press('Home')
    await page.keyboard.press('Tab')
    const firstFocusedElement = await page.evaluate(() => {
      const element = document.activeElement
      return element ? element.textContent : null
    })

    results.skipLinks = firstFocusedElement && firstFocusedElement.toLowerCase().includes('skip')
  } catch (error) {
    results.errors.push(`Keyboard navigation test failed: ${error.message}`)
  }

  return results
}

async function testScreenReaderCompatibility(page) {
  const results = {
    headingStructure: [],
    landmarks: [],
    ariaLabels: [],
    errors: [],
  }

  try {
    // Test heading structure
    results.headingStructure = await page.evaluate(() => {
      const headings = Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6'))
      return headings.map(h => ({
        level: parseInt(h.tagName.charAt(1)),
        text: h.textContent.trim(),
        id: h.id,
      }))
    })

    // Test landmarks
    results.landmarks = await page.evaluate(() => {
      const landmarks = Array.from(
        document.querySelectorAll('[role], main, nav, header, footer, aside, section')
      )
      return landmarks.map(l => ({
        tagName: l.tagName,
        role: l.getAttribute('role') || l.tagName.toLowerCase(),
        ariaLabel: l.getAttribute('aria-label'),
        ariaLabelledby: l.getAttribute('aria-labelledby'),
      }))
    })

    // Test ARIA labels
    results.ariaLabels = await page.evaluate(() => {
      const elementsWithAria = Array.from(
        document.querySelectorAll('[aria-label], [aria-labelledby], [aria-describedby]')
      )
      return elementsWithAria.map(el => ({
        tagName: el.tagName,
        ariaLabel: el.getAttribute('aria-label'),
        ariaLabelledby: el.getAttribute('aria-labelledby'),
        ariaDescribedby: el.getAttribute('aria-describedby'),
      }))
    })
  } catch (error) {
    results.errors.push(`Screen reader compatibility test failed: ${error.message}`)
  }

  return results
}

async function generateAccessibilityReport(results) {
  const reportDir = path.join(process.cwd(), 'test-results')
  if (!fs.existsSync(reportDir)) {
    fs.mkdirSync(reportDir, { recursive: true })
  }

  // Generate JSON report
  const jsonReport = {
    summary: {
      totalPages: results.length,
      totalViolations: results.reduce((sum, r) => sum + r.axe.violations.length, 0),
      criticalViolations: results.reduce(
        (sum, r) =>
          sum +
          r.axe.violations.filter(v => v.impact === 'critical' || v.impact === 'serious').length,
        0
      ),
      timestamp: new Date().toISOString(),
    },
    results,
  }

  fs.writeFileSync(
    path.join(reportDir, 'accessibility-report.json'),
    JSON.stringify(jsonReport, null, 2)
  )

  // Generate HTML report
  const htmlReport = generateHTMLReport(jsonReport)
  fs.writeFileSync(path.join(reportDir, 'accessibility-report.html'), htmlReport)

  console.log(`📄 Accessibility reports generated in ${reportDir}`)
}

function generateHTMLReport(data) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Accessibility Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .violation { background: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #ff0000; }
        .pass { background: #e6ffe6; padding: 10px; margin: 10px 0; border-left: 4px solid #00ff00; }
        .page-section { margin: 20px 0; border: 1px solid #ddd; padding: 15px; }
        .impact-critical { color: #d32f2f; font-weight: bold; }
        .impact-serious { color: #f57c00; font-weight: bold; }
        .impact-moderate { color: #fbc02d; }
        .impact-minor { color: #388e3c; }
    </style>
</head>
<body>
    <h1>Accessibility Test Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Pages Tested:</strong> ${data.summary.totalPages}</p>
        <p><strong>Total Violations:</strong> ${data.summary.totalViolations}</p>
        <p><strong>Critical/Serious Violations:</strong> ${data.summary.criticalViolations}</p>
        <p><strong>Generated:</strong> ${new Date(data.summary.timestamp).toLocaleString()}</p>
    </div>
    
    ${data.results
      .map(
        result => `
        <div class="page-section">
            <h3>Page: ${result.url}</h3>
            
            ${
              result.axe.violations.length === 0
                ? '<div class="pass">✅ No accessibility violations found</div>'
                : result.axe.violations
                    .map(
                      violation => `
                    <div class="violation">
                        <h4 class="impact-${violation.impact}">${violation.id} (${violation.impact})</h4>
                        <p><strong>Description:</strong> ${violation.description}</p>
                        <p><strong>Help:</strong> ${violation.help}</p>
                        <p><strong>Elements affected:</strong> ${violation.nodes.length}</p>
                    </div>
                `
                    )
                    .join('')
            }
            
            <h4>Keyboard Navigation</h4>
            <p>Tab order elements: ${result.keyboard.tabOrder.length}</p>
            <p>Skip links present: ${result.keyboard.skipLinks ? 'Yes' : 'No'}</p>
            
            <h4>Screen Reader Compatibility</h4>
            <p>Heading structure: ${result.screenReader.headingStructure.length} headings</p>
            <p>Landmarks: ${result.screenReader.landmarks.length} landmarks</p>
            <p>ARIA labels: ${result.screenReader.ariaLabels.length} elements with ARIA</p>
        </div>
    `
      )
      .join('')}
    
</body>
</html>
  `
}

// Run the tests if this script is executed directly
if (require.main === module) {
  runAccessibilityTests().catch(console.error)
}

module.exports = { runAccessibilityTests }
