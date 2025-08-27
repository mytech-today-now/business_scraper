/**
 * Example: Clean DuckDuckGo Scraping with Console Filtering
 *
 * This example demonstrates how to use the enhanced console filtering
 * to eliminate the browser noise you were experiencing.
 */

import { EnhancedDuckDuckGoScraper } from '@/lib/enhancedDuckDuckGoScraper'
import { setupCleanScraping } from '@/lib/consoleFilterUtils'
import puppeteer from 'puppeteer'

/**
 * Example 1: Using the Enhanced DuckDuckGo Scraper
 * This automatically handles console filtering and resource blocking
 */
async function exampleEnhancedScraper() {
  console.log('🔍 Example 1: Enhanced DuckDuckGo Scraper')

  const scraper = new EnhancedDuckDuckGoScraper()

  try {
    await scraper.initialize()

    const results = await scraper.scrapeResults({
      query: 'charter schools near me',
      page: 0,
      maxResults: 5,
      blockResources: true, // Blocks problematic resources
      filterConsole: true, // Filters console noise
    })

    console.log(`✅ Found ${results.length} results with minimal console noise`)
    results.forEach((result, index) => {
      console.log(`${index + 1}. ${result.title}`)
      console.log(`   URL: ${result.url}`)
      console.log(`   Domain: ${result.domain}`)
      console.log('')
    })
  } catch (error) {
    console.error('❌ Scraping failed:', error)
  } finally {
    await scraper.cleanup()
  }
}

/**
 * Example 2: Manual Setup with Custom Filtering
 * Shows how to apply console filtering to any Puppeteer page
 */
async function exampleManualSetup() {
  console.log('🔧 Example 2: Manual Console Filtering Setup')

  const browser = await puppeteer.launch({ headless: true })
  const page = await browser.newPage()

  try {
    // Apply clean scraping setup - this eliminates the console noise
    await setupCleanScraping(page, {
      consoleFilter: {
        filterLevel: 'strict', // Filter aggressively
        logCriticalErrors: true, // Still log real errors
        logPageErrors: true, // Log page errors
        customFilters: [
          // Add custom patterns
          'useTranslation: DISMISS is not available',
          'expanded-maps-vertical',
          'duckassist-ia',
        ],
      },
      resourceBlocking: 'strict', // Block problematic resources
    })

    console.log('🛡️  Console filtering and resource blocking applied')

    // Now navigate - you should see much cleaner console output
    await page.goto('https://duckduckgo.com/?q=charter+schools+near+me&t=h_&ia=web')

    // Wait for results
    await page.waitForSelector('[data-testid="result"], .result', { timeout: 10000 })

    console.log('✅ Page loaded with filtered console output')
  } catch (error) {
    console.error('❌ Manual setup failed:', error)
  } finally {
    await browser.close()
  }
}

/**
 * Example 3: Before and After Comparison
 * Shows the difference in console output
 */
async function exampleBeforeAfterComparison() {
  console.log('📊 Example 3: Before/After Console Comparison')

  // Before: Standard Puppeteer (lots of console noise)
  console.log('\n--- BEFORE (Standard Puppeteer) ---')
  const browser1 = await puppeteer.launch({ headless: true })
  const page1 = await browser1.newPage()

  let consoleMessages = 0
  page1.on('console', () => consoleMessages++)

  try {
    await page1.goto('https://duckduckgo.com/?q=charter+schools+near+me&t=h_&ia=web')
    await page1.waitForSelector('[data-testid="result"], .result', { timeout: 10000 })
    console.log(`📢 Console messages without filtering: ${consoleMessages}`)
  } catch (error) {
    console.log('❌ Standard approach failed or timed out')
  } finally {
    await browser1.close()
  }

  // After: With console filtering (clean output)
  console.log('\n--- AFTER (With Console Filtering) ---')
  const browser2 = await puppeteer.launch({ headless: true })
  const page2 = await browser2.newPage()

  let filteredMessages = 0
  await setupCleanScraping(page2, {
    consoleFilter: { filterLevel: 'strict', logCriticalErrors: true, logPageErrors: true },
    resourceBlocking: 'strict',
  })

  page2.on('console', () => filteredMessages++)

  try {
    await page2.goto('https://duckduckgo.com/?q=charter+schools+near+me&t=h_&ia=web')
    await page2.waitForSelector('[data-testid="result"], .result', { timeout: 10000 })
    console.log(`🔇 Console messages with filtering: ${filteredMessages}`)
    console.log(
      `📉 Reduction: ${(((consoleMessages - filteredMessages) / consoleMessages) * 100).toFixed(1)}%`
    )
  } catch (error) {
    console.log('❌ Filtered approach failed or timed out')
  } finally {
    await browser2.close()
  }
}

/**
 * Example 4: Testing Different Filter Levels
 */
async function exampleFilterLevels() {
  console.log('⚙️  Example 4: Testing Different Filter Levels')

  const filterLevels = ['minimal', 'moderate', 'strict'] as const

  for (const level of filterLevels) {
    console.log(`\n--- Testing ${level.toUpperCase()} filter level ---`)

    const browser = await puppeteer.launch({ headless: true })
    const page = await browser.newPage()

    let messageCount = 0
    await setupCleanScraping(page, {
      consoleFilter: {
        filterLevel: level,
        logCriticalErrors: true,
        logPageErrors: true,
      },
      resourceBlocking: level,
    })

    page.on('console', () => messageCount++)

    try {
      await page.goto('https://duckduckgo.com/?q=test+search&t=h_&ia=web', { timeout: 15000 })
      await page.waitForSelector('[data-testid="result"], .result', { timeout: 10000 })
      console.log(`📊 ${level} level: ${messageCount} console messages`)
    } catch (error) {
      console.log(`❌ ${level} level: Failed or timed out`)
    } finally {
      await browser.close()
    }
  }
}

/**
 * Run all examples
 */
async function runAllExamples() {
  console.log('🚀 DuckDuckGo Clean Scraping Examples\n')

  try {
    await exampleEnhancedScraper()
    console.log('\n' + '='.repeat(60) + '\n')

    await exampleManualSetup()
    console.log('\n' + '='.repeat(60) + '\n')

    await exampleBeforeAfterComparison()
    console.log('\n' + '='.repeat(60) + '\n')

    await exampleFilterLevels()
  } catch (error) {
    console.error('❌ Examples failed:', error)
  }

  console.log('\n✅ All examples completed!')
}

// Export for use in other files
export {
  exampleEnhancedScraper,
  exampleManualSetup,
  exampleBeforeAfterComparison,
  exampleFilterLevels,
  runAllExamples,
}

// Run examples if this file is executed directly
if (require.main === module) {
  runAllExamples()
}
