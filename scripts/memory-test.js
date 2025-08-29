#!/usr/bin/env node
/**
 * Memory Testing Script
 * Tests for memory leaks and performance issues
 */

const { chromium } = require('playwright')
const fs = require('fs')
const path = require('path')

const MEMORY_THRESHOLDS = {
  maxHeapSize: 100 * 1024 * 1024, // 100MB
  maxLeakRate: 5 * 1024 * 1024, // 5MB per operation
  maxGCPressure: 0.8, // 80% heap usage before GC
  maxRetainedObjects: 10000, // Max objects retained after GC
}

async function runMemoryTests() {
  console.log('🧠 Starting memory leak tests...')

  const browser = await chromium.launch({
    headless: true,
    args: ['--expose-gc', '--enable-precise-memory-info'],
  })

  const context = await browser.newContext()
  const page = await context.newPage()

  const results = []
  const baseUrl = process.env.TEST_URL || 'http://localhost:3000'

  try {
    // Test memory usage during normal operations
    const normalUsage = await testNormalMemoryUsage(page, baseUrl)
    results.push(normalUsage)

    // Test memory leaks during repeated operations
    const leakTest = await testMemoryLeaks(page, baseUrl)
    results.push(leakTest)

    // Test memory usage during heavy operations
    const heavyUsage = await testHeavyMemoryUsage(page, baseUrl)
    results.push(heavyUsage)

    // Test garbage collection effectiveness
    const gcTest = await testGarbageCollection(page, baseUrl)
    results.push(gcTest)

    // Generate memory report
    await generateMemoryReport(results)

    // Check if any tests failed
    const failedTests = results.filter(result => !result.passed)

    console.log(`\n📊 Memory Test Summary:`)
    console.log(`Total tests: ${results.length}`)
    console.log(`Passed: ${results.length - failedTests.length}`)
    console.log(`Failed: ${failedTests.length}`)

    if (failedTests.length > 0) {
      console.log('\n❌ Memory tests failed:')
      failedTests.forEach(test => {
        console.log(`  - ${test.testName}: ${test.failureReason}`)
      })
      process.exit(1)
    } else {
      console.log('✅ All memory tests passed')
      process.exit(0)
    }
  } catch (error) {
    console.error('❌ Memory testing failed:', error)
    process.exit(1)
  } finally {
    await browser.close()
  }
}

async function testNormalMemoryUsage(page, baseUrl) {
  console.log('Testing normal memory usage...')

  const measurements = []
  const pages = ['/', '/search', '/results', '/settings']

  for (const pagePath of pages) {
    await page.goto(`${baseUrl}${pagePath}`, { waitUntil: 'networkidle' })

    // Wait for page to stabilize
    await page.waitForTimeout(2000)

    const memory = await getMemoryUsage(page)
    measurements.push({
      page: pagePath,
      memory,
      timestamp: Date.now(),
    })

    console.log(`  ${pagePath}: ${Math.round(memory.usedJSHeapSize / 1024 / 1024)}MB`)
  }

  const maxMemory = Math.max(...measurements.map(m => m.memory.usedJSHeapSize))
  const avgMemory =
    measurements.reduce((sum, m) => sum + m.memory.usedJSHeapSize, 0) / measurements.length

  return {
    testName: 'Normal Memory Usage',
    measurements,
    maxMemory,
    avgMemory,
    passed: maxMemory <= MEMORY_THRESHOLDS.maxHeapSize,
    failureReason:
      maxMemory > MEMORY_THRESHOLDS.maxHeapSize
        ? `Max memory ${Math.round(maxMemory / 1024 / 1024)}MB exceeds threshold ${Math.round(MEMORY_THRESHOLDS.maxHeapSize / 1024 / 1024)}MB`
        : null,
  }
}

async function testMemoryLeaks(page, baseUrl) {
  console.log('Testing for memory leaks...')

  await page.goto(`${baseUrl}/search`, { waitUntil: 'networkidle' })

  const initialMemory = await getMemoryUsage(page)
  const measurements = [{ iteration: 0, memory: initialMemory }]

  // Perform repeated operations that might cause leaks
  for (let i = 1; i <= 10; i++) {
    // Simulate user interactions that might cause leaks
    await simulateUserInteractions(page)

    // Force garbage collection if available
    await page.evaluate(() => {
      if (window.gc) {
        window.gc()
      }
    })

    await page.waitForTimeout(1000)

    const memory = await getMemoryUsage(page)
    measurements.push({ iteration: i, memory })

    console.log(`  Iteration ${i}: ${Math.round(memory.usedJSHeapSize / 1024 / 1024)}MB`)
  }

  // Calculate memory growth rate
  const finalMemory = measurements[measurements.length - 1].memory
  const memoryGrowth = finalMemory.usedJSHeapSize - initialMemory.usedJSHeapSize
  const leakRate = memoryGrowth / measurements.length

  return {
    testName: 'Memory Leak Detection',
    measurements,
    initialMemory: initialMemory.usedJSHeapSize,
    finalMemory: finalMemory.usedJSHeapSize,
    memoryGrowth,
    leakRate,
    passed: leakRate <= MEMORY_THRESHOLDS.maxLeakRate,
    failureReason:
      leakRate > MEMORY_THRESHOLDS.maxLeakRate
        ? `Memory leak detected: ${Math.round(leakRate / 1024 / 1024)}MB per operation`
        : null,
  }
}

async function testHeavyMemoryUsage(page, baseUrl) {
  console.log('Testing heavy memory usage scenarios...')

  await page.goto(`${baseUrl}/search`, { waitUntil: 'networkidle' })

  const beforeMemory = await getMemoryUsage(page)

  // Simulate heavy operations
  await page.evaluate(() => {
    // Create large data structures
    const largeArray = new Array(100000).fill(0).map((_, i) => ({
      id: i,
      data: 'x'.repeat(100),
      timestamp: Date.now(),
    }))

    // Simulate DOM manipulation
    for (let i = 0; i < 1000; i++) {
      const div = document.createElement('div')
      div.innerHTML = `<span>Test ${i}</span>`
      document.body.appendChild(div)
    }

    // Clean up DOM
    const testDivs = document.querySelectorAll('div')
    testDivs.forEach(div => {
      if (div.innerHTML.includes('Test')) {
        div.remove()
      }
    })

    // Store reference to prevent immediate GC
    window.testData = largeArray
  })

  const afterMemory = await getMemoryUsage(page)

  // Clean up
  await page.evaluate(() => {
    delete window.testData
    if (window.gc) {
      window.gc()
    }
  })

  await page.waitForTimeout(2000)
  const cleanupMemory = await getMemoryUsage(page)

  const memoryIncrease = afterMemory.usedJSHeapSize - beforeMemory.usedJSHeapSize
  const memoryRecovered = afterMemory.usedJSHeapSize - cleanupMemory.usedJSHeapSize
  const recoveryRate = memoryRecovered / memoryIncrease

  return {
    testName: 'Heavy Memory Usage',
    beforeMemory: beforeMemory.usedJSHeapSize,
    afterMemory: afterMemory.usedJSHeapSize,
    cleanupMemory: cleanupMemory.usedJSHeapSize,
    memoryIncrease,
    memoryRecovered,
    recoveryRate,
    passed: recoveryRate >= 0.8, // Should recover at least 80% of memory
    failureReason:
      recoveryRate < 0.8
        ? `Poor memory recovery: only ${Math.round(recoveryRate * 100)}% recovered`
        : null,
  }
}

async function testGarbageCollection(page, baseUrl) {
  console.log('Testing garbage collection effectiveness...')

  await page.goto(`${baseUrl}`, { waitUntil: 'networkidle' })

  const measurements = []

  for (let i = 0; i < 5; i++) {
    // Create objects that should be garbage collected
    await page.evaluate(() => {
      const objects = []
      for (let j = 0; j < 10000; j++) {
        objects.push({
          id: j,
          data: new Array(100).fill(Math.random()),
          timestamp: Date.now(),
        })
      }
      // Don't store reference, should be eligible for GC
    })

    const beforeGC = await getMemoryUsage(page)

    // Force garbage collection
    await page.evaluate(() => {
      if (window.gc) {
        window.gc()
      }
    })

    await page.waitForTimeout(1000)

    const afterGC = await getMemoryUsage(page)

    measurements.push({
      iteration: i,
      beforeGC: beforeGC.usedJSHeapSize,
      afterGC: afterGC.usedJSHeapSize,
      collected: beforeGC.usedJSHeapSize - afterGC.usedJSHeapSize,
    })

    console.log(
      `  GC ${i + 1}: Collected ${Math.round((beforeGC.usedJSHeapSize - afterGC.usedJSHeapSize) / 1024 / 1024)}MB`
    )
  }

  const avgCollected = measurements.reduce((sum, m) => sum + m.collected, 0) / measurements.length
  const gcEffectiveness = avgCollected > 0

  return {
    testName: 'Garbage Collection',
    measurements,
    avgCollected,
    gcEffectiveness,
    passed: gcEffectiveness,
    failureReason: !gcEffectiveness ? 'Garbage collection appears ineffective' : null,
  }
}

async function simulateUserInteractions(page) {
  // Simulate various user interactions that might cause memory leaks
  await page.evaluate(() => {
    // Simulate form interactions
    const inputs = document.querySelectorAll('input, textarea')
    inputs.forEach(input => {
      input.value = 'test data ' + Math.random()
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })

    // Simulate button clicks
    const buttons = document.querySelectorAll('button')
    buttons.forEach((button, index) => {
      if (index < 3) {
        // Limit to first 3 buttons
        button.click()
      }
    })

    // Simulate scroll events
    window.scrollTo(0, Math.random() * 1000)

    // Create and remove event listeners
    const testHandler = () => {}
    document.addEventListener('click', testHandler)
    document.removeEventListener('click', testHandler)
  })

  await page.waitForTimeout(500)
}

async function getMemoryUsage(page) {
  return await page.evaluate(() => {
    if (performance.memory) {
      return {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit,
      }
    }
    return {
      usedJSHeapSize: 0,
      totalJSHeapSize: 0,
      jsHeapSizeLimit: 0,
    }
  })
}

async function generateMemoryReport(results) {
  const reportDir = path.join(process.cwd(), 'test-results')
  if (!fs.existsSync(reportDir)) {
    fs.mkdirSync(reportDir, { recursive: true })
  }

  const jsonReport = {
    summary: {
      totalTests: results.length,
      passedTests: results.filter(r => r.passed).length,
      failedTests: results.filter(r => !r.passed).length,
      timestamp: new Date().toISOString(),
      thresholds: MEMORY_THRESHOLDS,
    },
    results,
  }

  fs.writeFileSync(path.join(reportDir, 'memory-report.json'), JSON.stringify(jsonReport, null, 2))

  console.log(`📄 Memory report generated in ${reportDir}`)
}

// Run the tests if this script is executed directly
if (require.main === module) {
  runMemoryTests().catch(console.error)
}

module.exports = { runMemoryTests }
