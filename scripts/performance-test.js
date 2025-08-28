#!/usr/bin/env node
/**
 * Performance Testing Script
 * Runs automated performance tests and regression checks
 */

const { chromium } = require('playwright')
const fs = require('fs')
const path = require('path')

const PERFORMANCE_THRESHOLDS = {
  firstContentfulPaint: 2000, // 2 seconds
  largestContentfulPaint: 4000, // 4 seconds
  firstInputDelay: 100, // 100ms
  cumulativeLayoutShift: 0.1, // 0.1 CLS score
  timeToInteractive: 5000, // 5 seconds
  totalBlockingTime: 300, // 300ms
  speedIndex: 4000 // 4 seconds
}

const PAGES_TO_TEST = [
  { path: '/', name: 'Home' },
  { path: '/search', name: 'Search' },
  { path: '/results', name: 'Results' },
  { path: '/settings', name: 'Settings' },
  { path: '/export', name: 'Export' }
]

async function runPerformanceTests() {
  console.log('🚀 Starting performance tests...')
  
  const browser = await chromium.launch({ headless: true })
  const context = await browser.newContext()
  const page = await context.newPage()
  
  const results = []
  const baseUrl = process.env.TEST_URL || 'http://localhost:3000'
  
  try {
    for (const pageConfig of PAGES_TO_TEST) {
      console.log(`Testing performance for ${pageConfig.name}...`)
      
      const url = `${baseUrl}${pageConfig.path}`
      
      // Run multiple iterations for more accurate results
      const iterations = 3
      const pageResults = []
      
      for (let i = 0; i < iterations; i++) {
        console.log(`  Iteration ${i + 1}/${iterations}`)
        
        // Clear cache and cookies between iterations
        await context.clearCookies()
        await page.goto('about:blank')
        
        // Measure page load performance
        const performanceMetrics = await measurePagePerformance(page, url)
        
        // Measure JavaScript performance
        const jsMetrics = await measureJavaScriptPerformance(page)
        
        // Measure memory usage
        const memoryMetrics = await measureMemoryUsage(page)
        
        // Measure network performance
        const networkMetrics = await measureNetworkPerformance(page, url)
        
        pageResults.push({
          iteration: i + 1,
          performance: performanceMetrics,
          javascript: jsMetrics,
          memory: memoryMetrics,
          network: networkMetrics,
          timestamp: new Date().toISOString()
        })
      }
      
      // Calculate averages
      const averages = calculateAverages(pageResults)
      
      results.push({
        page: pageConfig.name,
        url,
        iterations: pageResults,
        averages,
        thresholds: PERFORMANCE_THRESHOLDS,
        passed: checkThresholds(averages, PERFORMANCE_THRESHOLDS)
      })
      
      // Log immediate results
      logPerformanceResults(pageConfig.name, averages)
    }
    
    // Generate performance report
    await generatePerformanceReport(results)
    
    // Check if any tests failed
    const failedTests = results.filter(result => !result.passed)
    
    console.log(`\n📊 Performance Test Summary:`)
    console.log(`Total pages tested: ${results.length}`)
    console.log(`Passed: ${results.length - failedTests.length}`)
    console.log(`Failed: ${failedTests.length}`)
    
    if (failedTests.length > 0) {
      console.log('\n❌ Performance tests failed:')
      failedTests.forEach(test => {
        console.log(`  - ${test.page}: Performance thresholds exceeded`)
      })
      process.exit(1)
    } else {
      console.log('✅ All performance tests passed')
      process.exit(0)
    }
    
  } catch (error) {
    console.error('❌ Performance testing failed:', error)
    process.exit(1)
  } finally {
    await browser.close()
  }
}

async function measurePagePerformance(page, url) {
  const startTime = Date.now()
  
  // Navigate and wait for load
  await page.goto(url, { waitUntil: 'networkidle' })
  
  // Get Web Vitals and other performance metrics
  const metrics = await page.evaluate(() => {
    return new Promise((resolve) => {
      // Wait for performance entries to be available
      setTimeout(() => {
        const navigation = performance.getEntriesByType('navigation')[0]
        const paint = performance.getEntriesByType('paint')
        
        const fcp = paint.find(entry => entry.name === 'first-contentful-paint')
        const lcp = performance.getEntriesByType('largest-contentful-paint')[0]
        
        resolve({
          domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
          loadComplete: navigation.loadEventEnd - navigation.loadEventStart,
          firstContentfulPaint: fcp ? fcp.startTime : null,
          largestContentfulPaint: lcp ? lcp.startTime : null,
          timeToInteractive: navigation.domInteractive - navigation.navigationStart,
          totalPageSize: navigation.transferSize || 0,
          resourceCount: performance.getEntriesByType('resource').length
        })
      }, 2000)
    })
  })
  
  const endTime = Date.now()
  metrics.totalLoadTime = endTime - startTime
  
  return metrics
}

async function measureJavaScriptPerformance(page) {
  return await page.evaluate(() => {
    const startTime = performance.now()
    
    // Measure JavaScript execution time
    let jsExecutionTime = 0
    const scripts = document.querySelectorAll('script')
    
    // Simulate some JavaScript work
    for (let i = 0; i < 1000; i++) {
      Math.random()
    }
    
    const endTime = performance.now()
    jsExecutionTime = endTime - startTime
    
    return {
      executionTime: jsExecutionTime,
      scriptCount: scripts.length,
      heapUsed: performance.memory ? performance.memory.usedJSHeapSize : null,
      heapTotal: performance.memory ? performance.memory.totalJSHeapSize : null,
      heapLimit: performance.memory ? performance.memory.jsHeapSizeLimit : null
    }
  })
}

async function measureMemoryUsage(page) {
  const metrics = await page.evaluate(() => {
    if (performance.memory) {
      return {
        usedJSHeapSize: performance.memory.usedJSHeapSize,
        totalJSHeapSize: performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
      }
    }
    return null
  })
  
  return metrics
}

async function measureNetworkPerformance(page, url) {
  const responses = []
  
  page.on('response', response => {
    responses.push({
      url: response.url(),
      status: response.status(),
      size: response.headers()['content-length'] || 0,
      timing: response.timing()
    })
  })
  
  await page.goto(url, { waitUntil: 'networkidle' })
  
  const totalSize = responses.reduce((sum, response) => sum + parseInt(response.size || 0), 0)
  const averageResponseTime = responses.length > 0 
    ? responses.reduce((sum, response) => sum + (response.timing?.responseEnd || 0), 0) / responses.length
    : 0
  
  return {
    requestCount: responses.length,
    totalSize,
    averageResponseTime,
    responses: responses.slice(0, 10) // Keep only first 10 for reporting
  }
}

function calculateAverages(iterations) {
  const metrics = {}
  const keys = ['performance', 'javascript', 'memory', 'network']
  
  keys.forEach(key => {
    metrics[key] = {}
    const firstIteration = iterations[0][key]
    
    if (firstIteration) {
      Object.keys(firstIteration).forEach(metric => {
        const values = iterations
          .map(iter => iter[key][metric])
          .filter(val => val !== null && val !== undefined && !isNaN(val))
        
        if (values.length > 0) {
          metrics[key][metric] = values.reduce((sum, val) => sum + val, 0) / values.length
        }
      })
    }
  })
  
  return metrics
}

function checkThresholds(averages, thresholds) {
  const performance = averages.performance || {}
  
  return (
    (performance.firstContentfulPaint || 0) <= thresholds.firstContentfulPaint &&
    (performance.largestContentfulPaint || 0) <= thresholds.largestContentfulPaint &&
    (performance.timeToInteractive || 0) <= thresholds.timeToInteractive &&
    (performance.totalLoadTime || 0) <= 10000 // 10 second max load time
  )
}

function logPerformanceResults(pageName, averages) {
  const perf = averages.performance || {}
  const js = averages.javascript || {}
  const memory = averages.memory || {}
  
  console.log(`  📊 ${pageName} Performance Results:`)
  console.log(`    FCP: ${Math.round(perf.firstContentfulPaint || 0)}ms`)
  console.log(`    LCP: ${Math.round(perf.largestContentfulPaint || 0)}ms`)
  console.log(`    TTI: ${Math.round(perf.timeToInteractive || 0)}ms`)
  console.log(`    Load Time: ${Math.round(perf.totalLoadTime || 0)}ms`)
  console.log(`    JS Execution: ${Math.round(js.executionTime || 0)}ms`)
  console.log(`    Memory Used: ${Math.round((memory.usedJSHeapSize || 0) / 1024 / 1024)}MB`)
}

async function generatePerformanceReport(results) {
  const reportDir = path.join(process.cwd(), 'test-results')
  if (!fs.existsSync(reportDir)) {
    fs.mkdirSync(reportDir, { recursive: true })
  }
  
  // Generate JSON report
  const jsonReport = {
    summary: {
      totalPages: results.length,
      passedPages: results.filter(r => r.passed).length,
      failedPages: results.filter(r => !r.passed).length,
      timestamp: new Date().toISOString(),
      thresholds: PERFORMANCE_THRESHOLDS
    },
    results
  }
  
  fs.writeFileSync(
    path.join(reportDir, 'performance-report.json'),
    JSON.stringify(jsonReport, null, 2)
  )
  
  // Generate HTML report
  const htmlReport = generateHTMLReport(jsonReport)
  fs.writeFileSync(
    path.join(reportDir, 'performance-report.html'),
    htmlReport
  )
  
  console.log(`📄 Performance reports generated in ${reportDir}`)
}

function generateHTMLReport(data) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .page-section { margin: 20px 0; border: 1px solid #ddd; padding: 15px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background: #f9f9f9; border-radius: 3px; }
        .passed { border-left: 4px solid #4caf50; }
        .failed { border-left: 4px solid #f44336; }
        .threshold-met { color: #4caf50; }
        .threshold-exceeded { color: #f44336; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Performance Test Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Pages Tested:</strong> ${data.summary.totalPages}</p>
        <p><strong>Passed:</strong> ${data.summary.passedPages}</p>
        <p><strong>Failed:</strong> ${data.summary.failedPages}</p>
        <p><strong>Generated:</strong> ${new Date(data.summary.timestamp).toLocaleString()}</p>
    </div>
    
    <h2>Performance Thresholds</h2>
    <table>
        <tr><th>Metric</th><th>Threshold</th></tr>
        <tr><td>First Contentful Paint</td><td>${data.summary.thresholds.firstContentfulPaint}ms</td></tr>
        <tr><td>Largest Contentful Paint</td><td>${data.summary.thresholds.largestContentfulPaint}ms</td></tr>
        <tr><td>Time to Interactive</td><td>${data.summary.thresholds.timeToInteractive}ms</td></tr>
        <tr><td>First Input Delay</td><td>${data.summary.thresholds.firstInputDelay}ms</td></tr>
    </table>
    
    ${data.results.map(result => `
        <div class="page-section ${result.passed ? 'passed' : 'failed'}">
            <h3>${result.page} ${result.passed ? '✅' : '❌'}</h3>
            <p><strong>URL:</strong> ${result.url}</p>
            
            <h4>Performance Metrics (Average)</h4>
            <div class="metric">
                <strong>FCP:</strong> 
                <span class="${(result.averages.performance?.firstContentfulPaint || 0) <= data.summary.thresholds.firstContentfulPaint ? 'threshold-met' : 'threshold-exceeded'}">
                    ${Math.round(result.averages.performance?.firstContentfulPaint || 0)}ms
                </span>
            </div>
            <div class="metric">
                <strong>LCP:</strong> 
                <span class="${(result.averages.performance?.largestContentfulPaint || 0) <= data.summary.thresholds.largestContentfulPaint ? 'threshold-met' : 'threshold-exceeded'}">
                    ${Math.round(result.averages.performance?.largestContentfulPaint || 0)}ms
                </span>
            </div>
            <div class="metric">
                <strong>TTI:</strong> 
                <span class="${(result.averages.performance?.timeToInteractive || 0) <= data.summary.thresholds.timeToInteractive ? 'threshold-met' : 'threshold-exceeded'}">
                    ${Math.round(result.averages.performance?.timeToInteractive || 0)}ms
                </span>
            </div>
            <div class="metric">
                <strong>Load Time:</strong> ${Math.round(result.averages.performance?.totalLoadTime || 0)}ms
            </div>
            
            <h4>Resource Metrics</h4>
            <div class="metric">
                <strong>Resources:</strong> ${Math.round(result.averages.performance?.resourceCount || 0)}
            </div>
            <div class="metric">
                <strong>Total Size:</strong> ${Math.round((result.averages.network?.totalSize || 0) / 1024)}KB
            </div>
            <div class="metric">
                <strong>Memory Used:</strong> ${Math.round((result.averages.memory?.usedJSHeapSize || 0) / 1024 / 1024)}MB
            </div>
        </div>
    `).join('')}
    
</body>
</html>
  `
}

// Run the tests if this script is executed directly
if (require.main === module) {
  runPerformanceTests().catch(console.error)
}

module.exports = { runPerformanceTests }
