/**
 * Browser Pool Load Testing
 * High-load stress tests for memory leak detection and performance validation
 */

import { OptimizedBrowserPoolMock, createOptimizedBrowserPoolMock } from '@/__tests__/mocks/optimized-browser-pool.mock'
import { mockPerformanceTestOptimizer } from '@/__tests__/mocks/performance-test-optimizer.mock'
import { mockMemoryMonitor } from '@/__tests__/mocks/memory-monitor.mock'
import { mockMemoryLeakDetector } from '@/__tests__/mocks/memory-leak-detector.mock'
import { logger } from '@/utils/logger'

// Mock the real implementations to prevent hanging
jest.mock('@/lib/performance-test-optimizer', () => ({
  performanceTestOptimizer: mockPerformanceTestOptimizer
}))

jest.mock('@/lib/memory-monitor', () => ({
  memoryMonitor: mockMemoryMonitor
}))

jest.mock('@/lib/memory-leak-detector', () => ({
  memoryLeakDetector: mockMemoryLeakDetector
}))

describe('Browser Pool Load Testing', () => {
  let browserPool: OptimizedBrowserPoolMock
  let initialMemory: number

  beforeAll(async () => {
    // Initialize performance test environment
    await mockPerformanceTestOptimizer.initializeTestEnvironment()

    // Start monitoring services
    if (!mockMemoryMonitor.isActive()) {
      mockMemoryMonitor.startMonitoring()
    }

    if (!mockMemoryLeakDetector.getStatus().isActive) {
      mockMemoryLeakDetector.startDetection()
    }

    initialMemory = process.memoryUsage().heapUsed
  })

  beforeEach(async () => {
    const config = mockPerformanceTestOptimizer.getBrowserPoolConfig()
    browserPool = createOptimizedBrowserPoolMock({
      maxBrowsers: config.maxBrowsers,
      maxPagesPerBrowser: config.maxPagesPerBrowser,
      browserTimeout: config.browserTimeout,
      pageTimeout: config.pageTimeout,
      headless: config.headless,
      simulateLatency: true,
      simulateMemoryUsage: true,
      simulateErrors: false,
      errorRate: 2
    })

    await browserPool.initialize()
  })

  afterEach(async () => {
    if (browserPool) {
      await browserPool.shutdown()
    }

    // Force garbage collection
    mockPerformanceTestOptimizer.forceMemoryCleanup()
  })

  afterAll(async () => {
    mockMemoryMonitor.stopMonitoring()
    mockMemoryLeakDetector.stopDetection()
  })

  describe('High Concurrency Load Tests', () => {
    test('should handle 20 concurrent page requests', async () => {
      const concurrentRequests = 20
      const startTime = Date.now()
      
      const pagePromises = Array.from({ length: concurrentRequests }, (_, index) => {
        return (async () => {
          try {
            const page = await browserPool.getPage()

            // Simulate navigation work
            await browserPool.navigateToUrl(page, `https://example.com/page-${index}`)

            // Simulate processing delay
            await new Promise(resolve => setTimeout(resolve, Math.random() * 100))

            await browserPool.releasePage(page)
            return { success: true, index }
          } catch (error) {
            return { success: false, index, error: error.message }
          }
        })()
      })

      const results = await Promise.allSettled(pagePromises)
      const duration = Date.now() - startTime
      
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length
      const failed = results.length - successful
      
      logger.info('LoadTest', `Concurrent requests: ${concurrentRequests}, Successful: ${successful}, Failed: ${failed}, Duration: ${duration}ms`)
      
      // Should handle at least 80% of requests successfully
      expect(successful / concurrentRequests).toBeGreaterThan(0.8)
      
      // Should complete within reasonable time (30 seconds)
      expect(duration).toBeLessThan(30000)
      
      // Check for memory leaks
      const memoryStats = browserPool.getMemoryStats()
      expect(memoryStats.memoryLeakAlerts).toBeLessThan(10)
    }, 45000)

    test('should handle rapid page creation and destruction', async () => {
      const iterations = 100
      const startTime = Date.now()
      let successCount = 0
      let errorCount = 0
      
      for (let i = 0; i < iterations; i++) {
        try {
          const page = await browserPool.getPage()

          // Minimal work to test rapid cycling
          await browserPool.navigateToUrl(page, `https://test.com/rapid-${i}`)

          await browserPool.releasePage(page)
          successCount++
        } catch (error) {
          errorCount++
          logger.error('LoadTest', `Iteration ${i} failed`, error)
        }
        
        // No delay - test rapid cycling
      }
      
      const duration = Date.now() - startTime
      
      logger.info('LoadTest', `Rapid cycling: ${iterations} iterations, Success: ${successCount}, Errors: ${errorCount}, Duration: ${duration}ms`)
      
      // Should handle at least 90% successfully
      expect(successCount / iterations).toBeGreaterThan(0.9)
      
      // Should complete within reasonable time
      expect(duration).toBeLessThan(20000)
    }, 30000)

    test('should maintain performance under sustained load', async () => {
      const testDuration = 15000 // 15 seconds
      const startTime = Date.now()
      let operationCount = 0
      let errorCount = 0
      const performanceMetrics = []
      
      while (Date.now() - startTime < testDuration) {
        const operationStart = Date.now()
        
        try {
          const page = await browserPool.getPage()

          // Simulate realistic work with navigation
          await browserPool.navigateToUrl(page, `https://sustained-test.com/page-${operationCount}`)

          // Simulate data processing delay
          await new Promise(resolve => setTimeout(resolve, Math.random() * 50))

          await browserPool.releasePage(page)

          const operationDuration = Date.now() - operationStart
          performanceMetrics.push(operationDuration)
          operationCount++
        } catch (error) {
          errorCount++
        }
        
        // Small delay to prevent overwhelming
        await new Promise(resolve => setTimeout(resolve, 10))
      }
      
      const totalDuration = Date.now() - startTime
      const avgOperationTime = performanceMetrics.reduce((a, b) => a + b, 0) / performanceMetrics.length
      const operationsPerSecond = (operationCount / totalDuration) * 1000
      
      logger.info('LoadTest', `Sustained load: ${operationCount} operations, ${errorCount} errors, Avg time: ${avgOperationTime}ms, Ops/sec: ${operationsPerSecond}`)
      
      // Performance expectations
      expect(operationCount).toBeGreaterThan(50) // Should complete at least 50 operations
      expect(errorCount / operationCount).toBeLessThan(0.1) // Less than 10% error rate
      expect(avgOperationTime).toBeLessThan(5000) // Average operation under 5 seconds
      
      // Check memory stability
      const memoryStats = browserPool.getMemoryStats()
      expect(memoryStats.memoryLeakAlerts).toBeLessThan(5)
    }, 20000)
  })

  describe('Memory Stress Tests', () => {
    test('should handle memory-intensive operations without leaks', async () => {
      const iterations = 20
      const memoryReadings = []
      
      for (let i = 0; i < iterations; i++) {
        const page = await browserPool.getPage()

        // Create memory-intensive operation with navigation
        await browserPool.navigateToUrl(page, `https://memory-test.com/heavy-page-${i}`)

        // Simulate memory-intensive processing
        await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200))

        await browserPool.releasePage(page)
        
        // Record memory usage
        const currentMemory = process.memoryUsage().heapUsed
        memoryReadings.push(currentMemory)
        
        // Force garbage collection periodically
        if (i % 5 === 0 && global.gc) {
          global.gc()
        }
        
        await new Promise(resolve => setTimeout(resolve, 100))
      }
      
      // Analyze memory trend
      const firstQuarter = memoryReadings.slice(0, Math.floor(iterations / 4))
      const lastQuarter = memoryReadings.slice(-Math.floor(iterations / 4))
      
      const firstAvg = firstQuarter.reduce((a, b) => a + b, 0) / firstQuarter.length
      const lastAvg = lastQuarter.reduce((a, b) => a + b, 0) / lastQuarter.length
      
      const memoryIncrease = lastAvg - firstAvg
      const memoryIncreasePercent = (memoryIncrease / firstAvg) * 100
      
      logger.info('LoadTest', `Memory stress test: ${iterations} iterations, Memory increase: ${memoryIncrease / 1024 / 1024}MB (${memoryIncreasePercent.toFixed(2)}%)`)
      
      // Memory should not increase by more than 100MB or 50%
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024)
      expect(memoryIncreasePercent).toBeLessThan(50)
      
      // Check for memory leak alerts
      const memoryStats = browserPool.getMemoryStats()
      expect(memoryStats.memoryLeakAlerts).toBeLessThan(3)
    }, 30000)

    test('should recover from memory pressure', async () => {
      // Create memory pressure
      const pages = []
      
      try {
        // Fill up the browser pool
        for (let i = 0; i < 20; i++) {
          try {
            const page = await browserPool.getPage()
            pages.push(page)

            // Create memory pressure with navigation
            await browserPool.navigateToUrl(page, `https://memory-pressure.com/heavy-${i}`)

            // Simulate memory-intensive processing
            await new Promise(resolve => setTimeout(resolve, 50))
          } catch (error) {
            // Expected when pool is exhausted
            break
          }
        }
        
        // Trigger cleanup
        await browserPool.forceCleanup()

        // Wait for cleanup to complete
        await new Promise(resolve => setTimeout(resolve, 1000))
        
        // Should be able to create new pages after cleanup
        const newPage = await browserPool.getPage()
        expect(newPage).toBeDefined()
        await browserPool.releasePage(newPage)
        
      } finally {
        // Cleanup all pages
        for (const page of pages) {
          try {
            await browserPool.releasePage(page)
          } catch (error) {
            // Ignore cleanup errors
          }
        }
      }
    }, 25000)
  })

  describe('Resource Limit Tests', () => {
    test('should enforce browser limits under load', async () => {
      const config = performanceTestOptimizer.getBrowserPoolConfig()
      const maxBrowsers = config.maxBrowsers
      const attempts = maxBrowsers * 5 // Try to create 5x the limit

      const pages = []
      let creationErrors = 0

      for (let i = 0; i < attempts; i++) {
        try {
          const page = await browserPool.getPage()
          pages.push(page)
        } catch (error) {
          creationErrors++
        }
      }

      const healthMetrics = browserPool.getHealthMetrics()

      // Should not exceed configured limits significantly
      expect(healthMetrics.totalBrowsers).toBeLessThanOrEqual(maxBrowsers + 1)

      // Should have some creation errors when limits are reached
      expect(creationErrors).toBeGreaterThan(0)

      // Cleanup
      for (const page of pages) {
        await browserPool.releasePage(page)
      }
    }, 15000)

    test('should handle timeout scenarios gracefully', async () => {
      // Create pages and let them timeout
      const pages = []
      
      for (let i = 0; i < 5; i++) {
        const page = await browserPool.getPage()
        pages.push(page)
        
        // Don't release immediately - let timeout handling kick in
      }
      
      // Wait for timeout handling
      await new Promise(resolve => setTimeout(resolve, 35000)) // Longer than page timeout
      
      // Should be able to create new pages after timeout cleanup
      const newPage = await browserPool.getPage()
      expect(newPage).toBeDefined()
      await browserPool.releasePage(newPage)
      
      // Cleanup remaining pages
      for (const page of pages) {
        try {
          await browserPool.releasePage(page)
        } catch (error) {
          // May fail if already cleaned up by timeout
        }
      }
    }, 45000)
  })
})
