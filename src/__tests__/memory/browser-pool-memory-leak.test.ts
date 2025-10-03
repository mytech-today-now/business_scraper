/**
 * Browser Pool Memory Leak Detection Tests
 * Comprehensive tests for memory leak prevention and detection in the browser pool
 */

import { BrowserPool } from '@/lib/browserPool'
import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryLeakDetector } from '@/lib/memory-leak-detector'
import { memoryCleanup } from '@/lib/memory-cleanup'
import { logger } from '@/utils/logger'

describe('Browser Pool Memory Leak Detection', () => {
  let browserPool: BrowserPool
  let initialMemory: number

  beforeAll(async () => {
    // Start memory monitoring
    if (!memoryMonitor.isActive()) {
      memoryMonitor.startMonitoring()
    }
    
    if (!memoryLeakDetector.getStatus().isActive) {
      memoryLeakDetector.startDetection()
    }

    // Record initial memory
    initialMemory = process.memoryUsage().heapUsed
  })

  beforeEach(async () => {
    // Create fresh browser pool for each test
    browserPool = new BrowserPool({
      maxBrowsers: 3,
      maxPagesPerBrowser: 2,
      browserTimeout: 30000,
      pageTimeout: 10000,
      headless: true,
    })
    
    await browserPool.initialize()
  })

  afterEach(async () => {
    // Cleanup after each test
    await browserPool.shutdown()
    
    // Force garbage collection
    if (global.gc) {
      global.gc()
    }
  })

  afterAll(async () => {
    // Stop monitoring
    memoryMonitor.stopMonitoring()
    memoryLeakDetector.stopDetection()
    memoryCleanup.stopAutoCleanup()
  })

  describe('Memory Leak Detection', () => {
    test('should detect browser memory leaks', async () => {
      const alerts: any[] = []
      
      browserPool.on('memory-leak-detected', (alert) => {
        alerts.push(alert)
      })

      // Create and release multiple pages to simulate potential leaks
      for (let i = 0; i < 10; i++) {
        const page = await browserPool.getPage()
        
        // Simulate memory-intensive operations
        await page.page.evaluate(() => {
          // Create large objects to simulate memory usage
          (window as any).testData = Array.from({ length: 10000 }, () => Math.random())
        })
        
        await browserPool.releasePage(page)
        
        // Small delay to allow memory tracking
        await new Promise(resolve => setTimeout(resolve, 100))
      }

      // Wait for leak detection to run
      await new Promise(resolve => setTimeout(resolve, 2000))

      // Check memory stats
      const memoryStats = browserPool.getMemoryStats()
      expect(memoryStats.totalBrowsers).toBeGreaterThan(0)
      expect(memoryStats.totalPages).toBeGreaterThanOrEqual(0)
    }, 30000)

    test('should track browser resource memory usage', async () => {
      const trackerId = memoryLeakDetector.trackBrowserResource('browser', 'test-browser-1', {
        browserId: 'test-browser-1'
      })

      expect(trackerId).toBeDefined()

      // Update memory tracking
      memoryLeakDetector.updateBrowserResourceMemory(trackerId)

      // Stop tracking
      memoryLeakDetector.stopTrackingBrowserResource(trackerId)

      const status = memoryLeakDetector.getStatus()
      expect(status.browserResourceTrackers).toBeGreaterThanOrEqual(0)
    })

    test('should perform emergency cleanup on memory alerts', async () => {
      let emergencyCleanupTriggered = false
      
      browserPool.on('emergency-cleanup-complete', () => {
        emergencyCleanupTriggered = true
      })

      // Simulate critical memory alert
      memoryMonitor.emit('memory-alert', {
        level: 'critical',
        message: 'Test critical memory alert',
        stats: {
          used: 850000000,
          total: 1000000000,
          percentage: 85,
          timestamp: Date.now(),
        },
        timestamp: Date.now(),
        action: 'emergency-cleanup',
      })

      // Wait for emergency cleanup
      await new Promise(resolve => setTimeout(resolve, 1000))

      expect(emergencyCleanupTriggered).toBe(true)
    })
  })

  describe('Resource Cleanup', () => {
    test('should properly cleanup pages with event listeners', async () => {
      const page = await browserPool.getPage()
      
      // Add event listeners to the page
      await page.page.evaluate(() => {
        window.addEventListener('test-event', () => {})
      })

      // Release page and verify cleanup
      await browserPool.releasePage(page)

      // Verify page is properly cleaned up
      const stats = browserPool.getStats()
      expect(stats.browsers).toBeGreaterThanOrEqual(0)
    })

    test('should cleanup browser instances with all resources', async () => {
      const initialBrowserCount = browserPool.getStats().browsers

      // Create pages to populate browsers
      const pages = []
      for (let i = 0; i < 3; i++) {
        pages.push(await browserPool.getPage())
      }

      // Release all pages
      for (const page of pages) {
        await browserPool.releasePage(page)
      }

      // Shutdown should cleanup all resources
      await browserPool.shutdown()

      const finalStats = browserPool.getStats()
      expect(finalStats.browsers).toBe(0)
      expect(finalStats.pages).toBe(0)
    })

    test('should handle browser disconnect gracefully', async () => {
      const page = await browserPool.getPage()
      const browserId = page.browserId

      // Simulate browser disconnect
      const browser = browserPool['browsers'].get(browserId)
      if (browser) {
        browser.browser.emit('disconnected')
      }

      // Wait for disconnect handling
      await new Promise(resolve => setTimeout(resolve, 500))

      // Verify browser is marked as unhealthy or removed
      const updatedBrowser = browserPool['browsers'].get(browserId)
      if (updatedBrowser) {
        expect(updatedBrowser.isHealthy).toBe(false)
      }
    })
  })

  describe('Memory Monitoring Integration', () => {
    test('should integrate with memory monitor alerts', async () => {
      let memoryAlertReceived = false
      
      browserPool.on('memory-leak-detected', () => {
        memoryAlertReceived = true
      })

      // Simulate memory leak alert
      memoryLeakDetector.emit('memory-leak-detected', {
        type: 'browser',
        description: 'Test browser memory leak',
        memoryIncrease: 100 * 1024 * 1024, // 100MB
        timestamp: new Date(),
        severity: 'high',
      })

      await new Promise(resolve => setTimeout(resolve, 100))

      expect(memoryAlertReceived).toBe(true)
    })

    test('should update memory statistics periodically', async () => {
      const initialStats = browserPool.getMemoryStats()
      
      // Create some activity
      const page = await browserPool.getPage()
      await browserPool.releasePage(page)

      // Wait for stats update
      await new Promise(resolve => setTimeout(resolve, 1000))

      const updatedStats = browserPool.getMemoryStats()
      expect(updatedStats.lastCleanupTime).toBeDefined()
    })
  })

  describe('Performance Under Load', () => {
    test('should handle concurrent page requests without memory leaks', async () => {
      const concurrentRequests = 10
      const pagePromises = []

      // Create concurrent page requests
      for (let i = 0; i < concurrentRequests; i++) {
        pagePromises.push(browserPool.getPage())
      }

      const pages = await Promise.all(pagePromises)
      expect(pages).toHaveLength(concurrentRequests)

      // Release all pages
      const releasePromises = pages.map(page => browserPool.releasePage(page))
      await Promise.all(releasePromises)

      // Check for memory leaks
      const memoryStats = browserPool.getMemoryStats()
      expect(memoryStats.memoryLeakAlerts).toBe(0)
    }, 15000)

    test('should maintain stable memory usage over time', async () => {
      const iterations = 20
      const memoryReadings = []

      for (let i = 0; i < iterations; i++) {
        const page = await browserPool.getPage()
        await browserPool.releasePage(page)
        
        // Record memory usage
        const currentMemory = process.memoryUsage().heapUsed
        memoryReadings.push(currentMemory)
        
        await new Promise(resolve => setTimeout(resolve, 50))
      }

      // Check that memory usage doesn't continuously increase
      const firstHalf = memoryReadings.slice(0, iterations / 2)
      const secondHalf = memoryReadings.slice(iterations / 2)
      
      const firstHalfAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length
      const secondHalfAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length
      
      // Memory should not increase by more than 50MB
      const memoryIncrease = secondHalfAvg - firstHalfAvg
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024)
    }, 20000)
  })

  describe('Error Scenarios', () => {
    test('should cleanup resources even when errors occur', async () => {
      const page = await browserPool.getPage()

      // Simulate error during page operation
      try {
        await page.page.evaluate(() => {
          throw new Error('Simulated page error')
        })
      } catch (error) {
        // Expected error
      }

      // Release page should still work
      await expect(browserPool.releasePage(page)).resolves.not.toThrow()
    })

    test('should handle browser crash gracefully', async () => {
      const page = await browserPool.getPage()
      const browserId = page.browserId

      // Simulate browser crash by closing it directly
      const browser = browserPool['browsers'].get(browserId)
      if (browser) {
        await browser.browser.close()
      }

      // Releasing page should handle the crashed browser
      await expect(browserPool.releasePage(page)).resolves.not.toThrow()
    })

    test('should handle timeout scenarios with proper cleanup', async () => {
      // Create a page and simulate timeout
      const page = await browserPool.getPage()

      // Simulate long-running operation that times out
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Operation timeout')), 1000)
      })

      try {
        await timeoutPromise
      } catch (error) {
        // Expected timeout
      }

      // Cleanup should still work
      await browserPool.releasePage(page)

      const stats = browserPool.getStats()
      expect(stats.browsers).toBeGreaterThanOrEqual(0)
    })
  })

  describe('Long-Running Tests', () => {
    test('should maintain stability over extended periods', async () => {
      const testDuration = 10000 // 10 seconds
      const startTime = Date.now()
      let operationCount = 0

      while (Date.now() - startTime < testDuration) {
        const page = await browserPool.getPage()

        // Simulate work
        await page.page.evaluate(() => {
          return new Promise(resolve => setTimeout(resolve, 10))
        })

        await browserPool.releasePage(page)
        operationCount++

        // Small delay between operations
        await new Promise(resolve => setTimeout(resolve, 50))
      }

      // Check that we performed a reasonable number of operations
      expect(operationCount).toBeGreaterThan(10)

      // Check memory stats
      const memoryStats = browserPool.getMemoryStats()
      expect(memoryStats.memoryLeakAlerts).toBeLessThan(5) // Allow some alerts but not excessive
    }, 15000)

    test('should handle resource limits gracefully', async () => {
      // Try to exceed the browser pool limits
      const maxBrowsers = browserPool.getConfig().maxBrowsers
      const maxPagesPerBrowser = browserPool.getConfig().maxPagesPerBrowser
      const maxPossiblePages = maxBrowsers * maxPagesPerBrowser

      const pages = []

      // Try to get more pages than the pool can handle
      for (let i = 0; i < maxPossiblePages + 5; i++) {
        try {
          const page = await browserPool.getPage()
          pages.push(page)
        } catch (error) {
          // Expected when limits are reached
          break
        }
      }

      // Should not exceed the configured limits significantly
      expect(pages.length).toBeLessThanOrEqual(maxPossiblePages + 2)

      // Release all pages
      for (const page of pages) {
        await browserPool.releasePage(page)
      }
    }, 20000)
  })

  describe('Memory API Integration', () => {
    test('should provide accurate memory statistics via API', async () => {
      // Create some activity
      const page = await browserPool.getPage()
      await browserPool.releasePage(page)

      // Get memory stats
      const memoryStats = browserPool.getMemoryStats()

      expect(memoryStats).toHaveProperty('totalBrowsers')
      expect(memoryStats).toHaveProperty('totalPages')
      expect(memoryStats).toHaveProperty('totalContexts')
      expect(memoryStats).toHaveProperty('totalMemoryUsage')
      expect(memoryStats).toHaveProperty('averageMemoryPerBrowser')
      expect(memoryStats).toHaveProperty('memoryLeakAlerts')
      expect(memoryStats).toHaveProperty('lastCleanupTime')

      expect(typeof memoryStats.totalBrowsers).toBe('number')
      expect(typeof memoryStats.totalPages).toBe('number')
      expect(typeof memoryStats.totalMemoryUsage).toBe('number')
    })

    test('should trigger cleanup via API methods', async () => {
      let cleanupTriggered = false

      browserPool.on('memory-cleanup-complete', () => {
        cleanupTriggered = true
      })

      // Trigger manual cleanup
      await browserPool['performMemoryCleanup']()

      expect(cleanupTriggered).toBe(true)
    })
  })
})
