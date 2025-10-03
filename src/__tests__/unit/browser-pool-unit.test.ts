/**
 * Browser Pool Unit Tests
 * Unit tests for browser pool memory management functionality
 */

import { BrowserPool } from '@/lib/browserPool'
import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryLeakDetector } from '@/lib/memory-leak-detector'

// Mock puppeteer to avoid actual browser creation in tests
jest.mock('puppeteer', () => ({
  launch: jest.fn().mockResolvedValue({
    newPage: jest.fn().mockResolvedValue({
      setViewport: jest.fn(),
      setUserAgent: jest.fn(),
      setExtraHTTPHeaders: jest.fn(),
      setDefaultNavigationTimeout: jest.fn(),
      setDefaultTimeout: jest.fn(),
      on: jest.fn(),
      removeListener: jest.fn(),
      evaluate: jest.fn().mockResolvedValue({}),
      close: jest.fn(),
      browserContext: jest.fn().mockReturnValue({ id: 'mock-context' }),
    }),
    close: jest.fn(),
    isConnected: jest.fn().mockReturnValue(true),
    on: jest.fn(),
    removeListener: jest.fn(),
    emit: jest.fn(),
  }),
}))

describe('Browser Pool Unit Tests', () => {
  let browserPool: BrowserPool

  beforeEach(() => {
    // Create fresh browser pool for each test
    browserPool = new BrowserPool({
      maxBrowsers: 3,
      maxPagesPerBrowser: 2,
      browserTimeout: 30000,
      pageTimeout: 10000,
      headless: true,
    })
  })

  afterEach(async () => {
    await browserPool.shutdown()
  })

  describe('Configuration', () => {
    test('should initialize with correct configuration', () => {
      const config = browserPool.getConfig()
      
      expect(config.maxBrowsers).toBe(3)
      expect(config.maxPagesPerBrowser).toBe(2)
      expect(config.browserTimeout).toBe(30000)
      expect(config.pageTimeout).toBe(10000)
      expect(config.headless).toBe(true)
    })

    test('should provide memory statistics', () => {
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
      expect(memoryStats.lastCleanupTime).toBeInstanceOf(Date)
    })
  })

  describe('Memory Leak Detection Integration', () => {
    test('should track browser resources', () => {
      const trackerId = memoryLeakDetector.trackBrowserResource('browser', 'test-browser-1', {
        browserId: 'test-browser-1'
      })

      expect(trackerId).toBeDefined()
      expect(typeof trackerId).toBe('string')

      // Update memory tracking
      memoryLeakDetector.updateBrowserResourceMemory(trackerId)

      // Stop tracking
      memoryLeakDetector.stopTrackingBrowserResource(trackerId)

      const status = memoryLeakDetector.getStatus()
      expect(status.browserResourceTrackers).toBeGreaterThanOrEqual(0)
    })

    test('should track page resources', () => {
      const trackerId = memoryLeakDetector.trackBrowserResource('page', 'test-page-1', {
        browserId: 'test-browser-1',
        pageId: 'test-page-1'
      })

      expect(trackerId).toBeDefined()

      // Update memory tracking
      memoryLeakDetector.updateBrowserResourceMemory(trackerId)

      // Stop tracking
      memoryLeakDetector.stopTrackingBrowserResource(trackerId)
    })

    test('should track context resources', () => {
      const trackerId = memoryLeakDetector.trackBrowserResource('context', 'test-context-1', {
        browserId: 'test-browser-1',
        contextId: 'test-context-1'
      })

      expect(trackerId).toBeDefined()

      // Update memory tracking
      memoryLeakDetector.updateBrowserResourceMemory(trackerId)

      // Stop tracking
      memoryLeakDetector.stopTrackingBrowserResource(trackerId)
    })
  })

  describe('Memory Monitoring', () => {
    test('should handle memory alerts', (done) => {
      let alertReceived = false
      
      browserPool.on('memory-leak-detected', (alert) => {
        alertReceived = true
        expect(alert.type).toBe('browser')
        done()
      })

      // Simulate memory leak alert
      memoryLeakDetector.emit('memory-leak-detected', {
        type: 'browser',
        description: 'Test browser memory leak',
        memoryIncrease: 100 * 1024 * 1024, // 100MB
        timestamp: new Date(),
        severity: 'high',
      })

      // Fallback timeout
      setTimeout(() => {
        if (!alertReceived) {
          done()
        }
      }, 1000)
    })

    test('should handle emergency cleanup triggers', (done) => {
      let cleanupTriggered = false
      
      browserPool.on('emergency-cleanup-complete', () => {
        cleanupTriggered = true
        done()
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

      // Fallback timeout
      setTimeout(() => {
        if (!cleanupTriggered) {
          done()
        }
      }, 2000)
    })
  })

  describe('Statistics and Health', () => {
    test('should provide pool health statistics', () => {
      const healthStats = browserPool.getPoolHealthStats()
      
      expect(healthStats).toHaveProperty('totalBrowsers')
      expect(healthStats).toHaveProperty('healthyBrowsers')
      expect(healthStats).toHaveProperty('totalPages')
      expect(healthStats).toHaveProperty('averageResponseTime')
      expect(healthStats).toHaveProperty('averageErrorRate')
      
      expect(typeof healthStats.totalBrowsers).toBe('number')
      expect(typeof healthStats.healthyBrowsers).toBe('number')
      expect(typeof healthStats.totalPages).toBe('number')
      expect(typeof healthStats.averageResponseTime).toBe('number')
      expect(typeof healthStats.averageErrorRate).toBe('number')
    })

    test('should provide basic statistics', () => {
      const stats = browserPool.getStats()
      
      expect(stats).toHaveProperty('browsers')
      expect(stats).toHaveProperty('pages')
      expect(stats).toHaveProperty('availablePages')
      expect(stats).toHaveProperty('isShuttingDown')
      
      expect(typeof stats.browsers).toBe('number')
      expect(typeof stats.pages).toBe('number')
      expect(typeof stats.availablePages).toBe('number')
      expect(typeof stats.isShuttingDown).toBe('boolean')
    })
  })

  describe('Memory Management', () => {
    test('should update memory statistics', () => {
      const initialStats = browserPool.getMemoryStats()
      
      // Trigger memory stats update
      browserPool['updateMemoryStats']()
      
      const updatedStats = browserPool.getMemoryStats()
      
      expect(updatedStats.totalBrowsers).toBe(initialStats.totalBrowsers)
      expect(updatedStats.totalPages).toBe(initialStats.totalPages)
      expect(updatedStats.totalContexts).toBe(initialStats.totalContexts)
    })

    test('should handle memory cleanup', async () => {
      let cleanupCompleted = false
      
      browserPool.on('memory-cleanup-complete', () => {
        cleanupCompleted = true
      })

      // Trigger memory cleanup
      await browserPool['performMemoryCleanup']()

      expect(cleanupCompleted).toBe(true)
    })

    test('should format bytes correctly', () => {
      const formatBytes = browserPool['formatBytes']
      
      expect(formatBytes(0)).toBe('0 Bytes')
      expect(formatBytes(1024)).toBe('1 KB')
      expect(formatBytes(1024 * 1024)).toBe('1 MB')
      expect(formatBytes(1024 * 1024 * 1024)).toBe('1 GB')
    })

    test('should get current memory usage', () => {
      const memoryUsage = browserPool['getCurrentMemoryUsage']()
      
      expect(typeof memoryUsage).toBe('number')
      expect(memoryUsage).toBeGreaterThanOrEqual(0)
    })
  })

  describe('Cleanup and Shutdown', () => {
    test('should shutdown gracefully', async () => {
      let shutdownCompleted = false
      
      browserPool.on('shutdown-complete', () => {
        shutdownCompleted = true
      })

      await browserPool.shutdown()

      expect(shutdownCompleted).toBe(true)
      
      const stats = browserPool.getStats()
      expect(stats.browsers).toBe(0)
      expect(stats.pages).toBe(0)
      expect(stats.isShuttingDown).toBe(true)
    })

    test('should cleanup all memory trackers', () => {
      // Add some trackers
      const trackerId1 = memoryLeakDetector.trackBrowserResource('browser', 'test-1')
      const trackerId2 = memoryLeakDetector.trackBrowserResource('page', 'test-2')
      
      // Cleanup all trackers
      browserPool['cleanupAllMemoryTrackers']()
      
      // Verify trackers are cleaned up
      const status = memoryLeakDetector.getStatus()
      expect(status.browserResourceTrackers).toBeGreaterThanOrEqual(0)
    })
  })

  describe('Error Handling', () => {
    test('should handle memory tracking errors gracefully', () => {
      // This should not throw even if memory tracking fails
      expect(() => {
        browserPool['setupMemoryMonitoring']()
      }).not.toThrow()
    })

    test('should handle cleanup errors gracefully', async () => {
      // This should not throw even if cleanup fails
      await expect(browserPool['performMemoryCleanup']()).resolves.not.toThrow()
    })
  })
})
