/**
 * Browser Pool Unit Tests
 * Unit tests for browser pool memory management functionality
 */

import { OptimizedBrowserPoolMock } from '../mocks/optimized-browser-pool.mock'

// Mock logger to avoid console output in tests
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('Browser Pool Unit Tests', () => {
  let browserPool: OptimizedBrowserPoolMock

  beforeEach(async () => {
    // Create fresh browser pool mock for each test
    browserPool = new OptimizedBrowserPoolMock({
      maxBrowsers: 3,
      maxPagesPerBrowser: 2,
      browserTimeout: 30000,
      pageTimeout: 10000,
      headless: true,
    })

    await browserPool.initialize()
  })

  afterEach(async () => {
    if (browserPool) {
      await browserPool.shutdown()
    }
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
      expect(memoryStats).toHaveProperty('totalMemoryUsage')
      expect(memoryStats).toHaveProperty('averageMemoryPerBrowser')
      expect(memoryStats).toHaveProperty('memoryLeakAlerts')
      expect(memoryStats).toHaveProperty('lastCleanupTime')

      expect(typeof memoryStats.totalBrowsers).toBe('number')
      expect(typeof memoryStats.totalPages).toBe('number')
      expect(typeof memoryStats.totalMemoryUsage).toBe('number')
      expect(typeof memoryStats.averageMemoryPerBrowser).toBe('number')
      expect(typeof memoryStats.memoryLeakAlerts).toBe('number')
      expect(memoryStats.lastCleanupTime).toBeInstanceOf(Date)
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
      expect(stats).toHaveProperty('activePages')
      expect(stats).toHaveProperty('totalPages')
      expect(stats).toHaveProperty('isShuttingDown')

      expect(typeof stats.browsers).toBe('number')
      expect(typeof stats.pages).toBe('number')
      expect(typeof stats.availablePages).toBe('number')
      expect(typeof stats.activePages).toBe('number')
      expect(typeof stats.totalPages).toBe('number')
      expect(typeof stats.isShuttingDown).toBe('boolean')
    })
  })

  describe('Basic Functionality', () => {
    test('should get and release pages', async () => {
      const page = await browserPool.getPage()
      expect(page).toBeDefined()
      expect(page.id).toBeDefined()
      expect(page.isActive).toBe(true)

      await browserPool.releasePage(page)
      expect(page.isActive).toBe(false)
    })

    test('should navigate to URL', async () => {
      const page = await browserPool.getPage()
      await browserPool.navigateToUrl(page, 'https://example.com')
      expect(page.url).toBe('https://example.com')

      await browserPool.releasePage(page)
    })

    test('should handle multiple pages', async () => {
      const page1 = await browserPool.getPage()
      const page2 = await browserPool.getPage()

      expect(page1.id).not.toBe(page2.id)

      await browserPool.releasePage(page1)
      await browserPool.releasePage(page2)
    })
  })

  describe('Memory Management', () => {
    test('should provide health metrics', () => {
      const healthMetrics = browserPool.getHealthMetrics()

      expect(healthMetrics).toHaveProperty('totalBrowsers')
      expect(healthMetrics).toHaveProperty('activeBrowsers')
      expect(healthMetrics).toHaveProperty('totalPages')
      expect(healthMetrics).toHaveProperty('activePages')
      expect(healthMetrics).toHaveProperty('availablePages')
      expect(healthMetrics).toHaveProperty('memoryUsage')
      expect(healthMetrics).toHaveProperty('memoryLeakAlerts')

      expect(typeof healthMetrics.totalBrowsers).toBe('number')
      expect(typeof healthMetrics.activeBrowsers).toBe('number')
      expect(typeof healthMetrics.totalPages).toBe('number')
      expect(typeof healthMetrics.activePages).toBe('number')
      expect(typeof healthMetrics.availablePages).toBe('number')
      expect(typeof healthMetrics.memoryUsage).toBe('number')
      expect(typeof healthMetrics.memoryLeakAlerts).toBe('number')
    })

    test('should perform cleanup', async () => {
      await expect(browserPool.forceCleanup()).resolves.not.toThrow()
    })
  })

  describe('Cleanup and Shutdown', () => {
    test('should shutdown gracefully', async () => {
      await expect(browserPool.shutdown()).resolves.not.toThrow()
    })
  })
})


