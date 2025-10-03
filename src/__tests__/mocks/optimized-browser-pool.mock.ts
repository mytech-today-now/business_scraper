/**
 * Optimized Browser Pool Mock for Performance Testing
 *
 * Provides a realistic mock of browser pool functionality without
 * the overhead of actual browser instances for performance testing.
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'

export interface MockBrowserPoolConfig {
  maxBrowsers: number
  maxPagesPerBrowser: number
  browserTimeout: number
  pageTimeout: number
  headless: boolean
  enableProxy: boolean
  userAgents: string[]
  viewports: Array<{ width: number; height: number }>
  simulateLatency: boolean
  simulateMemoryUsage: boolean
  simulateErrors: boolean
  errorRate: number // percentage
}

export interface MockPageInstance {
  id: string
  page: any // Mock page object
  browserId: string
  contextId?: string
  url: string
  isActive: boolean
  createdAt: Date
  lastUsed: Date
  memoryUsage: number
  memoryTrackerId?: string
  eventListeners: Map<string, Function>
  initialMemory: number
}

export interface MockBrowserInstance {
  id: string
  browser: any // Mock browser object
  pages: Map<string, MockPageInstance>
  contexts: Set<any>
  isActive: boolean
  isHealthy: boolean
  createdAt: Date
  lastUsed: Date
  memoryUsage: number
  memoryTrackerId?: string
  eventListeners: Map<string, Function>
  initialMemory: number
  currentMemory: number
}

export interface MockBrowserPoolStats {
  totalBrowsers: number
  totalPages: number
  totalContexts: number
  totalMemoryUsage: number
  averageMemoryPerBrowser: number
  memoryLeakAlerts: number
  lastCleanupTime: Date
}

export class OptimizedBrowserPoolMock extends EventEmitter {
  private config: MockBrowserPoolConfig
  private browsers: Map<string, MockBrowserInstance> = new Map()
  private availablePages: MockPageInstance[] = []
  private activePagesCount = 0
  private isShuttingDown = false
  private memoryStats: MockBrowserPoolStats
  private baseMemoryUsage = 50 * 1024 * 1024 // 50MB base
  private memoryLeakAlerts = 0
  private healthMetrics: Map<string, any> = new Map()
  private errorCounts: Map<string, number> = new Map()
  private resourceTrackers: Map<string, string> = new Map()
  private lastCleanupTime: Date = new Date()
  private healthCheckInterval?: NodeJS.Timeout
  private memoryCleanupInterval?: NodeJS.Timeout

  constructor(config: Partial<MockBrowserPoolConfig> = {}) {
    super()

    this.config = {
      maxBrowsers: 6,
      maxPagesPerBrowser: 3,
      browserTimeout: 90000,
      pageTimeout: 15000,
      headless: true,
      enableProxy: true,
      userAgents: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      ],
      viewports: [
        { width: 1920, height: 1080 },
        { width: 1366, height: 768 },
        { width: 1440, height: 900 }
      ],
      simulateLatency: true,
      simulateMemoryUsage: true,
      simulateErrors: false,
      errorRate: 5,
      ...config
    }

    this.memoryStats = {
      totalBrowsers: 0,
      totalPages: 0,
      totalContexts: 0,
      totalMemoryUsage: 0,
      averageMemoryPerBrowser: 0,
      memoryLeakAlerts: 0,
      lastCleanupTime: new Date()
    }

    // Setup memory monitoring integration (mock)
    this.setupMemoryMonitoring()

    // Start health check interval
    this.startHealthCheck()

    // Start memory cleanup interval
    this.startMemoryCleanup()

    logger.debug('OptimizedBrowserPoolMock', 'Initialized with config', this.config)
  }

  /**
   * Setup memory monitoring integration (mock)
   */
  private setupMemoryMonitoring(): void {
    try {
      // Mock memory monitoring setup
      logger.debug('OptimizedBrowserPoolMock', 'Memory monitoring setup complete (mock)')
    } catch (error) {
      logger.warn('OptimizedBrowserPoolMock', 'Failed to setup memory monitoring integration', error)
    }
  }

  /**
   * Initialize the browser pool
   */
  async initialize(): Promise<void> {
    if (this.config.simulateLatency) {
      await this.simulateDelay(100, 300)
    }

    // Create initial browser instances for better performance
    const initialBrowserCount = Math.min(2, this.config.maxBrowsers)
    const browserPromises = []

    for (let i = 0; i < initialBrowserCount; i++) {
      browserPromises.push(this.createBrowser())
    }

    const browsers = await Promise.allSettled(browserPromises)
    const successfulBrowsers = browsers.filter(result => result.status === 'fulfilled').length

    if (successfulBrowsers === 0) {
      throw new Error('Failed to create any browsers during initialization')
    }

    // Pre-create some pages for immediate availability
    const pagePromises = []
    const initialPageCount = Math.min(4, successfulBrowsers * 2)

    for (let i = 0; i < initialPageCount; i++) {
      pagePromises.push(this.createPage())
    }

    const pages = await Promise.allSettled(pagePromises)

    // Add successful pages to available pool
    for (const pageResult of pages) {
      if (pageResult.status === 'fulfilled' && pageResult.value) {
        this.availablePages.push(pageResult.value)
      }
    }

    logger.info('OptimizedBrowserPoolMock', `Browser pool initialized with ${this.browsers.size} browsers and ${this.availablePages.length} available pages`)
    this.emit('initialized')
  }

  /**
   * Shutdown the browser pool
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true

    logger.info('OptimizedBrowserPoolMock', 'Shutting down browser pool with comprehensive cleanup')

    // Stop all intervals
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval)
      this.healthCheckInterval = undefined
    }

    if (this.memoryCleanupInterval) {
      clearInterval(this.memoryCleanupInterval)
      this.memoryCleanupInterval = undefined
    }

    // Close all pages first with proper cleanup
    const pageClosePromises = this.availablePages.map(async pageInstance => {
      try {
        await this.closePageWithCleanup(pageInstance)
      } catch (error) {
        logger.error('OptimizedBrowserPoolMock', `Failed to close page during shutdown`, error)
      }
    })

    await Promise.allSettled(pageClosePromises)

    // Close all browsers with comprehensive cleanup
    const browserClosePromises = Array.from(this.browsers.values()).map(async browserInstance => {
      try {
        await this.closeBrowserWithCleanup(browserInstance)
      } catch (error) {
        logger.error('OptimizedBrowserPoolMock', `Failed to close browser ${browserInstance.id}`, error)
      }
    })

    await Promise.allSettled(browserClosePromises)

    // Clear all data structures
    this.browsers.clear()
    this.availablePages = []
    this.activePagesCount = 0
    this.healthMetrics.clear()
    this.errorCounts.clear()
    this.resourceTrackers.clear()

    // Update memory stats
    this.memoryStats.totalBrowsers = 0
    this.memoryStats.totalPages = 0
    this.memoryStats.totalContexts = 0
    this.memoryStats.lastCleanupTime = new Date()

    if (this.config.simulateLatency) {
      await this.simulateDelay(50, 150)
    }

    logger.info('OptimizedBrowserPoolMock', 'Browser pool shutdown complete')
    this.emit('shutdown-complete')
  }

  /**
   * Get a page for scraping
   */
  async getPage(): Promise<MockPageInstance> {
    if (this.isShuttingDown) {
      throw new Error('Browser pool is shutting down')
    }

    // Simulate error if configured
    if (this.config.simulateErrors && Math.random() * 100 < this.config.errorRate) {
      throw new Error('Simulated browser pool error')
    }

    // Try to get an available page first
    let pageInstance = this.getAvailablePage()

    if (!pageInstance) {
      // Create new page if possible
      pageInstance = await this.createPage()
    }

    // If still no page available, try to create a new browser and page
    if (!pageInstance && this.browsers.size < this.config.maxBrowsers) {
      logger.info('OptimizedBrowserPoolMock', 'Creating additional browser for page demand')
      const newBrowser = await this.createBrowser()
      if (newBrowser) {
        pageInstance = await this.createPage()
      }
    }

    // Last resort: wait a bit and try again for available pages (with timeout)
    if (!pageInstance) {
      logger.warn('OptimizedBrowserPoolMock', 'No pages available, waiting for page to become available')
      const maxWaitTime = 5000 // 5 seconds max wait
      const startWait = Date.now()

      while (!pageInstance && (Date.now() - startWait) < maxWaitTime) {
        await new Promise(resolve => setTimeout(resolve, 100))
        pageInstance = this.getAvailablePage()

        // Try to create more capacity if possible
        if (!pageInstance && this.browsers.size < this.config.maxBrowsers) {
          const newBrowser = await this.createBrowser()
          if (newBrowser) {
            pageInstance = await this.createPage()
          }
        }
      }
    }

    if (!pageInstance) {
      const stats = this.getStats()
      throw new Error(`No available browser capacity after waiting. Stats: ${JSON.stringify(stats)}`)
    }

    pageInstance.isActive = true
    pageInstance.lastUsed = new Date()
    this.activePagesCount++

    if (this.config.simulateLatency) {
      await this.simulateDelay(10, 50)
    }

    logger.debug('OptimizedBrowserPoolMock', `Page acquired. Active pages: ${this.activePagesCount}`)
    return pageInstance
  }

  /**
   * Get an available page from the pool
   */
  private getAvailablePage(): MockPageInstance | null {
    const availablePage = this.availablePages.find(p => !p.isActive)
    if (availablePage) {
      this.availablePages = this.availablePages.filter(p => p !== availablePage)
      return availablePage
    }
    return null
  }

  /**
   * Release a page back to the pool
   */
  async releasePage(pageInstance: MockPageInstance): Promise<void> {
    try {
      // Clean up page event listeners first
      await this.cleanupPageEventListeners(pageInstance)

      // Reset page state
      await this.resetPage(pageInstance)

      pageInstance.isActive = false
      pageInstance.lastUsed = new Date()
      this.activePagesCount--

      // Simulate memory cleanup
      if (this.config.simulateMemoryUsage) {
        pageInstance.memoryUsage = Math.max(pageInstance.memoryUsage * 0.8, 10 * 1024 * 1024) // Reduce by 20%
      }

      // Update memory tracking
      if (pageInstance.memoryTrackerId) {
        try {
          // Mock memory tracking update
          logger.debug('OptimizedBrowserPoolMock', 'Updated page memory tracking')
        } catch (error) {
          logger.warn('OptimizedBrowserPoolMock', 'Failed to update page memory tracking', error)
        }
      }

      // Add back to available pages if browser is still healthy
      const browser = this.browsers.get(pageInstance.browserId)
      if (browser?.isHealthy) {
        this.availablePages.push(pageInstance)
      } else {
        // Properly close page and cleanup memory tracking
        await this.closePageWithCleanup(pageInstance)
      }

      if (this.config.simulateLatency) {
        await this.simulateDelay(5, 20)
      }

      this.updateMemoryStats()
      logger.debug('OptimizedBrowserPoolMock', `Page released. Active pages: ${this.activePagesCount}`)
      this.emit('page-released', pageInstance)
    } catch (error) {
      logger.error('OptimizedBrowserPoolMock', 'Failed to release page', error)
      this.activePagesCount--

      // Ensure cleanup even on error
      try {
        await this.closePageWithCleanup(pageInstance)
      } catch (cleanupError) {
        logger.error('OptimizedBrowserPoolMock', 'Failed to cleanup page after release error', cleanupError)
      }
    }
  }

  /**
   * Navigate to URL (mock implementation)
   */
  async navigateToUrl(page: MockPageInstance, url: string): Promise<void> {
    if (this.config.simulateErrors && Math.random() * 100 < this.config.errorRate) {
      throw new Error(`Failed to navigate to ${url}`)
    }

    page.url = url
    page.lastUsed = new Date()

    // Simulate memory increase from navigation (smaller increase)
    if (this.config.simulateMemoryUsage) {
      page.memoryUsage += Math.random() * 2 * 1024 * 1024 // 0-2MB increase
    }

    if (this.config.simulateLatency) {
      await this.simulateDelay(200, 1000) // Simulate page load time
    }

    this.updateMemoryStats()
    this.emit('navigation', { page, url })
  }

  /**
   * Get configuration
   */
  getConfig(): MockBrowserPoolConfig {
    return { ...this.config }
  }

  /**
   * Get basic statistics
   */
  getStats() {
    return {
      browsers: this.browsers.size,
      pages: this.activePagesCount + this.availablePages.length,
      availablePages: this.availablePages.length,
      activePages: this.activePagesCount,
      totalPages: this.activePagesCount + this.availablePages.length,
      isShuttingDown: this.isShuttingDown,
    }
  }

  /**
   * Get pool health statistics
   */
  getPoolHealthStats() {
    return {
      totalBrowsers: this.browsers.size,
      healthyBrowsers: Array.from(this.browsers.values()).filter(b => b.isActive).length,
      totalPages: this.activePagesCount + this.availablePages.length,
      averageResponseTime: 100, // Mock value
      averageErrorRate: this.config.errorRate,
    }
  }

  /**
   * Get memory statistics
   */
  getMemoryStats(): MockBrowserPoolStats {
    this.updateMemoryStats()
    return { ...this.memoryStats }
  }

  /**
   * Get health metrics
   */
  getHealthMetrics() {
    return {
      totalBrowsers: this.browsers.size,
      activeBrowsers: Array.from(this.browsers.values()).filter(b => b.isActive).length,
      totalPages: this.activePagesCount + this.availablePages.length,
      activePages: this.activePagesCount,
      availablePages: this.availablePages.length,
      memoryUsage: this.memoryStats.totalMemoryUsage,
      memoryLeakAlerts: this.memoryLeakAlerts
    }
  }

  /**
   * Monitor browser health metrics
   */
  async monitorBrowserHealth(browserId: string): Promise<any | null> {
    const browser = this.browsers.get(browserId)
    if (!browser) return null

    try {
      const healthData = {
        memoryUsage: browser.memoryUsage,
        cpuUsage: Math.random() * 20, // Mock CPU usage
        activePages: browser.pages.size,
        responseTime: Date.now() - browser.lastUsed.getTime(),
        errorRate: this.calculateErrorRate(browserId),
        lastHealthCheck: new Date(),
      }

      this.healthMetrics.set(browserId, healthData)
      return healthData
    } catch (error) {
      logger.error('OptimizedBrowserPoolMock', `Failed to monitor browser health for ${browserId}`, error)
      return null
    }
  }

  /**
   * Calculate error rate for a browser
   */
  private calculateErrorRate(browserId: string): number {
    const errorCount = this.errorCounts.get(browserId) || 0
    const totalOperations = 100 // Mock total operations
    return totalOperations > 0 ? (errorCount / totalOperations) * 100 : 0
  }

  /**
   * Optimize browser allocation based on health metrics
   */
  async optimizeBrowserAllocation(): Promise<void> {
    for (const [browserId, metrics] of this.healthMetrics) {
      // Restart browsers with high memory usage or error rates
      if (metrics.memoryUsage > 512 * 1024 * 1024 || metrics.errorRate > 10) {
        logger.warn('OptimizedBrowserPoolMock', `Restarting browser ${browserId} due to poor health metrics`)
        await this.restartBrowser(browserId)
      }
    }
  }

  /**
   * Restart a specific browser with comprehensive cleanup
   */
  private async restartBrowser(browserId: string): Promise<void> {
    const browser = this.browsers.get(browserId)
    if (browser) {
      try {
        await this.closeBrowserWithCleanup(browser)
        this.handleBrowserDisconnect(browserId)
        // Create a new browser to replace it
        await this.createBrowser()
      } catch (error) {
        logger.error('OptimizedBrowserPoolMock', `Failed to restart browser ${browserId}`, error)
      }
    }
  }

  /**
   * Handle browser disconnect
   */
  private handleBrowserDisconnect(browserId: string): void {
    const browser = this.browsers.get(browserId)
    if (browser) {
      browser.isHealthy = false
      this.browsers.delete(browserId)

      // Remove pages from this browser
      this.availablePages = this.availablePages.filter(p => p.browserId !== browserId)
    }
  }

  /**
   * Force memory cleanup
   */
  async forceCleanup(): Promise<void> {
    // Clean up inactive pages
    const now = new Date()
    const cleanupThreshold = 5 * 60 * 1000 // 5 minutes

    for (const [browserId, browser] of this.browsers) {
      const pagesToRemove: string[] = []
      
      for (const [pageId, page] of browser.pages) {
        if (!page.isActive && (now.getTime() - page.lastUsed.getTime()) > cleanupThreshold) {
          pagesToRemove.push(pageId)
        }
      }

      for (const pageId of pagesToRemove) {
        browser.pages.delete(pageId)
        browser.memoryUsage = Math.max(browser.memoryUsage * 0.9, this.baseMemoryUsage)
      }
    }

    // Remove empty browsers
    const browsersToRemove: string[] = []
    for (const [browserId, browser] of this.browsers) {
      if (browser.pages.size === 0) {
        browsersToRemove.push(browserId)
      }
    }

    for (const browserId of browsersToRemove) {
      await this.closeBrowser(browserId)
    }

    this.memoryStats.lastCleanupTime = now
    this.updateMemoryStats()

    if (this.config.simulateLatency) {
      await this.simulateDelay(100, 300)
    }

    this.emit('cleanup-completed')
  }

  /**
   * Create a new browser instance
   */
  private async createBrowser(): Promise<MockBrowserInstance | null> {
    if (this.browsers.size >= this.config.maxBrowsers) {
      logger.warn('OptimizedBrowserPoolMock', 'Maximum browsers reached')
      return null
    }

    try {
      const browserId = `browser-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

      const initialMemory = this.getCurrentMemoryUsage()
      let memoryTrackerId: string | undefined

      try {
        memoryTrackerId = `mock-tracker-${browserId}`
        // Track this browser for memory leak detection
        this.resourceTrackers.set(browserId, memoryTrackerId)
      } catch (error) {
        logger.warn('OptimizedBrowserPoolMock', 'Failed to setup memory tracking for browser', error)
      }

      // Create mock browser object
      const mockBrowser = this.createMockBrowser()

      const browser: MockBrowserInstance = {
        id: browserId,
        browser: mockBrowser,
        pages: new Map(),
        contexts: new Set(),
        isActive: true,
        isHealthy: true,
        createdAt: new Date(),
        lastUsed: new Date(),
        memoryUsage: this.baseMemoryUsage + (Math.random() * 10 * 1024 * 1024), // Base + 0-10MB
        memoryTrackerId,
        eventListeners: new Map(),
        initialMemory,
        currentMemory: initialMemory,
      }

      // Setup browser event listeners with cleanup tracking
      this.setupBrowserEventListeners(browser)

      this.browsers.set(browserId, browser)

      if (this.config.simulateLatency) {
        await this.simulateDelay(500, 1500) // Browser startup time
      }

      logger.debug('OptimizedBrowserPoolMock', `Created browser ${browserId}`)
      this.emit('browser-created', browser)

      return browser
    } catch (error) {
      logger.error('OptimizedBrowserPoolMock', 'Failed to create browser', error)
      return null
    }
  }

  /**
   * Create a mock browser for testing
   */
  private createMockBrowser(): any {
    const EventEmitter = require('events')
    const mockBrowser = new EventEmitter()

    // Add browser methods
    Object.assign(mockBrowser, {
      newPage: async () => {
        return this.createMockPage()
      },
      close: async () => {},
      isConnected: () => true,
      disconnect: async () => {},
      version: async () => '1.0.0',
      userAgent: async () => 'Mock Browser',
      wsEndpoint: () => 'ws://mock-endpoint',
      process: () => ({ pid: 12345 }),
      pages: async () => [],
      createIncognitoBrowserContext: async () => ({
        newPage: async () => this.createMockPage(),
        close: async () => {},
        pages: async () => [],
        isIncognito: () => true,
      }),
    })

    return mockBrowser
  }

  /**
   * Create a mock page object
   */
  private createMockPage(): any {
    return {
      goto: async () => {},
      close: async () => {},
      evaluate: async () => {},
      setViewport: async () => {},
      setUserAgent: async () => {},
      setExtraHTTPHeaders: async () => {},
      setRequestInterception: async () => {},
      on: () => {},
      removeListener: () => {},
      target: () => ({
        createCDPSession: async () => ({
          send: async () => {}
        })
      }),
      browserContext: () => ({ id: 'mock-context' })
    }
  }

  /**
   * Create a new page instance
   */
  private async createPage(browserId?: string): Promise<MockPageInstance | null> {
    // Find browser with available capacity
    let targetBrowser: MockBrowserInstance | null = null

    if (browserId) {
      targetBrowser = this.browsers.get(browserId) || null
      if (targetBrowser && targetBrowser.pages.size >= this.config.maxPagesPerBrowser) {
        targetBrowser = null
      }
    } else {
      for (const browser of Array.from(this.browsers.values())) {
        if (browser.isHealthy && browser.pages.size < this.config.maxPagesPerBrowser) {
          targetBrowser = browser
          break
        }
      }
    }

    // Create new browser if needed
    if (!targetBrowser) {
      targetBrowser = await this.createBrowser()
    }

    if (!targetBrowser) {
      return null
    }

    try {
      const pageId = `page-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
      const mockPage = this.createMockPage()

      const initialMemory = this.getCurrentMemoryUsage()
      let memoryTrackerId: string | undefined

      try {
        memoryTrackerId = `mock-page-tracker-${pageId}`
        // Track this page for memory leak detection
        this.resourceTrackers.set(`page-${targetBrowser.id}-${Date.now()}`, memoryTrackerId)
      } catch (error) {
        logger.warn('OptimizedBrowserPoolMock', 'Failed to setup memory tracking for page', error)
      }

      const pageInstance: MockPageInstance = {
        id: pageId,
        page: mockPage,
        browserId: targetBrowser.id,
        contextId: 'mock-context',
        url: 'about:blank',
        isActive: false,
        createdAt: new Date(),
        lastUsed: new Date(),
        memoryUsage: 10 * 1024 * 1024 + (Math.random() * 5 * 1024 * 1024), // 10-15MB
        memoryTrackerId,
        eventListeners: new Map(),
        initialMemory,
      }

      // Setup page event listeners with cleanup tracking
      this.setupPageEventListeners(pageInstance)

      targetBrowser.pages.set(pageId, pageInstance)
      targetBrowser.memoryUsage += pageInstance.memoryUsage
      targetBrowser.lastUsed = new Date()

      if (this.config.simulateLatency) {
        await this.simulateDelay(100, 300) // Page creation time
      }

      logger.debug('OptimizedBrowserPoolMock', `Created page ${pageId} in browser ${targetBrowser.id}`)
      this.emit('page-created', { browser: targetBrowser, page: pageInstance })

      return pageInstance
    } catch (error) {
      logger.error('OptimizedBrowserPoolMock', 'Failed to create page', error)
      return null
    }
  }

  /**
   * Close a browser instance
   */
  private async closeBrowser(browserId: string): Promise<void> {
    const browser = this.browsers.get(browserId)
    if (!browser) return

    browser.isActive = false

    // Close all pages
    for (const page of browser.pages.values()) {
      if (page.isActive) {
        this.activePagesCount--
      }
    }

    this.browsers.delete(browserId)

    if (this.config.simulateLatency) {
      await this.simulateDelay(200, 500)
    }

    logger.debug('OptimizedBrowserPoolMock', `Closed browser ${browserId}`)
    this.emit('browser-closed', browser)
  }

  /**
   * Update memory statistics
   */
  private updateMemoryStats(): void {
    this.memoryStats.totalBrowsers = this.browsers.size
    this.memoryStats.totalPages = this.activePagesCount + this.availablePages.length
    this.memoryStats.totalContexts = Array.from(this.browsers.values())
      .reduce((total, browser) => total + browser.contexts.size, 0)

    const totalMemory = Array.from(this.browsers.values())
      .reduce((total, browser) => total + browser.memoryUsage, 0)

    this.memoryStats.totalMemoryUsage = totalMemory
    this.memoryStats.averageMemoryPerBrowser = this.browsers.size > 0 ? totalMemory / this.browsers.size : 0
    this.memoryStats.memoryLeakAlerts = this.memoryLeakAlerts

    // Simulate memory leak detection (less aggressive)
    if (this.config.simulateMemoryUsage && totalMemory > 1000 * 1024 * 1024) { // 1GB threshold (higher)
      this.memoryLeakAlerts++
      this.emit('memory-leak-detected', { totalMemory, threshold: 1000 * 1024 * 1024 })
    }
  }

  /**
   * Start health check interval
   */
  private startHealthCheck(): void {
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthCheck()
    }, 60000) // Check every minute
  }

  /**
   * Perform health check on browsers
   */
  private async performHealthCheck(): Promise<void> {
    const now = new Date()

    for (const [browserId, browser] of Array.from(this.browsers.entries())) {
      try {
        // Check browser age
        const age = now.getTime() - browser.createdAt.getTime()
        if (age > this.config.browserTimeout) {
          logger.info('OptimizedBrowserPoolMock', `Browser ${browserId} expired, recreating`)
          this.handleBrowserDisconnect(browserId)
          continue
        }

        // Update last used time if browser is active
        if (browser.pages.size > 0) {
          browser.lastUsed = now
        }
      } catch (error) {
        logger.error('OptimizedBrowserPoolMock', `Health check failed for browser ${browserId}`, error)
        this.handleBrowserDisconnect(browserId)
      }
    }

    // Clean up old available pages
    this.availablePages = this.availablePages.filter(pageInstance => {
      const age = now.getTime() - pageInstance.lastUsed.getTime()
      if (age > this.config.pageTimeout) {
        return false
      }
      return true
    })
  }

  /**
   * Start memory cleanup interval
   */
  private startMemoryCleanup(): void {
    this.memoryCleanupInterval = setInterval(async () => {
      await this.performMemoryCleanup()
    }, 300000) // Every 5 minutes
  }

  /**
   * Perform memory cleanup
   */
  private async performMemoryCleanup(): Promise<void> {
    try {
      logger.debug('OptimizedBrowserPoolMock', 'Performing memory cleanup')

      // Update memory stats
      this.updateMemoryStats()

      // Check for memory leaks
      await this.checkForMemoryLeaks()

      // Clean up stale resources
      await this.cleanupStaleResources()

      this.lastCleanupTime = new Date()
      this.memoryStats.lastCleanupTime = this.lastCleanupTime

      this.emit('memory-cleanup-complete', this.memoryStats)
    } catch (error) {
      logger.error('OptimizedBrowserPoolMock', 'Memory cleanup failed', error)
    }
  }

  /**
   * Check for memory leaks
   */
  private async checkForMemoryLeaks(): Promise<void> {
    for (const [browserId, browser] of this.browsers) {
      // Update browser memory tracking
      if (browser.memoryTrackerId) {
        const currentMemory = this.getCurrentMemoryUsage()
        browser.currentMemory = currentMemory

        // Check for significant memory increase (less aggressive)
        const memoryIncrease = currentMemory - browser.initialMemory
        if (memoryIncrease > 200 * 1024 * 1024) { // 200MB increase (higher threshold)
          logger.warn('OptimizedBrowserPoolMock', `Browser ${browserId} memory increase detected: ${this.formatBytes(memoryIncrease)}`)
          this.memoryLeakAlerts++

          // Emit memory leak alert
          this.emit('memory-leak-detected', {
            type: 'browser',
            description: `Browser ${browserId} has increased memory usage by ${this.formatBytes(memoryIncrease)}`,
            memoryIncrease,
            timestamp: new Date(),
            severity: memoryIncrease > 400 * 1024 * 1024 ? 'critical' : 'high',
          })
        }
      }
    }
  }

  /**
   * Clean up stale resources
   */
  private async cleanupStaleResources(): Promise<void> {
    const now = Date.now()

    // Clean up old available pages
    const stalePagesToRemove = this.availablePages.filter(page =>
      now - page.lastUsed.getTime() > this.config.pageTimeout
    )

    for (const stalePage of stalePagesToRemove) {
      await this.closePageWithCleanup(stalePage)
      const index = this.availablePages.indexOf(stalePage)
      if (index > -1) {
        this.availablePages.splice(index, 1)
      }
    }

    if (stalePagesToRemove.length > 0) {
      logger.debug('OptimizedBrowserPoolMock', `Cleaned up ${stalePagesToRemove.length} stale pages`)
    }
  }

  /**
   * Close browser with comprehensive cleanup
   */
  private async closeBrowserWithCleanup(browserInstance: MockBrowserInstance): Promise<void> {
    try {
      // Close all pages first
      const pageClosePromises = Array.from(browserInstance.pages.values()).map(async page => {
        try {
          await this.closePageWithCleanup(page)
        } catch (error) {
          logger.error('OptimizedBrowserPoolMock', 'Failed to close page during browser cleanup', error)
        }
      })
      await Promise.allSettled(pageClosePromises)

      // Close all contexts
      const contextClosePromises = Array.from(browserInstance.contexts).map(async context => {
        try {
          // Mock context close
        } catch (error) {
          logger.error('OptimizedBrowserPoolMock', 'Failed to close context during browser cleanup', error)
        }
      })
      await Promise.allSettled(contextClosePromises)

      // Remove event listeners
      this.cleanupBrowserEventListeners(browserInstance)

      // Stop memory tracking
      if (browserInstance.memoryTrackerId) {
        this.resourceTrackers.delete(browserInstance.id)
      }

      logger.debug('OptimizedBrowserPoolMock', `Browser ${browserInstance.id} closed with comprehensive cleanup`)
    } catch (error) {
      logger.error('OptimizedBrowserPoolMock', `Failed to close browser ${browserInstance.id} with cleanup`, error)
    }
  }

  /**
   * Close page with comprehensive cleanup
   */
  private async closePageWithCleanup(pageInstance: MockPageInstance): Promise<void> {
    try {
      // Clean up page event listeners
      await this.cleanupPageEventListeners(pageInstance)

      // Stop memory tracking
      if (pageInstance.memoryTrackerId) {
        const pageKey = `page-${pageInstance.browserId}-${pageInstance.createdAt.getTime()}`
        this.resourceTrackers.delete(pageKey)
      }

      // Remove from browser's page set
      const browser = this.browsers.get(pageInstance.browserId)
      if (browser) {
        browser.pages.delete(pageInstance.id)
      }

      logger.debug('OptimizedBrowserPoolMock', `Page closed with comprehensive cleanup`)
    } catch (error) {
      logger.error('OptimizedBrowserPoolMock', 'Failed to close page with cleanup', error)
    }
  }

  /**
   * Setup browser event listeners with cleanup tracking
   */
  private setupBrowserEventListeners(browserInstance: MockBrowserInstance): void {
    const disconnectHandler = () => {
      logger.warn('OptimizedBrowserPoolMock', `Browser ${browserInstance.id} disconnected`)
      this.handleBrowserDisconnect(browserInstance.id)
    }

    const targetChangedHandler = () => {
      // Mock memory tracking update
    }

    // Track event listeners for cleanup
    browserInstance.eventListeners.set('disconnected', disconnectHandler)
    browserInstance.eventListeners.set('targetchanged', targetChangedHandler)
  }

  /**
   * Setup page event listeners with cleanup tracking
   */
  private setupPageEventListeners(pageInstance: MockPageInstance): void {
    const errorHandler = (error: Error) => {
      logger.error('OptimizedBrowserPoolMock', `Page error in browser ${pageInstance.browserId}`, error)
      this.errorCounts.set(pageInstance.browserId, (this.errorCounts.get(pageInstance.browserId) || 0) + 1)
    }

    const responseHandler = () => {
      // Mock memory tracking update
    }

    // Track event listeners for cleanup
    pageInstance.eventListeners.set('pageerror', errorHandler)
    pageInstance.eventListeners.set('response', responseHandler)
  }

  /**
   * Cleanup browser event listeners
   */
  private cleanupBrowserEventListeners(browserInstance: MockBrowserInstance): void {
    browserInstance.eventListeners.clear()
  }

  /**
   * Cleanup page event listeners
   */
  private async cleanupPageEventListeners(pageInstance: MockPageInstance): Promise<void> {
    pageInstance.eventListeners.clear()
  }

  /**
   * Reset page state for reuse
   */
  private async resetPage(pageInstance: MockPageInstance): Promise<void> {
    try {
      // Mock page reset
      pageInstance.url = 'about:blank'
    } catch (error) {
      logger.warn('OptimizedBrowserPoolMock', 'Failed to reset page', error)
    }
  }

  /**
   * Get current memory usage
   */
  private getCurrentMemoryUsage(): number {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage().heapUsed
    }
    return this.baseMemoryUsage + Math.random() * 50 * 1024 * 1024 // Mock memory usage
  }

  /**
   * Format bytes to human readable format
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  /**
   * Simulate network/processing delay
   */
  private async simulateDelay(minMs: number, maxMs: number): Promise<void> {
    if (!this.config.simulateLatency) return
    const delay = Math.random() * (maxMs - minMs) + minMs
    return new Promise(resolve => setTimeout(resolve, delay))
  }
}

// Export factory function for easy mocking
export function createOptimizedBrowserPoolMock(config?: Partial<MockBrowserPoolConfig>): OptimizedBrowserPoolMock {
  return new OptimizedBrowserPoolMock(config)
}
