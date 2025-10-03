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
  simulateLatency: boolean
  simulateMemoryUsage: boolean
  simulateErrors: boolean
  errorRate: number // percentage
}

export interface MockPageInstance {
  id: string
  url: string
  isActive: boolean
  createdAt: Date
  lastUsed: Date
  memoryUsage: number
}

export interface MockBrowserInstance {
  id: string
  pages: Map<string, MockPageInstance>
  isActive: boolean
  createdAt: Date
  memoryUsage: number
}

export interface MockBrowserPoolStats {
  totalBrowsers: number
  totalPages: number
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

  constructor(config: Partial<MockBrowserPoolConfig> = {}) {
    super()
    
    this.config = {
      maxBrowsers: 4,
      maxPagesPerBrowser: 3,
      browserTimeout: 60000,
      pageTimeout: 30000,
      headless: true,
      simulateLatency: true,
      simulateMemoryUsage: true,
      simulateErrors: false,
      errorRate: 5,
      ...config
    }

    this.memoryStats = {
      totalBrowsers: 0,
      totalPages: 0,
      totalMemoryUsage: 0,
      averageMemoryPerBrowser: 0,
      memoryLeakAlerts: 0,
      lastCleanupTime: new Date()
    }

    logger.debug('OptimizedBrowserPoolMock', 'Initialized with config', this.config)
  }

  /**
   * Initialize the browser pool
   */
  async initialize(): Promise<void> {
    if (this.config.simulateLatency) {
      await this.simulateDelay(100, 300)
    }

    logger.info('OptimizedBrowserPoolMock', 'Browser pool initialized')
    this.emit('initialized')
  }

  /**
   * Shutdown the browser pool
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true

    // Close all browsers
    for (const [browserId, browser] of this.browsers) {
      await this.closeBrowser(browserId)
    }

    this.browsers.clear()
    this.availablePages = []
    this.activePagesCount = 0

    if (this.config.simulateLatency) {
      await this.simulateDelay(50, 150)
    }

    logger.info('OptimizedBrowserPoolMock', 'Browser pool shutdown complete')
    this.emit('shutdown')
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

    // Check if we have available pages
    if (this.availablePages.length > 0) {
      const page = this.availablePages.pop()!
      page.isActive = true
      page.lastUsed = new Date()
      this.activePagesCount++

      if (this.config.simulateLatency) {
        await this.simulateDelay(10, 50)
      }

      return page
    }

    // Create new browser if needed
    if (this.browsers.size < this.config.maxBrowsers) {
      const browser = await this.createBrowser()
      const page = await this.createPage(browser.id)
      
      this.activePagesCount++
      this.updateMemoryStats()

      return page
    }

    // Find browser with available capacity
    for (const [browserId, browser] of this.browsers) {
      if (browser.pages.size < this.config.maxPagesPerBrowser) {
        const page = await this.createPage(browserId)
        this.activePagesCount++
        this.updateMemoryStats()
        return page
      }
    }

    throw new Error('No available browser capacity')
  }

  /**
   * Release a page back to the pool
   */
  async releasePage(page: MockPageInstance): Promise<void> {
    page.isActive = false
    page.lastUsed = new Date()
    
    // Simulate memory cleanup
    if (this.config.simulateMemoryUsage) {
      page.memoryUsage = Math.max(page.memoryUsage * 0.8, 10 * 1024 * 1024) // Reduce by 20%
    }

    this.availablePages.push(page)
    this.activePagesCount--

    if (this.config.simulateLatency) {
      await this.simulateDelay(5, 20)
    }

    this.updateMemoryStats()
    this.emit('page-released', page)
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

    // Simulate memory increase from navigation
    if (this.config.simulateMemoryUsage) {
      page.memoryUsage += Math.random() * 5 * 1024 * 1024 // 0-5MB increase
    }

    if (this.config.simulateLatency) {
      await this.simulateDelay(200, 1000) // Simulate page load time
    }

    this.updateMemoryStats()
    this.emit('navigation', { page, url })
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
  private async createBrowser(): Promise<MockBrowserInstance> {
    const browserId = `browser-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    const browser: MockBrowserInstance = {
      id: browserId,
      pages: new Map(),
      isActive: true,
      createdAt: new Date(),
      memoryUsage: this.baseMemoryUsage + (Math.random() * 20 * 1024 * 1024) // Base + 0-20MB
    }

    this.browsers.set(browserId, browser)

    if (this.config.simulateLatency) {
      await this.simulateDelay(500, 1500) // Browser startup time
    }

    logger.debug('OptimizedBrowserPoolMock', `Created browser ${browserId}`)
    this.emit('browser-created', browser)

    return browser
  }

  /**
   * Create a new page instance
   */
  private async createPage(browserId: string): Promise<MockPageInstance> {
    const browser = this.browsers.get(browserId)
    if (!browser) {
      throw new Error(`Browser ${browserId} not found`)
    }

    const pageId = `page-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    
    const page: MockPageInstance = {
      id: pageId,
      url: 'about:blank',
      isActive: true,
      createdAt: new Date(),
      lastUsed: new Date(),
      memoryUsage: 15 * 1024 * 1024 + (Math.random() * 10 * 1024 * 1024) // 15-25MB
    }

    browser.pages.set(pageId, page)
    browser.memoryUsage += page.memoryUsage

    if (this.config.simulateLatency) {
      await this.simulateDelay(100, 300) // Page creation time
    }

    logger.debug('OptimizedBrowserPoolMock', `Created page ${pageId} in browser ${browserId}`)
    this.emit('page-created', { browser, page })

    return page
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

    const totalMemory = Array.from(this.browsers.values())
      .reduce((total, browser) => total + browser.memoryUsage, 0)

    this.memoryStats.totalMemoryUsage = totalMemory
    this.memoryStats.averageMemoryPerBrowser = this.browsers.size > 0 ? totalMemory / this.browsers.size : 0
    this.memoryStats.memoryLeakAlerts = this.memoryLeakAlerts

    // Simulate memory leak detection
    if (this.config.simulateMemoryUsage && totalMemory > 500 * 1024 * 1024) { // 500MB threshold
      this.memoryLeakAlerts++
      this.emit('memory-leak-detected', { totalMemory, threshold: 500 * 1024 * 1024 })
    }
  }

  /**
   * Simulate network/processing delay
   */
  private async simulateDelay(minMs: number, maxMs: number): Promise<void> {
    const delay = Math.random() * (maxMs - minMs) + minMs
    return new Promise(resolve => setTimeout(resolve, delay))
  }
}

// Export factory function for easy mocking
export function createOptimizedBrowserPoolMock(config?: Partial<MockBrowserPoolConfig>): OptimizedBrowserPoolMock {
  return new OptimizedBrowserPoolMock(config)
}
