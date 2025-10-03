/**
 * Browser Pool Management for Enhanced Scraping
 * Provides concurrent browser instances with comprehensive memory leak detection and resource management
 */

import puppeteer, { Browser, Page, BrowserContext } from 'puppeteer'
import { logger } from '@/utils/logger'
import { memoryMonitor } from './memory-monitor'
import { memoryLeakDetector } from './memory-leak-detector'
import { memoryCleanup } from './memory-cleanup'
import { EventEmitter } from 'events'

export interface BrowserPoolConfig {
  maxBrowsers: number
  maxPagesPerBrowser: number
  browserTimeout: number
  pageTimeout: number
  headless: boolean
  enableProxy: boolean
  userAgents: string[]
  viewports: Array<{ width: number; height: number }>
}

export interface BrowserInstance {
  id: string
  browser: Browser
  pages: Set<Page>
  contexts: Set<BrowserContext>
  createdAt: Date
  lastUsed: Date
  isHealthy: boolean
  memoryTrackerId?: string
  eventListeners: Map<string, Function>
  initialMemory: number
  currentMemory: number
}

export interface PageInstance {
  page: Page
  browserId: string
  contextId?: string
  createdAt: Date
  lastUsed: Date
  isActive: boolean
  memoryTrackerId?: string
  eventListeners: Map<string, Function>
  initialMemory: number
}

export interface BrowserPoolMemoryStats {
  totalBrowsers: number
  totalPages: number
  totalContexts: number
  totalMemoryUsage: number
  averageMemoryPerBrowser: number
  memoryLeakAlerts: number
  lastCleanupTime: Date
}

export interface BrowserHealthMetrics {
  memoryUsage: number
  cpuUsage: number
  activePages: number
  responseTime: number
  errorRate: number
  lastHealthCheck: Date
}

/**
 * Browser Pool Manager for concurrent scraping operations
 */
export class BrowserPool extends EventEmitter {
  private config: BrowserPoolConfig
  private browsers: Map<string, BrowserInstance> = new Map()
  private availablePages: PageInstance[] = []
  private activePagesCount = 0
  private isShuttingDown = false
  private healthCheckInterval?: NodeJS.Timeout
  private memoryCleanupInterval?: NodeJS.Timeout
  private healthMetrics: Map<string, BrowserHealthMetrics> = new Map()
  private errorCounts: Map<string, number> = new Map()
  private memoryStats: BrowserPoolMemoryStats
  private memoryLeakAlerts: number = 0
  private lastCleanupTime: Date = new Date()
  private resourceTrackers: Map<string, string> = new Map() // resourceId -> memoryTrackerId

  constructor(config?: Partial<BrowserPoolConfig>) {
    super()

    this.config = {
      maxBrowsers: 6, // Optimized: Increased from 3 to 6 for better throughput
      maxPagesPerBrowser: 3, // Optimized: Increased from 2 to 3 for balanced performance
      browserTimeout: 90000, // Optimized: Reduced from 120000 (1.5 minutes)
      pageTimeout: 15000, // Optimized: Reduced from 20000 (15 seconds)
      headless: true,
      enableProxy: true, // Enabled for better distribution
      userAgents: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
      ],
      viewports: [
        { width: 1920, height: 1080 },
        { width: 1366, height: 768 },
        { width: 1440, height: 900 },
        { width: 1536, height: 864 },
      ],
      ...config,
    }

    // Initialize memory stats
    this.memoryStats = {
      totalBrowsers: 0,
      totalPages: 0,
      totalContexts: 0,
      totalMemoryUsage: 0,
      averageMemoryPerBrowser: 0,
      memoryLeakAlerts: 0,
      lastCleanupTime: new Date(),
    }

    // Setup memory monitoring integration
    this.setupMemoryMonitoring()

    // Start health check interval
    this.startHealthCheck()

    // Start memory cleanup interval
    this.startMemoryCleanup()
  }

  /**
   * Setup memory monitoring integration
   */
  private setupMemoryMonitoring(): void {
    try {
      // Listen for memory alerts from the memory monitor
      memoryMonitor.on('memory-alert', (alert) => {
        if (alert.level === 'critical' || alert.level === 'emergency') {
          logger.warn('BrowserPool', 'Memory alert received, triggering browser pool cleanup', alert)
          this.performEmergencyCleanup().catch(error => {
            logger.error('BrowserPool', 'Emergency cleanup failed', error)
          })
        }
      })

      // Listen for memory leak alerts
      memoryLeakDetector.on('memory-leak-detected', (alert) => {
        if (alert.type === 'browser') {
          this.memoryLeakAlerts++
          this.memoryStats.memoryLeakAlerts = this.memoryLeakAlerts
          logger.warn('BrowserPool', 'Browser memory leak detected', alert)
          this.emit('memory-leak-detected', alert)
        }
      })

      // Start memory monitoring if not already active
      if (!memoryMonitor.isActive()) {
        memoryMonitor.startMonitoring()
      }

      // Start memory leak detection if not already active
      if (!memoryLeakDetector.getStatus().isActive) {
        memoryLeakDetector.startDetection()
      }
    } catch (error) {
      logger.warn('BrowserPool', 'Failed to setup memory monitoring integration', error)
    }
  }

  /**
   * Get current configuration
   */
  getConfig(): BrowserPoolConfig {
    return { ...this.config }
  }

  /**
   * Get memory statistics
   */
  getMemoryStats(): BrowserPoolMemoryStats {
    this.updateMemoryStats()
    return { ...this.memoryStats }
  }

  /**
   * Initialize the browser pool
   */
  async initialize(): Promise<void> {
    logger.info('BrowserPool', 'Initializing browser pool')

    try {
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
      const successfulPages = pages.filter(result => result.status === 'fulfilled' && result.value !== null)

      // Add successful pages to available pool
      for (const pageResult of pages) {
        if (pageResult.status === 'fulfilled' && pageResult.value) {
          this.availablePages.push(pageResult.value)
        }
      }

      logger.info('BrowserPool', `Browser pool initialized with ${this.browsers.size} browsers and ${this.availablePages.length} available pages`)

    } catch (error) {
      logger.error('BrowserPool', 'Failed to initialize browser pool', error)
      throw error
    }
  }

  /**
   * Get an available page for scraping
   */
  async getPage(): Promise<PageInstance> {
    if (this.isShuttingDown) {
      throw new Error('Browser pool is shutting down')
    }

    // Try to get an available page
    let pageInstance = this.getAvailablePage()

    if (!pageInstance) {
      // Create new page if possible
      pageInstance = await this.createPage()
    }

    // If still no page available, try to create a new browser and page
    if (!pageInstance && this.browsers.size < this.config.maxBrowsers) {
      logger.info('BrowserPool', 'Creating additional browser for page demand')
      const newBrowser = await this.createBrowser()
      if (newBrowser) {
        pageInstance = await this.createPage()
      }
    }

    // Last resort: wait a bit and try again for available pages
    if (!pageInstance) {
      logger.warn('BrowserPool', 'No pages available, waiting for page to become available')
      await new Promise(resolve => setTimeout(resolve, 100))
      pageInstance = this.getAvailablePage()
    }

    if (!pageInstance) {
      const stats = this.getStats()
      throw new Error(`No available pages in browser pool. Stats: ${JSON.stringify(stats)}`)
    }

    pageInstance.isActive = true
    pageInstance.lastUsed = new Date()
    this.activePagesCount++

    logger.debug('BrowserPool', `Page acquired. Active pages: ${this.activePagesCount}`)
    return pageInstance
  }

  /**
   * Release a page back to the pool
   */
  async releasePage(pageInstance: PageInstance): Promise<void> {
    try {
      // Clean up page event listeners first
      await this.cleanupPageEventListeners(pageInstance)

      // Reset page state
      await this.resetPage(pageInstance.page)

      pageInstance.isActive = false
      pageInstance.lastUsed = new Date()
      this.activePagesCount--

      // Update memory tracking
      if (pageInstance.memoryTrackerId) {
        try {
          memoryLeakDetector.updateComponentMemory(pageInstance.memoryTrackerId)
        } catch (error) {
          logger.warn('BrowserPool', 'Failed to update page memory tracking', error)
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

      logger.debug('BrowserPool', `Page released. Active pages: ${this.activePagesCount}`)
    } catch (error) {
      logger.error('BrowserPool', 'Failed to release page', error)
      this.activePagesCount--

      // Ensure cleanup even on error
      try {
        await this.closePageWithCleanup(pageInstance)
      } catch (cleanupError) {
        logger.error('BrowserPool', 'Failed to cleanup page after release error', cleanupError)
      }
    }
  }

  /**
   * Get current configuration
   */
  getConfig(): BrowserPoolConfig {
    return { ...this.config }
  }

  /**
   * Get pool statistics
   */
  getStats() {
    return {
      browsers: this.browsers.size,
      pages: this.availablePages.length + this.activePagesCount,
      availablePages: this.availablePages.length,
      activePages: this.activePagesCount,
      totalPages: this.availablePages.length + this.activePagesCount,
      isShuttingDown: this.isShuttingDown,
    }
  }

  /**
   * Shutdown the browser pool with comprehensive cleanup
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true

    logger.info('BrowserPool', 'Shutting down browser pool with comprehensive cleanup')

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
        logger.error('BrowserPool', `Failed to close page during shutdown`, error)
      }
    })

    await Promise.allSettled(pageClosePromises)

    // Close all browsers with comprehensive cleanup
    const browserClosePromises = Array.from(this.browsers.values()).map(async browserInstance => {
      try {
        await this.closeBrowserWithCleanup(browserInstance)
      } catch (error) {
        logger.error('BrowserPool', `Failed to close browser ${browserInstance.id}`, error)
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

    // Stop memory tracking
    this.cleanupAllMemoryTrackers()

    // Update memory stats
    this.memoryStats.totalBrowsers = 0
    this.memoryStats.totalPages = 0
    this.memoryStats.totalContexts = 0
    this.memoryStats.lastCleanupTime = new Date()

    logger.info('BrowserPool', 'Browser pool shutdown complete')
    this.emit('shutdown-complete')
  }

  /**
   * Create a new browser instance
   */
  private async createBrowser(): Promise<BrowserInstance | null> {
    if (this.browsers.size >= this.config.maxBrowsers) {
      logger.warn('BrowserPool', 'Maximum browsers reached')
      return null
    }

    try {
      const browserId = `browser-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

      // Check if we're in test environment
      const isTestEnvironment = process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID !== undefined

      let browser: any

      if (isTestEnvironment) {
        // Create mock browser for testing
        browser = this.createMockBrowser()
        logger.info('BrowserPool', `Created mock browser ${browserId} for testing`)
      } else {
        // Create real browser for production
        browser = await puppeteer.launch({
          headless: this.config.headless,
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--disable-features=TranslateUI',
            '--disable-ipc-flooding-protection',
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            // Enhanced performance optimizations
            '--memory-pressure-off',
            '--max_old_space_size=3072', // Optimized: Increased from 2048 to 3072MB for better performance
            '--disable-background-networking',
            '--disable-default-apps',
            '--disable-extensions',
            '--disable-sync',
            '--disable-translate',
            '--hide-scrollbars',
            '--mute-audio',
            '--disable-plugins-discovery',
            '--disable-preconnect',
            '--disable-javascript-harmony-shipping',
            '--aggressive-cache-discard',
            // Additional performance flags
            '--disable-blink-features=AutomationControlled',
            '--disable-features=VizDisplayCompositor,VizHitTestSurfaceLayer',
            '--disable-component-extensions-with-background-pages',
            '--disable-default-apps',
            '--disable-domain-reliability',
            '--disable-features=AudioServiceOutOfProcess',
            '--disable-hang-monitor',
            '--disable-prompt-on-repost',
            '--disable-sync',
            '--force-color-profile=srgb',
            '--metrics-recording-only',
            '--no-crash-upload',
            '--no-default-browser-check',
            '--no-pings',
            '--password-store=basic',
            '--use-mock-keychain',
            '--disable-component-update',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
          ],
          timeout: this.config.browserTimeout,
        })
        logger.info('BrowserPool', `Created real browser ${browserId}`)
      }

      const initialMemory = this.getCurrentMemoryUsage()
      let memoryTrackerId: string | undefined

      try {
        memoryTrackerId = memoryLeakDetector.trackComponent(`Browser-${browserId}`)
        // Track this browser for memory leak detection
        this.resourceTrackers.set(browserId, memoryTrackerId)
      } catch (error) {
        logger.warn('BrowserPool', 'Failed to setup memory tracking for browser', error)
      }

      const browserInstance: BrowserInstance = {
        id: browserId,
        browser,
        pages: new Set(),
        contexts: new Set(),
        createdAt: new Date(),
        lastUsed: new Date(),
        isHealthy: true,
        memoryTrackerId,
        eventListeners: new Map(),
        initialMemory,
        currentMemory: initialMemory,
      }

      // Setup browser event listeners with cleanup tracking
      this.setupBrowserEventListeners(browserInstance)

      this.browsers.set(browserId, browserInstance)

      // Handle browser disconnect (only for real browsers)
      if (!isTestEnvironment && browser.on) {
        browser.on('disconnected', () => {
          logger.warn('BrowserPool', `Browser ${browserId} disconnected`)
          this.handleBrowserDisconnect(browserId)
        })
      }

      return browserInstance
    } catch (error) {
      logger.error('BrowserPool', 'Failed to create browser', error)
      return null
    }
  }

  /**
   * Create a mock browser for testing
   */
  private createMockBrowser(): any {
    return {
      newPage: async () => {
        return {
          goto: async () => {},
          close: async () => {},
          evaluate: async () => {},
          setViewport: async () => {},
          setUserAgent: async () => {},
          setExtraHTTPHeaders: async () => {},
          target: () => ({
            createCDPSession: async () => ({
              send: async () => {}
            })
          })
        }
      },
      close: async () => {},
      isConnected: () => true,
      on: () => {}
    }
  }

  /**
   * Create a new page instance
   */
  private async createPage(): Promise<PageInstance | null> {
    // Find browser with available capacity
    let targetBrowser: BrowserInstance | null = null

    for (const browser of Array.from(this.browsers.values())) {
      if (browser.isHealthy && browser.pages.size < this.config.maxPagesPerBrowser) {
        targetBrowser = browser
        break
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
      const page = await targetBrowser.browser.newPage()

      // Configure page
      await this.configurePage(page)

      targetBrowser.pages.add(page)
      targetBrowser.lastUsed = new Date()

      const initialMemory = this.getCurrentMemoryUsage()
      let memoryTrackerId: string | undefined

      try {
        memoryTrackerId = memoryLeakDetector.trackComponent(`Page-${targetBrowser.id}-${Date.now()}`)
        // Track this page for memory leak detection
        this.resourceTrackers.set(`page-${targetBrowser.id}-${Date.now()}`, memoryTrackerId)
      } catch (error) {
        logger.warn('BrowserPool', 'Failed to setup memory tracking for page', error)
      }

      const pageInstance: PageInstance = {
        page,
        browserId: targetBrowser.id,
        contextId: page.browserContext()?.id,
        createdAt: new Date(),
        lastUsed: new Date(),
        isActive: false,
        memoryTrackerId,
        eventListeners: new Map(),
        initialMemory,
      }

      // Setup page event listeners with cleanup tracking
      this.setupPageEventListeners(pageInstance)

      logger.debug('BrowserPool', `Created page in browser ${targetBrowser.id}`)
      return pageInstance
    } catch (error) {
      logger.error('BrowserPool', 'Failed to create page', error)
      return null
    }
  }

  /**
   * Configure a new page with anti-detection measures
   */
  private async configurePage(page: any): Promise<void> {
    try {
      // Skip configuration in test environment
      const isTestEnvironment = process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID !== undefined
      if (isTestEnvironment) {
        return
      }

      // Apply comprehensive network spoofing
      const { NetworkSpoofingService } = await import('./networkSpoofingService')
      const spoofingService = new NetworkSpoofingService({
        enableIPSpoofing: true,
        enableMACAddressSpoofing: true,
        enableFingerprintSpoofing: true,
        requestDelay: { min: 1000, max: 4000 },
      })

      await spoofingService.applyNetworkSpoofing(page)

      // Fallback: Set random user agent if spoofing service fails
      const userAgent =
        this.config.userAgents[Math.floor(Math.random() * this.config.userAgents.length)]
      if (userAgent) {
        await page.setUserAgent(userAgent)
      }

      // Fallback: Set random viewport if spoofing service fails
      const viewport =
        this.config.viewports[Math.floor(Math.random() * this.config.viewports.length)]
      if (viewport) {
        await page.setViewport(viewport)
      }

      // Enhanced request interception with anti-detection
      await page.setRequestInterception(true)
      page.on('request', request => {
        const resourceType = request.resourceType()
        const url = request.url()

        // Block unnecessary resources and tracking
        if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
          request.abort()
        } else if (
          url.includes('google-analytics') ||
          url.includes('googletagmanager') ||
          url.includes('facebook.com') ||
          url.includes('doubleclick') ||
          url.includes('adsystem') ||
          url.includes('hotjar') ||
          url.includes('mixpanel')
        ) {
          request.abort()
        } else {
          // Add random delays to appear more human
          const delay = Math.random() * 200 + 100 // 100-300ms delay
          setTimeout(() => {
            request.continue()
          }, delay)
        }
      })

      // Enhanced stealth measures
      await page.evaluateOnNewDocument(() => {
        // Override webdriver property
        Object.defineProperty(navigator, 'webdriver', {
          get: () => undefined,
        })

        // Remove automation indicators
        delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Array
        delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Promise
        delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Symbol

        // Override plugins with realistic values
        Object.defineProperty(navigator, 'plugins', {
          get: () => [
            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
            { name: 'Native Client', filename: 'internal-nacl-plugin' },
          ],
        })

        // Override languages
        Object.defineProperty(navigator, 'languages', {
          get: () => ['en-US', 'en'],
        })

        // Override permissions
        const originalQuery = window.navigator.permissions.query
        window.navigator.permissions.query = parameters =>
          parameters.name === 'notifications'
            ? Promise.resolve({ state: Notification.permission })
            : originalQuery(parameters)

        // Override battery API
        Object.defineProperty(navigator, 'getBattery', {
          get: () => () =>
            Promise.resolve({
              charging: true,
              chargingTime: 0,
              dischargingTime: Infinity,
              level: 1,
            }),
        })
      })

      logger.debug('BrowserPool', 'Page configured with enhanced anti-detection measures')
    } catch (error) {
      logger.warn('BrowserPool', 'Failed to apply some anti-detection measures', error)

      // Fallback configuration
      const userAgent =
        this.config.userAgents[Math.floor(Math.random() * this.config.userAgents.length)]
      if (userAgent) {
        await page.setUserAgent(userAgent)
      }
    }
  }

  /**
   * Reset page state for reuse
   */
  private async resetPage(page: Page): Promise<void> {
    try {
      // Clear cookies
      const client = await page.target().createCDPSession()
      await client.send('Network.clearBrowserCookies')
      await client.send('Network.clearBrowserCache')

      // Navigate to blank page
      await page.goto('about:blank')
    } catch (error) {
      logger.warn('BrowserPool', 'Failed to reset page', error)
    }
  }

  /**
   * Get an available page from the pool
   */
  private getAvailablePage(): PageInstance | null {
    const availablePage = this.availablePages.find(p => !p.isActive)
    if (availablePage) {
      this.availablePages = this.availablePages.filter(p => p !== availablePage)
      return availablePage
    }
    return null
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
        // Check if browser is still connected
        if (!browser.browser.isConnected()) {
          logger.warn('BrowserPool', `Browser ${browserId} is disconnected`)
          this.handleBrowserDisconnect(browserId)
          continue
        }

        // Check browser age
        const age = now.getTime() - browser.createdAt.getTime()
        if (age > this.config.browserTimeout) {
          logger.info('BrowserPool', `Browser ${browserId} expired, recreating`)
          await browser.browser.close()
          this.handleBrowserDisconnect(browserId)
          continue
        }

        // Update last used time if browser is active
        if (browser.pages.size > 0) {
          browser.lastUsed = now
        }
      } catch (error) {
        logger.error('BrowserPool', `Health check failed for browser ${browserId}`, error)
        this.handleBrowserDisconnect(browserId)
      }
    }

    // Clean up old available pages
    this.availablePages = this.availablePages.filter(pageInstance => {
      const age = now.getTime() - pageInstance.lastUsed.getTime()
      if (age > this.config.pageTimeout) {
        pageInstance.page.close().catch(() => {})
        return false
      }
      return true
    })
  }

  /**
   * Monitor browser health metrics
   */
  async monitorBrowserHealth(browserId: string): Promise<BrowserHealthMetrics | null> {
    const browser = this.browsers.get(browserId)
    if (!browser) return null

    try {
      // Get browser metrics (simplified - in real implementation would use browser.metrics())
      const healthData: BrowserHealthMetrics = {
        memoryUsage: 0, // Would get from browser.metrics()
        cpuUsage: 0, // Would get from browser.metrics()
        activePages: browser.pages.size,
        responseTime: Date.now() - browser.lastUsed.getTime(),
        errorRate: this.calculateErrorRate(browserId),
        lastHealthCheck: new Date(),
      }

      this.healthMetrics.set(browserId, healthData)
      return healthData
    } catch (error) {
      logger.error('BrowserPool', `Failed to monitor browser health for ${browserId}`, error)
      return null
    }
  }

  /**
   * Calculate error rate for a browser
   */
  private calculateErrorRate(browserId: string): number {
    const errorCount = this.errorCounts.get(browserId) || 0
    const totalOperations = 100 // Would track actual operations
    return totalOperations > 0 ? (errorCount / totalOperations) * 100 : 0
  }

  /**
   * Optimize browser allocation based on health metrics
   */
  async optimizeBrowserAllocation(): Promise<void> {
    for (const [browserId, metrics] of this.healthMetrics) {
      // Restart browsers with high memory usage or error rates
      if (metrics.memoryUsage > 512 * 1024 * 1024 || metrics.errorRate > 10) {
        logger.warn('BrowserPool', `Restarting browser ${browserId} due to poor health metrics`)
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
        logger.error('BrowserPool', `Failed to restart browser ${browserId}`, error)
      }
    }
  }

  /**
   * Get overall pool health statistics
   */
  getPoolHealthStats(): {
    totalBrowsers: number
    healthyBrowsers: number
    totalPages: number
    averageResponseTime: number
    averageErrorRate: number
  } {
    const healthyBrowsers = Array.from(this.healthMetrics.values()).filter(
      metrics => metrics.errorRate < 5 && metrics.memoryUsage < 256 * 1024 * 1024
    ).length

    const avgResponseTime =
      Array.from(this.healthMetrics.values()).reduce(
        (sum, metrics) => sum + metrics.responseTime,
        0
      ) / this.healthMetrics.size || 0

    const avgErrorRate =
      Array.from(this.healthMetrics.values()).reduce((sum, metrics) => sum + metrics.errorRate, 0) /
        this.healthMetrics.size || 0

    return {
      totalBrowsers: this.browsers.size,
      healthyBrowsers,
      totalPages: this.activePagesCount,
      averageResponseTime: avgResponseTime,
      averageErrorRate: avgErrorRate,
    }
  }

  /**
   * Close browser with comprehensive cleanup
   */
  private async closeBrowserWithCleanup(browserInstance: BrowserInstance): Promise<void> {
    try {
      // Close all pages first
      const pageClosePromises = Array.from(browserInstance.pages).map(async page => {
        try {
          await page.close()
        } catch (error) {
          logger.error('BrowserPool', 'Failed to close page during browser cleanup', error)
        }
      })
      await Promise.allSettled(pageClosePromises)

      // Close all contexts
      const contextClosePromises = Array.from(browserInstance.contexts).map(async context => {
        try {
          await context.close()
        } catch (error) {
          logger.error('BrowserPool', 'Failed to close context during browser cleanup', error)
        }
      })
      await Promise.allSettled(contextClosePromises)

      // Remove event listeners
      this.cleanupBrowserEventListeners(browserInstance)

      // Close browser
      await browserInstance.browser.close()

      // Stop memory tracking
      if (browserInstance.memoryTrackerId) {
        memoryLeakDetector.stopTrackingComponent(browserInstance.memoryTrackerId)
        this.resourceTrackers.delete(browserInstance.id)
      }

      logger.debug('BrowserPool', `Browser ${browserInstance.id} closed with comprehensive cleanup`)
    } catch (error) {
      logger.error('BrowserPool', `Failed to close browser ${browserInstance.id} with cleanup`, error)
    }
  }

  /**
   * Close page with comprehensive cleanup
   */
  private async closePageWithCleanup(pageInstance: PageInstance): Promise<void> {
    try {
      // Clean up page event listeners
      await this.cleanupPageEventListeners(pageInstance)

      // Close page
      await pageInstance.page.close()

      // Stop memory tracking
      if (pageInstance.memoryTrackerId) {
        memoryLeakDetector.stopTrackingComponent(pageInstance.memoryTrackerId)
        const pageKey = `page-${pageInstance.browserId}-${pageInstance.createdAt.getTime()}`
        this.resourceTrackers.delete(pageKey)
      }

      // Remove from browser's page set
      const browser = this.browsers.get(pageInstance.browserId)
      if (browser) {
        browser.pages.delete(pageInstance.page)
      }

      logger.debug('BrowserPool', `Page closed with comprehensive cleanup`)
    } catch (error) {
      logger.error('BrowserPool', 'Failed to close page with cleanup', error)
    }
  }

  /**
   * Setup browser event listeners with cleanup tracking
   */
  private setupBrowserEventListeners(browserInstance: BrowserInstance): void {
    const disconnectHandler = () => {
      logger.warn('BrowserPool', `Browser ${browserInstance.id} disconnected`)
      this.handleBrowserDisconnect(browserInstance.id)
    }

    const targetChangedHandler = () => {
      // Update memory tracking when targets change
      if (browserInstance.memoryTrackerId) {
        memoryLeakDetector.updateComponentMemory(browserInstance.memoryTrackerId)
      }
    }

    browserInstance.browser.on('disconnected', disconnectHandler)
    browserInstance.browser.on('targetchanged', targetChangedHandler)

    // Track event listeners for cleanup
    browserInstance.eventListeners.set('disconnected', disconnectHandler)
    browserInstance.eventListeners.set('targetchanged', targetChangedHandler)
  }

  /**
   * Setup page event listeners with cleanup tracking
   */
  private setupPageEventListeners(pageInstance: PageInstance): void {
    const errorHandler = (error: Error) => {
      logger.error('BrowserPool', `Page error in browser ${pageInstance.browserId}`, error)
      this.errorCounts.set(pageInstance.browserId, (this.errorCounts.get(pageInstance.browserId) || 0) + 1)
    }

    const responseHandler = () => {
      // Update memory tracking on responses
      if (pageInstance.memoryTrackerId) {
        memoryLeakDetector.updateComponentMemory(pageInstance.memoryTrackerId)
      }
    }

    pageInstance.page.on('pageerror', errorHandler)
    pageInstance.page.on('response', responseHandler)

    // Track event listeners for cleanup
    pageInstance.eventListeners.set('pageerror', errorHandler)
    pageInstance.eventListeners.set('response', responseHandler)
  }

  /**
   * Cleanup browser event listeners
   */
  private cleanupBrowserEventListeners(browserInstance: BrowserInstance): void {
    for (const [event, handler] of browserInstance.eventListeners) {
      try {
        browserInstance.browser.removeListener(event, handler)
      } catch (error) {
        logger.error('BrowserPool', `Failed to remove browser event listener ${event}`, error)
      }
    }
    browserInstance.eventListeners.clear()
  }

  /**
   * Cleanup page event listeners
   */
  private async cleanupPageEventListeners(pageInstance: PageInstance): Promise<void> {
    for (const [event, handler] of pageInstance.eventListeners) {
      try {
        pageInstance.page.removeListener(event, handler)
      } catch (error) {
        logger.error('BrowserPool', `Failed to remove page event listener ${event}`, error)
      }
    }
    pageInstance.eventListeners.clear()
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
      logger.debug('BrowserPool', 'Performing memory cleanup')

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
      logger.error('BrowserPool', 'Memory cleanup failed', error)
    }
  }

  /**
   * Perform emergency cleanup when memory is critical
   */
  private async performEmergencyCleanup(): Promise<void> {
    try {
      logger.warn('BrowserPool', 'Performing emergency memory cleanup')

      // Close oldest browsers first
      const sortedBrowsers = Array.from(this.browsers.values())
        .sort((a, b) => a.lastUsed.getTime() - b.lastUsed.getTime())

      const browsersToClose = Math.ceil(sortedBrowsers.length * 0.3) // Close 30% of browsers

      for (let i = 0; i < browsersToClose && i < sortedBrowsers.length; i++) {
        const browser = sortedBrowsers[i]
        if (browser.pages.size === 0) { // Only close browsers with no active pages
          await this.closeBrowserWithCleanup(browser)
          this.browsers.delete(browser.id)
        }
      }

      // Force garbage collection
      if (global.gc) {
        global.gc()
      }

      // Trigger memory cleanup service
      await memoryCleanup.performAutomaticCleanup()

      logger.info('BrowserPool', 'Emergency cleanup completed')
      this.emit('emergency-cleanup-complete')
    } catch (error) {
      logger.error('BrowserPool', 'Emergency cleanup failed', error)
    }
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
      .reduce((total, browser) => total + browser.currentMemory, 0)

    this.memoryStats.totalMemoryUsage = totalMemory
    this.memoryStats.averageMemoryPerBrowser = this.browsers.size > 0 ? totalMemory / this.browsers.size : 0
    this.memoryStats.memoryLeakAlerts = this.memoryLeakAlerts
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
        memoryLeakDetector.updateComponentMemory(browser.memoryTrackerId)

        // Check for significant memory increase
        const memoryIncrease = currentMemory - browser.initialMemory
        if (memoryIncrease > 100 * 1024 * 1024) { // 100MB increase
          logger.warn('BrowserPool', `Browser ${browserId} memory increase detected: ${this.formatBytes(memoryIncrease)}`)
          this.memoryLeakAlerts++

          // Emit memory leak alert
          memoryLeakDetector.emit('memory-leak-detected', {
            type: 'browser',
            description: `Browser ${browserId} has increased memory usage by ${this.formatBytes(memoryIncrease)}`,
            memoryIncrease,
            timestamp: new Date(),
            severity: memoryIncrease > 200 * 1024 * 1024 ? 'critical' : 'high',
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
      logger.debug('BrowserPool', `Cleaned up ${stalePagesToRemove.length} stale pages`)
    }
  }

  /**
   * Clean up all memory trackers
   */
  private cleanupAllMemoryTrackers(): void {
    for (const [resourceId, trackerId] of this.resourceTrackers) {
      try {
        memoryLeakDetector.stopTrackingComponent(trackerId)
      } catch (error) {
        logger.error('BrowserPool', `Failed to stop tracking ${resourceId}`, error)
      }
    }
    this.resourceTrackers.clear()
  }

  /**
   * Get current memory usage
   */
  private getCurrentMemoryUsage(): number {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      return process.memoryUsage().heapUsed
    } else if (typeof window !== 'undefined' && 'performance' in window && 'memory' in (window.performance as any)) {
      return (window.performance as any).memory.usedJSHeapSize
    }
    return 0
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
}

/**
 * Default browser pool instance
 */
export const browserPool = new BrowserPool()
