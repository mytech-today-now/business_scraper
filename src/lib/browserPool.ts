/**
 * Browser Pool Management for Enhanced Scraping
 * Provides concurrent browser instances with resource management
 */

import puppeteer, { Browser, Page } from 'puppeteer'
import { logger } from '@/utils/logger'


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
  createdAt: Date
  lastUsed: Date
  isHealthy: boolean
}

export interface PageInstance {
  page: Page
  browserId: string
  createdAt: Date
  lastUsed: Date
  isActive: boolean
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
export class BrowserPool {
  private config: BrowserPoolConfig
  private browsers: Map<string, BrowserInstance> = new Map()
  private availablePages: PageInstance[] = []
  private activePagesCount = 0
  private isShuttingDown = false
  private healthCheckInterval?: NodeJS.Timeout
  private healthMetrics: Map<string, BrowserHealthMetrics> = new Map()
  private errorCounts: Map<string, number> = new Map()

  constructor(config?: Partial<BrowserPoolConfig>) {
    this.config = {
      maxBrowsers: 6,              // Increased from 3 to 6 for better concurrency
      maxPagesPerBrowser: 4,       // Reduced from 5 to 4 to balance load
      browserTimeout: 180000,      // Reduced from 300000 (3 minutes)
      pageTimeout: 30000,          // Reduced from 60000 (30 seconds)
      headless: true,
      enableProxy: true,           // Enabled for better distribution
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

    // Start health check interval
    this.startHealthCheck()
  }

  /**
   * Initialize the browser pool
   */
  async initialize(): Promise<void> {
    logger.info('BrowserPool', 'Initializing browser pool')
    
    // Create initial browser instance
    await this.createBrowser()
    
    logger.info('BrowserPool', `Browser pool initialized with ${this.browsers.size} browsers`)
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

    if (!pageInstance) {
      throw new Error('No available pages in browser pool')
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
      // Reset page state
      await this.resetPage(pageInstance.page)
      
      pageInstance.isActive = false
      pageInstance.lastUsed = new Date()
      this.activePagesCount--

      // Add back to available pages if browser is still healthy
      const browser = this.browsers.get(pageInstance.browserId)
      if (browser?.isHealthy) {
        this.availablePages.push(pageInstance)
      } else {
        await pageInstance.page.close()
      }

      logger.debug('BrowserPool', `Page released. Active pages: ${this.activePagesCount}`)
    } catch (error) {
      logger.error('BrowserPool', 'Failed to release page', error)
      this.activePagesCount--
    }
  }

  /**
   * Get pool statistics
   */
  getStats() {
    return {
      browsers: this.browsers.size,
      availablePages: this.availablePages.length,
      activePages: this.activePagesCount,
      totalPages: this.availablePages.length + this.activePagesCount,
      isShuttingDown: this.isShuttingDown,
    }
  }

  /**
   * Shutdown the browser pool
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true
    
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval)
    }

    logger.info('BrowserPool', 'Shutting down browser pool')

    // Close all browsers
    const closePromises = Array.from(this.browsers.values()).map(async (browserInstance) => {
      try {
        await browserInstance.browser.close()
      } catch (error) {
        logger.error('BrowserPool', `Failed to close browser ${browserInstance.id}`, error)
      }
    })

    await Promise.allSettled(closePromises)
    
    this.browsers.clear()
    this.availablePages = []
    this.activePagesCount = 0

    logger.info('BrowserPool', 'Browser pool shutdown complete')
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
      
      const browser = await puppeteer.launch({
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
          // Performance optimizations
          '--memory-pressure-off',
          '--max_old_space_size=4096',
          '--disable-background-networking',
          '--disable-default-apps',
          '--disable-extensions',
          '--disable-sync',
          '--disable-translate',
          '--hide-scrollbars',
          '--mute-audio',
          '--disable-plugins-discovery',
          '--disable-preconnect',
        ],
        timeout: this.config.browserTimeout,
      })

      const browserInstance: BrowserInstance = {
        id: browserId,
        browser,
        pages: new Set(),
        createdAt: new Date(),
        lastUsed: new Date(),
        isHealthy: true,
      }

      this.browsers.set(browserId, browserInstance)
      
      // Handle browser disconnect
      browser.on('disconnected', () => {
        logger.warn('BrowserPool', `Browser ${browserId} disconnected`)
        this.handleBrowserDisconnect(browserId)
      })

      logger.info('BrowserPool', `Created browser ${browserId}`)
      return browserInstance
    } catch (error) {
      logger.error('BrowserPool', 'Failed to create browser', error)
      return null
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

      const pageInstance: PageInstance = {
        page,
        browserId: targetBrowser.id,
        createdAt: new Date(),
        lastUsed: new Date(),
        isActive: false,
      }

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
  private async configurePage(page: Page): Promise<void> {
    try {
      // Apply comprehensive network spoofing
      const { NetworkSpoofingService } = await import('./networkSpoofingService')
      const spoofingService = new NetworkSpoofingService({
        enableIPSpoofing: true,
        enableMACAddressSpoofing: true,
        enableFingerprintSpoofing: true,
        requestDelay: { min: 1000, max: 4000 }
      })

      await spoofingService.applyNetworkSpoofing(page)

      // Fallback: Set random user agent if spoofing service fails
      const userAgent = this.config.userAgents[Math.floor(Math.random() * this.config.userAgents.length)]
      if (userAgent) {
        await page.setUserAgent(userAgent)
      }

      // Fallback: Set random viewport if spoofing service fails
      const viewport = this.config.viewports[Math.floor(Math.random() * this.config.viewports.length)]
      if (viewport) {
        await page.setViewport(viewport)
      }

      // Enhanced request interception with anti-detection
      await page.setRequestInterception(true)
      page.on('request', (request) => {
        const resourceType = request.resourceType()
        const url = request.url()

        // Block unnecessary resources and tracking
        if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
          request.abort()
        } else if (url.includes('google-analytics') ||
                   url.includes('googletagmanager') ||
                   url.includes('facebook.com') ||
                   url.includes('doubleclick') ||
                   url.includes('adsystem') ||
                   url.includes('hotjar') ||
                   url.includes('mixpanel')) {
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
            { name: 'Native Client', filename: 'internal-nacl-plugin' }
          ],
        })

        // Override languages
        Object.defineProperty(navigator, 'languages', {
          get: () => ['en-US', 'en'],
        })

        // Override permissions
        const originalQuery = window.navigator.permissions.query
        window.navigator.permissions.query = (parameters) => (
          parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
        )

        // Override battery API
        Object.defineProperty(navigator, 'getBattery', {
          get: () => () => Promise.resolve({
            charging: true,
            chargingTime: 0,
            dischargingTime: Infinity,
            level: 1
          }),
        })
      })

      logger.debug('BrowserPool', 'Page configured with enhanced anti-detection measures')
    } catch (error) {
      logger.warn('BrowserPool', 'Failed to apply some anti-detection measures', error)

      // Fallback configuration
      const userAgent = this.config.userAgents[Math.floor(Math.random() * this.config.userAgents.length)]
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
        cpuUsage: 0,    // Would get from browser.metrics()
        activePages: browser.pages.size,
        responseTime: Date.now() - browser.lastUsed.getTime(),
        errorRate: this.calculateErrorRate(browserId),
        lastHealthCheck: new Date()
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
   * Restart a specific browser
   */
  private async restartBrowser(browserId: string): Promise<void> {
    const browser = this.browsers.get(browserId)
    if (browser) {
      try {
        await browser.browser.close()
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

    const avgResponseTime = Array.from(this.healthMetrics.values())
      .reduce((sum, metrics) => sum + metrics.responseTime, 0) / this.healthMetrics.size || 0

    const avgErrorRate = Array.from(this.healthMetrics.values())
      .reduce((sum, metrics) => sum + metrics.errorRate, 0) / this.healthMetrics.size || 0

    return {
      totalBrowsers: this.browsers.size,
      healthyBrowsers,
      totalPages: this.activePagesCount,
      averageResponseTime: avgResponseTime,
      averageErrorRate: avgErrorRate
    }
  }
}

/**
 * Default browser pool instance
 */
export const browserPool = new BrowserPool()
