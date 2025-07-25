/**
 * Anti-Bot Detection Bypass System
 * Implements sophisticated techniques to avoid bot detection
 */

import { Page } from 'puppeteer'
import { logger } from '@/utils/logger'

export interface BotBypassConfig {
  enableFingerprinting: boolean
  enableMouseMovement: boolean
  enableRandomDelays: boolean
  enableCaptchaDetection: boolean
  enableProxyRotation: boolean
  minDelay: number
  maxDelay: number
  mouseMovementProbability: number
}

export interface MouseMovement {
  x: number
  y: number
  duration: number
}

export interface CaptchaDetection {
  detected: boolean
  type: string
  selector?: string
}

/**
 * Anti-Bot Detection Bypass Manager
 */
export class AntiBotBypass {
  private config: BotBypassConfig
  private userAgents: string[]
  private viewports: Array<{ width: number; height: number }>

  constructor(config?: Partial<BotBypassConfig>) {
    this.config = {
      enableFingerprinting: true,
      enableMouseMovement: true,
      enableRandomDelays: true,
      enableCaptchaDetection: true,
      enableProxyRotation: false,
      minDelay: 500,
      maxDelay: 3000,
      mouseMovementProbability: 0.3,
      ...config,
    }

    this.userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    ]

    this.viewports = [
      { width: 1920, height: 1080 },
      { width: 1366, height: 768 },
      { width: 1440, height: 900 },
      { width: 1536, height: 864 },
      { width: 1280, height: 720 },
    ]
  }

  /**
   * Apply comprehensive anti-bot bypass measures to a page
   */
  async applyBypassMeasures(page: Page): Promise<void> {
    logger.debug('AntiBotBypass', 'Applying anti-bot bypass measures')

    try {
      if (this.config.enableFingerprinting) {
        await this.applyBrowserFingerprinting(page)
      }

      await this.setupStealthMode(page)
      await this.randomizeHeaders(page)
      await this.setupRequestInterception(page)

      logger.debug('AntiBotBypass', 'Anti-bot bypass measures applied successfully')
    } catch (error) {
      logger.error('AntiBotBypass', 'Failed to apply bypass measures', error)
    }
  }

  /**
   * Perform human-like navigation to a URL
   */
  async navigateHumanLike(page: Page, url: string): Promise<void> {
    logger.debug('AntiBotBypass', `Navigating to ${url} with human-like behavior`)

    try {
      // Random delay before navigation
      if (this.config.enableRandomDelays) {
        await this.randomDelay()
      }

      // Navigate with realistic options
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 30000,
      })

      // Simulate human-like behavior after page load
      await this.simulateHumanBehavior(page)

    } catch (error) {
      logger.error('AntiBotBypass', `Failed to navigate to ${url}`, error)
      throw error
    }
  }

  /**
   * Detect CAPTCHA on the page
   */
  async detectCaptcha(page: Page): Promise<CaptchaDetection> {
    if (!this.config.enableCaptchaDetection) {
      return { detected: false, type: 'none' }
    }

    try {
      const captchaDetection = await page.evaluate(() => {
        // Common CAPTCHA selectors
        const captchaSelectors = [
          '.g-recaptcha',
          '#recaptcha',
          '.recaptcha',
          '.captcha',
          '.hcaptcha',
          '.cf-challenge',
          '[data-sitekey]',
          'iframe[src*="recaptcha"]',
          'iframe[src*="hcaptcha"]',
        ]

        for (const selector of captchaSelectors) {
          const element = document.querySelector(selector)
          if (element) {
            return {
              detected: true,
              type: selector.includes('recaptcha') ? 'recaptcha' : 
                    selector.includes('hcaptcha') ? 'hcaptcha' : 'unknown',
              selector,
            }
          }
        }

        // Check for challenge pages
        const bodyText = document.body.textContent?.toLowerCase() || ''
        if (bodyText.includes('verify you are human') || 
            bodyText.includes('security check') ||
            bodyText.includes('please complete the security check')) {
          return {
            detected: true,
            type: 'challenge',
          }
        }

        return { detected: false, type: 'none' }
      })

      if (captchaDetection.detected) {
        logger.warn('AntiBotBypass', `CAPTCHA detected: ${captchaDetection.type}`)
      }

      return captchaDetection
    } catch (error) {
      logger.error('AntiBotBypass', 'Failed to detect CAPTCHA', error)
      return { detected: false, type: 'error' }
    }
  }

  /**
   * Apply realistic browser fingerprinting
   */
  private async applyBrowserFingerprinting(page: Page): Promise<void> {
    // Set random user agent
    const userAgent = this.userAgents[Math.floor(Math.random() * this.userAgents.length)]
    if (userAgent) {
      await page.setUserAgent(userAgent)
    }

    // Set random viewport
    const viewport = this.viewports[Math.floor(Math.random() * this.viewports.length)]
    if (viewport) {
      await page.setViewport(viewport)
    }

    // Override navigator properties
    await page.evaluateOnNewDocument(() => {
      // Override webdriver property
      Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
      })

      // Override plugins
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
      window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
          Promise.resolve({
            state: Notification.permission,
            name: 'notifications',
            onchange: null,
            addEventListener: () => {},
            removeEventListener: () => {},
            dispatchEvent: () => false
          } as PermissionStatus) :
          originalQuery(parameters)
      )

      // Override screen properties
      Object.defineProperty(screen, 'colorDepth', {
        get: () => 24,
      })

      // Override timezone
      Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {
        value: function() {
          return {
            ...Intl.DateTimeFormat.prototype.resolvedOptions.call(this),
            timeZone: 'America/New_York',
          }
        },
      })
    })
  }

  /**
   * Setup stealth mode to avoid detection
   */
  private async setupStealthMode(page: Page): Promise<void> {
    await page.evaluateOnNewDocument(() => {
      // Remove automation indicators
      delete (window as any).chrome
      delete (window as any).__nightmare
      delete (window as any).__phantomas
      delete (window as any).callPhantom
      delete (window as any)._phantom

      // Override automation detection
      Object.defineProperty(window, 'outerHeight', {
        get: () => window.innerHeight,
      })

      Object.defineProperty(window, 'outerWidth', {
        get: () => window.innerWidth,
      })

      // Mock realistic browser behavior
      ;(window as any).chrome = {
        runtime: {},
        loadTimes: function() {
          return {
            commitLoadTime: Date.now() / 1000 - Math.random(),
            finishDocumentLoadTime: Date.now() / 1000 - Math.random(),
            finishLoadTime: Date.now() / 1000 - Math.random(),
            firstPaintAfterLoadTime: 0,
            firstPaintTime: Date.now() / 1000 - Math.random(),
            navigationType: 'Other',
            npnNegotiatedProtocol: 'h2',
            requestTime: Date.now() / 1000 - Math.random(),
            startLoadTime: Date.now() / 1000 - Math.random(),
            wasAlternateProtocolAvailable: false,
            wasFetchedViaSpdy: true,
            wasNpnNegotiated: true,
          }
        },
      }
    })
  }

  /**
   * Randomize HTTP headers
   */
  private async randomizeHeaders(page: Page): Promise<void> {
    const headers = {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Cache-Control': 'max-age=0',
    }

    await page.setExtraHTTPHeaders(headers)
  }

  /**
   * Setup request interception for stealth
   */
  private async setupRequestInterception(page: Page): Promise<void> {
    await page.setRequestInterception(true)

    page.on('request', (request) => {
      const headers = request.headers()
      
      // Remove automation headers
      delete headers['x-devtools-emulate-network-conditions-client-id']
      
      // Add realistic headers
      headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
      headers['sec-ch-ua-mobile'] = '?0'
      headers['sec-ch-ua-platform'] = '"Windows"'

      request.continue({ headers })
    })
  }

  /**
   * Simulate human-like behavior on the page
   */
  private async simulateHumanBehavior(page: Page): Promise<void> {
    try {
      // Random scroll
      if (Math.random() < 0.7) {
        await this.simulateScrolling(page)
      }

      // Random mouse movement
      if (this.config.enableMouseMovement && Math.random() < this.config.mouseMovementProbability) {
        await this.simulateMouseMovement(page)
      }

      // Random delay
      if (this.config.enableRandomDelays) {
        await this.randomDelay(1000, 3000)
      }
    } catch (error) {
      logger.warn('AntiBotBypass', 'Failed to simulate human behavior', error)
    }
  }

  /**
   * Simulate realistic scrolling behavior
   */
  private async simulateScrolling(page: Page): Promise<void> {
    const scrollSteps = Math.floor(Math.random() * 5) + 2
    
    for (let i = 0; i < scrollSteps; i++) {
      const scrollY = Math.floor(Math.random() * 500) + 100
      await page.evaluate((y) => {
        window.scrollBy(0, y)
      }, scrollY)
      
      await this.randomDelay(200, 800)
    }
  }

  /**
   * Simulate realistic mouse movement
   */
  private async simulateMouseMovement(page: Page): Promise<void> {
    const viewport = page.viewport()
    if (!viewport) return

    const movements = this.generateMousePath(viewport.width, viewport.height)
    
    for (const movement of movements) {
      await page.mouse.move(movement.x, movement.y)
      await this.randomDelay(50, 200)
    }
  }

  /**
   * Generate realistic mouse movement path
   */
  private generateMousePath(width: number, height: number): MouseMovement[] {
    const movements: MouseMovement[] = []
    const numMovements = Math.floor(Math.random() * 5) + 3
    
    let currentX = Math.floor(Math.random() * width)
    let currentY = Math.floor(Math.random() * height)
    
    for (let i = 0; i < numMovements; i++) {
      const targetX = Math.floor(Math.random() * width)
      const targetY = Math.floor(Math.random() * height)
      
      // Create smooth movement
      const steps = Math.floor(Math.random() * 10) + 5
      for (let step = 0; step <= steps; step++) {
        const progress = step / steps
        const x = currentX + (targetX - currentX) * progress
        const y = currentY + (targetY - currentY) * progress
        
        movements.push({
          x: Math.floor(x),
          y: Math.floor(y),
          duration: Math.floor(Math.random() * 100) + 50,
        })
      }
      
      currentX = targetX
      currentY = targetY
    }
    
    return movements
  }

  /**
   * Generate random delay
   */
  private async randomDelay(min?: number, max?: number): Promise<void> {
    const minDelay = min || this.config.minDelay
    const maxDelay = max || this.config.maxDelay
    const delay = Math.floor(Math.random() * (maxDelay - minDelay)) + minDelay
    
    await new Promise(resolve => setTimeout(resolve, delay))
  }

  /**
   * Check if page is blocked or challenged
   */
  async isPageBlocked(page: Page): Promise<boolean> {
    try {
      const content = await page.content()
      const title = await page.title()
      
      const blockIndicators = [
        'access denied',
        'blocked',
        'forbidden',
        'rate limit',
        'too many requests',
        'security check',
        'verify you are human',
        'cloudflare',
        'ddos protection',
      ]
      
      const contentLower = content.toLowerCase()
      const titleLower = title.toLowerCase()
      
      return blockIndicators.some(indicator => 
        contentLower.includes(indicator) || titleLower.includes(indicator)
      )
    } catch (error) {
      logger.error('AntiBotBypass', 'Failed to check if page is blocked', error)
      return false
    }
  }

  /**
   * Wait for page to be ready (no loading indicators)
   */
  async waitForPageReady(page: Page, timeout: number = 30000): Promise<void> {
    try {
      await page.waitForFunction(
        () => {
          // Check if page is still loading
          if (document.readyState !== 'complete') return false
          
          // Check for common loading indicators
          const loadingSelectors = [
            '.loading',
            '.spinner',
            '.loader',
            '[class*="loading"]',
            '[class*="spinner"]',
          ]
          
          for (const selector of loadingSelectors) {
            const element = document.querySelector(selector)
            if (element && getComputedStyle(element).display !== 'none') {
              return false
            }
          }
          
          return true
        },
        { timeout }
      )
    } catch (error) {
      logger.warn('AntiBotBypass', 'Timeout waiting for page ready', error)
    }
  }
}

/**
 * Default anti-bot bypass instance
 */
export const antiBotBypass = new AntiBotBypass()
