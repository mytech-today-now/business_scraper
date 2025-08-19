/**
 * Enhanced DuckDuckGo Scraper with Console Filtering and Resource Blocking
 * Addresses browser console noise and improves scraping performance
 */

import puppeteer, { Browser, Page } from 'puppeteer'
import { logger } from '@/lib/logger'

export interface DuckDuckGoResult {
  url: string
  title: string
  snippet: string
  domain: string
}

export interface DuckDuckGoScrapingOptions {
  query: string
  page?: number
  maxResults?: number
  timeout?: number
  blockResources?: boolean
  filterConsole?: boolean
}

export class EnhancedDuckDuckGoScraper {
  private browser: Browser | null = null
  private readonly config = {
    timeout: 30000,
    maxResults: 10,
    blockResources: true,
    filterConsole: true,
    retryAttempts: 3,
    retryDelay: 2000
  }

  /**
   * Initialize the scraper with enhanced browser configuration
   */
  async initialize(): Promise<void> {
    if (this.browser) return

    try {
      this.browser = await puppeteer.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu',
          '--disable-web-security',
          '--disable-features=VizDisplayCompositor',
          '--disable-background-timer-throttling',
          '--disable-backgrounding-occluded-windows',
          '--disable-renderer-backgrounding',
          '--disable-extensions',
          '--disable-plugins',
          '--disable-default-apps',
          '--disable-sync',
          '--disable-translate',
          '--hide-scrollbars',
          '--mute-audio',
          '--no-default-browser-check',
          '--no-first-run',
          '--disable-background-networking',
          '--disable-background-timer-throttling',
          '--disable-client-side-phishing-detection',
          '--disable-component-extensions-with-background-pages',
          '--disable-default-apps',
          '--disable-extensions',
          '--disable-features=TranslateUI',
          '--disable-hang-monitor',
          '--disable-ipc-flooding-protection',
          '--disable-popup-blocking',
          '--disable-prompt-on-repost',
          '--disable-sync',
          '--disable-web-resources',
          '--metrics-recording-only',
          '--no-first-run',
          '--safebrowsing-disable-auto-update',
          '--enable-automation',
          '--password-store=basic',
          '--use-mock-keychain'
        ]
      })

      logger.info('EnhancedDuckDuckGoScraper', 'Browser initialized successfully')
    } catch (error) {
      logger.error('EnhancedDuckDuckGoScraper', 'Failed to initialize browser', error)
      throw error
    }
  }

  /**
   * Scrape DuckDuckGo search results with enhanced error handling
   */
  async scrapeResults(options: DuckDuckGoScrapingOptions): Promise<DuckDuckGoResult[]> {
    const {
      query,
      page = 0,
      maxResults = this.config.maxResults,
      timeout = this.config.timeout,
      blockResources = this.config.blockResources,
      filterConsole = this.config.filterConsole
    } = options

    if (!this.browser) {
      await this.initialize()
    }

    let browserPage: Page | null = null
    let retryCount = 0

    while (retryCount < this.config.retryAttempts) {
      try {
        browserPage = await this.browser!.newPage()

        // Configure the page with enhanced settings
        await this.configurePage(browserPage, blockResources, filterConsole)

        // Construct DuckDuckGo search URL
        const searchUrl = this.buildSearchUrl(query, page)
        logger.info('EnhancedDuckDuckGoScraper', `Navigating to: ${searchUrl}`)

        // Navigate with enhanced error handling
        await this.navigateWithRetry(browserPage, searchUrl, timeout)

        // Wait for results with multiple selector strategies
        await this.waitForResults(browserPage)

        // Extract results using enhanced selectors
        const results = await this.extractResults(browserPage, maxResults)

        logger.info('EnhancedDuckDuckGoScraper', `Successfully extracted ${results.length} results`)
        return results

      } catch (error) {
        retryCount++
        logger.warn('EnhancedDuckDuckGoScraper', `Attempt ${retryCount} failed:`, error)

        if (browserPage) {
          await browserPage.close().catch(() => {})
          browserPage = null
        }

        if (retryCount >= this.config.retryAttempts) {
          logger.error('EnhancedDuckDuckGoScraper', `All ${this.config.retryAttempts} attempts failed`)
          throw error
        }

        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, this.config.retryDelay * retryCount))
      } finally {
        if (browserPage) {
          await browserPage.close().catch(() => {})
        }
      }
    }

    return []
  }

  /**
   * Configure page with resource blocking and console filtering
   */
  private async configurePage(page: Page, blockResources: boolean, filterConsole: boolean): Promise<void> {
    // Set user agent to appear more human-like
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    )

    // Set viewport
    await page.setViewport({ width: 1366, height: 768 })

    // Block unnecessary resources if enabled
    if (blockResources) {
      await page.setRequestInterception(true)
      page.on('request', (request) => {
        const resourceType = request.resourceType()
        const url = request.url()

        // Block unnecessary resources that cause console errors
        if (
          resourceType === 'image' ||
          resourceType === 'font' ||
          resourceType === 'media' ||
          resourceType === 'stylesheet' ||
          url.includes('analytics') ||
          url.includes('tracking') ||
          url.includes('ads') ||
          url.includes('mapkit') ||
          url.includes('favicon') ||
          url.includes('.ico') ||
          url.includes('preload')
        ) {
          request.abort()
        } else {
          request.continue()
        }
      })
    }

    // Filter console messages if enabled
    if (filterConsole) {
      page.on('console', (msg) => {
        const text = msg.text()
        
        // Only log critical errors, filter out noise
        if (
          msg.type() === 'error' &&
          !text.includes('Permissions-Policy') &&
          !text.includes('useTranslation') &&
          !text.includes('Failed to load resource') &&
          !text.includes('preload') &&
          !text.includes('net::ERR_FAILED') &&
          !text.includes('404') &&
          !text.includes('mapkit') &&
          !text.includes('favicon')
        ) {
          logger.warn('EnhancedDuckDuckGoScraper', `Browser console error: ${text}`)
        }
      })

      // Handle page errors
      page.on('pageerror', (error) => {
        logger.warn('EnhancedDuckDuckGoScraper', `Page error: ${error.message}`)
      })
    }
  }

  /**
   * Build DuckDuckGo search URL
   */
  private buildSearchUrl(query: string, page: number): string {
    const searchUrl = new URL('https://duckduckgo.com/')
    searchUrl.searchParams.set('t', 'h_')
    searchUrl.searchParams.set('q', query)
    searchUrl.searchParams.set('ia', 'web')

    if (page > 0) {
      searchUrl.searchParams.set('s', (page * 30).toString())
    }

    return searchUrl.toString()
  }

  /**
   * Navigate with retry logic
   */
  private async navigateWithRetry(page: Page, url: string, timeout: number): Promise<void> {
    await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout
    })

    // Additional wait for dynamic content
    await new Promise(resolve => setTimeout(resolve, 2000))
  }

  /**
   * Wait for search results with multiple strategies
   */
  private async waitForResults(page: Page): Promise<void> {
    const selectors = [
      '[data-testid="result"]',
      '.result',
      '.web-result',
      '.result__body',
      '.results .result',
      'article[data-testid="result"]',
      '[data-layout="organic"]'
    ]

    // Try multiple selectors
    for (const selector of selectors) {
      try {
        await page.waitForSelector(selector, { timeout: 10000 })
        logger.debug('EnhancedDuckDuckGoScraper', `Found results with selector: ${selector}`)
        return
      } catch (error) {
        logger.debug('EnhancedDuckDuckGoScraper', `Selector ${selector} not found, trying next...`)
      }
    }

    throw new Error('No search results found with any selector')
  }

  /**
   * Extract search results with enhanced selectors
   */
  private async extractResults(page: Page, maxResults: number): Promise<DuckDuckGoResult[]> {
    return await page.evaluate((maxResults: number) => {
      const results: DuckDuckGoResult[] = []

      // Enhanced selector strategy
      const resultSelectors = [
        '[data-testid="result"]',
        '.result',
        '.web-result',
        '.result__body',
        '.results .result',
        'article[data-testid="result"]',
        '[data-layout="organic"]'
      ]

      let resultElements: NodeListOf<Element> | null = null

      // Find the best selector that returns results
      for (const selector of resultSelectors) {
        const elements = document.querySelectorAll(selector)
        if (elements.length > 0) {
          resultElements = elements
          break
        }
      }

      if (!resultElements || resultElements.length === 0) {
        console.log('No result elements found')
        return results
      }

      console.log(`Found ${resultElements.length} result elements`)

      // Extract data from each result
      for (let i = 0; i < Math.min(resultElements.length, maxResults); i++) {
        try {
          const element = resultElements[i]

          // Enhanced link extraction
          const linkElement = element.querySelector('a[href]') || 
                             element.querySelector('h2 a') ||
                             element.querySelector('.result__title a') ||
                             element.querySelector('[data-testid="result-title-a"]')

          if (!linkElement) continue

          const url = linkElement.getAttribute('href') || ''
          if (!url || url.startsWith('javascript:') || url.includes('duckduckgo.com')) continue

          // Enhanced title extraction
          const title = linkElement.textContent?.trim() ||
                       element.querySelector('h2')?.textContent?.trim() ||
                       element.querySelector('.result__title')?.textContent?.trim() ||
                       'No title'

          // Enhanced snippet extraction
          const snippet = element.querySelector('.result__snippet')?.textContent?.trim() ||
                         element.querySelector('[data-testid="result-snippet"]')?.textContent?.trim() ||
                         element.querySelector('.result__body')?.textContent?.trim() ||
                         'No snippet'

          // Extract domain
          const domain = new URL(url).hostname.toLowerCase()

          // Filter out non-business domains
          const excludedDomains = [
            'wikipedia.org', 'facebook.com', 'twitter.com', 'linkedin.com',
            'youtube.com', 'instagram.com', 'pinterest.com', 'reddit.com',
            'yelp.com', 'yellowpages.com', 'google.com', 'bing.com'
          ]

          const isBusinessDomain = !excludedDomains.some(excluded => domain.includes(excluded)) &&
                                  !url.includes('duckduckgo.com') &&
                                  url.startsWith('http')

          if (isBusinessDomain && title && title !== 'No title') {
            results.push({
              url,
              title,
              snippet,
              domain
            })

            console.log(`Extracted: ${title} -> ${url}`)
          }

        } catch (error) {
          console.log(`Error processing result ${i}:`, error)
          continue
        }
      }

      console.log(`Total business results extracted: ${results.length}`)
      return results

    }, maxResults)
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    if (this.browser) {
      await this.browser.close()
      this.browser = null
      logger.info('EnhancedDuckDuckGoScraper', 'Browser closed')
    }
  }
}
