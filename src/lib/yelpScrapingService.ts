import puppeteer, { Browser, Page } from 'puppeteer'
import { logger } from '@/utils/logger'
import { zipCodeService } from './zipCodeService'
import { BusinessRecord } from '@/types/business'

export interface YelpSearchOptions {
  query: string
  location: string
  zipRadius: number
  maxResults: number
  maxPagesPerSite?: number
}

export interface YelpBusinessResult {
  url: string
  title: string
  snippet: string
  domain: string
  address?: string
  phone?: string
  yelpProfileUrl?: string
  businessRecords?: BusinessRecord[]
}

export class YelpScrapingService {
  private browser: Browser | null = null
  private requestCount = 0
  private lastRequestTime = 0
  private readonly minDelay = 2000 // Minimum 2 seconds between requests for Yelp
  private readonly maxRetries = 3

  /**
   * Initialize the browser instance with enhanced stealth settings for Yelp
   */
  private async initBrowser(): Promise<Browser> {
    if (this.browser) {
      return this.browser
    }

    logger.info('YelpScraping', 'Initializing Puppeteer browser with stealth settings')
    
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
        '--disable-blink-features=AutomationControlled',
        '--disable-extensions',
        '--disable-plugins',
        '--disable-images', // Speed up loading
        '--disable-javascript-harmony-shipping',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding'
      ]
    })

    return this.browser
  }

  /**
   * Create a new page with realistic human-like settings
   */
  private async createPage(): Promise<Page> {
    const browser = await this.initBrowser()
    const page = await browser.newPage()
    
    // Set realistic user agent and viewport
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
    await page.setViewport({ width: 1366, height: 768 })
    
    // Set extra headers to appear more like a real browser
    await page.setExtraHTTPHeaders({
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Cache-Control': 'max-age=0'
    })

    // Remove automation indicators
    await page.evaluateOnNewDocument(() => {
      // Remove webdriver property
      delete (navigator as any).webdriver
      
      // Mock plugins
      Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5]
      })
      
      // Mock languages
      Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en']
      })
    })

    return page
  }

  /**
   * Implement rate limiting with longer delays for Yelp
   */
  private async rateLimit(): Promise<void> {
    const now = Date.now()
    const timeSinceLastRequest = now - this.lastRequestTime
    
    if (timeSinceLastRequest < this.minDelay) {
      const delay = this.minDelay - timeSinceLastRequest
      logger.info('YelpScraping', `Rate limiting: waiting ${delay}ms`)
      await new Promise(resolve => setTimeout(resolve, delay))
    }
    
    this.lastRequestTime = Date.now()
    this.requestCount++
  }

  /**
   * Simulate human-like behavior to pass verification
   */
  private async simulateHumanBehavior(page: Page): Promise<void> {
    try {
      // Random mouse movements
      await page.mouse.move(Math.random() * 800, Math.random() * 600)
      await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000))
      
      // Random scroll
      await page.evaluate(() => {
        window.scrollTo(0, Math.random() * 300)
      })
      await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 700))
      
      // Check for human verification and handle it
      await this.handleHumanVerification(page)
      
    } catch (error) {
      logger.warn('YelpScraping', 'Error during human behavior simulation', error)
    }
  }

  /**
   * Handle Yelp's "is this user human" verification
   */
  private async handleHumanVerification(page: Page): Promise<void> {
    try {
      // Wait a bit to see if verification appears
      await new Promise(resolve => setTimeout(resolve, 2000))
      
      // Look for common verification elements
      const verificationSelectors = [
        '[data-testid="human-verification"]',
        '.human-verification',
        '.captcha',
        '.verification-challenge',
        'iframe[src*="captcha"]',
        'iframe[src*="recaptcha"]'
      ]
      
      for (const selector of verificationSelectors) {
        const element = await page.$(selector)
        if (element) {
          logger.info('YelpScraping', `Human verification detected: ${selector}`)
          
          // Wait longer and simulate more human behavior
          await new Promise(resolve => setTimeout(resolve, 5000 + Math.random() * 5000))
          
          // Additional mouse movements
          for (let i = 0; i < 3; i++) {
            await page.mouse.move(Math.random() * 1000, Math.random() * 700)
            await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000))
          }
          
          // Try to wait for verification to pass
          await page.waitForSelector('.search-results, [data-testid="search-results"], .searchResults', { 
            timeout: 30000 
          }).catch(() => {
            logger.warn('YelpScraping', 'Verification may not have passed, continuing anyway')
          })
          
          break
        }
      }
    } catch (error) {
      logger.warn('YelpScraping', 'Error handling human verification', error)
    }
  }

  /**
   * Search for businesses on Yelp
   */
  async searchBusinesses(options: YelpSearchOptions): Promise<YelpBusinessResult[]> {
    const { query, location, zipRadius, maxResults = 10000, maxPagesPerSite = 50 } = options

    logger.info('YelpScraping', `Starting Yelp RESTful search: ${query} in ${location} (radius: ${zipRadius}mi)`)

    let page: Page | null = null
    let retries = 0

    while (retries < this.maxRetries) {
      try {
        await this.rateLimit()
        
        page = await this.createPage()
        
        // Build RESTful Yelp search URL as specified
        const yelpSearchUrl = new URL('https://www.yelp.com/search')
        yelpSearchUrl.searchParams.set('find_desc', query.replace(/\s+/g, '+'))
        yelpSearchUrl.searchParams.set('find_loc', location)

        logger.info('YelpScraping', `Navigating to RESTful URL: ${yelpSearchUrl.toString()}`)
        
        // Navigate to Yelp search page
        await page.goto(yelpSearchUrl.toString(), { 
          waitUntil: 'networkidle2',
          timeout: 30000 
        })

        // Simulate human behavior and handle verification
        await this.simulateHumanBehavior(page)

        // Wait for search results to load
        await page.waitForSelector('.search-results, [data-testid="search-results"], .searchResults', { timeout: 15000 })

        // Extract business listings from YERP (Yelp Engine Results Page)
        const businessListings = await this.extractBusinessListingsFromYERP(page, maxResults)

        if (businessListings.length === 0) {
          logger.warn('YelpScraping', 'No businesses found on YERP')
          await page.close()
          return []
        }

        logger.info('YelpScraping', `Found ${businessListings.length} businesses on YERP`)

        // Extract business websites from Yelp profile pages
        const businessesWithWebsites = await this.extractBusinessWebsitesFromProfiles(page, businessListings, maxResults)

        // Perform deep scraping of business websites
        const businessesWithDeepData = await this.performDeepWebsiteScraping(businessesWithWebsites, maxPagesPerSite)

        // Filter businesses by ZIP radius if specified
        const filteredBusinesses = await this.filterByZipRadius(businessesWithDeepData, options)
        
        await page.close()
        
        logger.info('YelpScraping', `Successfully processed ${filteredBusinesses.length} businesses with deep scraping`)
        return filteredBusinesses

      } catch (error) {
        retries++
        logger.warn('YelpScraping', `Attempt ${retries} failed`, error)
        
        if (page) {
          await page.close().catch(() => {})
        }
        
        if (retries >= this.maxRetries) {
          throw new Error(`Yelp scraping failed after ${this.maxRetries} attempts: ${error}`)
        }
        
        // Exponential backoff with longer delays for Yelp
        const delay = Math.pow(2, retries) * 2000
        logger.info('YelpScraping', `Retrying in ${delay}ms`)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }

    return []
  }

  /**
   * Extract business listings from YERP (Yelp Engine Results Page) using the specified identifier
   */
  private async extractBusinessListingsFromYERP(page: Page, maxResults: number): Promise<any[]> {
    return await page.evaluate((maxResults) => {
      const businesses: any[] = []
      
      console.log('Extracting Yelp business listings from YERP...')

      // Use the specific identifier you mentioned for YERP entries
      const businessNameSelectors = [
        'div.businessName__09f24__HG_pC.y-css-mhg9c5[data-traffic-crawl-id="SearchResultBizName"]',
        '.businessName__09f24__HG_pC[data-traffic-crawl-id="SearchResultBizName"]',
        '[data-traffic-crawl-id="SearchResultBizName"]',
        '.businessName__09f24__HG_pC',
        '.business-name'
      ]
      
      let businessElements: NodeListOf<Element> | null = null
      
      for (const selector of businessNameSelectors) {
        businessElements = document.querySelectorAll(selector)
        if (businessElements.length > 0) {
          console.log(`Found ${businessElements.length} businesses using selector: ${selector}`)
          break
        }
      }
      
      if (!businessElements || businessElements.length === 0) {
        console.log('No business elements found')
        return businesses
      }
      
      for (let i = 0; i < Math.min(businessElements.length, maxResults); i++) {
        const businessElement = businessElements[i]

        if (!businessElement) {
          continue
        }

        try {
          // Extract business name and Yelp profile URL
          const nameLink = businessElement.querySelector('a') || businessElement.closest('a')
          const businessName = businessElement.textContent?.trim() || ''
          const profileUrl = nameLink?.getAttribute('href') || ''
          const fullProfileUrl = profileUrl.startsWith('/') ? `https://www.yelp.com${profileUrl}` : profileUrl
          
          if (!businessName || !fullProfileUrl) {
            continue
          }
          
          // Find the parent container for this business to extract additional info
          let businessContainer = businessElement.closest('[data-testid="search-result"]') || 
                                 businessElement.closest('.search-result') ||
                                 businessElement.closest('.businessContainer')
          
          let address = ''
          let phone = ''
          
          if (businessContainer) {
            // Look for address
            const addressElements = Array.from(businessContainer.querySelectorAll('[data-testid="address"], .address, .business-address'))
            for (const element of addressElements) {
              const text = element.textContent?.trim() || ''
              if (text.length > 5) {
                address = text
                break
              }
            }
            
            // Look for phone number
            const phoneElements = Array.from(businessContainer.querySelectorAll('[data-testid="phone"], .phone, .business-phone'))
            for (const element of phoneElements) {
              const text = element.textContent?.trim() || ''
              if (text.match(/\(\d{3}\)\s*\d{3}-\d{4}|\d{3}-\d{3}-\d{4}/)) {
                phone = text
                break
              }
            }
          }
          
          businesses.push({
            name: businessName,
            yelpProfileUrl: fullProfileUrl,
            address: address,
            phone: phone,
            snippet: `${businessName}${address ? ' - ' + address : ''}`.trim()
          })
          
          console.log(`Extracted business: ${businessName} -> ${fullProfileUrl}`)
          
        } catch (error) {
          console.log(`Error extracting business ${i}:`, error)
          continue
        }
      }
      
      console.log(`Total businesses extracted: ${businesses.length}`)
      return businesses
    }, maxResults)
  }

  /**
   * Extract business websites from Yelp profile pages using the specified URL pattern
   */
  private async extractBusinessWebsitesFromProfiles(page: Page, businesses: any[], maxResults: number): Promise<YelpBusinessResult[]> {
    const businessesWithWebsites: YelpBusinessResult[] = []
    
    // Limit to first few businesses to avoid too many requests
    const businessesToProcess = businesses.slice(0, Math.min(3, maxResults))
    
    for (const business of businessesToProcess) {
      try {
        await this.rateLimit()
        
        logger.info('YelpScraping', `Extracting website from: ${business.yelpProfileUrl}`)
        
        await page.goto(business.yelpProfileUrl, { 
          waitUntil: 'networkidle2',
          timeout: 20000 
        })

        // Simulate human behavior on business page
        await this.simulateHumanBehavior(page)

        // Wait for business page to load
        await page.waitForSelector('.business-website, [data-testid="business-website"], .biz-website', { timeout: 10000 })

        // Extract business website URL using the specific pattern you mentioned
        const websiteUrl = await page.evaluate(() => {
          console.log('Looking for business website URL on Yelp profile page...')

          // Look for the specific URL pattern you mentioned:
          // <div class="y-css-1ilqd8r"><a href="/biz_redir?url=https%3A%2F%2Fwww.rscbusinessgroup.com&amp;cachebuster=1753494273&amp;website_link_type=website&amp;src_bizid=eUpRo6nbHjcljDWfBywe5w&amp;s=59cd957b85fab6b8d7bc735840330c0796095d7bad24a1d0cbbc13f95a716a3a" class=" y-css-14ckas3" target="_blank">
          const websiteSelectors = [
            'div.y-css-1ilqd8r a[href*="biz_redir"]',
            'a[href*="biz_redir?url="]',
            'a[href*="website_link_type=website"]',
            '.business-website a',
            '[data-testid="business-website"] a',
            'a[href*="http"]:not([href*="yelp.com"]):not([href*="mailto:"]):not([href*="tel:"])'
          ]
          
          for (const selector of websiteSelectors) {
            const links = Array.from(document.querySelectorAll(selector)) as HTMLAnchorElement[]
            for (const link of links) {
              if (link.href) {
                // Handle biz_redir URLs - extract the actual business URL
                if (link.href.includes('biz_redir?url=')) {
                  try {
                    const urlParams = new URLSearchParams(link.href.split('?')[1])
                    const actualUrl = decodeURIComponent(urlParams.get('url') || '')
                    if (actualUrl && actualUrl.startsWith('http')) {
                      console.log(`Found business website via biz_redir: ${actualUrl}`)
                      return actualUrl
                    }
                  } catch (error) {
                    console.log('Error parsing biz_redir URL:', error)
                  }
                }
                // Handle direct URLs
                else if (!link.href.includes('yelp.com') &&
                         !link.href.includes('mailto:') &&
                         !link.href.includes('tel:') &&
                         !link.href.includes('facebook.com') &&
                         !link.href.includes('twitter.com') &&
                         !link.href.includes('instagram.com') &&
                         link.href.startsWith('http')) {
                  console.log(`Found direct website: ${link.href}`)
                  return link.href
                }
              }
            }
          }
          
          console.log('No business website found on this Yelp profile')
          return null
        })

        if (websiteUrl) {
          businessesWithWebsites.push({
            url: websiteUrl,
            title: business.name,
            snippet: business.snippet,
            domain: new URL(websiteUrl).hostname,
            address: business.address,
            phone: business.phone,
            yelpProfileUrl: business.yelpProfileUrl
          })
          
          logger.info('YelpScraping', `Extracted website: ${websiteUrl} for ${business.name}`)
        } else {
          logger.warn('YelpScraping', `No website found for ${business.name}`)
        }
        
      } catch (error) {
        logger.warn('YelpScraping', `Failed to extract website for ${business.name}`, error)
        continue
      }
    }

    return businessesWithWebsites
  }

  /**
   * Filter businesses by ZIP radius
   */
  private async filterByZipRadius(
    businesses: YelpBusinessResult[], 
    options: YelpSearchOptions
  ): Promise<YelpBusinessResult[]> {
    if (!options.zipRadius || options.zipRadius <= 0) {
      return businesses // No radius filtering requested
    }

    // Extract ZIP code from location
    const centerZip = zipCodeService.extractZipCodeFromAddress(options.location)
    if (!centerZip) {
      logger.warn('YelpScraping', `Could not extract ZIP code from location: ${options.location}`)
      return businesses // Return all if we can't extract center ZIP
    }

    const filteredBusinesses: YelpBusinessResult[] = []

    for (const business of businesses) {
      try {
        if (!business.address) {
          // If no address, include the business (can't filter)
          filteredBusinesses.push(business)
          continue
        }

        const isWithinRadius = await zipCodeService.isBusinessWithinRadius(
          business.address,
          centerZip,
          options.zipRadius
        )

        if (isWithinRadius) {
          filteredBusinesses.push(business)
        } else {
          logger.info('YelpScraping', 
            `Filtered out ${business.title} - outside ${options.zipRadius}mi radius from ${centerZip}`
          )
        }

      } catch (error) {
        logger.warn('YelpScraping', `Error filtering business ${business.title}`, error)
        // Include business if filtering fails
        filteredBusinesses.push(business)
      }
    }

    logger.info('YelpScraping', 
      `ZIP radius filtering: ${filteredBusinesses.length}/${businesses.length} businesses within ${options.zipRadius}mi of ${centerZip}`
    )

    return filteredBusinesses
  }

  /**
   * Close the browser instance
   */
  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close()
      this.browser = null
      logger.info('YelpScraping', 'Browser closed')
    }
  }

  /**
   * Perform deep scraping of business websites
   */
  private async performDeepWebsiteScraping(businesses: YelpBusinessResult[], maxPagesPerSite: number): Promise<YelpBusinessResult[]> {
    const businessesWithDeepData: YelpBusinessResult[] = []

    logger.info('YelpScraping', `Starting deep scraping of ${businesses.length} business websites`)

    for (const business of businesses) {
      try {
        await this.rateLimit()

        logger.info('YelpScraping', `Deep scraping website: ${business.url}`)

        // Import the scraper service for deep website scraping
        const { scraperService } = await import('@/model/scraperService')

        // Perform deep scraping of the business website using enhanced scraping
        const scrapingResult = await scraperService.scrapeWebsiteEnhanced(
          business.url,
          2, // depth
          maxPagesPerSite
        )

        if (scrapingResult && scrapingResult.length > 0) {
          // Add the scraped business records to the result
          const businessWithDeepData: YelpBusinessResult = {
            ...business,
            businessRecords: scrapingResult
          }

          businessesWithDeepData.push(businessWithDeepData)

          logger.info('YelpScraping', `Successfully scraped ${scrapingResult.length} business records from ${business.url}`)
        } else {
          // Keep the business even if deep scraping failed
          businessesWithDeepData.push(business)
          logger.warn('YelpScraping', `Deep scraping failed for ${business.url}, keeping basic info`)
        }

      } catch (error) {
        logger.error('YelpScraping', `Deep scraping error for ${business.url}:`, error)
        // Keep the business even if deep scraping failed
        businessesWithDeepData.push(business)
      }
    }

    logger.info('YelpScraping', `Completed deep scraping. ${businessesWithDeepData.length} businesses processed`)
    return businessesWithDeepData
  }

  /**
   * Get scraping statistics
   */
  getStats() {
    return {
      requestCount: this.requestCount,
      lastRequestTime: this.lastRequestTime,
      browserActive: !!this.browser
    }
  }
}

// Export singleton instance
export const yelpScrapingService = new YelpScrapingService()
