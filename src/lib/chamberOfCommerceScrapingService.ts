import puppeteer, { Browser, Page } from 'puppeteer'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'

export interface ChamberOfCommerceSearchOptions {
  url: string
  maxBusinesses: number
  maxPagesPerSite?: number
}

export interface ChamberOfCommerceBusinessResult {
  url: string
  title: string
  snippet: string
  domain: string
  address?: string
  phone?: string
  chamberProfileUrl?: string
  businessRecords?: BusinessRecord[]
}

export class ChamberOfCommerceScrapingService {
  private browser: Browser | null = null
  private requestCount = 0
  private lastRequestTime = 0
  private readonly minDelay = 2000 // Minimum 2 seconds between requests
  private readonly maxRetries = 3

  /**
   * Initialize the browser instance
   */
  private async initBrowser(): Promise<Browser> {
    if (this.browser) {
      return this.browser
    }

    logger.info('COCPScraping', 'Initializing Puppeteer browser for Chamber of Commerce processing')
    
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
   * Create a new page with stealth settings
   */
  private async createPage(): Promise<Page> {
    const browser = await this.initBrowser()
    const page = await browser.newPage()

    // Set realistic viewport
    await page.setViewport({ width: 1366, height: 768 })

    // Set user agent
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

    // Set extra headers
    await page.setExtraHTTPHeaders({
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Connection': 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
    })

    return page
  }

  /**
   * Rate limiting to avoid being blocked
   */
  private async rateLimit(): Promise<void> {
    const now = Date.now()
    const timeSinceLastRequest = now - this.lastRequestTime

    if (timeSinceLastRequest < this.minDelay) {
      const delay = this.minDelay - timeSinceLastRequest
      logger.debug('COCPScraping', `Rate limiting: waiting ${delay}ms`)
      await new Promise(resolve => setTimeout(resolve, delay))
    }

    this.lastRequestTime = Date.now()
    this.requestCount++
  }

  /**
   * Simulate human behavior on the page
   */
  private async simulateHumanBehavior(page: Page): Promise<void> {
    try {
      // Random mouse movements
      for (let i = 0; i < 3; i++) {
        await page.mouse.move(Math.random() * 1000, Math.random() * 700)
        await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000))
      }

      // Random scroll
      await page.evaluate(() => {
        window.scrollTo(0, Math.random() * document.body.scrollHeight * 0.5)
      })

      await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000))
    } catch (error) {
      logger.warn('COCPScraping', 'Error during human behavior simulation', error)
    }
  }

  /**
   * Process Chamber of Commerce pages to find business listings
   */
  async processChamberOfCommercePage(options: ChamberOfCommerceSearchOptions): Promise<ChamberOfCommerceBusinessResult[]> {
    const { url, maxBusinesses, maxPagesPerSite = 20 } = options
    
    logger.info('COCPScraping', `Starting Chamber of Commerce processing for: ${url}`)

    let page: Page | null = null
    let retries = 0

    while (retries < this.maxRetries) {
      try {
        await this.rateLimit()
        
        page = await this.createPage()
        
        logger.info('COCPScraping', `Navigating to Chamber of Commerce page: ${url}`)
        
        // Navigate to the Chamber of Commerce page
        await page.goto(url, { 
          waitUntil: 'networkidle2',
          timeout: 30000 
        })

        // Simulate human behavior
        await this.simulateHumanBehavior(page)

        // Wait for business listings to load
        await page.waitForSelector('a[placeid], .card, .business-listing', { timeout: 15000 })

        // Extract business listings from the Chamber of Commerce page
        const businessListings = await this.extractBusinessListingsFromChamberPage(page, maxBusinesses)
        
        if (businessListings.length === 0) {
          logger.warn('COCPScraping', 'No business listings found on Chamber of Commerce page')
          await page.close()
          return []
        }

        logger.info('COCPScraping', `Found ${businessListings.length} business listings on Chamber page`)

        // Extract business websites from Chamber profile pages
        const businessesWithWebsites = await this.extractBusinessWebsitesFromChamberProfiles(page, businessListings, maxBusinesses)
        
        // Perform deep scraping of business websites
        const businessesWithDeepData = await this.performDeepWebsiteScraping(businessesWithWebsites, maxPagesPerSite)
        
        await page.close()
        
        logger.info('COCPScraping', `Successfully processed ${businessesWithDeepData.length} businesses from Chamber of Commerce`)
        return businessesWithDeepData

      } catch (error) {
        retries++
        logger.warn('COCPScraping', `Processing attempt ${retries} failed:`, error)
        
        if (page) {
          await page.close().catch(() => {})
          page = null
        }
        
        if (retries >= this.maxRetries) {
          logger.error('COCPScraping', `All ${this.maxRetries} processing attempts failed`)
          throw error
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 2000 * retries))
      }
    }

    return []
  }

  /**
   * Extract business listings from Chamber of Commerce page using the specified pattern
   */
  private async extractBusinessListingsFromChamberPage(page: Page, maxBusinesses: number): Promise<any[]> {
    return await page.evaluate((maxBusinesses) => {
      const businesses: any[] = []
      
      console.log('Extracting business listings from Chamber of Commerce page...')
      
      // Look for the specific pattern you mentioned:
      // <a href="/business-directory/illinois/barrington/tax-preparation-service/2024858709-g3-accounting-tax" placeid="2024858709" class="card white-card card-hover-shadow mb-2 p-3 p-lg-4 FeaturedPlacePreview">
      const businessSelectors = [
        'a[placeid][href*="/business-directory/"]',
        'a.card[href*="/business-directory/"]',
        'a.FeaturedPlacePreview[href*="/business-directory/"]',
        'a[href*="/business-directory/"]',
        '.business-listing a',
        '.card a[href*="/business-directory/"]'
      ]
      
      let businessElements: NodeListOf<Element> | null = null
      
      for (const selector of businessSelectors) {
        businessElements = document.querySelectorAll(selector)
        if (businessElements.length > 0) {
          console.log(`Found ${businessElements.length} business listings using selector: ${selector}`)
          break
        }
      }
      
      if (!businessElements || businessElements.length === 0) {
        console.log('No business elements found on Chamber page')
        return businesses
      }
      
      for (let i = 0; i < Math.min(businessElements.length, maxBusinesses); i++) {
        const businessElement = businessElements[i] as HTMLAnchorElement

        if (!businessElement) {
          continue
        }

        try {
          // Extract business information
          const href = businessElement.getAttribute('href') || ''
          const placeid = businessElement.getAttribute('placeid') || ''
          const fullProfileUrl = href.startsWith('/') ? `https://www.chamberofcommerce.com${href}` : href
          
          // Extract business name from the link content or nearby elements
          const businessName = businessElement.textContent?.trim() || 
                              businessElement.querySelector('.business-name, .title, h3, h4')?.textContent?.trim() || 
                              `Business ${placeid}`
          
          if (!href || !fullProfileUrl.includes('chamberofcommerce.com')) {
            continue
          }
          
          // Extract additional info if available
          const businessContainer = businessElement.closest('.card') || businessElement
          const address = businessContainer.querySelector('.address, .location')?.textContent?.trim() || ''
          const phone = businessContainer.querySelector('.phone, .tel')?.textContent?.trim() || ''
          
          businesses.push({
            name: businessName,
            chamberProfileUrl: fullProfileUrl,
            placeid: placeid,
            href: href,
            address: address,
            phone: phone,
            snippet: `Chamber of Commerce listing for ${businessName}`
          })
          
          console.log(`Extracted business: ${businessName} -> ${fullProfileUrl}`)
          
        } catch (error) {
          console.log('Error extracting business info:', error)
          continue
        }
      }
      
      console.log(`Successfully extracted ${businesses.length} business listings`)
      return businesses
    }, maxBusinesses)
  }

  /**
   * Extract business websites from Chamber of Commerce profile pages
   */
  private async extractBusinessWebsitesFromChamberProfiles(page: Page, businesses: any[], maxBusinesses: number): Promise<ChamberOfCommerceBusinessResult[]> {
    const businessesWithWebsites: ChamberOfCommerceBusinessResult[] = []
    
    // Limit to first few businesses to avoid too many requests
    const businessesToProcess = businesses.slice(0, Math.min(5, maxBusinesses))
    
    for (const business of businessesToProcess) {
      try {
        await this.rateLimit()
        
        logger.info('COCPScraping', `Extracting website from Chamber profile: ${business.chamberProfileUrl}`)
        
        await page.goto(business.chamberProfileUrl, { 
          waitUntil: 'networkidle2',
          timeout: 20000 
        })

        // Simulate human behavior on business profile page
        await this.simulateHumanBehavior(page)

        // Wait for profile page to load
        await page.waitForSelector('main, .business-details, .profile, .content', { timeout: 10000 })

        // Extract business website URL from the profile page
        const websiteUrl = await page.evaluate(() => {
          console.log('Looking for business website URL on Chamber profile page...')
          
          // Look for website links that are NOT chamberofcommerce.com
          const websiteSelectors = [
            'a[href*="http"]:not([href*="chamberofcommerce.com"]):not([href*="mailto:"]):not([href*="tel:"])',
            '.website a',
            '.business-website a',
            '.contact-info a[href*="http"]',
            '.links a[href*="http"]',
            'a[href^="http"]:not([href*="chamberofcommerce.com"])'
          ]
          
          for (const selector of websiteSelectors) {
            const links = Array.from(document.querySelectorAll(selector)) as HTMLAnchorElement[]
            for (const link of links) {
              if (link.href && 
                  !link.href.includes('chamberofcommerce.com') && 
                  !link.href.includes('mailto:') && 
                  !link.href.includes('tel:') &&
                  !link.href.includes('facebook.com') &&
                  !link.href.includes('twitter.com') &&
                  !link.href.includes('instagram.com') &&
                  !link.href.includes('linkedin.com') &&
                  link.href.startsWith('http')) {
                console.log(`Found business website: ${link.href}`)
                return link.href
              }
            }
          }
          
          console.log('No external business website found on this Chamber profile')
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
            chamberProfileUrl: business.chamberProfileUrl
          })
          
          logger.info('COCPScraping', `Extracted website: ${websiteUrl} for ${business.name}`)
        } else {
          logger.warn('COCPScraping', `No website found for ${business.name}`)
        }
        
      } catch (error) {
        logger.warn('COCPScraping', `Failed to extract website for ${business.name}`, error)
        continue
      }
    }

    return businessesWithWebsites
  }

  /**
   * Perform deep scraping of business websites
   */
  private async performDeepWebsiteScraping(businesses: ChamberOfCommerceBusinessResult[], maxPagesPerSite: number): Promise<ChamberOfCommerceBusinessResult[]> {
    const businessesWithDeepData: ChamberOfCommerceBusinessResult[] = []
    
    logger.info('COCPScraping', `Starting deep scraping of ${businesses.length} business websites`)
    
    for (const business of businesses) {
      try {
        await this.rateLimit()
        
        logger.info('COCPScraping', `Deep scraping website: ${business.url}`)
        
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
          const businessWithDeepData: ChamberOfCommerceBusinessResult = {
            ...business,
            businessRecords: scrapingResult
          }
          
          businessesWithDeepData.push(businessWithDeepData)
          
          logger.info('COCPScraping', `Successfully scraped ${scrapingResult.length} business records from ${business.url}`)
        } else {
          // Keep the business even if deep scraping failed
          businessesWithDeepData.push(business)
          logger.warn('COCPScraping', `Deep scraping failed for ${business.url}, keeping basic info`)
        }
        
      } catch (error) {
        logger.error('COCPScraping', `Deep scraping error for ${business.url}:`, error)
        // Keep the business even if deep scraping failed
        businessesWithDeepData.push(business)
      }
    }
    
    logger.info('COCPScraping', `Completed deep scraping. ${businessesWithDeepData.length} businesses processed`)
    return businessesWithDeepData
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    if (this.browser) {
      await this.browser.close()
      this.browser = null
      logger.info('COCPScraping', 'Browser closed')
    }
  }

  /**
   * Get service status
   */
  getStatus() {
    return {
      requestCount: this.requestCount,
      lastRequestTime: this.lastRequestTime,
      browserActive: !!this.browser
    }
  }
}

// Export singleton instance
export const chamberOfCommerceScrapingService = new ChamberOfCommerceScrapingService()
