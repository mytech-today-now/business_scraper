import puppeteer, { Browser, Page } from 'puppeteer'
import { logger } from '@/utils/logger'
import { zipCodeService } from './zipCodeService'

export interface BBBSearchOptions {
  query: string
  location: string
  accreditedOnly: boolean
  zipRadius: number
  maxResults: number
}

export interface BBBBusinessResult {
  url: string
  title: string
  snippet: string
  domain: string
  address?: string
  phone?: string
  bbbProfileUrl?: string
}

export class BBBScrapingService {
  private browser: Browser | null = null
  private requestCount = 0
  private lastRequestTime = 0
  private readonly minDelay = 1000 // Minimum 1 second between requests
  private readonly maxRetries = 3

  /**
   * Initialize the browser instance
   */
  private async initBrowser(): Promise<Browser> {
    if (this.browser) {
      return this.browser
    }

    logger.info('BBBScraping', 'Initializing Puppeteer browser')

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
      ],
    })

    return this.browser
  }

  /**
   * Create a new page with realistic settings
   */
  private async createPage(): Promise<Page> {
    const browser = await this.initBrowser()
    const page = await browser.newPage()

    // Set realistic user agent and viewport
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    )
    await page.setViewport({ width: 1366, height: 768 })

    // Set extra headers to appear more like a real browser
    await page.setExtraHTTPHeaders({
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate',
      DNT: '1',
      Connection: 'keep-alive',
      'Upgrade-Insecure-Requests': '1',
    })

    return page
  }

  /**
   * Implement rate limiting
   */
  private async rateLimit(): Promise<void> {
    const now = Date.now()
    const timeSinceLastRequest = now - this.lastRequestTime

    if (timeSinceLastRequest < this.minDelay) {
      const delay = this.minDelay - timeSinceLastRequest
      logger.info('BBBScraping', `Rate limiting: waiting ${delay}ms`)
      await new Promise(resolve => setTimeout(resolve, delay))
    }

    this.lastRequestTime = Date.now()
    this.requestCount++
  }

  /**
   * Search for businesses on BBB
   */
  async searchBusinesses(options: BBBSearchOptions): Promise<BBBBusinessResult[]> {
    const { query, location, accreditedOnly, zipRadius, maxResults } = options

    logger.info(
      'BBBScraping',
      `Starting BBB search: ${query} in ${location} (accredited: ${accreditedOnly}, radius: ${zipRadius}mi)`
    )

    let page: Page | null = null
    let retries = 0

    while (retries < this.maxRetries) {
      try {
        await this.rateLimit()

        page = await this.createPage()

        // Build BBB search URL
        const bbbSearchUrl = new URL('https://www.bbb.org/search')
        bbbSearchUrl.searchParams.set('find_country', 'USA')
        bbbSearchUrl.searchParams.set('find_text', query)
        bbbSearchUrl.searchParams.set('find_loc', location)

        if (accreditedOnly) {
          bbbSearchUrl.searchParams.set('find_type', 'accredited')
        }

        logger.info('BBBScraping', `Navigating to: ${bbbSearchUrl.toString()}`)

        // Navigate to BBB search page
        await page.goto(bbbSearchUrl.toString(), {
          waitUntil: 'networkidle2',
          timeout: 30000,
        })

        // Wait for search results to load - updated selectors for current BBB structure
        try {
          await page.waitForSelector(
            'section[aria-label="Search results"], .search-results, h3 a[href*="/profile/"]',
            { timeout: 15000 }
          )
          logger.info('BBBScraping', 'Search results page loaded successfully')
        } catch (error) {
          logger.warn('BBBScraping', 'Search results selector not found, proceeding anyway')
          // Continue anyway as the page might have loaded but with different structure
        }

        // Extract business information from search results
        const businesses = await this.extractBusinessListings(page, maxResults)

        if (businesses.length === 0) {
          logger.warn('BBBScraping', 'No businesses found on search page')
          await page.close()
          return []
        }

        logger.info('BBBScraping', `Found ${businesses.length} businesses on search page`)

        // Extract actual business websites from BBB profile pages
        const businessesWithWebsites = await this.extractBusinessWebsites(
          page,
          businesses,
          maxResults
        )

        // Filter businesses by ZIP radius if specified
        const filteredBusinesses = await this.filterByZipRadius(businessesWithWebsites, options)

        await page.close()

        logger.info(
          'BBBScraping',
          `Successfully extracted ${filteredBusinesses.length} business websites (${businessesWithWebsites.length} before radius filtering)`
        )
        return filteredBusinesses
      } catch (error) {
        retries++
        logger.warn('BBBScraping', `Attempt ${retries} failed`, error)

        if (page) {
          await page.close().catch(() => {})
        }

        if (retries >= this.maxRetries) {
          throw new Error(`BBB scraping failed after ${this.maxRetries} attempts: ${error}`)
        }

        // Exponential backoff
        const delay = Math.pow(2, retries) * 1000
        logger.info('BBBScraping', `Retrying in ${delay}ms`)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }

    return []
  }

  /**
   * Extract business listings from BBB search results page
   */
  private async extractBusinessListings(page: Page, maxResults: number): Promise<any[]> {
    return await page.evaluate(maxResults => {
      const businesses: any[] = []

      // Look for the search results section first
      const searchResultsSection =
        document.querySelector('section[aria-label="Search results"]') ||
        document.querySelector('.search-results') ||
        document.querySelector('[data-testid="search-results"]')

      if (!searchResultsSection) {
        console.log('No search results section found')
        return businesses
      }

      // Look for individual business listings within the search results
      // Based on the current BBB structure, each business is in an article or div with h3 heading
      const businessSelectors = [
        'article h3 a[href*="/profile/"]',
        'div h3 a[href*="/profile/"]',
        'h3 a[href*="/profile/"]',
        'a[href*="/profile/"]',
      ]

      let businessLinks: NodeListOf<HTMLAnchorElement> | null = null

      for (const selector of businessSelectors) {
        businessLinks = searchResultsSection.querySelectorAll(
          selector
        ) as NodeListOf<HTMLAnchorElement>
        if (businessLinks.length > 0) {
          console.log(`Found ${businessLinks.length} business links using selector: ${selector}`)
          break
        }
      }

      if (!businessLinks || businessLinks.length === 0) {
        console.log('No business links found in search results')
        return businesses
      }

      for (let i = 0; i < Math.min(businessLinks.length, maxResults); i++) {
        const link = businessLinks.at(i)

        if (!link) {
          continue
        }

        const businessName = link.textContent?.trim() || ''
        const profileUrl = link.getAttribute('href') || ''
        const fullProfileUrl = profileUrl.startsWith('/')
          ? `https://www.bbb.org${profileUrl}`
          : profileUrl

        if (!businessName || !fullProfileUrl) {
          continue
        }

        // Find the parent container for this business to extract additional info
        const businessContainer =
          link.closest('article') || link.closest('div[class*="result"]') || link.closest('div')

        let address = ''
        let phone = ''

        if (businessContainer) {
          // Look for address - it's usually in the text content after the business name
          const addressElements = Array.from(businessContainer.querySelectorAll('p, div, span'))
          for (const element of addressElements) {
            const text = element.textContent?.trim() || ''
            // Look for patterns that indicate an address (contains street number, state, zip)
            if (text.match(/\d+.*[A-Z]{2}\s+\d{5}/) || (text.includes(',') && text.length > 10)) {
              address = text
              break
            }
          }

          // Look for phone number
          const phoneLinks = businessContainer.querySelectorAll('a[href^="tel:"]')
          if (phoneLinks.length > 0 && phoneLinks[0]) {
            phone = phoneLinks[0].textContent?.trim() || ''
          }
        }

        businesses.push({
          name: businessName,
          bbbProfileUrl: fullProfileUrl,
          address: address,
          phone: phone,
          snippet: `${businessName}${address ? ' - ' + address : ''}`.trim(),
        })

        console.log(`Extracted business: ${businessName} -> ${fullProfileUrl}`)
      }

      console.log(`Total businesses extracted: ${businesses.length}`)
      return businesses
    }, maxResults)
  }

  /**
   * Extract business websites from BBB profile pages
   */
  private async extractBusinessWebsites(
    page: Page,
    businesses: any[],
    maxResults: number
  ): Promise<BBBBusinessResult[]> {
    const businessesWithWebsites: BBBBusinessResult[] = []

    // Limit to first 5 businesses to avoid too many requests
    const businessesToProcess = businesses.slice(0, Math.min(5, maxResults))

    for (const business of businessesToProcess) {
      try {
        await this.rateLimit()

        logger.info('BBBScraping', `Extracting website from: ${business.bbbProfileUrl}`)

        await page.goto(business.bbbProfileUrl, {
          waitUntil: 'networkidle2',
          timeout: 20000,
        })

        // Wait for profile page to load
        try {
          await page.waitForSelector(
            'main, .business-details, .business-info, .contact-info, .business-profile, h1',
            { timeout: 10000 }
          )
          logger.info('BBBScraping', 'Business profile page loaded successfully')
        } catch (error) {
          logger.warn('BBBScraping', 'Profile page selector not found, proceeding anyway')
          // Continue anyway as the page might have loaded but with different structure
        }

        // Extract business website URL
        const websiteUrl = await page.evaluate(() => {
          console.log('Looking for business website on BBB profile page...')

          // Look for website links with multiple strategies
          const websiteSelectors = [
            // Common patterns for website links on BBB profiles
            'a[href*="http"]:not([href*="bbb.org"]):not([href*="mailto:"]):not([href*="tel:"]):not([href*="facebook"]):not([href*="twitter"]):not([href*="linkedin"]):not([href*="instagram"])',
            '.website a',
            '.business-website a',
            '.contact-info a[href^="http"]',
            'a[title*="website"]',
            'a[title*="Website"]',
            'a[aria-label*="website"]',
            'a[aria-label*="Website"]',
            'a[data-track*="website"]',
            // Look for links in business details sections
            '.business-details a[href^="http"]',
            '.business-info a[href^="http"]',
            '.contact-details a[href^="http"]',
          ]

          for (const selector of websiteSelectors) {
            const links = Array.from(document.querySelectorAll(selector)) as HTMLAnchorElement[]
            console.log(`Checking selector "${selector}": found ${links.length} links`)

            for (const link of links) {
              if (
                link.href &&
                !link.href.includes('bbb.org') &&
                !link.href.includes('mailto:') &&
                !link.href.includes('tel:') &&
                !link.href.includes('facebook.com') &&
                !link.href.includes('twitter.com') &&
                !link.href.includes('linkedin.com') &&
                !link.href.includes('instagram.com') &&
                !link.href.includes('youtube.com') &&
                !link.href.includes('yelp.com') &&
                !link.href.includes('google.com')
              ) {
                console.log(`Found potential website: ${link.href}`)
                return link.href
              }
            }
          }

          // If no direct website links found, look for any external links in the page content
          const allLinks = Array.from(
            document.querySelectorAll('a[href^="http"]')
          ) as HTMLAnchorElement[]
          console.log(`Checking all ${allLinks.length} external links as fallback...`)

          for (const link of allLinks) {
            const href = link.href
            const linkText = link.textContent?.toLowerCase() || ''

            // Skip social media, BBB, and other non-business sites
            if (
              href.includes('bbb.org') ||
              href.includes('facebook.com') ||
              href.includes('twitter.com') ||
              href.includes('linkedin.com') ||
              href.includes('instagram.com') ||
              href.includes('youtube.com') ||
              href.includes('yelp.com') ||
              href.includes('google.com') ||
              href.includes('mailto:') ||
              href.includes('tel:')
            ) {
              continue
            }

            // Look for links that might be business websites
            if (
              linkText.includes('website') ||
              linkText.includes('visit') ||
              linkText.includes('www.') ||
              href.match(/^https?:\/\/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/)
            ) {
              console.log(`Found fallback website: ${href}`)
              return href
            }
          }

          console.log('No business website found on this BBB profile')
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
            bbbProfileUrl: business.bbbProfileUrl,
          })

          logger.info('BBBScraping', `Extracted website: ${websiteUrl} for ${business.name}`)
        } else {
          logger.warn('BBBScraping', `No website found for ${business.name}`)
        }
      } catch (error) {
        logger.warn('BBBScraping', `Failed to extract website for ${business.name}`, error)
        continue
      }
    }

    return businessesWithWebsites
  }

  /**
   * Filter businesses by ZIP radius
   */
  private async filterByZipRadius(
    businesses: BBBBusinessResult[],
    options: BBBSearchOptions
  ): Promise<BBBBusinessResult[]> {
    if (!options.zipRadius || options.zipRadius <= 0) {
      return businesses // No radius filtering requested
    }

    // Extract ZIP code from location
    const centerZip = zipCodeService.extractZipCodeFromAddress(options.location)
    if (!centerZip) {
      logger.warn('BBBScraping', `Could not extract ZIP code from location: ${options.location}`)
      return businesses // Return all if we can't extract center ZIP
    }

    const filteredBusinesses: BBBBusinessResult[] = []

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
          logger.info(
            'BBBScraping',
            `Filtered out ${business.title} - outside ${options.zipRadius}mi radius from ${centerZip}`
          )
        }
      } catch (error) {
        logger.warn('BBBScraping', `Error filtering business ${business.title}`, error)
        // Include business if filtering fails
        filteredBusinesses.push(business)
      }
    }

    logger.info(
      'BBBScraping',
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
      logger.info('BBBScraping', 'Browser closed')
    }
  }

  /**
   * Get scraping statistics
   */
  getStats() {
    return {
      requestCount: this.requestCount,
      lastRequestTime: this.lastRequestTime,
      browserActive: !!this.browser,
    }
  }
}

// Export singleton instance
export const bbbScrapingService = new BBBScrapingService()
