import { NextRequest, NextResponse } from 'next/server'
import { searchEngine } from '@/model/searchEngine'
import { logger } from '@/utils/logger'
import { withApiSecurity } from '@/lib/api-security'
import { withValidation, commonSchemas } from '@/lib/validation-middleware'
import { getClientIP } from '@/lib/security'
import { validationService } from '@/utils/validation'
import { bbbScrapingService } from '@/lib/bbbScrapingService'
import { metrics } from '@/lib/metrics'
import type { Page } from 'puppeteer'

/**
 * Interface for search request data
 */
interface SearchRequestData {
  body: {
    provider: string
    query: string
    location: string
    maxResults?: number
    industry?: string
    enableOptimization?: boolean
    page?: number
    accreditedOnly?: boolean
    zipRadius?: number
    maxPagesPerSite?: number
    url?: string
  }
}

/**
 * Interface for search result item
 */
interface SearchResultItem {
  title: string
  url: string
  snippet?: string
  businessName?: string
  address?: string
  phone?: string
  website?: string
  rating?: number
  reviewCount?: number
}

/**
 * Search for businesses
 */
const searchHandler = withApiSecurity(
  withValidation(
    async (request: NextRequest, validatedData: SearchRequestData) => {
      const ip = getClientIP(request)
      const {
        provider,
        query,
        location,
        maxResults = 1000,
        industry,
        enableOptimization = false,
      } = validatedData.body || {}

      logger.info('Search API', `Search request from IP: ${ip}`, { provider, query, location })

      try {
        // Handle DuckDuckGo SERP scraping requests
        if (provider === 'duckduckgo-serp') {
          const { page = 0 } = validatedData.body || {}
          return await handleDuckDuckGoSERP(query, page, maxResults)
        }

        // Handle BBB business discovery requests
        if (provider === 'bbb-discovery') {
          const {
            location: bbbLocation,
            accreditedOnly = false,
            zipRadius = 10,
          } = validatedData.body || {}
          return await handleBBBBusinessDiscovery(
            query,
            bbbLocation || location,
            accreditedOnly,
            zipRadius,
            maxResults
          )
        }

        // Handle Yelp business discovery requests
        if (provider === 'yelp-discovery') {
          const {
            location: yelpLocation,
            zipRadius = 25,
            maxPagesPerSite = 20,
          } = validatedData.body || {}
          return await handleYelpBusinessDiscovery(
            query,
            yelpLocation || location,
            zipRadius,
            maxResults,
            maxPagesPerSite
          )
        }

        // Handle Chamber of Commerce processing requests
        if (provider === 'chamber-of-commerce') {
          const { url, maxPagesPerSite = 20 } = validatedData.body || {}
          return await handleChamberOfCommerceProcessing(url, maxResults, maxPagesPerSite)
        }

        // Handle comprehensive search using search orchestrator
        if (provider === 'comprehensive') {
          const {
            location: compLocation,
            zipRadius = 25,
            accreditedOnly = false,
          } = validatedData.body || {}
          return await handleComprehensiveSearch(
            query,
            compLocation || location,
            zipRadius,
            accreditedOnly,
            maxResults
          )
        }

        // Validate required fields for regular search
        if (!query || !location) {
          return NextResponse.json({ error: 'Query and location are required' }, { status: 400 })
        }

        // Sanitize inputs
        const sanitizedQuery = validationService.sanitizeInput(query).substring(0, 100)
        const sanitizedLocation = validationService.sanitizeInput(location).substring(0, 100)
        const sanitizedIndustry = industry
          ? validationService.sanitizeInput(industry).substring(0, 50)
          : undefined

        // Parse maxResults (no upper limit - gather as many as possible)
        const validMaxResults = Math.max(parseInt(maxResults) || 1000, 1)

        logger.info('Search API', `Search request: "${sanitizedQuery}" in "${sanitizedLocation}"`, {
          industry: sanitizedIndustry,
          maxResults: validMaxResults,
          enableOptimization,
        })

        let results
        let optimization
        let performance

        if (enableOptimization && sanitizedIndustry) {
          // Use optimized search
          const optimizedResult = await searchEngine.searchBusinessesOptimized(
            sanitizedQuery,
            sanitizedLocation,
            sanitizedIndustry,
            validMaxResults
          )

          results = optimizedResult.results
          optimization = optimizedResult.optimization
          performance = optimizedResult.performance
        } else {
          // Use regular search
          results = await searchEngine.searchBusinesses(
            sanitizedQuery,
            sanitizedLocation,
            validMaxResults,
            true // Enable validation
          )
        }

        logger.info('Search API', `Search completed: ${results.length} results found`)

        const response = {
          success: true,
          results,
          query: sanitizedQuery,
          location: sanitizedLocation,
          industry: sanitizedIndustry,
          maxResults: validMaxResults,
          count: results.length,
          ...(optimization && { optimization }),
          ...(performance && { performance }),
        }

        return NextResponse.json(response)
      } catch (error) {
        logger.error('Search API', 'Search request failed', error)

        return NextResponse.json(
          {
            success: false,
            error: 'Search failed',
            message: error instanceof Error ? error.message : 'Unknown error',
          },
          { status: 500 }
        )
      }
    },
    {
      body: [
        {
          field: 'provider',
          type: 'string' as const,
          allowedValues: [
            'duckduckgo-serp',
            'bbb-discovery',
            'yelp-discovery',
            'chamber-of-commerce',
            'comprehensive',
          ],
        },
        { field: 'query', required: true, type: 'string' as const, minLength: 1, maxLength: 500 },
        { field: 'location', type: 'string' as const, maxLength: 200 },
        { field: 'maxResults', type: 'number' as const, min: 1, max: 10000 },
        { field: 'industry', type: 'string' as const, maxLength: 100 },
        { field: 'enableOptimization', type: 'boolean' as const },
        { field: 'page', type: 'number' as const, min: 0, max: 100 },
        { field: 'accreditedOnly', type: 'boolean' as const },
        { field: 'zipRadius', type: 'number' as const, min: 1, max: 100 },
        { field: 'maxPagesPerSite', type: 'number' as const, min: 1, max: 50 },
        { field: 'url', type: 'url' as const },
      ],
    }
  ),
  {
    requireAuth: false, // Allow public access for now, but with rate limiting
    rateLimit: 'scraping',
    validateInput: false, // Disable to avoid conflict with withValidation middleware
    logRequests: true,
  }
)

export const POST = searchHandler

/**
 * Get search suggestions
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const { searchParams } = new URL(request.url)
    const query = searchParams.get('q') || ''
    const location = searchParams.get('location') || ''
    const industry = searchParams.get('industry') || ''

    if (!query) {
      return NextResponse.json({ error: 'Query parameter "q" is required' }, { status: 400 })
    }

    // Sanitize inputs
    const sanitizedQuery = validationService.sanitizeInput(query).substring(0, 100)
    const sanitizedLocation = location
      ? validationService.sanitizeInput(location).substring(0, 100)
      : undefined
    const sanitizedIndustry = industry
      ? validationService.sanitizeInput(industry).substring(0, 50)
      : undefined

    logger.info('Search API', `Suggestions request: "${sanitizedQuery}"`)

    const suggestions = searchEngine.getQuerySuggestions(
      sanitizedQuery,
      sanitizedLocation,
      sanitizedIndustry
    )

    return NextResponse.json({
      success: true,
      query: sanitizedQuery,
      suggestions,
      count: suggestions.length,
    })
  } catch (error) {
    logger.error('Search API', 'Suggestions request failed', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to get suggestions',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Handle DuckDuckGo SERP scraping to get real business websites using headless browser
 */
async function handleDuckDuckGoSERP(query: string, page: number, maxResults: number) {
  const startTime = Date.now()
  let browserInstance: any = null

  try {
    // Import rate limiting service
    const { RateLimitingService } = await import('@/lib/rateLimitingService')
    const rateLimiter = new RateLimitingService()

    // Check if DuckDuckGo is temporarily disabled due to repeated failures
    const failureCount = rateLimiter.getFailureCount('duckduckgo')
    if (failureCount >= 5) {
      logger.warn(
        'Search API',
        `DuckDuckGo temporarily disabled due to ${failureCount} consecutive failures`
      )
      return NextResponse.json(
        {
          success: false,
          error: 'Service temporarily unavailable',
          message: 'DuckDuckGo is temporarily disabled due to repeated rate limiting',
          retryAfter: 3600000, // 1 hour
        },
        { status: 503 }
      )
    }

    // Check rate limits and wait if necessary
    await rateLimiter.waitForRequest('duckduckgo')

    const rateLimitStatus = rateLimiter.canMakeRequest('duckduckgo')
    if (!rateLimitStatus.canMakeRequest) {
      logger.warn('Search API', `DuckDuckGo rate limit exceeded`, rateLimitStatus)
      return NextResponse.json(
        {
          success: false,
          error: 'Rate limit exceeded',
          message: '429',
          retryAfter: rateLimitStatus.recommendedDelay,
        },
        { status: 429 }
      )
    }

    logger.info('Search API', `DuckDuckGo SERP scraping: ${query} (page ${page + 1})`, {
      rateLimitStatus: {
        requestsInLastMinute: rateLimitStatus.requestsInLastMinute,
        requestsInLastHour: rateLimitStatus.requestsInLastHour,
        backoffLevel: rateLimitStatus.backoffLevel,
      },
    })

    // Import required modules
    const puppeteer = await import('puppeteer')
    const { NetworkSpoofingService } = await import('@/lib/networkSpoofingService')

    // Initialize network spoofing service with enhanced stealth
    const spoofingService = new NetworkSpoofingService({
      enableProxyRotation: false, // Disable for now to avoid connection issues
      enableIPSpoofing: true,
      enableMACAddressSpoofing: true,
      enableFingerprintSpoofing: true,
      requestDelay: { min: 8000, max: 20000 }, // Much longer delays for DuckDuckGo
    })

    // Get proxy arguments for browser launch (if enabled)
    const proxyArgs = spoofingService.getCurrentProxyArgs()

    // Launch browser with maximum stealth settings for DuckDuckGo
    browserInstance = await puppeteer.default.launch({
      headless: 'new',
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
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-features=TranslateUI',
        '--disable-ipc-flooding-protection',
        '--disable-automation',
        '--exclude-switches=enable-automation',
        '--disable-extensions-http-throttling',
        '--disable-client-side-phishing-detection',
        '--disable-sync',
        '--disable-default-apps',
        '--disable-component-update',
        '--disable-background-networking',
        '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ...proxyArgs,
      ],
      ignoreDefaultArgs: ['--enable-automation'],
      ignoreHTTPSErrors: true,
    })

    try {
      const browserPage = await browserInstance.newPage()

      // Apply comprehensive network spoofing
      await spoofingService.applyNetworkSpoofing(browserPage)

      // Apply enhanced console filtering and resource blocking
      const { setupCleanScraping } = await import('@/lib/consoleFilterUtils')
      await setupCleanScraping(browserPage, {
        consoleFilter: {
          filterLevel: 'strict',
          logCriticalErrors: true,
          logPageErrors: true,
          customFilters: [
            'useTranslation: DISMISS is not available',
            'expanded-maps-vertical',
            'duckassist-ia',
          ],
        },
        resourceBlocking: 'strict',
      })

      // Additional stealth measures
      await browserPage.evaluateOnNewDocument(() => {
        // Override webdriver property
        Object.defineProperty(navigator, 'webdriver', {
          get: () => undefined,
        })

        // Override automation properties
        delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Array
        delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Promise
        delete (window as any).cdc_adoQpoasnfa76pfcZLmcfl_Symbol

        // Override plugins
        Object.defineProperty(navigator, 'plugins', {
          get: () => [1, 2, 3, 4, 5],
        })

        // Override permissions
        const originalQuery = window.navigator.permissions.query
        window.navigator.permissions.query = parameters =>
          parameters.name === 'notifications'
            ? Promise.resolve({ state: Notification.permission })
            : originalQuery(parameters)
      })

      // Set additional headers to appear more human-like
      await browserPage.setExtraHTTPHeaders({
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        Pragma: 'no-cache',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        DNT: '1',
      })

      // Randomize user agent from a pool (backup to spoofing service)
      const userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
      ]

      // Backup user agent setting (spoofing service already handles this)
      const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)]
      logger.debug('Search API', `Using backup user agent: ${randomUserAgent.substring(0, 50)}...`)

      // Note: Resource blocking and console filtering is now handled by setupCleanScraping above

      // Construct DuckDuckGo search URL - use the format you specified
      const searchUrl = new URL('https://duckduckgo.com/')
      searchUrl.searchParams.set('t', 'h_')
      searchUrl.searchParams.set('q', query)
      searchUrl.searchParams.set('ia', 'web')

      if (page > 0) {
        searchUrl.searchParams.set('s', (page * 30).toString()) // DuckDuckGo shows ~30 results per page
      }

      logger.info('Search API', `Navigating to DuckDuckGo SERP: ${searchUrl.toString()}`)

      // Add much longer random delay before navigation to simulate human behavior
      await new Promise(resolve => setTimeout(resolve, 5000 + Math.random() * 10000))

      // Navigate to DuckDuckGo search page with longer timeout
      await browserPage.goto(searchUrl.toString(), {
        waitUntil: 'networkidle2',
        timeout: 60000, // Increased timeout to 60 seconds
      })

      // Simulate extensive human-like behavior after page load
      await new Promise(resolve => setTimeout(resolve, 3000 + Math.random() * 5000))

      // Multiple random mouse movements to simulate human browsing
      for (let i = 0; i < 3; i++) {
        await browserPage.mouse.move(Math.random() * 1200, Math.random() * 800)
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000))
      }

      // Simulate scrolling behavior
      await browserPage.evaluate(() => {
        window.scrollTo(0, Math.random() * 500)
      })
      await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 3000))

      // Check if page is blocked or rate limited
      const pageContent = await browserPage.content()
      const pageTitle = await browserPage.title()

      if (
        pageContent.includes('rate limit') ||
        pageContent.includes('too many requests') ||
        pageTitle.includes('blocked') ||
        pageContent.includes('429')
      ) {
        logger.warn('Search API', 'DuckDuckGo page indicates rate limiting or blocking')
        throw new Error('429')
      }

      // Wait for search results to load with increased timeout
      await browserPage.waitForSelector('[data-testid="result"], .result, .web-result', {
        timeout: 20000,
      })

      // Extract search results using the browser
      const results = await extractDuckDuckGoSERPResults(browserPage, maxResults)

      await browserInstance.close()
      browserInstance = null

      const responseTime = Date.now() - startTime

      // Record successful request
      const { RateLimitingService } = await import('@/lib/rateLimitingService')
      const rateLimiter = new RateLimitingService()
      rateLimiter.recordRequest('duckduckgo', true, responseTime, 200)

      logger.info('Search API', `DuckDuckGo SERP scraping returned ${results.length} results`, {
        responseTime,
        resultsCount: results.length,
      })

      return NextResponse.json({
        success: true,
        provider: 'duckduckgo-serp',
        query: query,
        page: page,
        results: results,
        count: results.length,
        responseTime,
      })
    } finally {
      if (browserInstance) {
        await browserInstance.close()
      }
    }
  } catch (error) {
    // Clean up browser if it exists
    if (browserInstance) {
      try {
        await browserInstance.close()
      } catch (closeError) {
        logger.warn('Search API', 'Failed to close browser', closeError)
      }
    }

    const responseTime = Date.now() - startTime

    // Record failed request
    try {
      const { RateLimitingService } = await import('@/lib/rateLimitingService')
      const rateLimiter = new RateLimitingService()

      // Determine error type and status code
      let statusCode = 500
      let errorType = 'unknown'

      if (error instanceof Error) {
        if (error.message.includes('429') || error.message.includes('Rate limit')) {
          statusCode = 429
          errorType = 'rate_limit'
        } else if (error.message.includes('timeout') || error.message.includes('Timeout')) {
          statusCode = 408
          errorType = 'timeout'
        } else if (error.message.includes('blocked') || error.message.includes('forbidden')) {
          statusCode = 403
          errorType = 'blocked'
        }
      }

      rateLimiter.recordRequest('duckduckgo', false, responseTime, statusCode, errorType)
    } catch (rateLimiterError) {
      logger.warn('Search API', 'Failed to record failed request in rate limiter', rateLimiterError)
    }

    logger.error('Search API', 'DuckDuckGo SERP scraping failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      responseTime,
      query,
      page,
    })

    // Check if this is a rate limiting error
    const isRateLimit =
      error instanceof Error &&
      (error.message.includes('429') || error.message.includes('Rate limit'))

    return NextResponse.json(
      {
        success: false,
        error: isRateLimit ? 'Rate limit exceeded' : 'DuckDuckGo SERP scraping failed',
        message: error instanceof Error ? error.message : 'Unknown error',
        responseTime,
      },
      { status: isRateLimit ? 429 : 500 }
    )
  }
}

/**
 * Extract search results from DuckDuckGo SERP using browser automation
 */
async function extractDuckDuckGoSERPResults(
  page: Page,
  maxResults: number
): Promise<SearchResultItem[]> {
  return await page.evaluate((maxResults: number) => {
    const results: SearchResultItem[] = []

    console.log('Extracting DuckDuckGo SERP results...')

    // Look for search result containers - DuckDuckGo uses various selectors
    const resultSelectors = [
      '[data-testid="result"]',
      '.result',
      '.web-result',
      '.result__body',
      '.results .result',
      'article[data-testid="result"]',
    ]

    let resultElements: NodeListOf<Element> | null = null

    for (const selector of resultSelectors) {
      resultElements = document.querySelectorAll(selector)
      if (resultElements.length > 0) {
        console.log(`Found ${resultElements.length} results using selector: ${selector}`)
        break
      }
    }

    if (!resultElements || resultElements.length === 0) {
      console.log('No search results found on page')
      return results
    }

    for (let i = 0; i < Math.min(resultElements.length, maxResults); i++) {
      const resultElement = resultElements[i]

      if (!resultElement) {
        continue
      }

      try {
        // Extract title and URL - look for the main result link
        const titleLinkSelectors = [
          'h2 a',
          'h3 a',
          '.result__title a',
          '.result__a',
          'a[data-testid="result-title-a"]',
          'a.result__url',
        ]

        let titleLink: HTMLAnchorElement | null = null
        let title = ''
        let url = ''

        for (const selector of titleLinkSelectors) {
          titleLink = resultElement.querySelector(selector) as HTMLAnchorElement
          if (titleLink && titleLink.href) {
            title = titleLink.textContent?.trim() || ''
            url = titleLink.href
            break
          }
        }

        if (!url || !title) {
          continue
        }

        // Extract snippet/description
        const snippetSelectors = [
          '.result__snippet',
          '.result__body',
          '.snippet',
          '[data-testid="result-snippet"]',
          '.result-snippet',
        ]

        let snippet = ''
        for (const selector of snippetSelectors) {
          const snippetElement = resultElement.querySelector(selector)
          if (snippetElement) {
            snippet = snippetElement.textContent?.trim() || ''
            break
          }
        }

        // Filter out non-business domains and DuckDuckGo internal links
        const domain = new URL(url).hostname.toLowerCase()

        // Define business domain filtering logic inline
        const excludedDomains = [
          'duckduckgo.com',
          'google.com',
          'bing.com',
          'yahoo.com',
          'wikipedia.org',
          'facebook.com',
          'twitter.com',
          'linkedin.com',
          'instagram.com',
          'youtube.com',
          'reddit.com',
          'pinterest.com',
          'amazon.com',
          'ebay.com',
          'craigslist.org',
        ]

        const isBusinessDomain =
          !excludedDomains.some(excluded => domain.includes(excluded)) &&
          !url.includes('duckduckgo.com') &&
          !url.includes('javascript:') &&
          !url.startsWith('javascript:') &&
          url.startsWith('http')

        if (isBusinessDomain) {
          results.push({
            url: url,
            title: title,
            snippet: snippet,
            domain: domain,
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
 * Parse DuckDuckGo SERP HTML to extract business website URLs (legacy fallback)
 */
function parseDuckDuckGoSERP(html: string, maxResults: number): SearchResultItem[] {
  const results: SearchResultItem[] = []

  try {
    // DuckDuckGo uses various CSS selectors for search results
    // We'll look for common patterns in the HTML

    // Extract URLs using regex patterns (more reliable than DOM parsing for server-side)
    const urlPatterns = [
      // Standard web result links
      /href="([^"]*uddg[^"]*)"[^>]*>([^<]+)</g,
      // Direct result links
      /href="(https?:\/\/[^"]+)"[^>]*class="[^"]*result[^"]*"[^>]*>([^<]+)</g,
      // Alternative result patterns
      /<a[^>]+href="(https?:\/\/[^"]+)"[^>]*>([^<]+)<\/a>/g,
    ]

    const urlRegex = /https?:\/\/[^\s<>"']+\.[a-z]{2,}/gi
    const urlMatches = html.match(urlRegex) || []

    // Extract titles and snippets from the HTML
    const titleRegex = /<h[1-6][^>]*>([^<]+)<\/h[1-6]>/gi
    const titleMatches = []
    let titleMatch
    while ((titleMatch = titleRegex.exec(html)) !== null) {
      titleMatches.push(titleMatch[1])
    }

    // Process found URLs
    const seenUrls = new Set<string>()

    for (const url of urlMatches) {
      if (results.length >= maxResults) break
      if (seenUrls.has(url)) continue

      try {
        const urlObj = new URL(url)
        const domain = urlObj.hostname.toLowerCase()

        // Filter out non-business domains
        if (shouldIncludeBusinessDomain(domain)) {
          seenUrls.add(url)

          // Try to find a matching title
          const title = titleMatches[results.length] || `Business - ${domain}`

          results.push({
            url: url,
            title: title,
            snippet: `Business website found via DuckDuckGo search`,
            domain: domain,
          })

          logger.info('Search API', `Extracted business URL: ${url}`)
        }
      } catch {
        // Skip invalid URLs
      }
    }
  } catch (error) {
    logger.warn('Search API', 'Failed to parse DuckDuckGo SERP HTML', error)
  }

  return results
}

/**
 * Determine if a domain should be included as a business result
 */
function shouldIncludeBusinessDomain(domain: string): boolean {
  // Exclude search engines, social media, and other non-business sites
  const excludeDomains = [
    'google.com',
    'bing.com',
    'yahoo.com',
    'duckduckgo.com',
    'facebook.com',
    'twitter.com',
    'instagram.com',
    'linkedin.com',
    'youtube.com',
    'wikipedia.org',
    'reddit.com',
    'pinterest.com',
    'amazon.com',
    'ebay.com',
    'craigslist.org',
  ]

  if (excludeDomains.some(excluded => domain.includes(excluded))) {
    return false
  }

  // Include business directory sites
  const businessDirectories = [
    'yelp.com',
    'yellowpages.com',
    'bbb.org',
    'foursquare.com',
    'tripadvisor.com',
    'angieslist.com',
  ]

  if (businessDirectories.some(directory => domain.includes(directory))) {
    return true
  }

  // Include domains that look like business websites
  const businessTLDs = ['.com', '.net', '.org', '.biz', '.info']
  const hasBusinessTLD = businessTLDs.some(tld => domain.endsWith(tld))

  const businessKeywords = [
    'restaurant',
    'cafe',
    'medical',
    'dental',
    'law',
    'legal',
    'clinic',
    'hospital',
    'shop',
    'store',
    'service',
    'repair',
    'salon',
    'spa',
    'fitness',
    'gym',
    'auto',
    'insurance',
  ]

  const hasBusinessKeyword = businessKeywords.some(keyword => domain.includes(keyword))

  return hasBusinessTLD && (hasBusinessKeyword || domain.split('.').length === 2)
}

/**
 * Handle BBB business discovery - uses dedicated BBB scraping service
 */
async function handleBBBBusinessDiscovery(
  query: string,
  location: string,
  accreditedOnly: boolean,
  zipRadius: number,
  maxResults: number
) {
  try {
    logger.info(
      'Search API',
      `BBB business discovery: ${query} in ${location} (accredited: ${accreditedOnly}, radius: ${zipRadius}mi)`
    )

    // Check if this is an industry category that should be expanded
    const expandedCriteria = expandIndustryCategories(query)

    if (expandedCriteria.length > 0) {
      logger.info(
        'Search API',
        `Expanded industry category "${query}" to: ${expandedCriteria.join(', ')}`
      )

      // Search for each expanded criteria individually
      const allBusinessWebsites: SearchResultItem[] = []
      const resultsPerCriteria = Math.ceil(maxResults / expandedCriteria.length)

      for (const criteria of expandedCriteria) {
        try {
          logger.info('Search API', `BBB searching for: "${criteria}" in ${location}`)

          const criteriaResults = await bbbScrapingService.searchBusinesses({
            query: criteria,
            location,
            accreditedOnly,
            zipRadius,
            maxResults: resultsPerCriteria,
          })

          allBusinessWebsites.push(...criteriaResults)

          if (allBusinessWebsites.length >= maxResults) {
            break
          }
        } catch (error) {
          logger.warn('Search API', `BBB search failed for criteria "${criteria}"`, error)
          continue
        }
      }

      // Remove duplicates and limit results
      const uniqueResults = removeDuplicateBusinesses(allBusinessWebsites).slice(0, maxResults)

      // Note: No longer adding directory search URLs as business results
      // Use dedicated discovery services (Yelp Discovery, BBB Discovery) instead

      logger.info(
        'Search API',
        `BBB business discovery returned ${uniqueResults.length} business websites for expanded criteria`
      )

      return NextResponse.json({
        success: true,
        provider: 'bbb-discovery',
        query: query,
        expandedTo: expandedCriteria,
        location: location,
        results: uniqueResults,
        count: uniqueResults.length,
      })
    }

    // Use the dedicated BBB scraping service for non-expanded queries
    const businessWebsites = await bbbScrapingService.searchBusinesses({
      query,
      location,
      accreditedOnly,
      zipRadius,
      maxResults,
    })

    // Note: No longer adding directory search URLs as business results
    // Use dedicated discovery services (Yelp Discovery, BBB Discovery) instead

    logger.info(
      'Search API',
      `BBB business discovery returned ${businessWebsites.length} business websites`
    )

    return NextResponse.json({
      success: true,
      provider: 'bbb-discovery',
      query: query,
      location: location,
      results: businessWebsites,
      count: businessWebsites.length,
    })
  } catch (error) {
    logger.error('Search API', 'BBB business discovery failed', error)

    // Return error when BBB scraping fails - no directory URLs as fallback
    return NextResponse.json(
      {
        success: false,
        error: 'BBB business discovery failed and no fallback available',
        provider: 'bbb-discovery',
        query: query,
        location: location,
        results: [],
        count: 0,
      },
      { status: 500 }
    )
  }
}

/**
 * Expand industry categories into their constituent keywords
 */
function expandIndustryCategories(query: string): string[] {
  const queryLower = query.toLowerCase().trim()

  // Define industry category mappings
  const industryMappings: Record<string, string[]> = {
    // Professional Services
    'professional services': ['consulting', 'legal', 'accounting', 'financial', 'insurance'],
    'professional services businesses': [
      'consulting',
      'legal',
      'accounting',
      'financial',
      'insurance',
    ],
    professional: ['consulting', 'legal', 'accounting', 'financial', 'insurance'],

    // Healthcare & Medical
    healthcare: ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    'healthcare & medical': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    'healthcare businesses': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    medical: ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    'medical businesses': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],

    // Restaurants & Food Service
    restaurants: ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'restaurants & food service': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'restaurant businesses': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'food service': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'food businesses': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],

    // Retail & Shopping
    retail: ['retail', 'store', 'shop', 'boutique', 'marketplace'],
    'retail & shopping': ['retail', 'store', 'shop', 'boutique', 'marketplace'],
    'retail businesses': ['retail', 'store', 'shop', 'boutique', 'marketplace'],
    shopping: ['retail', 'store', 'shop', 'boutique', 'marketplace'],

    // Construction & Contractors
    construction: ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],
    'construction & contractors': [
      'construction',
      'contractor',
      'builder',
      'renovation',
      'plumbing',
    ],
    'construction businesses': ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],
    contractors: ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],

    // Automotive
    automotive: ['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'],
    'automotive businesses': [
      'automotive',
      'car repair',
      'auto service',
      'mechanic',
      'tire service',
    ],
    auto: ['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'],
    'auto businesses': ['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'],

    // Technology
    technology: ['technology', 'IT services', 'software', 'computer repair', 'web design'],
    'technology businesses': [
      'technology',
      'IT services',
      'software',
      'computer repair',
      'web design',
    ],
    tech: ['technology', 'IT services', 'software', 'computer repair', 'web design'],
    'tech businesses': ['technology', 'IT services', 'software', 'computer repair', 'web design'],

    // Beauty & Personal Care
    beauty: ['salon', 'spa', 'beauty', 'hair', 'nail salon'],
    'beauty businesses': ['salon', 'spa', 'beauty', 'hair', 'nail salon'],
    'personal care': ['salon', 'spa', 'beauty', 'hair', 'nail salon'],
    'personal care businesses': ['salon', 'spa', 'beauty', 'hair', 'nail salon'],

    // Home Services
    'home services': ['cleaning', 'landscaping', 'pest control', 'home repair', 'HVAC'],
    'home services businesses': ['cleaning', 'landscaping', 'pest control', 'home repair', 'HVAC'],
    home: ['cleaning', 'landscaping', 'pest control', 'home repair', 'HVAC'],

    // Education
    education: ['school', 'tutoring', 'training', 'education', 'learning center'],
    'education businesses': ['school', 'tutoring', 'training', 'education', 'learning center'],
    educational: ['school', 'tutoring', 'training', 'education', 'learning center'],

    // Entertainment
    entertainment: ['entertainment', 'event planning', 'photography', 'music', 'recreation'],
    'entertainment businesses': [
      'entertainment',
      'event planning',
      'photography',
      'music',
      'recreation',
    ],
  }

  // Check for exact matches first using safe property access
  if (Object.prototype.hasOwnProperty.call(industryMappings, queryLower)) {
    return industryMappings[queryLower as keyof typeof industryMappings]
  }

  // Check for partial matches - but be more specific to avoid false matches
  for (const [category, keywords] of Object.entries(industryMappings)) {
    // Only match if the query contains the category as a whole word or phrase
    // This prevents "construction" from matching "professional" etc.
    if (queryLower.includes(category)) {
      return keywords
    }
  }

  return [] // No expansion found
}

/**
 * Remove duplicate businesses based on URL and title
 */
function removeDuplicateBusinesses(businesses: SearchResultItem[]): SearchResultItem[] {
  const seen = new Set<string>()
  const unique: SearchResultItem[] = []

  for (const business of businesses) {
    // Create a unique key based on URL and title
    const key = `${business.url}|${business.title}`.toLowerCase()

    if (!seen.has(key)) {
      seen.add(key)
      unique.push(business)
    }
  }

  return unique
}

/**
 * Generate alternative business search URLs when BBB scraping isn't available
 */
function generateAlternativeBusinessSearches(
  query: string,
  location: string,
  maxResults: number
): SearchResultItem[] {
  // Return empty array - directory search URLs should not be returned as business websites
  // The proper approach is to use dedicated discovery services (Yelp Discovery, BBB Discovery)
  // that extract actual business websites from directory pages
  logger.info(
    'Search API',
    `Not generating directory search URLs as business results for ${query} in ${location}`
  )
  return []
}

/**
 * Handle Yelp business discovery
 */
async function handleYelpBusinessDiscovery(
  query: string,
  location: string,
  zipRadius: number,
  maxResults: number,
  maxPagesPerSite: number = 20
) {
  try {
    logger.info(
      'Search API',
      `Yelp business discovery with deep scraping: ${query} in ${location} (max ${maxPagesPerSite} pages per site)`
    )

    // Import Yelp scraping service
    const { yelpScrapingService } = await import('@/lib/yelpScrapingService')

    const businessWebsites = await yelpScrapingService.searchBusinesses({
      query,
      location,
      zipRadius,
      maxResults,
      maxPagesPerSite,
    })

    logger.info(
      'Search API',
      `Yelp business discovery returned ${businessWebsites.length} business websites`
    )

    return NextResponse.json({
      success: true,
      provider: 'yelp-discovery',
      query: query,
      location: location,
      results: businessWebsites,
      count: businessWebsites.length,
    })
  } catch (error) {
    logger.error('Search API', 'Yelp business discovery failed', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Yelp business discovery failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Handle comprehensive search using the search orchestrator
 */
async function handleComprehensiveSearch(
  query: string,
  location: string,
  zipRadius: number,
  accreditedOnly: boolean,
  maxResults: number
) {
  try {
    logger.info('Search API', `Comprehensive search: ${query} in ${location}`)

    // Import search orchestrator
    const { searchOrchestrator } = await import('@/lib/searchProviderAbstraction')

    const results = await searchOrchestrator.searchBusinesses({
      query,
      location,
      zipRadius,
      accreditedOnly,
      maxResults,
    })

    logger.info('Search API', `Comprehensive search returned ${results.length} business results`)

    return NextResponse.json({
      success: true,
      provider: 'comprehensive',
      query: query,
      location: location,
      results: results,
      count: results.length,
      providerStats: searchOrchestrator.getProviderStats(),
    })
  } catch (error) {
    logger.error('Search API', 'Comprehensive search failed', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Comprehensive search failed',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Handle Chamber of Commerce processing
 */
async function handleChamberOfCommerceProcessing(
  url: string,
  maxResults: number,
  maxPagesPerSite: number = 20
) {
  try {
    logger.info(
      'Search API',
      `Chamber of Commerce processing: ${url} (max ${maxPagesPerSite} pages per site)`
    )

    // Import Chamber of Commerce scraping service
    const { chamberOfCommerceScrapingService } = await import(
      '@/lib/chamberOfCommerceScrapingService'
    )

    const businessWebsites = await chamberOfCommerceScrapingService.processChamberOfCommercePage({
      url,
      maxBusinesses: maxResults,
      maxPagesPerSite,
    })

    logger.info(
      'Search API',
      `Chamber of Commerce processing returned ${businessWebsites.length} business websites`
    )

    return NextResponse.json({
      success: true,
      provider: 'chamber-of-commerce',
      url: url,
      results: businessWebsites,
      count: businessWebsites.length,
    })
  } catch (error) {
    logger.error('Search API', 'Chamber of Commerce processing failed', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Chamber of Commerce processing failed',
        provider: 'chamber-of-commerce',
        url: url,
        results: [],
        count: 0,
      },
      { status: 500 }
    )
  }
}
