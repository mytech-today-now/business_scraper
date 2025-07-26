import { NextRequest, NextResponse } from 'next/server'
import { searchEngine } from '@/model/searchEngine'
import { logger } from '@/utils/logger'
import { validationService } from '@/utils/validation'
import { bbbScrapingService } from '@/lib/bbbScrapingService'

/**
 * Search for businesses
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { provider, query, location, maxResults = 10, industry, enableOptimization = false } = body

    // Handle DuckDuckGo proxy requests
    if (provider === 'duckduckgo') {
      return await handleDuckDuckGoProxy(query, maxResults)
    }

    // Handle DuckDuckGo SERP scraping requests
    if (provider === 'duckduckgo-serp') {
      const { page = 0 } = body
      return await handleDuckDuckGoSERP(query, page, maxResults)
    }

    // Handle BBB business discovery requests
    if (provider === 'bbb-discovery') {
      const { location, accreditedOnly = false, zipRadius = 10 } = body
      return await handleBBBBusinessDiscovery(query, location, accreditedOnly, zipRadius, maxResults)
    }

    // Handle Yelp business discovery requests
    if (provider === 'yelp-discovery') {
      const { location, zipRadius = 25, maxPagesPerSite = 20 } = body
      return await handleYelpBusinessDiscovery(query, location, zipRadius, maxResults, maxPagesPerSite)
    }

    // Handle Chamber of Commerce processing requests
    if (provider === 'chamber-of-commerce') {
      const { url, maxPagesPerSite = 20 } = body
      return await handleChamberOfCommerceProcessing(url, maxResults, maxPagesPerSite)
    }

    // Handle comprehensive search using search orchestrator
    if (provider === 'comprehensive') {
      const { location, zipRadius = 25, accreditedOnly = false } = body
      return await handleComprehensiveSearch(query, location, zipRadius, accreditedOnly, maxResults)
    }

    // Validate required fields for regular search
    if (!query || !location) {
      return NextResponse.json(
        { error: 'Query and location are required' },
        { status: 400 }
      )
    }

    // Sanitize inputs
    const sanitizedQuery = validationService.sanitizeInput(query).substring(0, 100)
    const sanitizedLocation = validationService.sanitizeInput(location).substring(0, 100)
    const sanitizedIndustry = industry ? validationService.sanitizeInput(industry).substring(0, 50) : undefined

    // Validate maxResults
    const validMaxResults = Math.min(Math.max(parseInt(maxResults) || 10, 1), 50)

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
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * Get search suggestions
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const query = searchParams.get('q') || ''
    const location = searchParams.get('location') || ''
    const industry = searchParams.get('industry') || ''

    if (!query) {
      return NextResponse.json(
        { error: 'Query parameter "q" is required' },
        { status: 400 }
      )
    }

    // Sanitize inputs
    const sanitizedQuery = validationService.sanitizeInput(query).substring(0, 100)
    const sanitizedLocation = location ? validationService.sanitizeInput(location).substring(0, 100) : undefined
    const sanitizedIndustry = industry ? validationService.sanitizeInput(industry).substring(0, 50) : undefined

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
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * Handle DuckDuckGo search proxy to avoid CORS issues
 */
async function handleDuckDuckGoProxy(query: string, maxResults: number) {
  try {
    logger.info('Search API', `DuckDuckGo proxy request: ${query}`)

    // Use DuckDuckGo's instant answer API
    const duckduckgoUrl = new URL('https://api.duckduckgo.com/')
    duckduckgoUrl.searchParams.set('q', query)
    duckduckgoUrl.searchParams.set('format', 'json')
    duckduckgoUrl.searchParams.set('no_html', '1')
    duckduckgoUrl.searchParams.set('skip_disambig', '1')

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 10000)

    const response = await fetch(duckduckgoUrl.toString(), {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      },
      signal: controller.signal
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      if (response.status === 503) {
        logger.warn('Search API', 'DuckDuckGo service temporarily unavailable (503), returning empty results')
        return NextResponse.json({
          success: true,
          provider: 'duckduckgo',
          query: query,
          results: [],
          count: 0,
          message: 'Search service temporarily unavailable'
        })
      }
      throw new Error(`DuckDuckGo API error: ${response.status}`)
    }

    const data = await response.json()

    // Log the actual response to understand what we're getting
    logger.info('Search API', `DuckDuckGo raw response:`, {
      hasRelatedTopics: !!(data.RelatedTopics && data.RelatedTopics.length > 0),
      relatedTopicsCount: data.RelatedTopics ? data.RelatedTopics.length : 0,
      hasAbstract: !!data.Abstract,
      abstractLength: data.Abstract ? data.Abstract.length : 0,
      hasResults: !!(data.Results && data.Results.length > 0),
      resultsCount: data.Results ? data.Results.length : 0,
      keys: Object.keys(data)
    })

    // Parse DuckDuckGo results
    const results = parseDuckDuckGoResults(data, maxResults)

    logger.info('Search API', `DuckDuckGo proxy returning ${results.length} results`)

    return NextResponse.json({
      success: true,
      provider: 'duckduckgo',
      query: query,
      results: results,
      count: results.length
    })

  } catch (error) {
    logger.error('Search API', 'DuckDuckGo proxy failed', error)
    return NextResponse.json(
      {
        success: false,
        error: 'DuckDuckGo search failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * Parse DuckDuckGo API response into standardized results
 */
function parseDuckDuckGoResults(data: any, maxResults: number): any[] {
  const results: any[] = []

  try {
    // Log what we're parsing for debugging
    logger.info('Search API', 'Parsing DuckDuckGo results...', {
      hasRelatedTopics: !!(data.RelatedTopics && data.RelatedTopics.length > 0),
      hasResults: !!(data.Results && data.Results.length > 0),
      hasAnswer: !!data.Answer,
      hasAbstract: !!data.Abstract
    })

    // Parse Results array first (if available)
    if (data.Results && Array.isArray(data.Results)) {
      logger.info('Search API', `Processing ${data.Results.length} Results entries`)
      for (const result of data.Results) {
        if (results.length >= maxResults) break

        if (result.FirstURL && result.Text) {
          try {
            const url = new URL(result.FirstURL)
            results.push({
              url: result.FirstURL,
              title: result.Text.split(' - ')[0] || result.Text.substring(0, 60),
              snippet: result.Text,
              domain: url.hostname
            })
            logger.info('Search API', `Added result from Results: ${result.FirstURL}`)
          } catch (error) {
            logger.warn('Search API', `Invalid URL in Results: ${result.FirstURL}`)
          }
        }
      }
    }

    // Parse related topics (often contains business listings)
    if (data.RelatedTopics && Array.isArray(data.RelatedTopics)) {
      logger.info('Search API', `Processing ${data.RelatedTopics.length} RelatedTopics entries`)
      for (const topic of data.RelatedTopics) {
        if (results.length >= maxResults) break

        if (topic.FirstURL && topic.Text) {
          try {
            const url = new URL(topic.FirstURL)
            const domain = url.hostname.toLowerCase()

            // Be less restrictive initially to see what we get
            const businessSites = [
              'yelp.com', 'yellowpages.com', 'whitepages.com',
              'foursquare.com', 'tripadvisor.com', 'bbb.org', 'angieslist.com',
              'wikipedia.org' // Include Wikipedia for now to see if we get any results
            ]

            const isBusinessSite = businessSites.some(site => domain.includes(site))
            const hasBusinessKeywords = [
              'restaurant', 'medical', 'dental', 'law', 'clinic', 'shop', 'service',
              'business', 'company', 'professional' // Add more general terms
            ].some(keyword => topic.Text.toLowerCase().includes(keyword))

            // Be more permissive for debugging
            if (isBusinessSite || hasBusinessKeywords || domain.includes('.com')) {
              results.push({
                url: topic.FirstURL,
                title: topic.Text.split(' - ')[0] || topic.Text.substring(0, 60),
                snippet: topic.Text,
                domain: url.hostname
              })
              logger.info('Search API', `Added result from RelatedTopics: ${topic.FirstURL}`)
            } else {
              logger.info('Search API', `Skipped result: ${domain} - ${topic.Text.substring(0, 50)}`)
            }
          } catch (error) {
            logger.warn('Search API', `Invalid URL in RelatedTopics: ${topic.FirstURL}`)
          }
        }
      }
    }

    // Parse abstract if it contains useful business information
    if (data.Abstract && data.AbstractURL && data.Abstract.length > 50) {
      try {
        const url = new URL(data.AbstractURL)

        // Only include if it's clearly business-related
        const businessKeywords = [
          'business', 'company', 'service', 'restaurant', 'medical', 'clinic',
          'shop', 'store', 'office', 'center', 'professional'
        ]

        const isBusinessRelated = businessKeywords.some(keyword =>
          data.Abstract.toLowerCase().includes(keyword) ||
          (data.Heading && data.Heading.toLowerCase().includes(keyword))
        )

        if (isBusinessRelated && results.length < maxResults) {
          results.push({
            url: data.AbstractURL,
            title: data.Heading || 'Business Information',
            snippet: data.Abstract,
            domain: url.hostname
          })
        }
      } catch {
        // Skip invalid URLs
      }
    }

  } catch (error) {
    logger.warn('Search API', 'Failed to parse DuckDuckGo results', error)
  }

  return results.slice(0, maxResults)
}

/**
 * Handle DuckDuckGo SERP scraping to get real business websites using headless browser
 */
async function handleDuckDuckGoSERP(query: string, page: number, maxResults: number) {
  try {
    logger.info('Search API', `DuckDuckGo SERP scraping: ${query} (page ${page + 1})`)

    // Import Puppeteer dynamically
    const puppeteer = await import('puppeteer')

    // Launch browser with stealth settings
    const browser = await puppeteer.default.launch({
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
        '--disable-features=VizDisplayCompositor'
      ]
    })

    try {
      const browserPage = await browser.newPage()

      // Set realistic user agent and viewport
      await browserPage.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
      await browserPage.setViewport({ width: 1366, height: 768 })

      // Set extra headers to appear more like a real browser
      await browserPage.setExtraHTTPHeaders({
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
      })

      // Construct DuckDuckGo search URL - use the format you specified
      const searchUrl = new URL('https://duckduckgo.com/')
      searchUrl.searchParams.set('t', 'h_')
      searchUrl.searchParams.set('q', query)
      searchUrl.searchParams.set('ia', 'web')

      if (page > 0) {
        searchUrl.searchParams.set('s', (page * 30).toString()) // DuckDuckGo shows ~30 results per page
      }

      logger.info('Search API', `Navigating to DuckDuckGo SERP: ${searchUrl.toString()}`)

      // Navigate to DuckDuckGo search page
      await browserPage.goto(searchUrl.toString(), {
        waitUntil: 'networkidle2',
        timeout: 30000
      })

      // Wait for search results to load
      await browserPage.waitForSelector('[data-testid="result"], .result, .web-result', { timeout: 15000 })

      // Extract search results using the browser
      const results = await extractDuckDuckGoSERPResults(browserPage, maxResults)

      await browser.close()

      logger.info('Search API', `DuckDuckGo SERP scraping returned ${results.length} results`)

      return NextResponse.json({
        success: true,
        provider: 'duckduckgo-serp',
        query: query,
        page: page,
        results: results,
        count: results.length
      })

    } finally {
      await browser.close()
    }

  } catch (error) {
    logger.error('Search API', 'DuckDuckGo SERP scraping failed', error)
    return NextResponse.json(
      {
        success: false,
        error: 'DuckDuckGo SERP scraping failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * Extract search results from DuckDuckGo SERP using browser automation
 */
async function extractDuckDuckGoSERPResults(page: any, maxResults: number): Promise<any[]> {
  return await page.evaluate((maxResults: number) => {
    const results: any[] = []

    console.log('Extracting DuckDuckGo SERP results...')

    // Look for search result containers - DuckDuckGo uses various selectors
    const resultSelectors = [
      '[data-testid="result"]',
      '.result',
      '.web-result',
      '.result__body',
      '.results .result',
      'article[data-testid="result"]'
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
          'a.result__url'
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
          '.result-snippet'
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
          'duckduckgo.com', 'google.com', 'bing.com', 'yahoo.com',
          'wikipedia.org', 'facebook.com', 'twitter.com', 'linkedin.com',
          'instagram.com', 'youtube.com', 'reddit.com', 'pinterest.com',
          'amazon.com', 'ebay.com', 'craigslist.org'
        ]

        const isBusinessDomain = !excludedDomains.some(excluded => domain.includes(excluded)) &&
                                !url.includes('duckduckgo.com') &&
                                !url.includes('javascript:') &&
                                url.startsWith('http')

        if (isBusinessDomain) {
          results.push({
            url: url,
            title: title,
            snippet: snippet,
            domain: domain
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
function parseDuckDuckGoSERP(html: string, maxResults: number): any[] {
  const results: any[] = []

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
      /<a[^>]+href="(https?:\/\/[^"]+)"[^>]*>([^<]+)<\/a>/g
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
            domain: domain
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
    'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
    'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'youtube.com', 'wikipedia.org', 'reddit.com', 'pinterest.com',
    'amazon.com', 'ebay.com', 'craigslist.org'
  ]

  if (excludeDomains.some(excluded => domain.includes(excluded))) {
    return false
  }

  // Include business directory sites
  const businessDirectories = [
    'yelp.com', 'yellowpages.com', 'bbb.org',
    'foursquare.com', 'tripadvisor.com', 'angieslist.com'
  ]

  if (businessDirectories.some(directory => domain.includes(directory))) {
    return true
  }

  // Include domains that look like business websites
  const businessTLDs = ['.com', '.net', '.org', '.biz', '.info']
  const hasBusinessTLD = businessTLDs.some(tld => domain.endsWith(tld))

  const businessKeywords = [
    'restaurant', 'cafe', 'medical', 'dental', 'law', 'legal',
    'clinic', 'hospital', 'shop', 'store', 'service', 'repair',
    'salon', 'spa', 'fitness', 'gym', 'auto', 'insurance'
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
    logger.info('Search API', `BBB business discovery: ${query} in ${location} (accredited: ${accreditedOnly}, radius: ${zipRadius}mi)`)

    // Check if this is an industry category that should be expanded
    const expandedCriteria = expandIndustryCategories(query)

    if (expandedCriteria.length > 0) {
      logger.info('Search API', `Expanded industry category "${query}" to: ${expandedCriteria.join(', ')}`)

      // Search for each expanded criteria individually
      const allBusinessWebsites: any[] = []
      const resultsPerCriteria = Math.ceil(maxResults / expandedCriteria.length)

      for (const criteria of expandedCriteria) {
        try {
          logger.info('Search API', `BBB searching for: "${criteria}" in ${location}`)

          const criteriaResults = await bbbScrapingService.searchBusinesses({
            query: criteria,
            location,
            accreditedOnly,
            zipRadius,
            maxResults: resultsPerCriteria
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

      logger.info('Search API', `BBB business discovery returned ${uniqueResults.length} business websites for expanded criteria`)

      return NextResponse.json({
        success: true,
        provider: 'bbb-discovery',
        query: query,
        expandedTo: expandedCriteria,
        location: location,
        results: uniqueResults,
        count: uniqueResults.length
      })
    }

    // Use the dedicated BBB scraping service for non-expanded queries
    const businessWebsites = await bbbScrapingService.searchBusinesses({
      query,
      location,
      accreditedOnly,
      zipRadius,
      maxResults
    })

    // Note: No longer adding directory search URLs as business results
    // Use dedicated discovery services (Yelp Discovery, BBB Discovery) instead

    logger.info('Search API', `BBB business discovery returned ${businessWebsites.length} business websites`)

    return NextResponse.json({
      success: true,
      provider: 'bbb-discovery',
      query: query,
      location: location,
      results: businessWebsites,
      count: businessWebsites.length
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
        count: 0
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
    'professional services businesses': ['consulting', 'legal', 'accounting', 'financial', 'insurance'],
    'professional': ['consulting', 'legal', 'accounting', 'financial', 'insurance'],

    // Healthcare & Medical
    'healthcare': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    'healthcare & medical': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    'healthcare businesses': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    'medical': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    'medical businesses': ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],

    // Restaurants & Food Service
    'restaurants': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'restaurants & food service': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'restaurant businesses': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'food service': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    'food businesses': ['restaurant', 'cafe', 'food service', 'catering', 'dining'],

    // Retail & Shopping
    'retail': ['retail', 'store', 'shop', 'boutique', 'marketplace'],
    'retail & shopping': ['retail', 'store', 'shop', 'boutique', 'marketplace'],
    'retail businesses': ['retail', 'store', 'shop', 'boutique', 'marketplace'],
    'shopping': ['retail', 'store', 'shop', 'boutique', 'marketplace'],

    // Construction & Contractors
    'construction': ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],
    'construction & contractors': ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],
    'construction businesses': ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],
    'contractors': ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],

    // Automotive
    'automotive': ['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'],
    'automotive businesses': ['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'],
    'auto': ['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'],
    'auto businesses': ['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'],

    // Technology
    'technology': ['technology', 'IT services', 'software', 'computer repair', 'web design'],
    'technology businesses': ['technology', 'IT services', 'software', 'computer repair', 'web design'],
    'tech': ['technology', 'IT services', 'software', 'computer repair', 'web design'],
    'tech businesses': ['technology', 'IT services', 'software', 'computer repair', 'web design'],

    // Beauty & Personal Care
    'beauty': ['salon', 'spa', 'beauty', 'hair', 'nail salon'],
    'beauty businesses': ['salon', 'spa', 'beauty', 'hair', 'nail salon'],
    'personal care': ['salon', 'spa', 'beauty', 'hair', 'nail salon'],
    'personal care businesses': ['salon', 'spa', 'beauty', 'hair', 'nail salon'],

    // Home Services
    'home services': ['cleaning', 'landscaping', 'pest control', 'home repair', 'HVAC'],
    'home services businesses': ['cleaning', 'landscaping', 'pest control', 'home repair', 'HVAC'],
    'home': ['cleaning', 'landscaping', 'pest control', 'home repair', 'HVAC'],

    // Education
    'education': ['school', 'tutoring', 'training', 'education', 'learning center'],
    'education businesses': ['school', 'tutoring', 'training', 'education', 'learning center'],
    'educational': ['school', 'tutoring', 'training', 'education', 'learning center'],

    // Entertainment
    'entertainment': ['entertainment', 'event planning', 'photography', 'music', 'recreation'],
    'entertainment businesses': ['entertainment', 'event planning', 'photography', 'music', 'recreation']
  }

  // Check for exact matches first
  if (industryMappings[queryLower]) {
    return industryMappings[queryLower]
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
function removeDuplicateBusinesses(businesses: any[]): any[] {
  const seen = new Set<string>()
  const unique: any[] = []

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
function generateAlternativeBusinessSearches(query: string, location: string, maxResults: number): any[] {
  // Return empty array - directory search URLs should not be returned as business websites
  // The proper approach is to use dedicated discovery services (Yelp Discovery, BBB Discovery)
  // that extract actual business websites from directory pages
  logger.info('Search API', `Not generating directory search URLs as business results for ${query} in ${location}`)
  return []
}

/**
 * Handle Yelp business discovery
 */
async function handleYelpBusinessDiscovery(query: string, location: string, zipRadius: number, maxResults: number, maxPagesPerSite: number = 20) {
  try {
    logger.info('Search API', `Yelp business discovery with deep scraping: ${query} in ${location} (max ${maxPagesPerSite} pages per site)`)

    // Import Yelp scraping service
    const { yelpScrapingService } = await import('@/lib/yelpScrapingService')

    const businessWebsites = await yelpScrapingService.searchBusinesses({
      query,
      location,
      zipRadius,
      maxResults,
      maxPagesPerSite
    })

    logger.info('Search API', `Yelp business discovery returned ${businessWebsites.length} business websites`)

    return NextResponse.json({
      success: true,
      provider: 'yelp-discovery',
      query: query,
      location: location,
      results: businessWebsites,
      count: businessWebsites.length
    })

  } catch (error) {
    logger.error('Search API', 'Yelp business discovery failed', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Yelp business discovery failed',
        message: error instanceof Error ? error.message : 'Unknown error'
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
      maxResults
    })

    logger.info('Search API', `Comprehensive search returned ${results.length} business results`)

    return NextResponse.json({
      success: true,
      provider: 'comprehensive',
      query: query,
      location: location,
      results: results,
      count: results.length,
      providerStats: searchOrchestrator.getProviderStats()
    })

  } catch (error) {
    logger.error('Search API', 'Comprehensive search failed', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Comprehensive search failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * Handle Chamber of Commerce processing
 */
async function handleChamberOfCommerceProcessing(url: string, maxResults: number, maxPagesPerSite: number = 20) {
  try {
    logger.info('Search API', `Chamber of Commerce processing: ${url} (max ${maxPagesPerSite} pages per site)`)

    // Import Chamber of Commerce scraping service
    const { chamberOfCommerceScrapingService } = await import('@/lib/chamberOfCommerceScrapingService')

    const businessWebsites = await chamberOfCommerceScrapingService.processChamberOfCommercePage({
      url,
      maxBusinesses: maxResults,
      maxPagesPerSite
    })

    logger.info('Search API', `Chamber of Commerce processing returned ${businessWebsites.length} business websites`)

    return NextResponse.json({
      success: true,
      provider: 'chamber-of-commerce',
      url: url,
      results: businessWebsites,
      count: businessWebsites.length
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
        count: 0
      },
      { status: 500 }
    )
  }
}