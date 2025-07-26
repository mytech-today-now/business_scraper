'use client'

import { retrieveApiCredentials, ApiCredentials } from '@/utils/secureStorage'
import { logger } from '@/utils/logger'
import { DEFAULT_INDUSTRIES } from '@/lib/industry-config'
import { storage } from '@/model/storage'

export interface SearchResult {
  url: string
  title: string
  snippet: string
  domain: string
}

/**
 * Client-side search engine that uses stored API credentials
 * This service runs in the browser and uses the user's configured API keys
 */
export class ClientSearchEngine {
  private credentials: ApiCredentials | null = null
  private cachedIndustries: { name: string; keywords: string[]; domainBlacklist?: string[] }[] = []
  private isInitialized = false

  /**
   * Initialize the search engine with stored credentials
   */
  async initialize(): Promise<void> {
    try {
      this.credentials = await retrieveApiCredentials()
      await this.loadIndustries()
      this.isInitialized = true

      if (this.credentials) {
        logger.info('ClientSearchEngine', 'Initialized with stored credentials', {
          hasGoogleSearch: !!this.credentials.googleSearchApiKey,
          hasAzureSearch: !!this.credentials.azureSearchApiKey,
          hasGoogleMaps: !!this.credentials.googleMapsApiKey
        })
      } else {
        logger.info('ClientSearchEngine', 'No stored credentials found, using fallback methods')
      }
    } catch (error) {
      logger.error('ClientSearchEngine', 'Failed to initialize with stored credentials', error)
      this.credentials = null
      this.isInitialized = true
    }
  }

  /**
   * Load industries from storage (both default and custom)
   */
  private async loadIndustries(): Promise<void> {
    try {
      // Start with default industries
      this.cachedIndustries = DEFAULT_INDUSTRIES.map(industry => ({
        name: industry.name,
        keywords: industry.keywords
      }))

      // Try to load all industries from storage (including custom ones)
      try {
        const allIndustries = await storage.getAllIndustries()
        if (allIndustries.length > 0) {
          // Use stored industries (which include both default and custom)
          this.cachedIndustries = allIndustries.map(industry => ({
            name: industry.name,
            keywords: industry.keywords,
            domainBlacklist: industry.domainBlacklist
          }))
        } else {
          // Fallback to default industries if none stored
          this.cachedIndustries = DEFAULT_INDUSTRIES.map(industry => ({
            name: industry.name,
            keywords: industry.keywords,
            domainBlacklist: industry.domainBlacklist
          }))
        }
        logger.info('ClientSearchEngine', `Loaded ${this.cachedIndustries.length} industries`)
      } catch (error) {
        logger.warn('ClientSearchEngine', 'Failed to load industries from storage, using defaults only', error)
        // Fallback to default industries
        this.cachedIndustries = DEFAULT_INDUSTRIES.map(industry => ({
          name: industry.name,
          keywords: industry.keywords,
          domainBlacklist: industry.domainBlacklist
        }))
      }
    } catch (error) {
      logger.error('ClientSearchEngine', 'Failed to load industries', error)
      // Fallback to default industries
      this.cachedIndustries = DEFAULT_INDUSTRIES.map(industry => ({
        name: industry.name,
        keywords: industry.keywords
      }))
    }
  }

  /**
   * Search for business websites using available APIs
   */
  async searchBusinesses(
    query: string,
    location: string,
    maxResults: number = 10
  ): Promise<SearchResult[]> {
    if (!this.isInitialized) {
      await this.initialize()
    }

    // Extract keywords from query for industry-specific blacklist filtering
    const queryKeywords = query.toLowerCase().split(/\s+/).filter(Boolean)

    const searchMethods = [
      () => this.searchWithGoogle(query, location, maxResults),
      () => this.searchWithAzure(query, location, maxResults),
      () => this.searchWithDuckDuckGo(query, location, maxResults)
    ]

    for (const searchMethod of searchMethods) {
      try {
        const results = await searchMethod()
        if (results.length > 0) {
          // Apply domain blacklist filtering with industry keywords
          const filteredResults = this.applyDomainBlacklist(results, queryKeywords)
          if (filteredResults.length > 0) {
            return filteredResults
          }
        }
      } catch (error) {
        logger.warn('ClientSearchEngine', 'Search method failed, trying next', error)
        continue
      }
    }

    logger.warn('ClientSearchEngine', 'All search methods failed')
    return []
  }

  /**
   * Search using Google Custom Search API
   */
  private async searchWithGoogle(
    query: string,
    location: string,
    maxResults: number
  ): Promise<SearchResult[]> {
    if (!this.credentials?.googleSearchApiKey || !this.credentials?.googleSearchEngineId) {
      throw new Error('Google Search API credentials not configured')
    }

    const searchQuery = `${query} ${location}`
    const url = new URL('https://www.googleapis.com/customsearch/v1')
    url.searchParams.set('key', this.credentials.googleSearchApiKey)
    url.searchParams.set('cx', this.credentials.googleSearchEngineId)
    url.searchParams.set('q', searchQuery)
    url.searchParams.set('num', Math.min(maxResults, 10).toString())
    url.searchParams.set('safe', 'medium')
    url.searchParams.set('lr', 'lang_en')
    url.searchParams.set('gl', 'us')

    try {
      logger.info('ClientSearchEngine', `Searching Google with query: ${searchQuery}`)
      
      const response = await fetch(url.toString())
      if (!response.ok) {
        throw new Error(`Google Search API error: ${response.status}`)
      }

      const data = await response.json()
      const results = this.parseGoogleResults(data, maxResults)
      
      logger.info('ClientSearchEngine', `Google search returned ${results.length} results`)
      return results
    } catch (error) {
      logger.error('ClientSearchEngine', 'Google search failed', error)
      throw error
    }
  }

  /**
   * Search using Azure AI Foundry "Grounding with Bing Custom Search" API
   * This replaces the deprecated Bing Search API (discontinued August 2025)
   */
  private async searchWithAzure(
    query: string,
    location: string,
    maxResults: number
  ): Promise<SearchResult[]> {
    if (!this.credentials?.azureSearchApiKey || !this.credentials?.azureSearchEndpoint) {
      logger.info('ClientSearchEngine', 'Azure AI Foundry credentials not configured, skipping Azure search')
      return []
    }

    const searchQuery = `${query} ${location}`

    // Ensure proper URL construction (avoid double slashes)
    const baseUrl = this.credentials.azureSearchEndpoint.endsWith('/')
      ? this.credentials.azureSearchEndpoint.slice(0, -1)
      : this.credentials.azureSearchEndpoint

    // Use the new Grounding with Bing Custom Search endpoint
    const url = new URL(`${baseUrl}/bing/v7.0/custom/search`)

    try {
      logger.info('ClientSearchEngine', `Searching Azure AI Foundry with query: ${searchQuery}`)

      const requestBody = {
        q: searchQuery,
        count: Math.min(maxResults, 50),
        offset: 0,
        mkt: 'en-US',
        safesearch: 'Moderate',
        responseFilter: 'Webpages',
        freshness: 'Month',
        textDecorations: false,
        textFormat: 'Raw'
      }

      const response = await fetch(url.toString(), {
        method: 'POST',
        headers: {
          'Ocp-Apim-Subscription-Key': this.credentials.azureSearchApiKey,
          'Content-Type': 'application/json',
          'User-Agent': 'BusinessScraperApp/1.0'
        },
        body: JSON.stringify(requestBody)
      })

      if (!response.ok) {
        const errorText = await response.text()
        logger.error('ClientSearchEngine', `Azure AI Foundry API error: ${response.status} - ${errorText}`)
        throw new Error(`Azure AI Foundry API error: ${response.status}`)
      }

      const data = await response.json()
      const results = this.parseAzureGroundingResults(data, maxResults)

      logger.info('ClientSearchEngine', `Azure AI Foundry search returned ${results.length} results`)
      return results
    } catch (error) {
      logger.error('ClientSearchEngine', 'Azure AI Foundry search failed', error)
      throw error
    }
  }

  /**
   * Comprehensive search that includes individual criteria parsing and BBB business discovery
   * Returns actual business website URLs that can be scraped for contact info
   */
  private async searchWithDuckDuckGo(
    query: string,
    location: string,
    maxResults: number
  ): Promise<SearchResult[]> {
    try {
      logger.info('ClientSearchEngine', `Starting comprehensive search for ${query} in ${location}`)

      const allResults: SearchResult[] = []

      // Parse industry criteria into individual search terms
      const searchCriteria = this.parseIndustryCriteria(query)
      logger.info('ClientSearchEngine', `Parsed ${searchCriteria.length} individual search criteria: ${searchCriteria.join(', ')}`)

      // Strategy 1: Search each criteria individually using DuckDuckGo SERP
      for (const criteria of searchCriteria) {
        if (allResults.length >= maxResults) break

        const serpResults = await this.searchDuckDuckGoSERP(criteria, location, Math.ceil(maxResults / searchCriteria.length))
        allResults.push(...serpResults)
      }

      // Strategy 2: Comprehensive business discovery for each criteria (BBB + Yelp + SERP)
      for (const criteria of searchCriteria) {
        if (allResults.length >= maxResults) break

        const comprehensiveResults = await this.searchComprehensiveBusinessDiscovery(criteria, location, Math.ceil(maxResults / searchCriteria.length))
        allResults.push(...comprehensiveResults)
      }

      // Strategy 3: Search other business directories
      const directoryResults = await this.searchBusinessDirectories(query, location, maxResults)
      allResults.push(...directoryResults)

      // Strategy 4: Use DuckDuckGo instant answer API as fallback
      if (allResults.length < maxResults) {
        const instantResults = await this.searchDuckDuckGoInstantAnswer(`${query} ${location}`)
        allResults.push(...instantResults)
      }

      // Filter, validate, and deduplicate results (now async to handle Chamber of Commerce processing)
      const validResults = await this.filterValidBusinessResults(allResults)
      const uniqueResults = this.removeDuplicateResults(validResults)
      const finalResults = uniqueResults.slice(0, maxResults)

      if (finalResults.length > 0) {
        logger.info('ClientSearchEngine', `Comprehensive search returned ${finalResults.length} real business results`)
        return finalResults
      }

      // Final fallback: generate real business directory URLs
      logger.info('ClientSearchEngine', 'All search methods returned no results, generating directory URLs')
      const fallbackResults = this.generateRealBusinessDirectoryUrls(query, location, maxResults)

      if (fallbackResults.length > 0) {
        logger.info('ClientSearchEngine', `Generated ${fallbackResults.length} real business directory URLs`)
        return fallbackResults
      }

      throw new Error('No real business websites found in comprehensive search')

    } catch (error) {
      logger.warn('ClientSearchEngine', 'Comprehensive search failed', error)
      throw error
    }
  }

  /**
   * Search DuckDuckGo SERP pages and extract business websites
   * This is the core method that scrapes actual search results
   */
  private async searchDuckDuckGoSERP(query: string, location: string, maxResults: number): Promise<SearchResult[]> {
    try {
      const searchQueries = [
        `${query} ${location}`,
        `${query} businesses ${location}`,
        `${query} ${location} contact phone`,
        `"${query}" "${location}" phone email`
      ]

      const allResults: SearchResult[] = []
      // Get configurable number of SERP pages from credentials
      const maxPagesPerQuery = this.credentials?.duckduckgoSerpPages || 2

      for (const searchQuery of searchQueries) {
        if (allResults.length >= maxResults) break

        logger.info('ClientSearchEngine', `Scraping DuckDuckGo SERP for: ${searchQuery}`)

        // Scrape multiple pages of results
        for (let page = 0; page < maxPagesPerQuery; page++) {
          if (allResults.length >= maxResults) break

          const pageResults = await this.scrapeDuckDuckGoPage(searchQuery, page)
          allResults.push(...pageResults)

          logger.info('ClientSearchEngine', `Page ${page + 1}: Found ${pageResults.length} results`)

          // Small delay between pages to be respectful
          await new Promise(resolve => setTimeout(resolve, 1000))
        }
      }

      return allResults.slice(0, maxResults)

    } catch (error) {
      logger.warn('ClientSearchEngine', 'DuckDuckGo SERP scraping failed', error)
      return []
    }
  }

  /**
   * Scrape a single DuckDuckGo search results page
   */
  private async scrapeDuckDuckGoPage(query: string, page: number): Promise<SearchResult[]> {
    try {
      // Use server-side proxy to scrape DuckDuckGo SERP
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'duckduckgo-serp',
          query: query,
          page: page,
          maxResults: 10
        })
      })

      if (!response.ok) {
        throw new Error(`DuckDuckGo SERP API error: ${response.status}`)
      }

      const data = await response.json()

      if (!data.success) {
        throw new Error(data.error || 'DuckDuckGo SERP search failed')
      }

      // Convert server response to SearchResult format
      const results = (data.results || []).map((result: any) => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet || '',
        domain: result.domain || new URL(result.url).hostname
      }))

      return results

    } catch (error) {
      logger.warn('ClientSearchEngine', `Failed to scrape DuckDuckGo page ${page + 1}`, error)
      return []
    }
  }

  /**
   * Search business directories with targeted queries
   */
  private async searchBusinessDirectories(query: string, location: string, maxResults: number): Promise<SearchResult[]> {
    try {
      const directoryQueries = [
        `${query} ${location} site:yelp.com`,
        `${query} ${location} site:yellowpages.com`,
        `${query} ${location} site:bbb.org`,
        `${query} ${location} site:foursquare.com`
      ]

      const allResults: SearchResult[] = []

      for (const directoryQuery of directoryQueries) {
        if (allResults.length >= maxResults) break

        const results = await this.searchDuckDuckGoInstantAnswer(directoryQuery)
        allResults.push(...results)
      }

      return allResults.slice(0, maxResults)

    } catch (error) {
      logger.warn('ClientSearchEngine', 'Business directory search failed', error)
      return []
    }
  }

  /**
   * Search using DuckDuckGo instant answer API (fallback method)
   */
  private async searchDuckDuckGoInstantAnswer(searchQuery: string): Promise<SearchResult[]> {
    try {
      logger.info('ClientSearchEngine', `Calling DuckDuckGo instant answer API: ${searchQuery}`)

      // Use our server as a proxy to avoid CORS issues
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'duckduckgo',
          query: searchQuery,
          maxResults: 10
        })
      })

      if (!response.ok) {
        throw new Error(`DuckDuckGo proxy API error: ${response.status}`)
      }

      const data = await response.json()

      if (!data.success) {
        return []
      }

      // Convert server response to SearchResult format
      const results = (data.results || []).map((result: any) => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet || '',
        domain: result.domain || new URL(result.url).hostname
      }))

      logger.info('ClientSearchEngine', `DuckDuckGo instant answer returned ${results.length} results`)
      return results

    } catch (error) {
      logger.warn('ClientSearchEngine', 'DuckDuckGo instant answer search failed', error)
      return []
    }
  }

  /**
   * Filter results to only include valid business websites and process special directories
   */
  private async filterValidBusinessResults(results: SearchResult[]): Promise<SearchResult[]> {
    const validResults: SearchResult[] = []

    for (const result of results) {
      try {
        const url = new URL(result.url)
        const domain = url.hostname.toLowerCase()

        // Check for Chamber of Commerce URLs and process them
        if (domain.includes('chamberofcommerce.com')) {
          logger.info('ClientSearchEngine', `Detected Chamber of Commerce URL: ${result.url}`)
          const chamberResults = await this.processChamberOfCommerceUrl(result.url, 5)
          validResults.push(...chamberResults)
          continue
        }

        // Include known business directory sites
        const businessDirectories = [
          'yelp.com', 'yellowpages.com', 'whitepages.com',
          'foursquare.com', 'tripadvisor.com', 'bbb.org', 'angieslist.com',
          'nextdoor.com', 'citysearch.com', 'mapquest.com'
        ]

        // Check if it's a business directory
        const isBusinessDirectory = businessDirectories.some(dir => domain.includes(dir))

        // Check if it looks like a real business website
        const hasBusinessTLD = ['.com', '.net', '.org', '.biz', '.info'].some(tld => domain.endsWith(tld))
        const hasBusinessKeywords = [
          'restaurant', 'cafe', 'medical', 'dental', 'law', 'legal',
          'clinic', 'hospital', 'shop', 'store', 'service', 'repair',
          'salon', 'spa', 'fitness', 'gym', 'auto', 'insurance'
        ].some(keyword => domain.includes(keyword) || result.title.toLowerCase().includes(keyword))

        // Exclude obvious non-business sites
        const excludeDomains = [
          'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
          'wikipedia.org', 'youtube.com', 'facebook.com', 'twitter.com',
          'instagram.com', 'linkedin.com', 'reddit.com', 'pinterest.com',
          'amazon.com', 'ebay.com', 'craigslist.org'
        ]

        const isExcluded = excludeDomains.some(excluded => domain.includes(excluded))

        // Include valid business results
        if (!isExcluded && (isBusinessDirectory || (hasBusinessTLD && hasBusinessKeywords))) {
          validResults.push(result)
        }

      } catch (error) {
        logger.warn('ClientSearchEngine', `Error processing result ${result.url}:`, error)
      }
    }

    return validResults
  }

  /**
   * Parse DuckDuckGo instant answer results
   */
  private parseDuckDuckGoInstantResults(data: any): SearchResult[] {
    const results: SearchResult[] = []

    // Parse related topics (often contains business listings)
    if (data.RelatedTopics && Array.isArray(data.RelatedTopics)) {
      for (const topic of data.RelatedTopics) {
        if (topic.FirstURL && topic.Text) {
          try {
            const url = new URL(topic.FirstURL)
            const domain = url.hostname.toLowerCase()

            // Focus on business directory sites and real business websites
            const businessSites = [
              'yelp.com', 'yellowpages.com', 'whitepages.com',
              'foursquare.com', 'tripadvisor.com', 'bbb.org', 'angieslist.com'
            ]

            const isBusinessSite = businessSites.some(site => domain.includes(site))
            const hasBusinessKeywords = [
              'restaurant', 'medical', 'dental', 'law', 'clinic', 'shop', 'service'
            ].some(keyword => topic.Text.toLowerCase().includes(keyword))

            if (isBusinessSite || hasBusinessKeywords) {
              results.push({
                url: topic.FirstURL,
                title: topic.Text.split(' - ')[0] || topic.Text.substring(0, 60),
                snippet: topic.Text,
                domain: url.hostname
              })
            }
          } catch {
            // Skip invalid URLs
          }
        }
      }
    }

    // Parse abstract if it contains useful business information
    if (data.Abstract && data.AbstractURL && data.Abstract.length > 50) {
      try {
        const url = new URL(data.AbstractURL)
        const domain = url.hostname.toLowerCase()

        // Only include if it's clearly business-related
        const businessKeywords = [
          'business', 'company', 'service', 'restaurant', 'medical', 'clinic',
          'shop', 'store', 'office', 'center', 'professional'
        ]

        const isBusinessRelated = businessKeywords.some(keyword =>
          data.Abstract.toLowerCase().includes(keyword) ||
          (data.Heading && data.Heading.toLowerCase().includes(keyword))
        )

        if (isBusinessRelated) {
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

    return results
  }



  /**
   * Generate real business directory URLs when API searches fail
   * These are actual, scrapeable business directory pages
   */
  private generateRealBusinessDirectoryUrls(query: string, location: string, maxResults: number): SearchResult[] {
    const results: SearchResult[] = []

    // Real business directory sites with their search URL patterns
    const businessDirectories = [
      {
        name: 'Yelp',
        domain: 'yelp.com',
        searchUrl: (q: string, loc: string) => `https://www.yelp.com/search?find_desc=${encodeURIComponent(q)}&find_loc=${encodeURIComponent(loc)}`,
        description: 'Business reviews and contact information'
      },
      {
        name: 'YellowPages',
        domain: 'yellowpages.com',
        searchUrl: (q: string, loc: string) => `https://www.yellowpages.com/search?search_terms=${encodeURIComponent(q)}&geo_location_terms=${encodeURIComponent(loc)}`,
        description: 'Local business directory and listings'
      },

      {
        name: 'Better Business Bureau',
        domain: 'bbb.org',
        searchUrl: (q: string, loc: string) => `https://www.bbb.org/search?find_country=USA&find_text=${encodeURIComponent(q)}&find_type=accredited&find_loc=${encodeURIComponent(loc)}`,
        description: 'Accredited business listings'
      },
      {
        name: 'Foursquare',
        domain: 'foursquare.com',
        searchUrl: (q: string, loc: string) => `https://foursquare.com/explore?mode=url&near=${encodeURIComponent(loc)}&q=${encodeURIComponent(q)}`,
        description: 'Local business discovery and reviews'
      }
    ]

    // Generate URLs for each directory
    for (let i = 0; i < Math.min(maxResults, businessDirectories.length); i++) {
      const directory = businessDirectories[i]

      if (!directory) continue

      try {
        const searchUrl = directory.searchUrl(query, location)

        results.push({
          url: searchUrl,
          title: `${query} businesses in ${location} - ${directory.name}`,
          snippet: `Find ${query} businesses in ${location} on ${directory.name}. ${directory.description}`,
          domain: directory.domain
        })

        logger.info('ClientSearchEngine', `Generated real directory URL: ${searchUrl}`)

      } catch (error) {
        logger.warn('ClientSearchEngine', `Failed to generate URL for ${directory.name}`, error)
      }
    }

    return results
  }

  /**
   * Parse industry criteria into individual search terms
   * Handles quoted phrases, comma-separated terms, and industry category expansion
   */
  private parseIndustryCriteria(query: string): string[] {
    const criteria: string[] = []

    // First, extract quoted phrases (these take priority over industry expansion)
    const quotedRegex = /"([^"]+)"/g
    let match: RegExpExecArray | null
    const quotedPhrases: string[] = []

    while ((match = quotedRegex.exec(query)) !== null) {
      if (match && match[1]) {
        quotedPhrases.push(match[1].trim())
      }
    }

    // Remove quoted phrases from the query to process remaining terms
    let remainingQuery = query.replace(quotedRegex, '').trim()

    // If we have quoted phrases, process the remaining query normally
    if (quotedPhrases.length > 0) {
      // Split remaining terms by comma and clean them
      const remainingTerms = remainingQuery
        .split(',')
        .map(term => term.trim())
        .filter(term => term.length > 0 && !term.match(/^[&\s]+$/)) // Remove empty terms and "&" symbols

      // Combine quoted phrases and individual terms
      criteria.push(...quotedPhrases)
      criteria.push(...remainingTerms)

      // Remove duplicates and empty terms
      const uniqueSet = new Set(criteria)
      const uniqueCriteria = Array.from(uniqueSet).filter((term: string) => term && term.length > 0)

      logger.info('ClientSearchEngine', `Parsed criteria from "${query}": ${uniqueCriteria.join(', ')}`)
      return uniqueCriteria
    }

    // If no quoted phrases, check if this is an industry category that should be expanded
    const expandedCriteria = this.expandIndustryCategories(query)
    if (expandedCriteria.length > 0) {
      logger.info('ClientSearchEngine', `Expanded industry category "${query}" to: ${expandedCriteria.join(', ')}`)
      return expandedCriteria
    }

    // Split remaining terms by comma and clean them
    const remainingTerms = remainingQuery
      .split(',')
      .map(term => term.trim())
      .filter(term => term.length > 0 && !term.match(/^[&\s]+$/)) // Remove empty terms and "&" symbols

    criteria.push(...remainingTerms)

    // Remove duplicates and empty terms
    const uniqueSet = new Set(criteria)
    const uniqueCriteria = Array.from(uniqueSet).filter((term: string) => term && term.length > 0)

    logger.info('ClientSearchEngine', `Parsed criteria from "${query}": ${uniqueCriteria.join(', ')}`)

    return uniqueCriteria.length > 0 ? uniqueCriteria : [query] // Fallback to original query if parsing fails
  }

  /**
   * Expand industry categories into their constituent keywords
   */
  private expandIndustryCategories(query: string): string[] {
    const queryLower = query.toLowerCase().trim()

    // Debug logging to understand what query is being processed
    logger.info('ClientSearchEngine', `Expanding industry categories for query: "${query}" (lowercase: "${queryLower}")`)

    // First, try to find a matching industry from stored configurations
    // This handles both default and custom industries dynamically
    const matchingIndustry = this.findMatchingIndustry(queryLower)
    if (matchingIndustry) {
      logger.info('ClientSearchEngine', `Found matching industry: "${matchingIndustry.name}" with keywords: ${matchingIndustry.keywords.join(', ')}`)
      return matchingIndustry.keywords
    }

    // Fallback to hardcoded mappings for backward compatibility
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
      logger.info('ClientSearchEngine', `Found exact match for "${queryLower}"`)
      return industryMappings[queryLower]
    }

    // Check for partial matches - but be more specific to avoid false matches
    for (const [category, keywords] of Object.entries(industryMappings)) {
      // Only match if the query contains the category as a whole word or phrase
      // This prevents "construction" from matching "professional" etc.
      if (queryLower.includes(category)) {
        logger.info('ClientSearchEngine', `Found partial match: "${queryLower}" contains "${category}"`)
        return keywords
      }
    }

    logger.info('ClientSearchEngine', `No industry expansion found for "${queryLower}"`)

    return [] // No expansion found
  }

  /**
   * Find matching industry from cached configurations (both default and custom)
   */
  private findMatchingIndustry(queryLower: string): { name: string; keywords: string[] } | null {
    try {
      // Use cached industries (includes both default and custom)
      const industries = this.cachedIndustries

      // Check for exact name matches first
      for (const industry of industries) {
        if (industry.name.toLowerCase() === queryLower) {
          return industry
        }
      }

      // Check for partial name matches (but be careful with the logic)
      for (const industry of industries) {
        const industryNameLower = industry.name.toLowerCase()
        // Only match if the query contains the industry name, not the other way around
        // This prevents false matches like "construction" matching "professional"
        if (queryLower.includes(industryNameLower)) {
          return industry
        }
      }

      return null
    } catch (error) {
      logger.warn('ClientSearchEngine', 'Failed to find matching industry', error)
      return null
    }
  }

  /**
   * Comprehensive business discovery - uses abstracted search orchestrator
   * This method coordinates BBB, Yelp, and SERP searches regardless of search provider
   */
  private async searchComprehensiveBusinessDiscovery(criteria: string, location: string, maxResults: number): Promise<SearchResult[]> {
    try {
      logger.info('ClientSearchEngine', `Starting comprehensive business discovery for "${criteria}" in ${location}`)

      // Use server-side comprehensive search orchestrator
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'comprehensive',
          query: criteria,
          location: location,
          maxResults: maxResults,
          accreditedOnly: this.credentials?.bbbAccreditedOnly || false,
          zipRadius: this.credentials?.zipRadius || 25
        })
      })

      if (!response.ok) {
        throw new Error(`Comprehensive search API error: ${response.status}`)
      }

      const data = await response.json()

      if (!data.success) {
        throw new Error(data.error || 'Comprehensive search failed')
      }

      // Convert server response to SearchResult format
      const results = (data.results || []).map((result: any) => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet || `Business found via ${result.source} for ${criteria}`,
        domain: result.domain || new URL(result.url).hostname,
        source: result.source,
        address: result.address,
        phone: result.phone
      }))

      logger.info('ClientSearchEngine', `Comprehensive search returned ${results.length} business websites for "${criteria}"`)
      logger.info('ClientSearchEngine', `Provider stats: ${JSON.stringify(data.providerStats)}`)
      return results

    } catch (error) {
      logger.warn('ClientSearchEngine', `Comprehensive search failed for "${criteria}"`, error)
      return []
    }
  }

  /**
   * BBB business discovery - uses BBB as a conduit to find real business websites
   */
  private async searchBBBBusinessDiscovery(criteria: string, location: string, maxResults: number): Promise<SearchResult[]> {
    try {
      logger.info('ClientSearchEngine', `Starting BBB business discovery for "${criteria}" in ${location}`)

      // Use server-side BBB scraping to avoid CORS issues
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'bbb-discovery',
          query: criteria,
          location: location,
          maxResults: maxResults,
          accreditedOnly: this.credentials?.bbbAccreditedOnly || false,
          zipRadius: this.credentials?.zipRadius || 10
        })
      })

      if (!response.ok) {
        throw new Error(`BBB discovery API error: ${response.status}`)
      }

      const data = await response.json()

      if (!data.success) {
        throw new Error(data.error || 'BBB discovery failed')
      }

      // Convert server response to SearchResult format
      const results = (data.results || []).map((result: any) => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet || `Business found via BBB discovery for ${criteria}`,
        domain: result.domain || new URL(result.url).hostname
      }))

      logger.info('ClientSearchEngine', `BBB discovery returned ${results.length} business websites for "${criteria}"`)
      return results

    } catch (error) {
      logger.warn('ClientSearchEngine', `BBB discovery failed for "${criteria}"`, error)
      return []
    }
  }

  /**
   * Chamber of Commerce processing - processes chamberofcommerce.com URLs to find business websites
   */
  private async processChamberOfCommerceUrl(url: string, maxResults: number): Promise<SearchResult[]> {
    try {
      logger.info('ClientSearchEngine', `Starting Chamber of Commerce processing for: ${url}`)

      // Use server-side Chamber of Commerce processing to avoid CORS issues
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'chamber-of-commerce',
          url: url,
          maxResults: maxResults,
          maxPagesPerSite: 20
        })
      })

      if (!response.ok) {
        throw new Error(`Chamber of Commerce processing API error: ${response.status}`)
      }

      const data = await response.json()

      if (!data.success) {
        throw new Error(data.error || 'Chamber of Commerce processing failed')
      }

      // Convert server response to SearchResult format
      const results = (data.results || []).map((result: any) => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet || `Business found via Chamber of Commerce processing`,
        domain: result.domain || new URL(result.url).hostname,
        address: result.address,
        phone: result.phone
      }))

      logger.info('ClientSearchEngine', `Chamber of Commerce processing returned ${results.length} business websites`)
      return results

    } catch (error) {
      logger.warn('ClientSearchEngine', `Chamber of Commerce processing failed for "${url}"`, error)
      return []
    }
  }

  /**
   * Yelp business discovery - uses Yelp as a conduit to find real business websites
   */
  private async searchYelpBusinessDiscovery(criteria: string, location: string, maxResults: number): Promise<SearchResult[]> {
    try {
      logger.info('ClientSearchEngine', `Starting Yelp business discovery for "${criteria}" in ${location}`)

      // Use server-side Yelp scraping to avoid CORS issues
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'yelp-discovery',
          query: criteria,
          location: location,
          maxResults: maxResults,
          zipRadius: this.credentials?.zipRadius || 25,
          maxPagesPerSite: 20
        })
      })

      if (!response.ok) {
        throw new Error(`Yelp discovery API error: ${response.status}`)
      }

      const data = await response.json()

      if (!data.success) {
        throw new Error(data.error || 'Yelp discovery failed')
      }

      // Convert server response to SearchResult format
      const results = (data.results || []).map((result: any) => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet || `Business found via Yelp discovery for ${criteria}`,
        domain: result.domain || new URL(result.url).hostname,
        address: result.address,
        phone: result.phone
      }))

      logger.info('ClientSearchEngine', `Yelp discovery returned ${results.length} business websites for "${criteria}"`)
      return results

    } catch (error) {
      logger.warn('ClientSearchEngine', `Yelp discovery failed for "${criteria}"`, error)
      return []
    }
  }

  /**
   * Remove duplicate results based on domain and title similarity
   */
  private removeDuplicateResults(results: SearchResult[]): SearchResult[] {
    const seen = new Set<string>()
    const unique: SearchResult[] = []

    for (const result of results) {
      const key = `${result.domain}-${result.title.toLowerCase().substring(0, 30)}`
      if (!seen.has(key)) {
        seen.add(key)
        unique.push(result)
      }
    }

    return unique
  }



  /**
   * Categorize business query to generate more relevant results
   */
  private categorizeBusinessQuery(query: string): string[] {
    const queryLower = query.toLowerCase()
    const categories: string[] = []

    // Food & Dining
    if (queryLower.includes('restaurant') || queryLower.includes('food') || queryLower.includes('dining') ||
        queryLower.includes('cafe') || queryLower.includes('pizza') || queryLower.includes('burger')) {
      categories.push('restaurant')
    }

    // Healthcare
    if (queryLower.includes('medical') || queryLower.includes('health') || queryLower.includes('doctor') ||
        queryLower.includes('clinic') || queryLower.includes('hospital') || queryLower.includes('dental')) {
      categories.push('healthcare')
    }

    // Professional Services
    if (queryLower.includes('professional') || queryLower.includes('service') || queryLower.includes('consulting') ||
        queryLower.includes('legal') || queryLower.includes('accounting') || queryLower.includes('law')) {
      categories.push('professional')
    }

    // Retail
    if (queryLower.includes('shop') || queryLower.includes('store') || queryLower.includes('retail') ||
        queryLower.includes('clothing') || queryLower.includes('electronics')) {
      categories.push('retail')
    }

    // Beauty & Wellness
    if (queryLower.includes('salon') || queryLower.includes('spa') || queryLower.includes('beauty') ||
        queryLower.includes('fitness') || queryLower.includes('gym')) {
      categories.push('beauty')
    }

    // If no specific category found, use general business
    if (categories.length === 0) {
      categories.push('general')
    }

    return categories
  }





  /**
   * Parse Google Custom Search results
   */
  private parseGoogleResults(data: any, maxResults: number): SearchResult[] {
    if (!data.items) return []

    return data.items.slice(0, maxResults).map((item: any) => ({
      url: item.link,
      title: item.title,
      snippet: item.snippet || '',
      domain: new URL(item.link).hostname
    }))
  }

  /**
   * Parse Azure AI Foundry "Grounding with Bing Custom Search" results
   */
  private parseAzureGroundingResults(data: any, maxResults: number): SearchResult[] {
    const results: SearchResult[] = []

    // The new Grounding with Bing Custom Search API returns results in webPages.value format
    if (!data.webPages?.value) {
      logger.warn('ClientSearchEngine', 'No webPages.value found in Azure AI Foundry response')
      return []
    }

    for (const item of data.webPages.value) {
      if (results.length >= maxResults) break

      try {
        const url = item.url

        // Additional URL validation
        if (!url || !url.startsWith('http')) {
          continue
        }

        const domain = new URL(url).hostname

        results.push({
          url: url,
          title: item.name || '',
          snippet: item.snippet || '',
          domain: domain,
        })

      } catch (error) {
        logger.warn('ClientSearchEngine', 'Failed to parse Azure AI Foundry result item', error)
        continue
      }
    }

    return results
  }

  /**
   * Legacy method for backward compatibility
   * @deprecated Use parseAzureGroundingResults instead
   */
  private parseAzureResults(data: any, maxResults: number): SearchResult[] {
    return this.parseAzureGroundingResults(data, maxResults)
  }

  /**
   * Check if any API credentials are configured
   */
  hasApiCredentials(): boolean {
    return !!(
      this.credentials?.googleSearchApiKey ||
      this.credentials?.azureSearchApiKey
    )
  }

  /**
   * Apply domain blacklist filtering to search results
   * Uses both global blacklist and industry-specific blacklists
   */
  private applyDomainBlacklist(results: SearchResult[], industryKeywords?: string[]): SearchResult[] {
    // Collect all blacklist patterns
    const allBlacklistPatterns: string[] = []

    // Add global domain blacklist
    if (this.credentials?.domainBlacklist && this.credentials.domainBlacklist.length > 0) {
      allBlacklistPatterns.push(...this.credentials.domainBlacklist)
    }

    // Add industry-specific blacklists
    if (industryKeywords && this.cachedIndustries) {
      for (const industry of this.cachedIndustries) {
        // Check if this industry matches the search keywords
        const hasMatchingKeyword = industry.keywords.some(keyword =>
          industryKeywords.some(searchKeyword =>
            searchKeyword.toLowerCase().includes(keyword.toLowerCase()) ||
            keyword.toLowerCase().includes(searchKeyword.toLowerCase())
          )
        )

        if (hasMatchingKeyword && industry.domainBlacklist && industry.domainBlacklist.length > 0) {
          allBlacklistPatterns.push(...industry.domainBlacklist)
        }
      }
    }

    if (allBlacklistPatterns.length === 0) {
      return results
    }

    const blacklistedPatterns = allBlacklistPatterns.map(pattern =>
      pattern.toLowerCase().trim()
    )

    const filteredResults = results.filter(result => {
      try {
        const url = new URL(result.url)
        const domain = url.hostname.toLowerCase()

        // Remove www. prefix for comparison
        const cleanDomain = domain.startsWith('www.') ? domain.substring(4) : domain

        // Check if domain matches any blacklist pattern (exact or wildcard)
        const isBlacklisted = this.isDomainBlacklisted(domain, blacklistedPatterns) ||
                             this.isDomainBlacklisted(cleanDomain, blacklistedPatterns)

        if (isBlacklisted) {
          logger.debug('ClientSearchEngine', `Filtered out blacklisted domain: ${domain}`)
        }

        return !isBlacklisted
      } catch (error) {
        // If URL parsing fails, keep the result
        logger.warn('ClientSearchEngine', `Failed to parse URL for blacklist filtering: ${result.url}`)
        return true
      }
    })

    if (filteredResults.length < results.length) {
      logger.info('ClientSearchEngine', `Domain blacklist filtered ${results.length - filteredResults.length} results`)
    }

    return filteredResults
  }

  /**
   * Check if a domain matches any blacklist pattern (supports wildcards)
   * @param domain - Domain to check
   * @param blacklistedPatterns - Array of blacklist patterns
   * @returns True if domain is blacklisted
   */
  private isDomainBlacklisted(domain: string, blacklistedPatterns: string[]): boolean {
    return blacklistedPatterns.some(pattern => {
      // Handle exact match (no wildcards)
      if (!pattern.includes('*')) {
        return domain === pattern
      }

      // Handle wildcard patterns
      if (pattern.startsWith('*.') && pattern.substring(2).indexOf('*') === -1) {
        // Pattern like "*.statefarm.com" (subdomain wildcard, no other wildcards)
        const baseDomain = pattern.substring(2) // Remove "*."

        // Exact match with base domain
        if (domain === baseDomain) {
          return true
        }

        // Subdomain match (domain ends with .baseDomain)
        if (domain.endsWith('.' + baseDomain)) {
          return true
        }
      } else if (pattern.endsWith('*') && pattern.substring(0, pattern.length - 1).indexOf('*') === -1) {
        // Pattern like "statefarm.*" (TLD wildcard, no other wildcards)
        const basePattern = pattern.substring(0, pattern.length - 1) // Remove "*"
        return domain.startsWith(basePattern)
      } else {
        // Pattern contains * in the middle or multiple wildcards - convert to regex
        const regexPattern = pattern
          .replace(/\./g, '\\.')  // Escape dots
          .replace(/\*/g, '.*')   // Convert * to .*

        const regex = new RegExp('^' + regexPattern + '$', 'i')
        return regex.test(domain)
      }

      return false
    })
  }

  /**
   * Get available search providers
   */
  getAvailableProviders(): string[] {
    const providers: string[] = []

    if (this.credentials?.googleSearchApiKey && this.credentials?.googleSearchEngineId) {
      providers.push('Google Custom Search')
    }

    if (this.credentials?.azureSearchApiKey && this.credentials?.azureSearchEndpoint) {
      providers.push('Azure AI Search')
    }

    providers.push('DuckDuckGo (Free)')

    return providers
  }

  /**
   * Refresh credentials from storage
   */
  async refreshCredentials(): Promise<void> {
    await this.initialize()
  }
}

// Export singleton instance
export const clientSearchEngine = new ClientSearchEngine()
