import { logger } from '@/utils/logger'
import { bbbScrapingService } from './bbbScrapingService'
import { yelpScrapingService } from './yelpScrapingService'

/**
 * Provider performance metrics for quality scoring
 */
export interface ProviderMetrics {
  name: string
  totalRequests: number
  successfulRequests: number
  failedRequests: number
  averageResponseTime: number
  averageResultCount: number
  qualityScore: number
  lastUsed: Date
  costPerRequest?: number
  quotaRemaining?: number
}

/**
 * Search performance data for a single request
 */
export interface SearchPerformance {
  providerName: string
  startTime: number
  endTime: number
  responseTime: number
  resultCount: number
  success: boolean
  error?: string
  qualityScore: number
}

/**
 * Provider selection strategy
 */
export type ProviderStrategy = 'round-robin' | 'quality-based' | 'cost-optimized' | 'fastest-first'

/**
 * Cost tracking and quota management
 */
export interface CostTracker {
  providerName: string
  dailyCost: number
  monthlyCost: number
  dailyQuota: number
  monthlyQuota: number
  dailyUsage: number
  monthlyUsage: number
  costPerRequest: number
  lastReset: Date
}

/**
 * Quota limits configuration
 */
export interface QuotaLimits {
  dailyRequestLimit?: number
  monthlyRequestLimit?: number
  dailyCostLimit?: number
  monthlyCostLimit?: number
  enableQuotaEnforcement: boolean
}

export interface SearchOptions {
  query: string
  location: string
  zipRadius?: number
  maxResults: number
  accreditedOnly?: boolean
}

export interface BusinessResult {
  url: string
  title: string
  snippet: string
  domain: string
  address?: string
  phone?: string
  source: 'serp' | 'bbb' | 'yelp' | 'direct'
  sourceUrl?: string
}

export interface SearchProvider {
  name: string
  searchSERP(options: SearchOptions): Promise<BusinessResult[]>
}

export interface BusinessDiscoveryProvider {
  name: string
  searchBusinesses(options: SearchOptions): Promise<BusinessResult[]>
}

/**
 * Abstract search orchestrator that coordinates SERP, BBB, and Yelp searches
 * regardless of the underlying search provider (Google, Bing, DuckDuckGo)
 */
export class SearchOrchestrator {
  private searchProviders: SearchProvider[] = []
  private businessDiscoveryProviders: BusinessDiscoveryProvider[] = []
  private providerMetrics: Map<string, ProviderMetrics> = new Map()
  private costTrackers: Map<string, CostTracker> = new Map()
  private strategy: ProviderStrategy = 'quality-based'
  private quotaLimits: QuotaLimits = {
    enableQuotaEnforcement: true,
    dailyRequestLimit: 1000,
    monthlyRequestLimit: 10000,
    dailyCostLimit: 50.0,
    monthlyCostLimit: 500.0
  }

  constructor() {
    // Initialize business discovery providers
    this.businessDiscoveryProviders = [
      new BBBDiscoveryProvider(),
      new YelpDiscoveryProvider()
    ]
  }

  /**
   * Register a search provider (Google, Bing, DuckDuckGo)
   */
  registerSearchProvider(provider: SearchProvider): void {
    this.searchProviders.push(provider)
    this.initializeProviderMetrics(provider.name)
    this.initializeCostTracker(provider.name)
    logger.info('SearchOrchestrator', `Registered search provider: ${provider.name}`)
  }

  /**
   * Set provider selection strategy
   */
  setStrategy(strategy: ProviderStrategy): void {
    this.strategy = strategy
    logger.info('SearchOrchestrator', `Provider strategy set to: ${strategy}`)
  }

  /**
   * Get provider performance metrics
   */
  getProviderMetrics(): ProviderMetrics[] {
    return Array.from(this.providerMetrics.values())
  }

  /**
   * Get cost tracking information
   */
  getCostTrackers(): CostTracker[] {
    return Array.from(this.costTrackers.values())
  }

  /**
   * Set quota limits
   */
  setQuotaLimits(limits: Partial<QuotaLimits>): void {
    this.quotaLimits = { ...this.quotaLimits, ...limits }
    logger.info('SearchOrchestrator', 'Updated quota limits', this.quotaLimits)
  }

  /**
   * Get current quota limits
   */
  getQuotaLimits(): QuotaLimits {
    return { ...this.quotaLimits }
  }

  /**
   * Check if provider can be used based on quota limits
   */
  canUseProvider(providerName: string): boolean {
    if (!this.quotaLimits.enableQuotaEnforcement) return true

    const costTracker = this.costTrackers.get(providerName)
    if (!costTracker) return true

    // Check daily limits
    if (this.quotaLimits.dailyRequestLimit !== undefined && costTracker.dailyUsage >= this.quotaLimits.dailyRequestLimit) {
      logger.warn('SearchOrchestrator', `${providerName} daily request limit exceeded`)
      return false
    }

    if (this.quotaLimits.dailyCostLimit !== undefined && costTracker.dailyCost >= this.quotaLimits.dailyCostLimit) {
      logger.warn('SearchOrchestrator', `${providerName} daily cost limit exceeded`)
      return false
    }

    // Check monthly limits
    if (this.quotaLimits.monthlyRequestLimit !== undefined && costTracker.monthlyUsage >= this.quotaLimits.monthlyRequestLimit) {
      logger.warn('SearchOrchestrator', `${providerName} monthly request limit exceeded`)
      return false
    }

    if (this.quotaLimits.monthlyCostLimit !== undefined && costTracker.monthlyCost >= this.quotaLimits.monthlyCostLimit) {
      logger.warn('SearchOrchestrator', `${providerName} monthly cost limit exceeded`)
      return false
    }

    return true
  }

  /**
   * Initialize metrics for a new provider
   */
  private initializeProviderMetrics(providerName: string): void {
    if (!this.providerMetrics.has(providerName)) {
      this.providerMetrics.set(providerName, {
        name: providerName,
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        averageResponseTime: 0,
        averageResultCount: 0,
        qualityScore: 0.5, // Start with neutral score
        lastUsed: new Date(),
        costPerRequest: this.getProviderCostPerRequest(providerName)
      })
    }
  }

  /**
   * Initialize cost tracker for a new provider
   */
  private initializeCostTracker(providerName: string): void {
    if (!this.costTrackers.has(providerName)) {
      this.costTrackers.set(providerName, {
        providerName,
        dailyCost: 0,
        monthlyCost: 0,
        dailyQuota: this.quotaLimits.dailyRequestLimit || 1000,
        monthlyQuota: this.quotaLimits.monthlyRequestLimit || 10000,
        dailyUsage: 0,
        monthlyUsage: 0,
        costPerRequest: this.getProviderCostPerRequest(providerName),
        lastReset: new Date()
      })
    }
  }

  /**
   * Get cost per request for a provider (in USD)
   */
  private getProviderCostPerRequest(providerName: string): number {
    const costs: Record<string, number> = {
      'Google': 0.005, // $5 per 1000 requests
      'Bing': 0.003,   // $3 per 1000 requests
      'Azure': 0.003,  // Same as Bing
      'DuckDuckGo': 0, // Free
      'BBB Discovery': 0, // Free
      'Yelp Discovery': 0 // Free
    }
    return costs[providerName] || 0
  }

  /**
   * Perform comprehensive business search using all available methods with intelligent provider selection
   */
  async searchBusinesses(options: SearchOptions): Promise<BusinessResult[]> {
    const allResults: BusinessResult[] = []
    const performances: SearchPerformance[] = []

    logger.info('SearchOrchestrator', `Starting comprehensive search for: ${options.query} in ${options.location} using ${this.strategy} strategy`)

    // 1. Search using SERP providers with intelligent selection and quota checking
    const orderedProviders = this.orderProvidersByStrategy(this.searchProviders)
      .filter(provider => this.canUseProvider(provider.name))
    const resultsPerMethod = Math.ceil(options.maxResults / (orderedProviders.length + this.businessDiscoveryProviders.length))

    for (const provider of orderedProviders) {
      // Double-check quota before each request
      if (!this.canUseProvider(provider.name)) {
        logger.warn('SearchOrchestrator', `Skipping ${provider.name} due to quota limits`)
        continue
      }

      const performance = await this.searchWithProvider(provider, {
        ...options,
        maxResults: resultsPerMethod
      })

      performances.push(performance)

      // Track cost and usage
      this.trackProviderUsage(provider.name, performance.success)

      if (performance.success) {
        // Add results with source information
        const resultsWithSource = performance.resultCount > 0 ?
          await provider.searchSERP({ ...options, maxResults: resultsPerMethod }) : []
        allResults.push(...resultsWithSource)

        logger.info('SearchOrchestrator',
          `${provider.name} returned ${performance.resultCount} results in ${performance.responseTime}ms (cost: $${this.getProviderCostPerRequest(provider.name).toFixed(4)})`)
      } else {
        logger.warn('SearchOrchestrator',
          `${provider.name} search failed: ${performance.error}`)
      }
    }

    // 2. Search using business discovery providers (BBB, Yelp)
    for (const provider of this.businessDiscoveryProviders) {
      try {
        logger.info('SearchOrchestrator', `Searching with ${provider.name}`)
        const results = await provider.searchBusinesses({
          ...options,
          maxResults: resultsPerMethod
        })
        
        allResults.push(...results)
        logger.info('SearchOrchestrator', `${provider.name} returned ${results.length} results`)
        
      } catch (error) {
        logger.warn('SearchOrchestrator', `${provider.name} search failed`, error)
        continue
      }
    }

    // 3. Deduplicate and rank results
    const uniqueResults = this.deduplicateResults(allResults)
    const rankedResults = this.rankResults(uniqueResults, options)

    // 4. Update provider metrics based on performance
    this.updateProviderMetrics(performances)

    // 5. Return all results (no artificial limiting)
    const finalResults = rankedResults

    logger.info('SearchOrchestrator',
      `Search completed: ${allResults.length} total → ${uniqueResults.length} unique → ${finalResults.length} final results`)

    return finalResults
  }

  /**
   * Order providers based on the selected strategy
   */
  private orderProvidersByStrategy(providers: SearchProvider[]): SearchProvider[] {
    switch (this.strategy) {
      case 'quality-based':
        return [...providers].sort((a, b) => {
          const metricsA = this.providerMetrics.get(a.name)
          const metricsB = this.providerMetrics.get(b.name)
          return (metricsB?.qualityScore || 0) - (metricsA?.qualityScore || 0)
        })

      case 'fastest-first':
        return [...providers].sort((a, b) => {
          const metricsA = this.providerMetrics.get(a.name)
          const metricsB = this.providerMetrics.get(b.name)
          return (metricsA?.averageResponseTime || Infinity) - (metricsB?.averageResponseTime || Infinity)
        })

      case 'cost-optimized':
        return [...providers].sort((a, b) => {
          const metricsA = this.providerMetrics.get(a.name)
          const metricsB = this.providerMetrics.get(b.name)
          return (metricsA?.costPerRequest || 0) - (metricsB?.costPerRequest || 0)
        })

      case 'round-robin':
      default:
        return providers
    }
  }

  /**
   * Search with a single provider and track performance
   */
  private async searchWithProvider(provider: SearchProvider, options: SearchOptions): Promise<SearchPerformance> {
    const startTime = Date.now()
    let success = false
    let resultCount = 0
    let error: string | undefined

    try {
      const results = await provider.searchSERP(options)
      resultCount = results.length
      success = true
    } catch (err) {
      error = err instanceof Error ? err.message : String(err)
      success = false
    }

    const endTime = Date.now()
    const responseTime = endTime - startTime
    const qualityScore = this.calculateQualityScore(resultCount, responseTime, success)

    return {
      providerName: provider.name,
      startTime,
      endTime,
      responseTime,
      resultCount,
      success,
      error,
      qualityScore
    }
  }

  /**
   * Calculate quality score based on performance metrics
   */
  private calculateQualityScore(resultCount: number, responseTime: number, success: boolean): number {
    if (!success) return 0

    // Base score from result count (0-0.6)
    const resultScore = Math.min(resultCount / 50, 0.6) // Max 0.6 for 50+ results

    // Speed score (0-0.3)
    const speedScore = Math.max(0, 0.3 - (responseTime / 10000)) // Penalty for slow responses

    // Success bonus (0.1)
    const successBonus = 0.1

    return Math.min(resultScore + speedScore + successBonus, 1.0)
  }

  /**
   * Update provider metrics based on search performances
   */
  private updateProviderMetrics(performances: SearchPerformance[]): void {
    for (const performance of performances) {
      const metrics = this.providerMetrics.get(performance.providerName)
      if (!metrics) continue

      // Update counters
      metrics.totalRequests++
      if (performance.success) {
        metrics.successfulRequests++
      } else {
        metrics.failedRequests++
      }

      // Update averages using exponential moving average
      const alpha = 0.1 // Smoothing factor
      metrics.averageResponseTime = metrics.averageResponseTime * (1 - alpha) + performance.responseTime * alpha
      metrics.averageResultCount = metrics.averageResultCount * (1 - alpha) + performance.resultCount * alpha
      metrics.qualityScore = metrics.qualityScore * (1 - alpha) + performance.qualityScore * alpha
      metrics.lastUsed = new Date()

      logger.debug('SearchOrchestrator',
        `Updated metrics for ${performance.providerName}: quality=${metrics.qualityScore.toFixed(3)}, avgTime=${metrics.averageResponseTime.toFixed(0)}ms`)
    }
  }

  /**
   * Track provider usage and costs
   */
  private trackProviderUsage(providerName: string, success: boolean): void {
    const costTracker = this.costTrackers.get(providerName)
    if (!costTracker) return

    const cost = costTracker.costPerRequest
    const now = new Date()

    // Reset daily counters if it's a new day
    if (this.isNewDay(costTracker.lastReset, now)) {
      costTracker.dailyCost = 0
      costTracker.dailyUsage = 0
    }

    // Reset monthly counters if it's a new month
    if (this.isNewMonth(costTracker.lastReset, now)) {
      costTracker.monthlyCost = 0
      costTracker.monthlyUsage = 0
    }

    // Update usage and costs
    costTracker.dailyUsage++
    costTracker.monthlyUsage++
    costTracker.dailyCost += cost
    costTracker.monthlyCost += cost
    costTracker.lastReset = now

    logger.debug('SearchOrchestrator',
      `${providerName} usage: daily=${costTracker.dailyUsage}/$${costTracker.dailyCost.toFixed(4)}, monthly=${costTracker.monthlyUsage}/$${costTracker.monthlyCost.toFixed(4)}`)
  }

  /**
   * Check if it's a new day since last reset
   */
  private isNewDay(lastReset: Date, now: Date): boolean {
    return lastReset.toDateString() !== now.toDateString()
  }

  /**
   * Check if it's a new month since last reset
   */
  private isNewMonth(lastReset: Date, now: Date): boolean {
    return lastReset.getMonth() !== now.getMonth() || lastReset.getFullYear() !== now.getFullYear()
  }

  /**
   * Remove duplicate businesses based on URL and title similarity
   */
  private deduplicateResults(results: BusinessResult[]): BusinessResult[] {
    const seen = new Map<string, BusinessResult>()
    const unique: BusinessResult[] = []

    for (const result of results) {
      // Create a unique key based on domain and normalized title
      const domain = result.domain.toLowerCase().replace(/^www\./, '')
      const normalizedTitle = result.title.toLowerCase().replace(/[^a-z0-9]/g, '')
      const key = `${domain}|${normalizedTitle.substring(0, 20)}`

      if (!seen.has(key)) {
        seen.set(key, result)
        unique.push(result)
      } else {
        // If we have a duplicate, prefer certain sources
        const existing = seen.get(key)!
        if (this.shouldReplaceResult(existing, result)) {
          seen.set(key, result)
          const index = unique.findIndex(r => r === existing)
          if (index !== -1) {
            unique[index] = result
          }
        }
      }
    }

    return unique
  }

  /**
   * Determine if a new result should replace an existing one
   */
  private shouldReplaceResult(existing: BusinessResult, newResult: BusinessResult): boolean {
    // Prefer results with more complete information
    const existingScore = this.getResultQualityScore(existing)
    const newScore = this.getResultQualityScore(newResult)
    
    return newScore > existingScore
  }

  /**
   * Calculate a quality score for a business result
   */
  private getResultQualityScore(result: BusinessResult): number {
    let score = 0
    
    // Source preference: direct business websites > BBB > Yelp > SERP
    switch (result.source) {
      case 'direct': score += 40; break
      case 'bbb': score += 30; break
      case 'yelp': score += 20; break
      case 'serp': score += 10; break
    }
    
    // Bonus for having contact information
    if (result.phone) score += 15
    if (result.address) score += 10
    
    // Bonus for longer, more descriptive snippets
    if (result.snippet && result.snippet.length > 50) score += 5
    
    // Bonus for business domains (not social media, directories)
    if (!result.domain.includes('facebook.com') && 
        !result.domain.includes('linkedin.com') &&
        !result.domain.includes('yelp.com') &&
        !result.domain.includes('yellowpages.com')) {
      score += 10
    }
    
    return score
  }

  /**
   * Rank results by relevance and quality
   */
  private rankResults(results: BusinessResult[], options: SearchOptions): BusinessResult[] {
    return results.sort((a, b) => {
      const scoreA = this.getResultQualityScore(a)
      const scoreB = this.getResultQualityScore(b)
      
      // Primary sort by quality score
      if (scoreA !== scoreB) {
        return scoreB - scoreA
      }
      
      // Secondary sort by title relevance to query
      const queryLower = options.query.toLowerCase()
      const titleRelevanceA = a.title.toLowerCase().includes(queryLower) ? 1 : 0
      const titleRelevanceB = b.title.toLowerCase().includes(queryLower) ? 1 : 0
      
      return titleRelevanceB - titleRelevanceA
    })
  }

  /**
   * Get statistics about registered providers
   */
  getProviderStats() {
    return {
      searchProviders: this.searchProviders.map(p => p.name),
      businessDiscoveryProviders: this.businessDiscoveryProviders.map(p => p.name),
      totalProviders: this.searchProviders.length + this.businessDiscoveryProviders.length
    }
  }
}

/**
 * BBB Business Discovery Provider
 */
class BBBDiscoveryProvider implements BusinessDiscoveryProvider {
  name = 'BBB Discovery'

  async searchBusinesses(options: SearchOptions): Promise<BusinessResult[]> {
    try {
      const results = await bbbScrapingService.searchBusinesses({
        query: options.query,
        location: options.location,
        accreditedOnly: options.accreditedOnly || false,
        zipRadius: options.zipRadius || 25,
        maxResults: options.maxResults
      })

      return results.map(result => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet,
        domain: result.domain,
        address: result.address,
        phone: result.phone,
        source: 'bbb' as const,
        sourceUrl: result.bbbProfileUrl
      }))
    } catch (error) {
      logger.error('BBBDiscoveryProvider', 'Search failed', error)
      return []
    }
  }
}

/**
 * Yelp Business Discovery Provider
 */
class YelpDiscoveryProvider implements BusinessDiscoveryProvider {
  name = 'Yelp Discovery'

  async searchBusinesses(options: SearchOptions): Promise<BusinessResult[]> {
    try {
      const results = await yelpScrapingService.searchBusinesses({
        query: options.query,
        location: options.location,
        zipRadius: options.zipRadius || 25,
        maxResults: options.maxResults
      })

      return results.map(result => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet,
        domain: result.domain,
        address: result.address,
        phone: result.phone,
        source: 'yelp' as const,
        sourceUrl: result.yelpProfileUrl
      }))
    } catch (error) {
      logger.error('YelpDiscoveryProvider', 'Search failed', error)
      return []
    }
  }
}

/**
 * DuckDuckGo SERP Provider
 */
export class DuckDuckGoProvider implements SearchProvider {
  name = 'DuckDuckGo'

  async searchSERP(options: SearchOptions): Promise<BusinessResult[]> {
    try {
      const response = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: 'duckduckgo-serp',
          query: `${options.query} ${options.location}`,
          page: 0,
          maxResults: options.maxResults
        })
      })

      if (!response.ok) {
        throw new Error(`DuckDuckGo API error: ${response.status}`)
      }

      const data = await response.json()
      if (!data.success) {
        throw new Error(data.error || 'DuckDuckGo search failed')
      }

      return (data.results || []).map((result: any) => ({
        url: result.url,
        title: result.title,
        snippet: result.snippet || '',
        domain: result.domain,
        source: 'serp' as const
      }))
    } catch (error) {
      logger.error('DuckDuckGoProvider', 'Search failed', error)
      return []
    }
  }
}

/**
 * Google Custom Search API Provider
 */
export class GoogleProvider implements SearchProvider {
  name = 'Google'
  private config = {
    timeout: 30000,
    maxRetries: 3,
    retryDelay: 1000,
    userAgent: 'BusinessScraperApp/1.0 (Business Discovery Tool)'
  }

  async searchSERP(options: SearchOptions): Promise<BusinessResult[]> {
    try {
      // Get API credentials from environment or config
      const apiKey = process.env.GOOGLE_SEARCH_API_KEY
      const searchEngineId = process.env.GOOGLE_SEARCH_ENGINE_ID

      if (!apiKey || !searchEngineId) {
        logger.info('GoogleProvider', 'Google Custom Search API credentials not configured, skipping Google search')
        return []
      }

      const searchQuery = this.formatGoogleQuery(options.query, options.location)
      const results = await this.performGoogleSearch(apiKey, searchEngineId, searchQuery, options.maxResults)

      logger.info('GoogleProvider', `Google search returned ${results.length} results`)
      return results

    } catch (error) {
      logger.error('GoogleProvider', 'Google search failed', error)
      return []
    }
  }

  /**
   * Format search query specifically for Google Custom Search requirements
   */
  private formatGoogleQuery(query: string, location: string): string {
    const cleanQuery = query.trim()
    const cleanLocation = location.trim()

    let googleQuery = cleanQuery

    // Add location if provided
    if (cleanLocation) {
      googleQuery += ` ${cleanLocation}`
    }

    // Add site restrictions to filter out directories and social media
    const excludeSites = [
      'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
      'yelp.com', 'yellowpages.com', 'whitepages.com', 'superpages.com',
      'foursquare.com', 'tripadvisor.com', 'indeed.com', 'glassdoor.com',
      'craigslist.org', 'amazon.com', 'ebay.com'
    ]

    for (const site of excludeSites) {
      googleQuery += ` -site:${site}`
    }

    // Add file type restrictions
    googleQuery += ' -filetype:pdf -filetype:doc -filetype:docx -filetype:ppt'

    // Prefer business-related domains and content
    googleQuery += ' (site:*.com OR site:*.org OR site:*.net OR site:*.biz)'

    return googleQuery
  }

  /**
   * Perform Google Custom Search API request with retry logic
   */
  private async performGoogleSearch(
    apiKey: string,
    searchEngineId: string,
    query: string,
    maxResults: number
  ): Promise<BusinessResult[]> {
    const allResults: BusinessResult[] = []
    const maxResultsPerRequest = 10 // Google Custom Search API limit
    const totalRequests = Math.ceil(Math.min(maxResults, 100) / maxResultsPerRequest) // Google allows max 100 results per day for free tier

    for (let i = 0; i < totalRequests; i++) {
      const startIndex = (i * maxResultsPerRequest) + 1
      const requestMaxResults = Math.min(maxResultsPerRequest, maxResults - allResults.length)

      if (requestMaxResults <= 0) break

      try {
        const results = await this.makeGoogleApiRequest(
          apiKey,
          searchEngineId,
          query,
          startIndex,
          requestMaxResults
        )

        allResults.push(...results)

        // If we got fewer results than requested, we've reached the end
        if (results.length < requestMaxResults) {
          break
        }

        // Add delay between requests to respect rate limits
        if (i < totalRequests - 1) {
          await this.delay(this.config.retryDelay)
        }

      } catch (error) {
        logger.warn('GoogleProvider', `Request ${i + 1} failed`, error)
        break // Stop on error to avoid wasting quota
      }
    }

    return allResults
  }

  /**
   * Make a single Google Custom Search API request
   */
  private async makeGoogleApiRequest(
    apiKey: string,
    searchEngineId: string,
    query: string,
    startIndex: number,
    num: number
  ): Promise<BusinessResult[]> {
    const url = new URL('https://www.googleapis.com/customsearch/v1')
    url.searchParams.set('key', apiKey)
    url.searchParams.set('cx', searchEngineId)
    url.searchParams.set('q', query)
    url.searchParams.set('num', num.toString())
    url.searchParams.set('start', startIndex.toString())
    url.searchParams.set('safe', 'medium')
    url.searchParams.set('lr', 'lang_en')
    url.searchParams.set('gl', 'us')
    url.searchParams.set('filter', '1') // Enable duplicate filtering

    logger.info('GoogleProvider', `Making Google API request: ${query} (start: ${startIndex}, num: ${num})`)

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'User-Agent': this.config.userAgent,
        'Accept': 'application/json'
      },
      signal: this.createTimeoutSignal(this.config.timeout)
    })

    if (!response.ok) {
      const errorText = await response.text()
      if (response.status === 403) {
        throw new Error('Google API quota exceeded or access denied')
      } else if (response.status === 400) {
        throw new Error('Google API bad request - check query format')
      } else if (response.status === 429) {
        throw new Error('Google API rate limit exceeded')
      } else {
        throw new Error(`Google API error: ${response.status} - ${errorText}`)
      }
    }

    const data = await response.json()
    return this.parseGoogleResults(data)
  }

  /**
   * Parse Google search results into standardized format
   */
  private parseGoogleResults(data: any): BusinessResult[] {
    const results: BusinessResult[] = []

    if (!data.items) {
      logger.warn('GoogleProvider', 'No items found in Google response')
      return results
    }

    for (const item of data.items) {
      try {
        const url = item.link
        const domain = this.extractDomain(url)

        // Validate business domain
        if (!this.isValidBusinessDomain(domain)) {
          continue
        }

        // Additional URL validation
        if (!url || !url.startsWith('http')) {
          continue
        }

        results.push({
          url: url,
          title: item.title || '',
          snippet: item.snippet || '',
          domain: domain,
          source: 'serp' as const
        })

      } catch (error) {
        logger.warn('GoogleProvider', 'Failed to parse Google result item', error)
        continue
      }
    }

    return results
  }

  /**
   * Extract domain from URL
   */
  private extractDomain(url: string): string {
    try {
      const urlObj = new URL(url)
      return urlObj.hostname.replace(/^www\./, '')
    } catch {
      return ''
    }
  }

  /**
   * Validate if domain is suitable for business discovery
   */
  private isValidBusinessDomain(domain: string): boolean {
    if (!domain) return false

    // Domain blacklist
    const blacklistedDomains = [
      'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
      'yelp.com', 'yellowpages.com', 'whitepages.com', 'superpages.com',
      'foursquare.com', 'tripadvisor.com', 'indeed.com', 'glassdoor.com',
      'craigslist.org', 'amazon.com', 'ebay.com', 'wikipedia.org',
      'youtube.com', 'pinterest.com', 'reddit.com', 'quora.com'
    ]

    return !blacklistedDomains.some(blocked => domain.includes(blocked))
  }

  /**
   * Utility function to add delay
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  /**
   * Create timeout signal compatible with older Node.js versions
   */
  private createTimeoutSignal(timeoutMs: number): AbortSignal {
    const controller = new AbortController()
    setTimeout(() => controller.abort(), timeoutMs)
    return controller.signal
  }
}

/**
 * Bing Search Provider with support for both legacy Bing API and Azure AI Foundry
 */
export class BingProvider implements SearchProvider {
  name = 'Bing'
  private config = {
    timeout: 30000,
    maxRetries: 3,
    retryDelay: 1000,
    userAgent: 'BusinessScraperApp/1.0 (Business Discovery Tool)'
  }

  async searchSERP(options: SearchOptions): Promise<BusinessResult[]> {
    try {
      // Try Azure AI Foundry first (new approach), then fallback to legacy Bing API
      const azureResults = await this.searchWithAzureAIFoundry(options)
      if (azureResults.length > 0) {
        return azureResults
      }

      // Fallback to legacy Bing Search API
      const legacyResults = await this.searchWithLegacyBing(options)
      return legacyResults

    } catch (azureError) {
      // If Azure fails, try legacy Bing API as fallback
      try {
        logger.warn('BingProvider', 'Azure AI Foundry failed, trying legacy Bing API', azureError)
        const legacyResults = await this.searchWithLegacyBing(options)
        return legacyResults
      } catch (legacyError) {
        logger.error('BingProvider', 'Both Azure and legacy Bing search failed', { azureError, legacyError })
        return []
      }
    }
  }

  /**
   * Search using Azure AI Foundry "Grounding with Bing Custom Search" API
   * This is the new recommended approach replacing the deprecated Bing Search API
   */
  private async searchWithAzureAIFoundry(options: SearchOptions): Promise<BusinessResult[]> {
    const azureApiKey = process.env.AZURE_AI_FOUNDRY_API_KEY
    const azureEndpoint = process.env.AZURE_AI_FOUNDRY_ENDPOINT

    if (!azureApiKey || !azureEndpoint) {
      logger.info('BingProvider', 'Azure AI Foundry credentials not configured, trying legacy Bing API')
      return []
    }

    const searchQuery = this.formatBingQuery(options.query, options.location)

    // Ensure proper URL construction
    const baseUrl = azureEndpoint.endsWith('/') ? azureEndpoint.slice(0, -1) : azureEndpoint
    const url = new URL(`${baseUrl}/bing/v7.0/custom/search`)

    try {
      logger.info('BingProvider', `Searching Azure AI Foundry with query: ${searchQuery}`)

      const requestBody = {
        q: searchQuery,
        count: Math.min(options.maxResults, 50),
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
          'Ocp-Apim-Subscription-Key': azureApiKey,
          'Content-Type': 'application/json',
          'User-Agent': this.config.userAgent
        },
        body: JSON.stringify(requestBody),
        signal: this.createTimeoutSignal(this.config.timeout)
      })

      if (!response.ok) {
        const errorText = await response.text()
        logger.error('BingProvider', `Azure AI Foundry API error: ${response.status} - ${errorText}`)
        throw new Error(`Azure AI Foundry API error: ${response.status}`)
      }

      const data = await response.json()
      const results = this.parseAzureResults(data)

      logger.info('BingProvider', `Azure AI Foundry search returned ${results.length} results`)
      return results

    } catch (error) {
      logger.error('BingProvider', 'Azure AI Foundry search failed', error)
      throw error
    }
  }

  /**
   * Search using legacy Bing Search API (deprecated August 2025)
   */
  private async searchWithLegacyBing(options: SearchOptions): Promise<BusinessResult[]> {
    const apiKey = process.env.BING_SEARCH_API_KEY

    if (!apiKey) {
      logger.info('BingProvider', 'Legacy Bing API key not configured, skipping Bing search')
      return []
    }

    const searchQuery = this.formatBingQuery(options.query, options.location)

    try {
      logger.info('BingProvider', `Searching legacy Bing API with query: ${searchQuery}`)

      const response = await fetch('https://api.bing.microsoft.com/v7.0/search', {
        method: 'GET',
        headers: {
          'Ocp-Apim-Subscription-Key': apiKey,
          'User-Agent': this.config.userAgent,
          'X-MSEdge-ClientID': this.generateClientId()
        },
        signal: this.createTimeoutSignal(this.config.timeout)
      })

      if (!response.ok) {
        const errorText = await response.text()
        if (response.status === 401) {
          throw new Error('Bing API authentication failed - check API key')
        } else if (response.status === 403) {
          throw new Error('Bing API quota exceeded or access denied')
        } else if (response.status === 429) {
          throw new Error('Bing API rate limit exceeded')
        } else {
          throw new Error(`Bing API error: ${response.status} - ${errorText}`)
        }
      }

      const data = await response.json()
      const results = this.parseLegacyBingResults(data)

      logger.info('BingProvider', `Legacy Bing search returned ${results.length} results`)
      return results

    } catch (error) {
      logger.error('BingProvider', 'Legacy Bing search failed', error)
      throw error
    }
  }

  /**
   * Format search query specifically for Bing's requirements
   */
  private formatBingQuery(query: string, location: string): string {
    const cleanQuery = query.trim()
    const cleanLocation = location.trim()

    let bingQuery = cleanQuery

    // Add location if provided
    if (cleanLocation) {
      bingQuery += ` ${cleanLocation}`
    }

    // Add site restrictions to filter out directories and social media
    const excludeSites = [
      'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
      'yelp.com', 'yellowpages.com', 'whitepages.com', 'superpages.com',
      'foursquare.com', 'tripadvisor.com', 'google.com', 'bing.com',
      'indeed.com', 'glassdoor.com', 'craigslist.org'
    ]

    for (const site of excludeSites) {
      bingQuery += ` -site:${site}`
    }

    // Add file type restrictions
    bingQuery += ' -filetype:pdf -filetype:doc -filetype:docx'

    // Prefer business-related domains
    bingQuery += ' (site:*.com OR site:*.org OR site:*.net OR site:*.biz)'

    return bingQuery
  }

  /**
   * Parse Azure AI Foundry "Grounding with Bing Custom Search" results
   */
  private parseAzureResults(data: any): BusinessResult[] {
    const results: BusinessResult[] = []

    if (!data.webPages?.value) {
      logger.warn('BingProvider', 'No webPages.value found in Azure AI Foundry response')
      return results
    }

    for (const item of data.webPages.value) {
      try {
        const url = item.url
        const domain = this.extractDomain(url)

        // Validate business domain
        if (!this.isValidBusinessDomain(domain)) {
          continue
        }

        // Additional URL validation
        if (!url || !url.startsWith('http')) {
          continue
        }

        results.push({
          url: url,
          title: item.name || '',
          snippet: item.snippet || '',
          domain: domain,
          source: 'serp' as const
        })

      } catch (error) {
        logger.warn('BingProvider', 'Failed to parse Azure AI Foundry result item', error)
        continue
      }
    }

    return results
  }

  /**
   * Parse legacy Bing Search API results
   */
  private parseLegacyBingResults(data: any): BusinessResult[] {
    const results: BusinessResult[] = []

    if (!data.webPages?.value) {
      logger.warn('BingProvider', 'No web pages found in legacy Bing response')
      return results
    }

    for (const item of data.webPages.value) {
      try {
        const url = item.url
        const domain = this.extractDomain(url)

        // Validate business domain
        if (!this.isValidBusinessDomain(domain)) {
          continue
        }

        // Additional URL validation
        if (!url || !url.startsWith('http')) {
          continue
        }

        results.push({
          url: url,
          title: item.name || '',
          snippet: item.snippet || '',
          domain: domain,
          source: 'serp' as const
        })

      } catch (error) {
        logger.warn('BingProvider', 'Failed to parse legacy Bing result item', error)
        continue
      }
    }

    return results
  }

  /**
   * Extract domain from URL
   */
  private extractDomain(url: string): string {
    try {
      const urlObj = new URL(url)
      return urlObj.hostname.replace(/^www\./, '')
    } catch {
      return ''
    }
  }

  /**
   * Validate if domain is suitable for business discovery
   */
  private isValidBusinessDomain(domain: string): boolean {
    if (!domain) return false

    // Domain blacklist
    const blacklistedDomains = [
      'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
      'yelp.com', 'yellowpages.com', 'whitepages.com', 'superpages.com',
      'foursquare.com', 'tripadvisor.com', 'indeed.com', 'glassdoor.com',
      'craigslist.org', 'amazon.com', 'ebay.com', 'wikipedia.org',
      'youtube.com', 'pinterest.com', 'reddit.com', 'quora.com'
    ]

    return !blacklistedDomains.some(blocked => domain.includes(blocked))
  }

  /**
   * Generate a client ID for Bing API tracking
   */
  private generateClientId(): string {
    return `business-scraper-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }

  /**
   * Create timeout signal compatible with older Node.js versions
   */
  private createTimeoutSignal(timeoutMs: number): AbortSignal {
    const controller = new AbortController()
    setTimeout(() => controller.abort(), timeoutMs)
    return controller.signal
  }
}

// Export singleton instance
export const searchOrchestrator = new SearchOrchestrator()

// Register available search providers
searchOrchestrator.registerSearchProvider(new DuckDuckGoProvider())
searchOrchestrator.registerSearchProvider(new GoogleProvider())
searchOrchestrator.registerSearchProvider(new BingProvider())
