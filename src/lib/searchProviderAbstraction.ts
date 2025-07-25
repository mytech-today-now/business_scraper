import { logger } from '@/utils/logger'
import { bbbScrapingService } from './bbbScrapingService'
import { yelpScrapingService } from './yelpScrapingService'

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
    logger.info('SearchOrchestrator', `Registered search provider: ${provider.name}`)
  }

  /**
   * Perform comprehensive business search using all available methods
   */
  async searchBusinesses(options: SearchOptions): Promise<BusinessResult[]> {
    const allResults: BusinessResult[] = []
    const resultsPerMethod = Math.ceil(options.maxResults / (this.searchProviders.length + this.businessDiscoveryProviders.length))

    logger.info('SearchOrchestrator', `Starting comprehensive search for: ${options.query} in ${options.location}`)

    // 1. Search using SERP providers (Google, Bing, DuckDuckGo)
    for (const provider of this.searchProviders) {
      try {
        logger.info('SearchOrchestrator', `Searching with ${provider.name}`)
        const results = await provider.searchSERP({
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
    
    // 4. Limit to requested number of results
    const finalResults = rankedResults.slice(0, options.maxResults)

    logger.info('SearchOrchestrator', 
      `Search completed: ${allResults.length} total → ${uniqueResults.length} unique → ${finalResults.length} final results`
    )

    return finalResults
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
 * Google Search Provider (placeholder for when Google API is configured)
 */
export class GoogleProvider implements SearchProvider {
  name = 'Google'

  async searchSERP(options: SearchOptions): Promise<BusinessResult[]> {
    try {
      // This would use Google Custom Search API when configured
      logger.info('GoogleProvider', 'Google search not yet implemented')
      return []
    } catch (error) {
      logger.error('GoogleProvider', 'Search failed', error)
      return []
    }
  }
}

/**
 * Bing Search Provider (placeholder for when Bing API is configured)
 */
export class BingProvider implements SearchProvider {
  name = 'Bing'

  async searchSERP(options: SearchOptions): Promise<BusinessResult[]> {
    try {
      // This would use Bing Search API when configured
      logger.info('BingProvider', 'Bing search not yet implemented')
      return []
    } catch (error) {
      logger.error('BingProvider', 'Search failed', error)
      return []
    }
  }
}

// Export singleton instance
export const searchOrchestrator = new SearchOrchestrator()

// Register available search providers
searchOrchestrator.registerSearchProvider(new DuckDuckGoProvider())
searchOrchestrator.registerSearchProvider(new GoogleProvider())
searchOrchestrator.registerSearchProvider(new BingProvider())
