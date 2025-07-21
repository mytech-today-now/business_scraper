'use strict'

import axios from 'axios'
import { logger } from '@/utils/logger'

/**
 * Search result interface
 */
export interface SearchResult {
  url: string
  title: string
  snippet: string
  domain: string
}

/**
 * Search engine configuration
 */
export interface SearchEngineConfig {
  timeout: number
  maxRetries: number
  retryDelay: number
  userAgent: string
  maxResults: number
}

/**
 * Default search engine configuration
 */
const DEFAULT_CONFIG: SearchEngineConfig = {
  timeout: 10000,
  maxRetries: 3,
  retryDelay: 1000,
  userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  maxResults: 50,
}

/**
 * Search engine service for finding business websites
 * Implements multiple search providers with fallback support
 */
export class SearchEngineService {
  private config: SearchEngineConfig
  private cache: Map<string, SearchResult[]> = new Map()

  constructor(config: Partial<SearchEngineConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Search for business websites
   * @param query - Search query
   * @param location - Location (ZIP code or city)
   * @param maxResults - Maximum number of results
   * @returns Promise resolving to search results
   */
  async searchBusinesses(
    query: string, 
    location: string, 
    maxResults: number = this.config.maxResults
  ): Promise<SearchResult[]> {
    const cacheKey = `${query}-${location}-${maxResults}`
    
    // Check cache first
    if (this.cache.has(cacheKey)) {
      logger.info('SearchEngine', `Cache hit for query: ${query}`)
      return this.cache.get(cacheKey)!
    }

    try {
      // Try multiple search methods
      const results = await this.searchWithFallback(query, location, maxResults)
      
      // Cache results
      if (results.length > 0) {
        this.cache.set(cacheKey, results)
      }
      
      logger.info('SearchEngine', `Found ${results.length} results for: ${query}`)
      return results
    } catch (error) {
      logger.error('SearchEngine', `Search failed for: ${query}`, error)
      return []
    }
  }

  /**
   * Search using multiple providers with fallback
   * @param query - Search query
   * @param location - Location
   * @param maxResults - Maximum results
   * @returns Promise resolving to search results
   */
  private async searchWithFallback(
    query: string, 
    location: string, 
    maxResults: number
  ): Promise<SearchResult[]> {
    const searchMethods = [
      () => this.searchWithDuckDuckGo(query, location, maxResults),
      () => this.searchWithBing(query, location, maxResults),
      () => this.searchWithYandex(query, location, maxResults),
    ]

    for (const searchMethod of searchMethods) {
      try {
        const results = await this.withRetry(searchMethod)
        if (results.length > 0) {
          return results
        }
      } catch (error) {
        logger.warn('SearchEngine', 'Search method failed, trying next fallback', error)
        continue
      }
    }

    return []
  }

  /**
   * Search using DuckDuckGo (no API key required)
   * @param query - Search query
   * @param location - Location
   * @param maxResults - Maximum results
   * @returns Promise resolving to search results
   */
  private async searchWithDuckDuckGo(
    query: string, 
    location: string, 
    maxResults: number
  ): Promise<SearchResult[]> {
    const searchQuery = `${query} ${location} site:*.com OR site:*.org OR site:*.net -site:facebook.com -site:yelp.com -site:yellowpages.com`
    
    try {
      // Use DuckDuckGo Instant Answer API (limited but free)
      const response = await axios.get('https://api.duckduckgo.com/', {
        params: {
          q: searchQuery,
          format: 'json',
          no_html: '1',
          skip_disambig: '1',
        },
        timeout: this.config.timeout,
        headers: {
          'User-Agent': this.config.userAgent,
        },
      })

      const results: SearchResult[] = []
      
      // Parse related topics (limited results)
      if (response.data.RelatedTopics) {
        for (const topic of response.data.RelatedTopics.slice(0, maxResults)) {
          if (topic.FirstURL && topic.Text) {
            const url = topic.FirstURL
            const domain = this.extractDomain(url)
            
            if (this.isValidBusinessDomain(domain)) {
              results.push({
                url,
                title: topic.Text.split(' - ')[0] || 'Business',
                snippet: topic.Text,
                domain,
              })
            }
          }
        }
      }

      return results
    } catch (error) {
      logger.error('SearchEngine', 'DuckDuckGo search failed', error)
      return []
    }
  }

  /**
   * Search using Bing (requires API key but has free tier)
   * @param query - Search query
   * @param location - Location
   * @param maxResults - Maximum results
   * @returns Promise resolving to search results
   */
  private async searchWithBing(
    query: string, 
    location: string, 
    maxResults: number
  ): Promise<SearchResult[]> {
    const apiKey = process.env.BING_SEARCH_API_KEY
    if (!apiKey) {
      return []
    }

    const searchQuery = `${query} ${location} -site:facebook.com -site:yelp.com -site:yellowpages.com`
    
    try {
      const response = await axios.get('https://api.bing.microsoft.com/v7.0/search', {
        params: {
          q: searchQuery,
          count: Math.min(maxResults, 50),
          offset: 0,
          mkt: 'en-US',
          safesearch: 'Moderate',
        },
        headers: {
          'Ocp-Apim-Subscription-Key': apiKey,
          'User-Agent': this.config.userAgent,
        },
        timeout: this.config.timeout,
      })

      const results: SearchResult[] = []
      
      if (response.data.webPages?.value) {
        for (const item of response.data.webPages.value) {
          const domain = this.extractDomain(item.url)
          
          if (this.isValidBusinessDomain(domain)) {
            results.push({
              url: item.url,
              title: item.name,
              snippet: item.snippet || '',
              domain,
            })
          }
        }
      }

      return results
    } catch (error) {
      logger.error('SearchEngine', 'Bing search failed', error)
      return []
    }
  }

  /**
   * Search using Yandex (free API with limitations)
   * @param query - Search query
   * @param location - Location
   * @param maxResults - Maximum results
   * @returns Promise resolving to search results
   */
  private async searchWithYandex(
    query: string, 
    location: string, 
    maxResults: number
  ): Promise<SearchResult[]> {
    const apiKey = process.env.YANDEX_SEARCH_API_KEY
    if (!apiKey) {
      return []
    }

    const searchQuery = `${query} ${location}`
    
    try {
      const response = await axios.get('https://yandex.com/search/xml', {
        params: {
          query: searchQuery,
          lr: 213, // Moscow region ID (can be changed)
          l10n: 'en',
          sortby: 'rlv',
          filter: 'none',
          maxpassages: 3,
          groupby: `attr=d.mode=deep.groups-on-page=${Math.min(maxResults, 10)}.docs-in-group=1`,
        },
        headers: {
          'Authorization': `Api-Key ${apiKey}`,
          'User-Agent': this.config.userAgent,
        },
        timeout: this.config.timeout,
      })

      // Yandex returns XML, would need XML parsing
      // For now, return empty array
      return []
    } catch (error) {
      logger.error('SearchEngine', 'Yandex search failed', error)
      return []
    }
  }

  /**
   * Generate business-specific search queries
   * @param industry - Industry name
   * @param location - Location
   * @returns Array of search queries
   */
  generateSearchQueries(industry: string, location: string): string[] {
    const baseQueries = [
      `${industry} businesses ${location}`,
      `${industry} companies ${location}`,
      `${industry} services ${location}`,
      `${industry} near ${location}`,
      `local ${industry} ${location}`,
    ]

    // Add industry-specific variations
    const variations = [
      'contact',
      'about us',
      'directory',
      'professional',
      'commercial',
    ]

    const expandedQueries: string[] = []
    
    for (const base of baseQueries) {
      expandedQueries.push(base)
      
      // Add some variations
      for (const variation of variations.slice(0, 2)) {
        expandedQueries.push(`${base} ${variation}`)
      }
    }

    return expandedQueries.slice(0, 10) // Limit to prevent too many requests
  }

  /**
   * Extract domain from URL
   * @param url - URL string
   * @returns Domain name
   */
  private extractDomain(url: string): string {
    try {
      return new URL(url).hostname.toLowerCase()
    } catch {
      return ''
    }
  }

  /**
   * Check if domain is valid for business scraping
   * @param domain - Domain name
   * @returns Boolean indicating if domain is valid
   */
  private isValidBusinessDomain(domain: string): boolean {
    if (!domain) return false
    
    // Exclude common non-business domains
    const excludedDomains = [
      'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
      'yelp.com', 'yellowpages.com', 'google.com', 'youtube.com',
      'wikipedia.org', 'amazon.com', 'ebay.com', 'craigslist.org',
      'indeed.com', 'glassdoor.com', 'zillow.com', 'realtor.com',
      'tripadvisor.com', 'booking.com', 'expedia.com',
    ]
    
    // Exclude social media and directory sites
    const excludedPatterns = [
      /\.facebook\.com$/,
      /\.twitter\.com$/,
      /\.linkedin\.com$/,
      /\.instagram\.com$/,
      /\.pinterest\.com$/,
      /\.reddit\.com$/,
      /\.tumblr\.com$/,
    ]
    
    // Check excluded domains
    if (excludedDomains.some(excluded => domain.includes(excluded))) {
      return false
    }
    
    // Check excluded patterns
    if (excludedPatterns.some(pattern => pattern.test(domain))) {
      return false
    }
    
    // Must be a proper domain
    if (!domain.includes('.') || domain.length < 4) {
      return false
    }
    
    return true
  }

  /**
   * Execute function with retry logic
   * @param fn - Function to execute
   * @returns Promise resolving to function result
   */
  private async withRetry<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: Error | null = null

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        return await fn()
      } catch (error) {
        lastError = error as Error
        
        if (attempt < this.config.maxRetries) {
          const delay = this.config.retryDelay * Math.pow(2, attempt - 1)
          await new Promise(resolve => setTimeout(resolve, delay))
        }
      }
    }

    throw lastError
  }

  /**
   * Clear search cache
   */
  clearCache(): void {
    this.cache.clear()
    logger.info('SearchEngine', 'Cache cleared')
  }

  /**
   * Get cache statistics
   * @returns Cache statistics
   */
  getCacheStats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys()),
    }
  }
}

/**
 * Default search engine instance
 */
export const searchEngine = new SearchEngineService()
