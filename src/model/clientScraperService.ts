'use client'

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import { clientSearchEngine } from './clientSearchEngine'
import { retrieveApiCredentials } from '@/utils/secureStorage'

/**
 * Client-side scraper service that communicates with API routes
 * This service runs in the browser and makes HTTP requests to server-side APIs
 */
export class ClientScraperService {
  private baseUrl = '/api'

  /**
   * Initialize the scraper service
   */
  async initialize(): Promise<void> {
    // Initialize the client search engine with stored credentials
    await clientSearchEngine.initialize()

    // Check if we have stored API credentials
    const credentials = await retrieveApiCredentials()
    const hasApiCredentials = !!(credentials && credentials.googleSearchApiKey)

    logger.info('ClientScraper', `Initializing scraper - Has API credentials: ${hasApiCredentials}`)

    try {
      const response = await fetch(`${this.baseUrl}/scrape`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'initialize' }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      if (!result.success) {
        throw new Error('Failed to initialize scraper')
      }

      logger.info('ClientScraper', 'Scraper initialized successfully')
    } catch (error) {
      logger.error('ClientScraper', 'Failed to initialize scraper', error)
      throw error
    }
  }

  /**
   * Search for websites based on industry and location
   */
  async searchForWebsites(
    query: string,
    zipCode: string,
    maxResults: number = 50
  ): Promise<string[]> {
    try {
      // Use stored API credentials with client search engine (includes DuckDuckGo SERP scraping)
      const searchResults = await clientSearchEngine.searchBusinesses(query, zipCode, maxResults)
      const urls = searchResults.map(result => result.url)

      if (urls.length > 0) {
        const source = clientSearchEngine.hasApiCredentials() ? 'API credentials' : 'DuckDuckGo SERP scraping'
        logger.info('ClientScraper', `Found ${urls.length} URLs using ${source} for query: ${query}`)
        return urls
      }

      logger.warn('ClientScraper', `Client search returned no results for query: ${query}`)
      return []
    } catch (error) {
      logger.error('ClientScraper', `Search failed for query: ${query}`, error)
      return []
    }
  }

  /**
   * Scrape a website for business information
   */
  async scrapeWebsite(url: string, depth: number = 2, maxPages: number = 5): Promise<BusinessRecord[]> {
    try {
      const response = await fetch(`${this.baseUrl}/scrape`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'scrape',
          url,
          depth,
          maxPages,
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      logger.info('ClientScraper', `Scraped ${result.businesses.length} businesses from: ${url}`)
      return result.businesses
    } catch (error) {
      logger.error('ClientScraper', `Failed to scrape website: ${url}`, error)
      return []
    }
  }

  /**
   * Cleanup scraper resources
   */
  async cleanup(): Promise<void> {
    try {
      const response = await fetch(`${this.baseUrl}/scrape`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'cleanup' }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      if (!result.success) {
        throw new Error('Failed to cleanup scraper')
      }

      logger.info('ClientScraper', 'Scraper cleaned up successfully')
    } catch (error) {
      logger.error('ClientScraper', 'Failed to cleanup scraper', error)
      throw error
    }
  }

  /**
   * Geocode an address
   */
  async geocodeAddress(address: string): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/geocode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      return result.result
    } catch (error) {
      logger.error('ClientScraper', `Failed to geocode address: ${address}`, error)
      return null
    }
  }

  /**
   * Get scraping statistics
   */
  getStats() {
    return {
      totalSites: 0,
      successfulScrapes: 0,
      failedScrapes: 0,
      totalBusinesses: 0,
      startTime: new Date(),
    }
  }

  /**
   * Refresh API credentials from storage
   */
  async refreshCredentials(): Promise<void> {
    await clientSearchEngine.refreshCredentials()

    // Log credential status
    const credentials = await retrieveApiCredentials()
    const hasCredentials = !!(credentials && credentials.googleSearchApiKey)

    logger.info('ClientScraper', `Credentials refreshed - Has API credentials: ${hasCredentials}`)
  }

  /**
   * Reset scraping statistics
   */
  resetStats(): void {
    // This would be handled server-side for real scraping
    logger.info('ClientScraper', 'Stats reset requested - handled server-side')
  }
}

/**
 * Default client scraper instance
 */
export const clientScraperService = new ClientScraperService()
