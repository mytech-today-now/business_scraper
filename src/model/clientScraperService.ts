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
  private maxRetries = 3
  private retryDelay = 1000 // 1 second base delay

  /**
   * Check if the scraping API is available
   */
  async checkApiHealth(): Promise<boolean> {
    try {
      const response = await this.fetchWithRetry(`${this.baseUrl}/scrape`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      })

      if (response.ok) {
        const result = await response.json()
        return result.status === 'Scrape API is working'
      }
      return false
    } catch (error) {
      logger.error('ClientScraper', 'API health check failed', error)
      return false
    }
  }

  /**
   * Enhanced fetch with retry logic and connection failure handling
   */
  private async fetchWithRetry(url: string, options: RequestInit, retryCount = 0): Promise<Response> {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 30000) // 30 second timeout

      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      })

      clearTimeout(timeoutId)
      return response
    } catch (error) {
      const isConnectionError = error instanceof TypeError &&
        (error.message.includes('Failed to fetch') ||
         error.message.includes('ERR_CONNECTION_REFUSED') ||
         error.message.includes('NetworkError'))

      const isTimeoutError = error.name === 'AbortError'

      if ((isConnectionError || isTimeoutError) && retryCount < this.maxRetries) {
        const delay = this.retryDelay * Math.pow(2, retryCount) // Exponential backoff
        logger.warn('ClientScraper', `Connection failed, retrying in ${delay}ms (attempt ${retryCount + 1}/${this.maxRetries})`, error)

        await new Promise(resolve => setTimeout(resolve, delay))
        return this.fetchWithRetry(url, options, retryCount + 1)
      }

      // If we've exhausted retries or it's a different error, throw it
      throw error
    }
  }

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

    // Check API health before attempting initialization
    const isApiHealthy = await this.checkApiHealth()
    if (!isApiHealthy) {
      throw new Error('Scraping API is not available. Please check server connection.')
    }

    try {
      const response = await this.fetchWithRetry(`${this.baseUrl}/scrape`, {
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
      const response = await this.fetchWithRetry(`${this.baseUrl}/scrape`, {
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
      return result.businesses || []
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
      const response = await this.fetchWithRetry(`${this.baseUrl}/scrape`, {
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
      // Don't throw error for cleanup failures - log and continue
      logger.warn('ClientScraper', 'Cleanup failed but continuing - this may leave resources uncleaned')
    }
  }

  /**
   * Geocode an address
   */
  async geocodeAddress(address: string): Promise<any> {
    try {
      const response = await this.fetchWithRetry(`${this.baseUrl}/geocode`, {
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
