'use client'

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import { demoScraperService } from './demoScraperService'
import { clientSearchEngine } from './clientSearchEngine'
import { retrieveApiCredentials } from '@/utils/secureStorage'

/**
 * Client-side scraper service that communicates with API routes
 * This service runs in the browser and makes HTTP requests to server-side APIs
 */
export class ClientScraperService {
  private baseUrl = '/api'
  private useDemoMode = process.env.NODE_ENV === 'development'

  /**
   * Set demo mode
   * @param demoMode - Whether to use demo mode
   */
  setDemoMode(demoMode: boolean): void {
    this.useDemoMode = demoMode
    logger.info('ClientScraper', `Demo mode ${demoMode ? 'enabled' : 'disabled'}`)
  }

  /**
   * Get current demo mode status
   * @returns Whether demo mode is enabled
   */
  isDemoMode(): boolean {
    return this.useDemoMode
  }

  /**
   * Initialize the scraper service
   */
  async initialize(): Promise<void> {
    // Initialize the client search engine with stored credentials
    await clientSearchEngine.initialize()

    // Check if we have stored API credentials (but don't override user's demo mode preference)
    const credentials = await retrieveApiCredentials()
    const hasApiCredentials = !!(credentials && credentials.googleSearchApiKey)

    logger.info('ClientScraper', `Initializing scraper - Demo mode: ${this.useDemoMode}, Has API credentials: ${hasApiCredentials}`)

    if (this.useDemoMode) {
      await demoScraperService.initialize()
      logger.info('ClientScraper', 'Demo mode enabled by user preference')
      return
    }

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
      logger.warn('ClientScraper', 'Failed to initialize real scraper, falling back to demo mode', error)
      this.useDemoMode = true
      await demoScraperService.initialize()
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
    if (this.useDemoMode) {
      return await demoScraperService.searchForWebsites(query, zipCode, maxResults)
    }

    try {
      // Try using stored API credentials with client search engine (includes DuckDuckGo fallback)
      const searchResults = await clientSearchEngine.searchBusinesses(query, zipCode, maxResults)
      const urls = searchResults.map(result => result.url)

      if (urls.length > 0) {
        const source = clientSearchEngine.hasApiCredentials() ? 'API credentials' : 'DuckDuckGo search'
        logger.info('ClientScraper', `Found ${urls.length} URLs using ${source} for query: ${query}`)
        return urls
      }

      // When demo mode is OFF, don't fall back to server API that generates fake URLs
      logger.warn('ClientScraper', `Client search returned no results for query: ${query}. No server fallback in real mode.`)
      return []
    } catch (error) {
      logger.error('ClientScraper', `All search methods failed for query: ${query}`, error)
      // Don't fall back to demo data when user wants real scraping
      // Return empty array to indicate no real results found
      return []
    }
  }

  /**
   * Scrape a website for business information
   */
  async scrapeWebsite(url: string, depth: number = 2, maxPages: number = 5): Promise<BusinessRecord[]> {
    if (this.useDemoMode) {
      return await demoScraperService.scrapeWebsite(url, depth, maxPages)
    }

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
      // Don't fall back to demo data when user wants real scraping
      // Return empty array to indicate scraping failed
      return []
    }
  }

  /**
   * Cleanup scraper resources
   */
  async cleanup(): Promise<void> {
    if (this.useDemoMode) {
      await demoScraperService.cleanup()
      return
    }

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
      logger.warn('ClientScraper', 'Failed to cleanup scraper, using demo cleanup', error)
      await demoScraperService.cleanup()
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
    if (this.useDemoMode) {
      return demoScraperService.getStats()
    }

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

    // Log credential status but don't override user's demo mode preference
    const credentials = await retrieveApiCredentials()
    const hasCredentials = !!(credentials && credentials.googleSearchApiKey)

    logger.info('ClientScraper', `Credentials refreshed - Has API credentials: ${hasCredentials}, Demo mode: ${this.useDemoMode}`)
  }

  /**
   * Reset scraping statistics
   */
  resetStats(): void {
    if (this.useDemoMode) {
      demoScraperService.resetStats()
    }
    // This would be handled server-side for real scraping
  }
}

/**
 * Default client scraper instance
 */
export const clientScraperService = new ClientScraperService()
