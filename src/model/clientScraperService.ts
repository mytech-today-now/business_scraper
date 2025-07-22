'use client'

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import { demoScraperService } from './demoScraperService'

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
    if (this.useDemoMode) {
      await demoScraperService.initialize()
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
      const response = await fetch(`${this.baseUrl}/scrape`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'search',
          query,
          zipCode,
          maxResults,
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      const urls = result.urls || []
      logger.info('ClientScraper', `Found ${urls.length} URLs for query: ${query}`)

      // If no URLs found, fall back to demo mode
      if (urls.length === 0) {
        logger.warn('ClientScraper', `No URLs found for query: ${query}, falling back to demo mode`)
        this.useDemoMode = true
        return await demoScraperService.searchForWebsites(query, zipCode, maxResults)
      }

      return urls
    } catch (error) {
      logger.warn('ClientScraper', `Failed to search for websites: ${query}, using demo mode`, error)
      this.useDemoMode = true
      return await demoScraperService.searchForWebsites(query, zipCode, maxResults)
    }
  }

  /**
   * Scrape a website for business information
   */
  async scrapeWebsite(url: string, depth: number = 2): Promise<BusinessRecord[]> {
    if (this.useDemoMode) {
      return await demoScraperService.scrapeWebsite(url, depth)
    }

    try {
      const response = await fetch(`${this.baseUrl}/scrape`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'scrape',
          url,
          depth,
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      logger.info('ClientScraper', `Scraped ${result.businesses.length} businesses from: ${url}`)
      return result.businesses
    } catch (error) {
      logger.warn('ClientScraper', `Failed to scrape website: ${url}, using demo mode`, error)
      this.useDemoMode = true
      return await demoScraperService.scrapeWebsite(url, depth)
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
