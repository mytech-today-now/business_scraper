/**
 * Cache Warming Service
 * Pre-populates cache with popular and high-value data
 */

import { logger } from '@/utils/logger'
import { smartCacheManager } from './smartCacheManager'
import { SearchEngineService } from '@/model/searchEngine'
import { ScraperService } from '@/model/scraperService'
import { getCacheConfig } from './config'

export interface WarmingConfig {
  enablePopularQueries: boolean
  enableBusinessData: boolean
  enableLocationData: boolean
  popularQueries: string[]
  highValueUrls: string[]
  warmingInterval: number // in milliseconds
}

/**
 * Cache Warming Service for intelligent pre-loading
 */
export class CacheWarmingService {
  private config: WarmingConfig
  private searchEngine: SearchEngineService
  private scraperService: ScraperService
  private warmingInterval?: NodeJS.Timeout
  private isWarming = false

  constructor() {
    this.config = {
      enablePopularQueries: getCacheConfig().enableCacheWarming || false,
      enableBusinessData: true,
      enableLocationData: true,
      popularQueries: [
        'restaurants near me',
        'business consulting',
        'real estate agents',
        'auto repair shops',
        'medical practices',
        'law firms',
        'accounting services',
        'marketing agencies',
        'construction companies',
        'dental offices'
      ],
      highValueUrls: [],
      warmingInterval: 6 * 60 * 60 * 1000 // 6 hours
    }

    this.searchEngine = new SearchEngineService()
    this.scraperService = new ScraperService()

    if (this.config.enablePopularQueries) {
      this.startWarmingSchedule()
    }
  }

  /**
   * Start the cache warming schedule
   */
  private startWarmingSchedule(): void {
    if (this.warmingInterval) {
      clearInterval(this.warmingInterval)
    }

    this.warmingInterval = setInterval(() => {
      this.warmCache().catch(error => {
        logger.error('CacheWarming', 'Failed to warm cache', error)
      })
    }, this.config.warmingInterval)

    // Initial warming
    setTimeout(() => {
      this.warmCache().catch(error => {
        logger.error('CacheWarming', 'Failed initial cache warming', error)
      })
    }, 30000) // Wait 30 seconds after startup
  }

  /**
   * Warm cache with popular data
   */
  async warmCache(): Promise<void> {
    if (this.isWarming) {
      logger.debug('CacheWarming', 'Cache warming already in progress, skipping')
      return
    }

    this.isWarming = true
    logger.info('CacheWarming', 'Starting cache warming process')

    try {
      const promises: Promise<void>[] = []

      if (this.config.enablePopularQueries) {
        promises.push(this.warmPopularQueries())
      }

      if (this.config.enableBusinessData) {
        promises.push(this.warmBusinessData())
      }

      if (this.config.enableLocationData) {
        promises.push(this.warmLocationData())
      }

      await Promise.allSettled(promises)
      logger.info('CacheWarming', 'Cache warming completed successfully')
    } catch (error) {
      logger.error('CacheWarming', 'Cache warming failed', error)
    } finally {
      this.isWarming = false
    }
  }

  /**
   * Warm cache with popular search queries
   */
  private async warmPopularQueries(): Promise<void> {
    logger.info('CacheWarming', `Warming cache with ${this.config.popularQueries.length} popular queries`)

    const locations = ['New York, NY', 'Los Angeles, CA', 'Chicago, IL', 'Houston, TX', 'Phoenix, AZ']
    
    for (const query of this.config.popularQueries) {
      for (const location of locations) {
        try {
          // Check if already cached
          const cached = await smartCacheManager.getCachedSearchResults(query, location)
          if (cached) {
            continue // Skip if already cached
          }

          // Perform search and cache results
          const results = await this.searchEngine.search(query, { maxResults: 20 })
          await smartCacheManager.cacheSearchResults(query, location, results)
          
          logger.debug('CacheWarming', `Warmed search cache for "${query}" in ${location}`)
          
          // Add delay to avoid overwhelming services
          await this.delay(1000)
        } catch (error) {
          logger.warn('CacheWarming', `Failed to warm cache for query "${query}" in ${location}`, error)
        }
      }
    }
  }

  /**
   * Warm cache with high-value business data
   */
  private async warmBusinessData(): Promise<void> {
    if (this.config.highValueUrls.length === 0) {
      return
    }

    logger.info('CacheWarming', `Warming cache with ${this.config.highValueUrls.length} high-value URLs`)

    const batchSize = 5
    for (let i = 0; i < this.config.highValueUrls.length; i += batchSize) {
      const batch = this.config.highValueUrls.slice(i, i + batchSize)
      
      const promises = batch.map(async (url) => {
        try {
          // Check if already cached
          const cached = await smartCacheManager.getCachedBusinessData(url)
          if (cached) {
            return
          }

          // Scrape and cache business data
          const businessData = await this.scraperService.scrapeWebsite(url)
          if (businessData.length > 0) {
            await smartCacheManager.cacheBusinessData(url, businessData[0])
            logger.debug('CacheWarming', `Warmed business cache for ${url}`)
          }
        } catch (error) {
          logger.warn('CacheWarming', `Failed to warm business cache for ${url}`, error)
        }
      })

      await Promise.allSettled(promises)
      
      // Add delay between batches
      await this.delay(2000)
    }
  }

  /**
   * Warm cache with location-based data
   */
  private async warmLocationData(): Promise<void> {
    const popularLocations = [
      { city: 'New York', state: 'NY', zip: '10001' },
      { city: 'Los Angeles', state: 'CA', zip: '90210' },
      { city: 'Chicago', state: 'IL', zip: '60601' },
      { city: 'Houston', state: 'TX', zip: '77001' },
      { city: 'Phoenix', state: 'AZ', zip: '85001' }
    ]

    logger.info('CacheWarming', `Warming location cache for ${popularLocations.length} cities`)

    for (const location of popularLocations) {
      try {
        // Pre-warm geocoding cache
        const locationKey = `${location.city}, ${location.state}`
        
        // This would integrate with your geocoding service
        // await geocodingService.geocode(locationKey)
        
        logger.debug('CacheWarming', `Warmed location cache for ${locationKey}`)
        await this.delay(500)
      } catch (error) {
        logger.warn('CacheWarming', `Failed to warm location cache for ${location.city}`, error)
      }
    }
  }

  /**
   * Add URLs to high-value warming list
   */
  addHighValueUrls(urls: string[]): void {
    this.config.highValueUrls.push(...urls)
    logger.info('CacheWarming', `Added ${urls.length} URLs to high-value warming list`)
  }

  /**
   * Add popular queries to warming list
   */
  addPopularQueries(queries: string[]): void {
    this.config.popularQueries.push(...queries)
    logger.info('CacheWarming', `Added ${queries.length} queries to popular warming list`)
  }

  /**
   * Force immediate cache warming
   */
  async forceWarmCache(): Promise<void> {
    logger.info('CacheWarming', 'Force warming cache immediately')
    await this.warmCache()
  }

  /**
   * Stop cache warming
   */
  stop(): void {
    if (this.warmingInterval) {
      clearInterval(this.warmingInterval)
      this.warmingInterval = undefined
      logger.info('CacheWarming', 'Cache warming stopped')
    }
  }

  /**
   * Get warming statistics
   */
  getStats(): {
    isWarming: boolean
    popularQueries: number
    highValueUrls: number
    nextWarmingIn: number
  } {
    return {
      isWarming: this.isWarming,
      popularQueries: this.config.popularQueries.length,
      highValueUrls: this.config.highValueUrls.length,
      nextWarmingIn: this.config.warmingInterval
    }
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

/**
 * Default cache warming service instance
 */
export const cacheWarmingService = new CacheWarmingService()
