/**
 * Smart Cache Manager with Multi-Level Caching Strategy
 * Implements L1 (Memory), L2 (Redis), and L3 (Disk) caching layers
 */

import { logger } from '@/utils/logger'
import { getCache } from './cache'
import { getCacheConfig } from './config'
import { BusinessRecord } from '@/types/business'
import { ExtractedContact } from './contactExtractor'
import { SearchResult } from '@/model/searchEngine'
import crypto from 'crypto'

export interface CacheEntry<T = unknown> {
  data: T
  timestamp: number
  ttl: number
  accessCount: number
  lastAccessed: number
}

export interface CacheStats {
  l1Hits: number
  l1Misses: number
  l2Hits: number
  l2Misses: number
  l3Hits: number
  l3Misses: number
  totalRequests: number
  hitRate: number
}

/**
 * Smart Cache Manager with intelligent caching strategies
 */
export class SmartCacheManager {
  private l1Cache: Map<string, CacheEntry> = new Map()
  private stats: CacheStats = {
    l1Hits: 0,
    l1Misses: 0,
    l2Hits: 0,
    l2Misses: 0,
    l3Hits: 0,
    l3Misses: 0,
    totalRequests: 0,
    hitRate: 0
  }
  private config = getCacheConfig()

  constructor() {
    // Start cache cleanup interval
    setInterval(() => this.cleanupExpiredEntries(), 5 * 60 * 1000) // Every 5 minutes
  }

  /**
   * Generate intelligent cache key with hierarchical structure
   */
  private generateCacheKey(type: string, params: any): string {
    const hash = crypto.createHash('md5').update(JSON.stringify(params)).digest('hex')
    return `bs:${type}:${hash}`
  }

  /**
   * Get data from multi-level cache
   */
  async get<T>(type: string, params: any): Promise<T | null> {
    const key = this.generateCacheKey(type, params)
    this.stats.totalRequests++

    // L1 Cache (Memory) - Fastest
    const l1Entry = this.l1Cache.get(key)
    if (l1Entry && !this.isExpired(l1Entry)) {
      this.stats.l1Hits++
      l1Entry.accessCount++
      l1Entry.lastAccessed = Date.now()
      this.updateHitRate()
      logger.debug('SmartCache', `L1 cache hit for ${key}`)
      return l1Entry.data as T
    }
    this.stats.l1Misses++

    // L2 Cache (Redis) - Medium speed
    try {
      const cache = await getCache()
      const l2Data = await cache.get<T>(key)
      if (l2Data !== null) {
        this.stats.l2Hits++
        // Promote to L1 cache
        this.setL1Cache(key, l2Data, this.config.l1Cache?.ttl || 1800000)
        this.updateHitRate()
        logger.debug('SmartCache', `L2 cache hit for ${key}, promoted to L1`)
        return l2Data
      }
      this.stats.l2Misses++
    } catch (error) {
      logger.error('SmartCache', `L2 cache error for ${key}`, error)
    }

    // L3 Cache (Disk) would be implemented here
    this.stats.l3Misses++
    this.updateHitRate()
    return null
  }

  /**
   * Set data in appropriate cache levels
   */
  async set<T>(type: string, params: any, data: T, ttl?: number): Promise<void> {
    const key = this.generateCacheKey(type, params)
    const actualTtl = ttl || this.getTtlForType(type)

    // Set in L1 cache (hot data)
    this.setL1Cache(key, data, actualTtl)

    // Set in L2 cache (warm data)
    try {
      const cache = await getCache()
      await cache.set(key, data, actualTtl)
      logger.debug('SmartCache', `Data cached in L1 and L2 for ${key}`)
    } catch (error) {
      logger.error('SmartCache', `Failed to set L2 cache for ${key}`, error)
    }
  }

  /**
   * Cache search results with optimized TTL
   */
  async cacheSearchResults(query: string, location: string, results: SearchResult[]): Promise<void> {
    await this.set('search', { query, location }, results, 3600000) // 1 hour
  }

  /**
   * Cache business data with longer TTL
   */
  async cacheBusinessData(url: string, data: BusinessRecord): Promise<void> {
    await this.set('business', { url }, data, 7200000) // 2 hours
  }

  /**
   * Cache contact information with extended TTL
   */
  async cacheContactInfo(url: string, contacts: ExtractedContact): Promise<void> {
    await this.set('contacts', { url }, contacts, 14400000) // 4 hours
  }

  /**
   * Get cached search results
   */
  async getCachedSearchResults(query: string, location: string): Promise<SearchResult[] | null> {
    return await this.get<SearchResult[]>('search', { query, location })
  }

  /**
   * Get cached business data
   */
  async getCachedBusinessData(url: string): Promise<BusinessRecord | null> {
    return await this.get<BusinessRecord>('business', { url })
  }

  /**
   * Get cached contact information
   */
  async getCachedContactInfo(url: string): Promise<ExtractedContact | null> {
    return await this.get<ExtractedContact>('contacts', { url })
  }

  /**
   * Set data in L1 cache
   */
  private setL1Cache<T>(key: string, data: T, ttl: number): void {
    const maxSize = this.config.l1Cache?.maxSize || 1000
    
    // Evict oldest entries if cache is full
    if (this.l1Cache.size >= maxSize) {
      this.evictLRU()
    }

    this.l1Cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl,
      accessCount: 1,
      lastAccessed: Date.now()
    })
  }

  /**
   * Check if cache entry is expired
   */
  private isExpired(entry: CacheEntry): boolean {
    return Date.now() > (entry.timestamp + entry.ttl)
  }

  /**
   * Get TTL based on data type
   */
  private getTtlForType(type: string): number {
    switch (type) {
      case 'search':
        return this.config.l1Cache?.ttl || 1800000 // 30 minutes
      case 'business':
        return this.config.l2Cache?.ttl || 7200000 // 2 hours
      case 'contacts':
        return this.config.l3Cache?.ttl || 14400000 // 4 hours
      default:
        return this.config.memory.ttl
    }
  }

  /**
   * Evict least recently used entries
   */
  private evictLRU(): void {
    let oldestKey = ''
    let oldestTime = Date.now()

    for (const [key, entry] of this.l1Cache) {
      if (entry.lastAccessed < oldestTime) {
        oldestTime = entry.lastAccessed
        oldestKey = key
      }
    }

    if (oldestKey) {
      this.l1Cache.delete(oldestKey)
      logger.debug('SmartCache', `Evicted LRU entry: ${oldestKey}`)
    }
  }

  /**
   * Clean up expired entries
   */
  private cleanupExpiredEntries(): void {
    const now = Date.now()
    let cleanedCount = 0

    for (const [key, entry] of this.l1Cache) {
      if (this.isExpired(entry)) {
        this.l1Cache.delete(key)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      logger.info('SmartCache', `Cleaned up ${cleanedCount} expired cache entries`)
    }
  }

  /**
   * Update hit rate statistics
   */
  private updateHitRate(): void {
    const totalHits = this.stats.l1Hits + this.stats.l2Hits + this.stats.l3Hits
    this.stats.hitRate = this.stats.totalRequests > 0 ? (totalHits / this.stats.totalRequests) * 100 : 0
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    return { ...this.stats }
  }

  /**
   * Clear all cache levels
   */
  async clearAll(): Promise<void> {
    this.l1Cache.clear()
    try {
      const cache = await getCache()
      await cache.clear()
      logger.info('SmartCache', 'All cache levels cleared')
    } catch (error) {
      logger.error('SmartCache', 'Failed to clear L2 cache', error)
    }
  }
}

/**
 * Default smart cache manager instance
 */
export const smartCacheManager = new SmartCacheManager()
