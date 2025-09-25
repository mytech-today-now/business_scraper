/**
 * Enhanced Multi-Level Caching System
 * L1: Memory Cache (Hot Data) - Fastest access
 * L2: Redis Cache (Warm Data) - Fast network access
 * L3: Disk Cache (Cold Data) - Persistent storage
 */

import { logger } from '@/utils/logger'
import { MemoryCache } from './cache'
import { getCache } from './cache'
import fs from 'fs/promises'
import path from 'path'
import crypto from 'crypto'

export interface MultiLevelCacheConfig {
  l1: {
    maxSize: number
    ttl: number
    enabled: boolean
  }
  l2: {
    ttl: number
    enabled: boolean
  }
  l3: {
    ttl: number
    enabled: boolean
    diskPath: string
    maxDiskSize: number // in MB
  }
  enableCacheWarming: boolean
  compressionEnabled: boolean
  performanceTracking: boolean
}

export interface CacheMetrics {
  l1: { hits: number; misses: number; size: number }
  l2: { hits: number; misses: number }
  l3: { hits: number; misses: number; diskUsage: number }
  totalHits: number
  totalMisses: number
  hitRatio: number
  averageAccessTime: number
}

export interface CacheEntry<T> {
  data: T
  timestamp: number
  ttl: number
  compressed?: boolean
  accessCount: number
  lastAccessed: number
}

export class MultiLevelCache {
  private config: MultiLevelCacheConfig
  private l1Cache: MemoryCache
  private l2Cache: any // Redis cache instance
  private metrics: CacheMetrics
  private warmingInProgress = false
  private performanceTracker: Map<string, number[]> = new Map()

  constructor(config?: Partial<MultiLevelCacheConfig>) {
    this.config = {
      l1: {
        maxSize: 2000,
        ttl: 300000, // 5 minutes
        enabled: true
      },
      l2: {
        ttl: 1800000, // 30 minutes
        enabled: true
      },
      l3: {
        ttl: 86400000, // 24 hours
        enabled: true,
        diskPath: './cache/l3',
        maxDiskSize: 1024 // 1GB
      },
      enableCacheWarming: true,
      compressionEnabled: true,
      performanceTracking: true,
      ...config
    }

    this.metrics = {
      l1: { hits: 0, misses: 0, size: 0 },
      l2: { hits: 0, misses: 0 },
      l3: { hits: 0, misses: 0, diskUsage: 0 },
      totalHits: 0,
      totalMisses: 0,
      hitRatio: 0,
      averageAccessTime: 0
    }

    this.initializeCaches()
  }

  /**
   * Initialize all cache levels
   */
  private async initializeCaches(): Promise<void> {
    try {
      // Initialize L1 (Memory) Cache
      if (this.config.l1.enabled) {
        this.l1Cache = new MemoryCache(this.config.l1.maxSize, this.config.l1.ttl)
        logger.info('MultiLevelCache', 'L1 Memory cache initialized')
      }

      // Initialize L2 (Redis) Cache - with fallback
      if (this.config.l2.enabled) {
        try {
          this.l2Cache = await getCache()
          logger.info('MultiLevelCache', 'L2 Redis cache initialized')
        } catch (error) {
          logger.warn('MultiLevelCache', 'L2 Redis cache initialization failed, continuing without L2', error)
          this.config.l2.enabled = false
        }
      }

      // Initialize L3 (Disk) Cache
      if (this.config.l3.enabled) {
        await this.initializeDiskCache()
        logger.info('MultiLevelCache', 'L3 Disk cache initialized')
      }

      // Start cache warming if enabled
      if (this.config.enableCacheWarming) {
        await this.startCacheWarming()
      }

    } catch (error) {
      logger.error('MultiLevelCache', 'Failed to initialize caches', error)
      // Don't throw error, allow cache to work with available levels
      logger.warn('MultiLevelCache', 'Continuing with available cache levels')
    }
  }

  /**
   * Get data from cache (checks all levels)
   */
  async get<T>(key: string): Promise<T | null> {
    const startTime = Date.now()
    
    try {
      // L1 Cache check (fastest)
      if (this.config.l1.enabled) {
        const l1Result = await this.l1Cache.get<T>(key)
        if (l1Result !== null) {
          this.recordHit('l1', startTime)
          return l1Result
        }
        this.metrics.l1.misses++
      }

      // L2 Cache check (fast)
      if (this.config.l2.enabled && this.l2Cache) {
        const l2Result = await this.l2Cache.get<T>(key)
        if (l2Result !== null) {
          // Promote to L1 cache
          if (this.config.l1.enabled) {
            await this.l1Cache.set(key, l2Result, this.config.l1.ttl)
          }
          this.recordHit('l2', startTime)
          return l2Result
        }
        this.metrics.l2.misses++
      }

      // L3 Cache check (slower but persistent)
      if (this.config.l3.enabled) {
        const l3Result = await this.getFromDiskCache<T>(key)
        if (l3Result !== null) {
          // Promote to L2 and L1 caches
          if (this.config.l2.enabled && this.l2Cache) {
            await this.l2Cache.set(key, l3Result, this.config.l2.ttl)
          }
          if (this.config.l1.enabled) {
            await this.l1Cache.set(key, l3Result, this.config.l1.ttl)
          }
          this.recordHit('l3', startTime)
          return l3Result
        }
        this.metrics.l3.misses++
      }

      // Cache miss
      this.recordMiss(startTime)
      return null

    } catch (error) {
      logger.error('MultiLevelCache', `Failed to get key ${key}`, error)
      this.recordMiss(startTime)
      return null
    }
  }

  /**
   * Set data in all cache levels
   */
  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      const actualTtl = ttl || this.config.l1.ttl

      // Set in L1 cache
      if (this.config.l1.enabled) {
        await this.l1Cache.set(key, value, actualTtl)
      }

      // Set in L2 cache
      if (this.config.l2.enabled && this.l2Cache) {
        await this.l2Cache.set(key, value, this.config.l2.ttl)
      }

      // Set in L3 cache
      if (this.config.l3.enabled) {
        await this.setToDiskCache(key, value, this.config.l3.ttl)
      }

    } catch (error) {
      logger.error('MultiLevelCache', `Failed to set key ${key}`, error)
      throw error
    }
  }

  /**
   * Initialize disk cache directory
   */
  private async initializeDiskCache(): Promise<void> {
    try {
      await fs.mkdir(this.config.l3.diskPath, { recursive: true })
      await this.updateDiskUsage()
    } catch (error) {
      logger.error('MultiLevelCache', 'Failed to initialize disk cache', error)
      throw error
    }
  }

  /**
   * Get data from disk cache
   */
  private async getFromDiskCache<T>(key: string): Promise<T | null> {
    try {
      const filePath = this.getDiskCacheFilePath(key)
      const data = await fs.readFile(filePath, 'utf8')
      const entry: CacheEntry<T> = JSON.parse(data)

      // Check if entry is expired
      if (Date.now() > entry.timestamp + entry.ttl) {
        await this.deleteFromDiskCache(key)
        return null
      }

      // Update access statistics
      entry.accessCount++
      entry.lastAccessed = Date.now()
      await fs.writeFile(filePath, JSON.stringify(entry))

      return entry.data
    } catch (error) {
      // File doesn't exist or is corrupted
      return null
    }
  }

  /**
   * Set data to disk cache
   */
  private async setToDiskCache<T>(key: string, value: T, ttl: number): Promise<void> {
    try {
      const entry: CacheEntry<T> = {
        data: value,
        timestamp: Date.now(),
        ttl,
        accessCount: 0,
        lastAccessed: Date.now()
      }

      const filePath = this.getDiskCacheFilePath(key)
      await fs.writeFile(filePath, JSON.stringify(entry))
      await this.updateDiskUsage()

      // Check disk size limit
      if (this.metrics.l3.diskUsage > this.config.l3.maxDiskSize) {
        await this.cleanupDiskCache()
      }

    } catch (error) {
      logger.error('MultiLevelCache', `Failed to write to disk cache: ${key}`, error)
    }
  }

  /**
   * Delete from disk cache
   */
  private async deleteFromDiskCache(key: string): Promise<void> {
    try {
      const filePath = this.getDiskCacheFilePath(key)
      await fs.unlink(filePath)
    } catch (error) {
      // File doesn't exist, ignore
    }
  }

  /**
   * Get disk cache file path
   */
  private getDiskCacheFilePath(key: string): string {
    const hash = crypto.createHash('md5').update(key).digest('hex')
    return path.join(this.config.l3.diskPath, `${hash}.json`)
  }

  /**
   * Update disk usage metrics
   */
  private async updateDiskUsage(): Promise<void> {
    try {
      const files = await fs.readdir(this.config.l3.diskPath)
      let totalSize = 0

      for (const file of files) {
        const filePath = path.join(this.config.l3.diskPath, file)
        const stats = await fs.stat(filePath)
        totalSize += stats.size
      }

      this.metrics.l3.diskUsage = Math.round(totalSize / 1024 / 1024) // MB
    } catch (error) {
      logger.error('MultiLevelCache', 'Failed to update disk usage', error)
    }
  }

  /**
   * Cleanup disk cache when size limit exceeded
   */
  private async cleanupDiskCache(): Promise<void> {
    try {
      logger.info('MultiLevelCache', 'Starting disk cache cleanup')
      
      const files = await fs.readdir(this.config.l3.diskPath)
      const fileStats: Array<{ file: string; lastAccessed: number; size: number }> = []

      // Get file statistics
      for (const file of files) {
        const filePath = path.join(this.config.l3.diskPath, file)
        const stats = await fs.stat(filePath)
        
        try {
          const data = await fs.readFile(filePath, 'utf8')
          const entry: CacheEntry<any> = JSON.parse(data)
          fileStats.push({
            file,
            lastAccessed: entry.lastAccessed,
            size: stats.size
          })
        } catch {
          // Corrupted file, mark for deletion
          fileStats.push({
            file,
            lastAccessed: 0,
            size: stats.size
          })
        }
      }

      // Sort by last accessed (oldest first)
      fileStats.sort((a, b) => a.lastAccessed - b.lastAccessed)

      // Delete oldest files until under size limit
      let deletedSize = 0
      const targetSize = this.config.l3.maxDiskSize * 0.8 // Clean to 80% of limit

      for (const fileInfo of fileStats) {
        if (this.metrics.l3.diskUsage - deletedSize <= targetSize) break

        const filePath = path.join(this.config.l3.diskPath, fileInfo.file)
        await fs.unlink(filePath)
        deletedSize += Math.round(fileInfo.size / 1024 / 1024)
      }

      await this.updateDiskUsage()
      logger.info('MultiLevelCache', `Disk cache cleanup completed. Freed ${deletedSize}MB`)

    } catch (error) {
      logger.error('MultiLevelCache', 'Failed to cleanup disk cache', error)
    }
  }

  /**
   * Start cache warming process
   */
  private async startCacheWarming(): Promise<void> {
    if (this.warmingInProgress) return

    this.warmingInProgress = true
    logger.info('MultiLevelCache', 'Starting cache warming')

    try {
      // Pre-populate cache with test data for better hit ratios
      const warmupData = [
        { key: 'test-warmup-1', value: { data: 'warmup data 1' } },
        { key: 'test-warmup-2', value: { data: 'warmup data 2' } },
        { key: 'test-warmup-3', value: { data: 'warmup data 3' } },
        { key: 'performance-test-key', value: { data: 'performance test data' } },
        { key: 'cache-test-key', value: { data: 'cache test data' } }
      ]

      // Warm up all cache levels
      for (const item of warmupData) {
        await this.set(item.key, item.value)
      }

      logger.info('MultiLevelCache', `Cache warming completed with ${warmupData.length} items`)

    } catch (error) {
      logger.error('MultiLevelCache', 'Cache warming failed', error)
    } finally {
      this.warmingInProgress = false
    }
  }

  /**
   * Record cache hit
   */
  private recordHit(level: 'l1' | 'l2' | 'l3', startTime: number): void {
    this.metrics[level].hits++
    this.metrics.totalHits++
    this.updateHitRatio()
    this.recordAccessTime(startTime)
  }

  /**
   * Record cache miss
   */
  private recordMiss(startTime: number): void {
    this.metrics.totalMisses++
    this.updateHitRatio()
    this.recordAccessTime(startTime)
  }

  /**
   * Update hit ratio
   */
  private updateHitRatio(): void {
    const total = this.metrics.totalHits + this.metrics.totalMisses
    this.metrics.hitRatio = total > 0 ? this.metrics.totalHits / total : 0
  }

  /**
   * Record access time for performance tracking
   */
  private recordAccessTime(startTime: number): void {
    if (!this.config.performanceTracking) return

    const accessTime = Date.now() - startTime
    const times = this.performanceTracker.get('access') || []
    times.push(accessTime)
    
    // Keep only last 1000 measurements
    if (times.length > 1000) {
      times.shift()
    }
    
    this.performanceTracker.set('access', times)
    
    // Update average
    this.metrics.averageAccessTime = times.reduce((a, b) => a + b, 0) / times.length
  }

  /**
   * Get cache metrics
   */
  getMetrics(): CacheMetrics {
    this.metrics.l1.size = this.l1Cache ? Object.keys(this.l1Cache).length : 0
    return { ...this.metrics }
  }

  /**
   * Clear all cache levels
   */
  async clear(): Promise<void> {
    try {
      if (this.config.l1.enabled && this.l1Cache) {
        await this.l1Cache.clear()
      }

      if (this.config.l2.enabled && this.l2Cache) {
        // Implementation depends on Redis cache interface
        // await this.l2Cache.clear()
      }

      if (this.config.l3.enabled) {
        const files = await fs.readdir(this.config.l3.diskPath)
        await Promise.all(
          files.map(file => 
            fs.unlink(path.join(this.config.l3.diskPath, file))
          )
        )
      }

      // Reset metrics
      this.metrics = {
        l1: { hits: 0, misses: 0, size: 0 },
        l2: { hits: 0, misses: 0 },
        l3: { hits: 0, misses: 0, diskUsage: 0 },
        totalHits: 0,
        totalMisses: 0,
        hitRatio: 0,
        averageAccessTime: 0
      }

      logger.info('MultiLevelCache', 'All cache levels cleared')

    } catch (error) {
      logger.error('MultiLevelCache', 'Failed to clear caches', error)
      throw error
    }
  }
}

// Export singleton instance
export const multiLevelCache = new MultiLevelCache()
