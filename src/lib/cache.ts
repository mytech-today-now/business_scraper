/**
 * Caching system with Redis support and in-memory fallback
 */

import { getCacheConfig } from './config'
import { Features } from './feature-flags'
import { logger } from '@/utils/logger'
import { metrics } from '@/lib/metrics'

// Redis client interface (simplified for our use case)
interface RedisClient {
  get(key: string): Promise<string | null>
  set(key: string, value: string): Promise<void>
  setEx(key: string, seconds: number, value: string): Promise<void>
  del(key: string): Promise<number>
  flushDb(): Promise<void>
  exists(key: string): Promise<number>
  keys(pattern: string): Promise<string[]>
  connect(): Promise<void>
  quit(): Promise<void>
  on(event: string, listener: (...args: unknown[]) => void): void
}

// Redis configuration interface
interface RedisConfig {
  host: string
  port: number
  password?: string
  db: number
  keyPrefix: string
}

// Cache interface with proper generics
export interface CacheInterface {
  get<T>(key: string): Promise<T | null>
  set<T>(key: string, value: T, ttl?: number): Promise<void>
  delete(key: string): Promise<void>
  clear(): Promise<void>
  exists(key: string): Promise<boolean>
  keys(pattern?: string): Promise<string[]>
  close(): Promise<void>
}

// Cache entry for in-memory cache with generic type
interface CacheEntry<T = unknown> {
  value: T
  expiry: number
}

/**
 * In-memory cache implementation
 */
class MemoryCache implements CacheInterface {
  private cache = new Map<string, CacheEntry<unknown>>()
  private cleanupInterval: NodeJS.Timeout | null = null
  private readonly defaultTtl: number
  private readonly maxSize: number

  constructor(maxSize: number = 1000, defaultTtl: number = 3600000) {
    this.maxSize = maxSize
    this.defaultTtl = defaultTtl

    // Start cleanup interval (every 5 minutes)
    this.cleanupInterval = setInterval(() => {
      this.cleanup()
    }, 5 * 60 * 1000)

    logger.info('Cache', 'Memory cache initialized', { maxSize, defaultTtl })
  }

  async get<T>(key: string): Promise<T | null> {
    const startTime = Date.now()
    const keyPrefix = key.split(':')[0] || 'unknown'

    try {
      await metrics.initialize()

      const entry = this.cache.get(key)

      if (!entry) {
        // Record cache miss
        metrics.cacheMisses.inc({ cache_type: 'memory', key_prefix: keyPrefix })
        const duration = (Date.now() - startTime) / 1000
        metrics.cacheOperationDuration.observe(
          { operation: 'get', cache_type: 'memory' },
          duration
        )
        return null
      }

      // Check if expired
      if (Date.now() > entry.expiry) {
        this.cache.delete(key)
        // Record cache miss for expired entry
        metrics.cacheMisses.inc({ cache_type: 'memory', key_prefix: keyPrefix })
        const duration = (Date.now() - startTime) / 1000
        metrics.cacheOperationDuration.observe(
          { operation: 'get', cache_type: 'memory' },
          duration
        )
        return null
      }

      // Record cache hit
      metrics.cacheHits.inc({ cache_type: 'memory', key_prefix: keyPrefix })
      const duration = (Date.now() - startTime) / 1000
      metrics.cacheOperationDuration.observe(
        { operation: 'get', cache_type: 'memory' },
        duration
      )

      return entry.value as T
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000
      metrics.cacheOperationDuration.observe(
        { operation: 'get', cache_type: 'memory' },
        duration
      )
      throw error
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    const startTime = Date.now()

    try {
      await metrics.initialize()

      const actualTtl = ttl || this.defaultTtl
      const expiry = Date.now() + actualTtl

      // Check if we need to evict entries
      if (this.cache.size >= this.maxSize) {
        this.evictOldest()
      }

      this.cache.set(key, { value, expiry })

      // Record cache operation metrics
      const duration = (Date.now() - startTime) / 1000
      metrics.cacheOperationDuration.observe(
        { operation: 'set', cache_type: 'memory' },
        duration
      )
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000
      metrics.cacheOperationDuration.observe(
        { operation: 'set', cache_type: 'memory' },
        duration
      )
      throw error
    }
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key)
  }

  async clear(): Promise<void> {
    this.cache.clear()
  }

  async exists(key: string): Promise<boolean> {
    const entry = this.cache.get(key)
    
    if (!entry) {
      return false
    }
    
    // Check if expired
    if (Date.now() > entry.expiry) {
      this.cache.delete(key)
      return false
    }
    
    return true
  }

  async keys(pattern?: string): Promise<string[]> {
    const allKeys = Array.from(this.cache.keys())
    
    if (!pattern) {
      return allKeys
    }
    
    // Simple pattern matching (supports * wildcard) - secure implementation
    // Use a safe pattern matching approach instead of dynamic RegExp
    const normalizedPattern = pattern.toLowerCase()

    if (normalizedPattern === '*') {
      return allKeys // Return all keys for wildcard
    }

    // For simple patterns, use string methods instead of regex
    if (!normalizedPattern.includes('*')) {
      return allKeys.filter(key => key.toLowerCase() === normalizedPattern)
    }

    // For patterns with wildcards, use a safe approach
    const parts = normalizedPattern.split('*')
    return allKeys.filter(key => {
      const lowerKey = key.toLowerCase()
      let currentIndex = 0

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i]
        if (part === '') continue

        const foundIndex = lowerKey.indexOf(part, currentIndex)
        if (foundIndex === -1) return false

        if (i === 0 && foundIndex !== 0) return false // Must start with first part
        if (i === parts.length - 1 && !lowerKey.endsWith(part)) return false // Must end with last part

        currentIndex = foundIndex + part.length
      }

      return true
    })
    return allKeys.filter(key => regex.test(key))
  }

  async close(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
    this.cache.clear()
    logger.info('Cache', 'Memory cache closed')
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now()
    let cleanedCount = 0

    // Convert entries to array to avoid iterator issues
    const entries = Array.from(this.cache.entries())
    for (const [key, entry] of entries) {
      if (now > entry.expiry) {
        this.cache.delete(key)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      logger.debug('Cache', `Cleaned up ${cleanedCount} expired cache entries`)
    }
  }

  /**
   * Evict oldest entries when cache is full
   */
  private evictOldest(): void {
    // Simple LRU: remove entries that expire soonest
    const entries = Array.from(this.cache.entries())
    entries.sort((a, b) => a[1].expiry - b[1].expiry)
    
    // Remove 10% of entries
    const toRemove = Math.max(1, Math.floor(entries.length * 0.1))
    
    for (let i = 0; i < toRemove && i < entries.length; i++) {
      const entry = entries.at(i)
      if (entry) {
        this.cache.delete(entry[0])
      }
    }
    
    logger.debug('Cache', `Evicted ${toRemove} cache entries due to size limit`)
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const now = Date.now()
    let expiredCount = 0
    
    // Convert values to array to avoid iterator issues
    const values = Array.from(this.cache.values())
    for (const entry of values) {
      if (now > entry.expiry) {
        expiredCount++
      }
    }
    
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      expired: expiredCount,
      active: this.cache.size - expiredCount
    }
  }
}

/**
 * Redis cache implementation
 */
class RedisCache implements CacheInterface {
  private client: RedisClient | null = null
  private connected = false
  private readonly config: RedisConfig

  constructor(config: RedisConfig) {
    this.config = config
  }

  private async ensureConnected(): Promise<void> {
    if (this.connected && this.client) {
      return
    }

    try {
      // Dynamically import Redis (optional dependency)
      // Use dynamic import instead of eval for security
      const redisModule = await import('redis').catch(() => null)
      if (!redisModule) {
        throw new Error('Redis module not available')
      }
      const Redis = redisModule.default || redisModule

      // Type assertion for the Redis client factory
      const createClient = (Redis as { createClient: (config: unknown) => RedisClient }).createClient

      this.client = createClient({
        host: this.config.host,
        port: this.config.port,
        password: this.config.password,
        db: this.config.db,
        keyPrefix: this.config.keyPrefix,
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: 3,
      })

      this.client.on('error', (error: Error) => {
        logger.error('Cache', 'Redis error', error)
        this.connected = false
      })

      this.client.on('connect', () => {
        logger.info('Cache', 'Redis connected')
        this.connected = true
      })

      this.client.on('disconnect', () => {
        logger.warn('Cache', 'Redis disconnected')
        this.connected = false
      })

      await this.client.connect()

    } catch (error) {
      logger.error('Cache', 'Failed to connect to Redis', error)
      throw new Error('Redis connection failed')
    }
  }

  async get<T>(key: string): Promise<T | null> {
    const startTime = Date.now()
    const keyPrefix = key.split(':')[0] || 'unknown'

    try {
      await metrics.initialize()
      await this.ensureConnected()
      if (!this.client) {
        throw new Error('Redis client not available')
      }

      const value = await this.client.get(key)
      const duration = (Date.now() - startTime) / 1000

      if (value === null) {
        // Record cache miss
        metrics.cacheMisses.inc({ cache_type: 'redis', key_prefix: keyPrefix })
        metrics.cacheOperationDuration.observe(
          { operation: 'get', cache_type: 'redis' },
          duration
        )
        return null
      }

      // Record cache hit
      metrics.cacheHits.inc({ cache_type: 'redis', key_prefix: keyPrefix })
      metrics.cacheOperationDuration.observe(
        { operation: 'get', cache_type: 'redis' },
        duration
      )

      return JSON.parse(value) as T
    } catch (error) {
      const duration = (Date.now() - startTime) / 1000
      const keyPrefix = key.split(':')[0] || 'unknown'

      // Record cache miss on error
      metrics.cacheMisses.inc({ cache_type: 'redis', key_prefix: keyPrefix })
      metrics.cacheOperationDuration.observe(
        { operation: 'get', cache_type: 'redis' },
        duration
      )

      logger.error('Cache', `Failed to get key ${key} from Redis`, error)
      return null
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      await this.ensureConnected()
      if (!this.client) {
        throw new Error('Redis client not available')
      }

      const serialized = JSON.stringify(value)

      if (ttl) {
        await this.client.setEx(key, Math.floor(ttl / 1000), serialized)
      } else {
        await this.client.set(key, serialized)
      }
    } catch (error) {
      logger.error('Cache', `Failed to set key ${key} in Redis`, error)
      throw error
    }
  }

  async delete(key: string): Promise<void> {
    try {
      await this.ensureConnected()
      await this.client.del(key)
    } catch (error) {
      logger.error('Cache', `Failed to delete key ${key} from Redis`, error)
      throw error
    }
  }

  async clear(): Promise<void> {
    try {
      await this.ensureConnected()
      await this.client.flushDb()
    } catch (error) {
      logger.error('Cache', 'Failed to clear Redis cache', error)
      throw error
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      await this.ensureConnected()
      const result = await this.client.exists(key)
      return result === 1
    } catch (error) {
      logger.error('Cache', `Failed to check existence of key ${key} in Redis`, error)
      return false
    }
  }

  async keys(pattern?: string): Promise<string[]> {
    try {
      await this.ensureConnected()
      const searchPattern = pattern || '*'
      return await this.client.keys(searchPattern)
    } catch (error) {
      logger.error('Cache', `Failed to get keys with pattern ${pattern} from Redis`, error)
      return []
    }
  }

  async close(): Promise<void> {
    if (this.client) {
      try {
        await this.client.quit()
        this.connected = false
        logger.info('Cache', 'Redis connection closed')
      } catch (error) {
        logger.error('Cache', 'Error closing Redis connection', error)
      }
    }
  }
}

/**
 * Cache factory and manager
 */
class CacheManager {
  private cache: CacheInterface | null = null
  private initialized = false

  async getCache(): Promise<CacheInterface> {
    if (!this.initialized) {
      await this.initialize()
    }
    
    if (!this.cache) {
      throw new Error('Cache not initialized')
    }
    
    return this.cache
  }

  private async initialize(): Promise<void> {
    if (!Features.isCachingEnabled()) {
      logger.info('Cache', 'Caching is disabled by feature flag')
      this.cache = new MemoryCache(1, 1000) // Minimal cache
      this.initialized = true
      return
    }

    const config = getCacheConfig()
    
    try {
      if (config.type === 'redis' && config.redis) {
        logger.info('Cache', 'Initializing Redis cache')
        this.cache = new RedisCache(config.redis)
        
        // Test Redis connection
        await this.cache.set('test', 'connection', 1000)
        await this.cache.delete('test')
        
        logger.info('Cache', 'Redis cache initialized successfully')
      } else {
        throw new Error('Redis not configured or not available')
      }
    } catch (error) {
      logger.warn('Cache', 'Failed to initialize Redis cache, falling back to memory cache', error)
      
      // Fallback to memory cache
      this.cache = new MemoryCache(
        config.memory.maxSize,
        config.memory.ttl
      )
    }
    
    this.initialized = true
  }

  async close(): Promise<void> {
    if (this.cache) {
      await this.cache.close()
      this.cache = null
      this.initialized = false
    }
  }
}

// Global cache manager
const cacheManager = new CacheManager()

/**
 * Get the cache instance
 */
export async function getCache(): Promise<CacheInterface> {
  return cacheManager.getCache()
}

/**
 * Close the cache
 */
export async function closeCache(): Promise<void> {
  return cacheManager.close()
}

// Type for cacheable method
type CacheableMethod<T = unknown> = (...args: unknown[]) => Promise<T>

/**
 * Cache decorator for functions
 */
export function cached(ttl: number = 3600000, keyPrefix: string = '') {
  return function <T>(
    _target: object,
    propertyName: string,
    descriptor: TypedPropertyDescriptor<CacheableMethod<T>>
  ) {
    const method = descriptor.value
    if (!method) {
      throw new Error('Cached decorator can only be applied to methods')
    }

    descriptor.value = async function (...args: unknown[]): Promise<T> {
      if (!Features.isCachingEnabled()) {
        return method.apply(this, args)
      }

      try {
        const cache = await getCache()
        const key = `${keyPrefix}${propertyName}:${JSON.stringify(args)}`

        // Try to get from cache
        const cached = await cache.get<T>(key)
        if (cached !== null) {
          logger.debug('Cache', `Cache hit for ${key}`)
          return cached
        }

        // Execute method and cache result
        const result = await method.apply(this, args)
        await cache.set(key, result, ttl)

        logger.debug('Cache', `Cache miss for ${key}, result cached`)
        return result

      } catch (error) {
        logger.error('Cache', `Cache error for ${propertyName}`, error)
        // Fallback to executing method without cache
        return method.apply(this, args)
      }
    } as CacheableMethod<T>
  }
}

/**
 * Simple cache helper functions
 */
export const CacheHelper = {
  /**
   * Get value from cache
   */
  async get<T>(key: string): Promise<T | null> {
    try {
      const cache = await getCache()
      return cache.get<T>(key)
    } catch (error) {
      logger.error('Cache', `Failed to get ${key}`, error)
      return null
    }
  },

  /**
   * Set value in cache
   */
  async set<T>(key: string, value: T, ttl?: number): Promise<void> {
    try {
      const cache = await getCache()
      await cache.set(key, value, ttl)
    } catch (error) {
      logger.error('Cache', `Failed to set ${key}`, error)
    }
  },

  /**
   * Delete value from cache
   */
  async delete(key: string): Promise<void> {
    try {
      const cache = await getCache()
      await cache.delete(key)
    } catch (error) {
      logger.error('Cache', `Failed to delete ${key}`, error)
    }
  },

  /**
   * Check if key exists in cache
   */
  async exists(key: string): Promise<boolean> {
    try {
      const cache = await getCache()
      return cache.exists(key)
    } catch (error) {
      logger.error('Cache', `Failed to check existence of ${key}`, error)
      return false
    }
  },

  /**
   * Get or set pattern - get value, or set it if not exists
   */
  async getOrSet<T>(
    key: string,
    factory: () => Promise<T>,
    ttl?: number
  ): Promise<T> {
    try {
      const cache = await getCache()

      // Try to get existing value
      const existing = await cache.get<T>(key)
      if (existing !== null) {
        return existing
      }

      // Generate new value
      const value = await factory()

      // Cache the new value
      await cache.set(key, value, ttl)

      return value
    } catch (error) {
      logger.error('Cache', `Failed getOrSet for ${key}`, error)
      // Fallback to factory function
      return factory()
    }
  },

  /**
   * Clear all cache entries
   */
  async clear(): Promise<void> {
    try {
      const cache = await getCache()
      await cache.clear()
      logger.info('Cache', 'Cache cleared')
    } catch (error) {
      logger.error('Cache', 'Failed to clear cache', error)
    }
  }
}

// Export cache types
export { MemoryCache, RedisCache }
