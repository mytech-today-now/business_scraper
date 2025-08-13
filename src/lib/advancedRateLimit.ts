/**
 * Advanced Rate Limiting System
 * Implements sophisticated rate limiting with sliding windows, different endpoint types,
 * and both IP-based and user-based rate limiting
 */

import { NextRequest } from 'next/server'
import { getClientIP } from './security'
import { logger } from '@/utils/logger'

export interface RateLimitConfig {
  windowMs: number
  maxRequests: number
  skipSuccessfulRequests?: boolean
  skipFailedRequests?: boolean
  keyGenerator?: (request: NextRequest) => string
  onLimitReached?: (key: string, request: NextRequest) => void
}

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetTime: number
  retryAfter?: number
}

export interface SlidingWindowEntry {
  timestamp: number
  count: number
}

export interface RateLimitEntry {
  requests: SlidingWindowEntry[]
  totalRequests: number
  firstRequest: number
  lastRequest: number
}

/**
 * Advanced Rate Limiting Service
 */
export class AdvancedRateLimitService {
  private rateLimitStore = new Map<string, RateLimitEntry>()
  private cleanupInterval: NodeJS.Timeout | null = null

  constructor() {
    // Start cleanup interval (every 5 minutes)
    this.cleanupInterval = setInterval(() => {
      this.cleanup()
    }, 5 * 60 * 1000)
  }

  /**
   * Check rate limit using sliding window algorithm
   */
  checkRateLimit(key: string, config: RateLimitConfig): RateLimitResult {
    const now = Date.now()
    const windowStart = now - config.windowMs

    // Get or create rate limit entry
    let entry = this.rateLimitStore.get(key)
    if (!entry) {
      entry = {
        requests: [],
        totalRequests: 0,
        firstRequest: now,
        lastRequest: now
      }
      this.rateLimitStore.set(key, entry)
    }

    // Remove expired requests from sliding window
    entry.requests = entry.requests.filter(req => req.timestamp > windowStart)

    // Count current requests in window
    const currentRequests = entry.requests.reduce((sum, req) => sum + req.count, 0)

    // Check if limit exceeded
    const allowed = currentRequests < config.maxRequests
    const remaining = Math.max(0, config.maxRequests - currentRequests)

    if (allowed) {
      // Add current request
      const lastEntry = entry.requests[entry.requests.length - 1]
      if (lastEntry && now - lastEntry.timestamp < 1000) {
        // Increment count for requests within the same second
        lastEntry.count++
      } else {
        // Add new entry
        entry.requests.push({ timestamp: now, count: 1 })
      }
      
      entry.totalRequests++
      entry.lastRequest = now
    } else {
      // Calculate retry after time
      const oldestRequest = entry.requests[0]
      const retryAfter = oldestRequest ? Math.ceil((oldestRequest.timestamp + config.windowMs - now) / 1000) : Math.ceil(config.windowMs / 1000)
      
      if (config.onLimitReached) {
        // Note: We can't pass the actual request here, but we can log the key
        logger.warn('RateLimit', `Rate limit exceeded for key: ${key}`)
      }

      return {
        allowed: false,
        remaining: 0,
        resetTime: oldestRequest ? oldestRequest.timestamp + config.windowMs : now + config.windowMs,
        retryAfter
      }
    }

    // Calculate reset time (when the oldest request will expire)
    const oldestRequest = entry.requests[0]
    const resetTime = oldestRequest ? oldestRequest.timestamp + config.windowMs : now + config.windowMs

    return {
      allowed: true,
      remaining,
      resetTime
    }
  }

  /**
   * Check rate limit for API endpoints with different configurations
   */
  checkApiRateLimit(request: NextRequest, endpointType: 'general' | 'scraping' | 'auth' | 'upload' | 'export'): RateLimitResult {
    const ip = getClientIP(request)
    const sessionId = request.cookies.get('session-id')?.value
    
    // Use session ID if available, otherwise fall back to IP
    const key = sessionId ? `session:${sessionId}` : `ip:${ip}`
    
    const configs: Record<string, RateLimitConfig> = {
      general: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 100,
        onLimitReached: () => logger.warn('RateLimit', `General API rate limit exceeded for ${key}`)
      },
      scraping: {
        windowMs: 60 * 60 * 1000, // 1 hour
        maxRequests: 10,
        onLimitReached: () => logger.warn('RateLimit', `Scraping rate limit exceeded for ${key}`)
      },
      auth: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 5,
        onLimitReached: () => logger.warn('RateLimit', `Auth rate limit exceeded for ${key}`)
      },
      upload: {
        windowMs: 60 * 60 * 1000, // 1 hour
        maxRequests: 20,
        onLimitReached: () => logger.warn('RateLimit', `Upload rate limit exceeded for ${key}`)
      },
      export: {
        windowMs: 60 * 60 * 1000, // 1 hour
        maxRequests: 50,
        onLimitReached: () => logger.warn('RateLimit', `Export rate limit exceeded for ${key}`)
      }
    }

    const config = configs[endpointType]
    return this.checkRateLimit(`${endpointType}:${key}`, config)
  }

  /**
   * Check burst rate limit (short-term high-frequency protection)
   */
  checkBurstRateLimit(key: string): RateLimitResult {
    const config: RateLimitConfig = {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 20,
      onLimitReached: () => logger.warn('RateLimit', `Burst rate limit exceeded for ${key}`)
    }

    return this.checkRateLimit(`burst:${key}`, config)
  }

  /**
   * Check rate limit for specific actions (like form submissions)
   */
  checkActionRateLimit(request: NextRequest, action: string): RateLimitResult {
    const ip = getClientIP(request)
    const key = `action:${action}:${ip}`
    
    const config: RateLimitConfig = {
      windowMs: 5 * 60 * 1000, // 5 minutes
      maxRequests: 3,
      onLimitReached: () => logger.warn('RateLimit', `Action rate limit exceeded for ${action} from ${ip}`)
    }

    return this.checkRateLimit(key, config)
  }

  /**
   * Get rate limit status without incrementing
   */
  getRateLimitStatus(key: string, config: RateLimitConfig): RateLimitResult {
    const now = Date.now()
    const windowStart = now - config.windowMs

    const entry = this.rateLimitStore.get(key)
    if (!entry) {
      return {
        allowed: true,
        remaining: config.maxRequests,
        resetTime: now + config.windowMs
      }
    }

    // Count current requests in window (without modifying)
    const currentRequests = entry.requests
      .filter(req => req.timestamp > windowStart)
      .reduce((sum, req) => sum + req.count, 0)

    const remaining = Math.max(0, config.maxRequests - currentRequests)
    const allowed = currentRequests < config.maxRequests

    const oldestRequest = entry.requests.find(req => req.timestamp > windowStart)
    const resetTime = oldestRequest ? oldestRequest.timestamp + config.windowMs : now + config.windowMs

    return {
      allowed,
      remaining,
      resetTime,
      retryAfter: allowed ? undefined : Math.ceil((resetTime - now) / 1000)
    }
  }

  /**
   * Reset rate limit for a specific key
   */
  resetRateLimit(key: string): void {
    this.rateLimitStore.delete(key)
    logger.info('RateLimit', `Rate limit reset for key: ${key}`)
  }

  /**
   * Get all rate limit entries (for monitoring)
   */
  getAllRateLimits(): Map<string, RateLimitEntry> {
    return new Map(this.rateLimitStore)
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now()
    const maxAge = 24 * 60 * 60 * 1000 // 24 hours

    let cleanedCount = 0
    for (const [key, entry] of this.rateLimitStore.entries()) {
      if (now - entry.lastRequest > maxAge) {
        this.rateLimitStore.delete(key)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      logger.info('RateLimit', `Cleaned up ${cleanedCount} expired rate limit entries`)
    }
  }

  /**
   * Destroy the service and cleanup
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
    this.rateLimitStore.clear()
  }
}

/**
 * Default advanced rate limit service instance
 */
export const advancedRateLimitService = new AdvancedRateLimitService()
