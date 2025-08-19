/**
 * Advanced Rate Limiting Service for Search Engines
 * Implements intelligent rate limiting with provider-specific rules
 */

import { logger } from '@/utils/logger'

export interface ProviderLimits {
  name: string
  requestsPerMinute: number
  requestsPerHour: number
  requestsPerDay: number
  minDelayBetweenRequests: number
  maxConcurrentRequests: number
  backoffMultiplier: number
  maxBackoffDelay: number
  resetHour: number // Hour of day when daily limits reset (0-23)
}

export interface RequestRecord {
  timestamp: number
  provider: string
  success: boolean
  responseTime: number
  statusCode?: number
  errorType?: string
}

export interface RateLimitStatus {
  provider: string
  canMakeRequest: boolean
  nextAvailableTime?: number
  requestsInLastMinute: number
  requestsInLastHour: number
  requestsInLastDay: number
  recommendedDelay: number
  backoffLevel: number
}

/**
 * Rate Limiting Service
 */
export class RateLimitingService {
  private requestHistory: Map<string, RequestRecord[]> = new Map()
  private lastRequestTime: Map<string, number> = new Map()
  private backoffLevels: Map<string, number> = new Map()
  private providerLimits: Map<string, ProviderLimits> = new Map()

  constructor() {
    this.initializeProviderLimits()
  }

  /**
   * Initialize rate limits for different search providers
   */
  private initializeProviderLimits(): void {
    const providers: ProviderLimits[] = [
      {
        name: 'duckduckgo',
        requestsPerMinute: 1,
        requestsPerHour: 10,
        requestsPerDay: 100,
        minDelayBetweenRequests: 45000, // 45 seconds
        maxConcurrentRequests: 1,
        backoffMultiplier: 2,
        maxBackoffDelay: 300000, // 5 minutes
        resetHour: 0
      },
      {
        name: 'google',
        requestsPerMinute: 5,
        requestsPerHour: 100,
        requestsPerDay: 1000,
        minDelayBetweenRequests: 12000, // 12 seconds
        maxConcurrentRequests: 2,
        backoffMultiplier: 1.5,
        maxBackoffDelay: 180000, // 3 minutes
        resetHour: 0
      },
      {
        name: 'bing',
        requestsPerMinute: 10,
        requestsPerHour: 200,
        requestsPerDay: 2000,
        minDelayBetweenRequests: 6000, // 6 seconds
        maxConcurrentRequests: 3,
        backoffMultiplier: 1.5,
        maxBackoffDelay: 120000, // 2 minutes
        resetHour: 0
      },
      {
        name: 'bbb',
        requestsPerMinute: 3,
        requestsPerHour: 50,
        requestsPerDay: 500,
        minDelayBetweenRequests: 20000, // 20 seconds
        maxConcurrentRequests: 1,
        backoffMultiplier: 2,
        maxBackoffDelay: 240000, // 4 minutes
        resetHour: 0
      },
      {
        name: 'yelp',
        requestsPerMinute: 5,
        requestsPerHour: 100,
        requestsPerDay: 1000,
        minDelayBetweenRequests: 12000, // 12 seconds
        maxConcurrentRequests: 2,
        backoffMultiplier: 1.5,
        maxBackoffDelay: 180000, // 3 minutes
        resetHour: 0
      }
    ]

    providers.forEach(provider => {
      this.providerLimits.set(provider.name, provider)
      this.requestHistory.set(provider.name, [])
      this.backoffLevels.set(provider.name, 0)
    })

    logger.info('RateLimiting', `Initialized rate limits for ${providers.length} providers`)
  }

  /**
   * Check if a request can be made to a provider
   */
  canMakeRequest(provider: string): RateLimitStatus {
    const limits = this.providerLimits.get(provider)
    if (!limits) {
      return {
        provider,
        canMakeRequest: false,
        requestsInLastMinute: 0,
        requestsInLastHour: 0,
        requestsInLastDay: 0,
        recommendedDelay: 60000,
        backoffLevel: 0
      }
    }

    const now = Date.now()
    const history = this.requestHistory.get(provider) || []
    const lastRequestTime = this.lastRequestTime.get(provider) || 0
    const backoffLevel = this.backoffLevels.get(provider) || 0

    // Clean old records
    this.cleanOldRecords(provider)

    // Count recent requests
    const oneMinuteAgo = now - 60000
    const oneHourAgo = now - 3600000
    const oneDayAgo = now - 86400000

    const requestsInLastMinute = history.filter(r => r.timestamp > oneMinuteAgo).length
    const requestsInLastHour = history.filter(r => r.timestamp > oneHourAgo).length
    const requestsInLastDay = history.filter(r => r.timestamp > oneDayAgo).length

    // Check time-based limits
    const timeSinceLastRequest = now - lastRequestTime
    const minDelay = Math.max(
      limits.minDelayBetweenRequests,
      limits.minDelayBetweenRequests * Math.pow(limits.backoffMultiplier, backoffLevel)
    )

    let canMakeRequest = true
    let nextAvailableTime: number | undefined
    let recommendedDelay = minDelay

    // Check various limits
    if (timeSinceLastRequest < minDelay) {
      canMakeRequest = false
      nextAvailableTime = lastRequestTime + minDelay
      recommendedDelay = minDelay - timeSinceLastRequest
    } else if (requestsInLastMinute >= limits.requestsPerMinute) {
      canMakeRequest = false
      const oldestInMinute = history.find(r => r.timestamp > oneMinuteAgo)
      nextAvailableTime = oldestInMinute ? oldestInMinute.timestamp + 60000 : now + 60000
      recommendedDelay = Math.max(recommendedDelay, nextAvailableTime - now)
    } else if (requestsInLastHour >= limits.requestsPerHour) {
      canMakeRequest = false
      const oldestInHour = history.find(r => r.timestamp > oneHourAgo)
      nextAvailableTime = oldestInHour ? oldestInHour.timestamp + 3600000 : now + 3600000
      recommendedDelay = Math.max(recommendedDelay, nextAvailableTime - now)
    } else if (requestsInLastDay >= limits.requestsPerDay) {
      canMakeRequest = false
      const oldestInDay = history.find(r => r.timestamp > oneDayAgo)
      nextAvailableTime = oldestInDay ? oldestInDay.timestamp + 86400000 : now + 86400000
      recommendedDelay = Math.max(recommendedDelay, nextAvailableTime - now)
    }

    return {
      provider,
      canMakeRequest,
      nextAvailableTime,
      requestsInLastMinute,
      requestsInLastHour,
      requestsInLastDay,
      recommendedDelay,
      backoffLevel
    }
  }

  /**
   * Record a request attempt
   */
  recordRequest(provider: string, success: boolean, responseTime: number, statusCode?: number, errorType?: string): void {
    const now = Date.now()
    const history = this.requestHistory.get(provider) || []
    
    const record: RequestRecord = {
      timestamp: now,
      provider,
      success,
      responseTime,
      statusCode,
      errorType
    }

    history.push(record)
    this.requestHistory.set(provider, history)
    this.lastRequestTime.set(provider, now)

    // Adjust backoff level based on success/failure
    const currentBackoff = this.backoffLevels.get(provider) || 0
    
    if (success) {
      // Gradually reduce backoff on success
      this.backoffLevels.set(provider, Math.max(0, currentBackoff - 1))
    } else {
      // Increase backoff on failure
      const limits = this.providerLimits.get(provider)
      if (limits) {
        const maxBackoffLevel = Math.log(limits.maxBackoffDelay / limits.minDelayBetweenRequests) / Math.log(limits.backoffMultiplier)
        this.backoffLevels.set(provider, Math.min(maxBackoffLevel, currentBackoff + 1))
      }
    }

    // Clean old records periodically
    if (history.length > 1000) {
      this.cleanOldRecords(provider)
    }

    logger.debug('RateLimiting', `Recorded request for ${provider}`, {
      success,
      responseTime,
      statusCode,
      errorType,
      backoffLevel: this.backoffLevels.get(provider)
    })
  }

  /**
   * Wait for the recommended delay before making a request
   */
  async waitForRequest(provider: string): Promise<void> {
    const status = this.canMakeRequest(provider)
    
    if (!status.canMakeRequest && status.recommendedDelay > 0) {
      logger.info('RateLimiting', `Waiting ${status.recommendedDelay}ms before ${provider} request`, {
        requestsInLastMinute: status.requestsInLastMinute,
        requestsInLastHour: status.requestsInLastHour,
        backoffLevel: status.backoffLevel
      })
      
      await new Promise(resolve => setTimeout(resolve, status.recommendedDelay))
    }
  }

  /**
   * Clean old records to prevent memory leaks
   */
  private cleanOldRecords(provider: string): void {
    const history = this.requestHistory.get(provider) || []
    const oneDayAgo = Date.now() - 86400000
    
    const cleanedHistory = history.filter(r => r.timestamp > oneDayAgo)
    this.requestHistory.set(provider, cleanedHistory)
  }

  /**
   * Reset backoff for a provider
   */
  resetBackoff(provider: string): void {
    this.backoffLevels.set(provider, 0)
    logger.info('RateLimiting', `Reset backoff for ${provider}`)
  }

  /**
   * Get statistics for all providers
   */
  getStats(): any {
    const stats: any = {}
    
    for (const [provider, limits] of this.providerLimits) {
      const status = this.canMakeRequest(provider)
      const history = this.requestHistory.get(provider) || []
      const recentFailures = history.filter(r => !r.success && r.timestamp > Date.now() - 3600000).length
      
      stats[provider] = {
        ...status,
        limits,
        recentFailures,
        totalRequests: history.length,
        averageResponseTime: history.length > 0 ? 
          history.reduce((sum, r) => sum + r.responseTime, 0) / history.length : 0
      }
    }
    
    return stats
  }

  /**
   * Update provider limits dynamically
   */
  updateProviderLimits(provider: string, newLimits: Partial<ProviderLimits>): void {
    const currentLimits = this.providerLimits.get(provider)
    if (currentLimits) {
      const updatedLimits = { ...currentLimits, ...newLimits }
      this.providerLimits.set(provider, updatedLimits)
      logger.info('RateLimiting', `Updated limits for ${provider}`, newLimits)
    }
  }
}
