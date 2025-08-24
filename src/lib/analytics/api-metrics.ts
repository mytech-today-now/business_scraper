/**
 * API Metrics Service
 * Enhanced API monitoring and performance metrics
 */

import { usageAnalyticsService } from './usage-analytics'
import { logger } from '@/utils/logger'

/**
 * Rate limiting data structures
 */
interface RateLimitBucket {
  tokens: number
  lastRefill: number
  windowStart: number
  requestCount: number
}

interface ClientRateLimit {
  minute: RateLimitBucket
  hour: RateLimitBucket
  day: RateLimitBucket
}

/**
 * Enhanced API Metrics Service
 */
export class ApiMetricsService {
  private rateLimits: Map<string, ClientRateLimit> = new Map()
  private globalRateLimit: ClientRateLimit
  private alertThresholds = {
    errorRate: 5, // 5% error rate threshold
    responseTime: 2000, // 2 second response time threshold
    rateLimitHits: 10 // 10 rate limit hits per minute threshold
  }

  constructor() {
    this.globalRateLimit = this.createRateLimitBucket()
    this.initializeService()
  }

  /**
   * Initialize the metrics service
   */
  private initializeService(): void {
    logger.info('ApiMetrics', 'Initializing API metrics service')
    
    // Start periodic cleanup and monitoring
    setInterval(() => {
      this.cleanupRateLimits()
      this.checkAlerts()
    }, 60 * 1000) // Every minute
  }

  /**
   * Create rate limit bucket
   */
  private createRateLimitBucket(): ClientRateLimit {
    const now = Date.now()
    return {
      minute: {
        tokens: 0,
        lastRefill: now,
        windowStart: now,
        requestCount: 0
      },
      hour: {
        tokens: 0,
        lastRefill: now,
        windowStart: now,
        requestCount: 0
      },
      day: {
        tokens: 0,
        lastRefill: now,
        windowStart: now,
        requestCount: 0
      }
    }
  }

  /**
   * Check rate limit for client
   */
  checkRateLimit(
    clientId: string,
    limits: {
      requestsPerMinute: number
      requestsPerHour: number
      requestsPerDay?: number
    }
  ): {
    allowed: boolean
    remaining: {
      minute: number
      hour: number
      day: number
    }
    resetTime: {
      minute: number
      hour: number
      day: number
    }
    rateLimitHit: boolean
  } {
    const now = Date.now()
    let clientLimits = this.rateLimits.get(clientId)
    
    if (!clientLimits) {
      clientLimits = this.createRateLimitBucket()
      this.rateLimits.set(clientId, clientLimits)
    }

    // Check and update each time window
    const minuteCheck = this.checkWindow(
      clientLimits.minute,
      limits.requestsPerMinute,
      60 * 1000, // 1 minute
      now
    )

    const hourCheck = this.checkWindow(
      clientLimits.hour,
      limits.requestsPerHour,
      60 * 60 * 1000, // 1 hour
      now
    )

    const dayCheck = this.checkWindow(
      clientLimits.day,
      limits.requestsPerDay || limits.requestsPerHour * 24,
      24 * 60 * 60 * 1000, // 1 day
      now
    )

    const allowed = minuteCheck.allowed && hourCheck.allowed && dayCheck.allowed
    const rateLimitHit = !allowed

    if (allowed) {
      // Consume tokens
      clientLimits.minute.requestCount++
      clientLimits.hour.requestCount++
      clientLimits.day.requestCount++
    }

    return {
      allowed,
      remaining: {
        minute: minuteCheck.remaining,
        hour: hourCheck.remaining,
        day: dayCheck.remaining
      },
      resetTime: {
        minute: minuteCheck.resetTime,
        hour: hourCheck.resetTime,
        day: dayCheck.resetTime
      },
      rateLimitHit
    }
  }

  /**
   * Check individual time window
   */
  private checkWindow(
    bucket: RateLimitBucket,
    limit: number,
    windowSize: number,
    now: number
  ): {
    allowed: boolean
    remaining: number
    resetTime: number
  } {
    // Reset window if expired
    if (now - bucket.windowStart >= windowSize) {
      bucket.windowStart = now
      bucket.requestCount = 0
    }

    const allowed = bucket.requestCount < limit
    const remaining = Math.max(0, limit - bucket.requestCount)
    const resetTime = bucket.windowStart + windowSize

    return {
      allowed,
      remaining,
      resetTime: Math.ceil(resetTime / 1000) // Convert to seconds
    }
  }

  /**
   * Record API request metrics
   */
  recordRequest(
    clientId: string,
    endpoint: string,
    method: string,
    statusCode: number,
    responseTime: number,
    dataTransferred: number = 0,
    metadata?: {
      userAgent?: string
      ip?: string
      rateLimitHit?: boolean
    }
  ): void {
    // Record in usage analytics
    usageAnalyticsService.recordUsage(
      clientId,
      endpoint,
      method,
      statusCode,
      responseTime,
      dataTransferred,
      metadata
    )

    // Update health status based on metrics
    this.updateHealthMetrics(endpoint, statusCode, responseTime)
  }

  /**
   * Update health metrics
   */
  private updateHealthMetrics(endpoint: string, statusCode: number, responseTime: number): void {
    const isError = statusCode >= 400
    const isSlowResponse = responseTime > this.alertThresholds.responseTime

    if (isError || isSlowResponse) {
      const errorType = isError ? 'http_error' : 'slow_response'
      const severity = statusCode >= 500 ? 'critical' : isSlowResponse ? 'medium' : 'low'

      usageAnalyticsService.updateHealthStatus('api-framework', {
        status: isError && statusCode >= 500 ? 'unhealthy' : 'degraded',
        lastCheck: new Date().toISOString(),
        responseTime,
        uptime: process.uptime(),
        errors: [{
          timestamp: new Date().toISOString(),
          error: `${errorType}: ${endpoint} - ${statusCode} (${responseTime}ms)`,
          severity
        }],
        metrics: {
          lastResponseTime: responseTime,
          lastStatusCode: statusCode
        }
      })
    }
  }

  /**
   * Get rate limit status for client
   */
  getRateLimitStatus(clientId: string): {
    minute: { requests: number; resetTime: number }
    hour: { requests: number; resetTime: number }
    day: { requests: number; resetTime: number }
  } | null {
    const clientLimits = this.rateLimits.get(clientId)
    if (!clientLimits) {
      return null
    }

    const now = Date.now()

    return {
      minute: {
        requests: clientLimits.minute.requestCount,
        resetTime: Math.ceil((clientLimits.minute.windowStart + 60 * 1000) / 1000)
      },
      hour: {
        requests: clientLimits.hour.requestCount,
        resetTime: Math.ceil((clientLimits.hour.windowStart + 60 * 60 * 1000) / 1000)
      },
      day: {
        requests: clientLimits.day.requestCount,
        resetTime: Math.ceil((clientLimits.day.windowStart + 24 * 60 * 60 * 1000) / 1000)
      }
    }
  }

  /**
   * Get performance metrics
   */
  getPerformanceMetrics(): {
    realTime: {
      requestsPerMinute: number
      averageResponseTime: number
      errorRate: number
      activeClients: number
    }
    alerts: Array<{
      type: string
      message: string
      severity: 'low' | 'medium' | 'high' | 'critical'
      timestamp: string
    }>
    rateLimitStats: {
      totalClients: number
      rateLimitHits: number
      topRateLimitedClients: Array<{
        clientId: string
        hits: number
      }>
    }
  } {
    const realTime = usageAnalyticsService.getRealTimeMetrics()
    const alerts = this.generateAlerts(realTime)
    const rateLimitStats = this.getRateLimitStats()

    return {
      realTime,
      alerts,
      rateLimitStats
    }
  }

  /**
   * Generate alerts based on metrics
   */
  private generateAlerts(metrics: any): Array<{
    type: string
    message: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    timestamp: string
  }> {
    const alerts: any[] = []
    const timestamp = new Date().toISOString()

    // Error rate alert
    if (metrics.errorRate > this.alertThresholds.errorRate) {
      alerts.push({
        type: 'high_error_rate',
        message: `Error rate is ${metrics.errorRate.toFixed(2)}% (threshold: ${this.alertThresholds.errorRate}%)`,
        severity: metrics.errorRate > 10 ? 'critical' : 'high',
        timestamp
      })
    }

    // Response time alert
    if (metrics.averageResponseTime > this.alertThresholds.responseTime) {
      alerts.push({
        type: 'slow_response',
        message: `Average response time is ${metrics.averageResponseTime.toFixed(0)}ms (threshold: ${this.alertThresholds.responseTime}ms)`,
        severity: metrics.averageResponseTime > 5000 ? 'critical' : 'medium',
        timestamp
      })
    }

    // High traffic alert
    if (metrics.requestsPerMinute > 500) {
      alerts.push({
        type: 'high_traffic',
        message: `High traffic detected: ${metrics.requestsPerMinute} requests/minute`,
        severity: metrics.requestsPerMinute > 1000 ? 'high' : 'medium',
        timestamp
      })
    }

    return alerts
  }

  /**
   * Get rate limit statistics
   */
  private getRateLimitStats(): {
    totalClients: number
    rateLimitHits: number
    topRateLimitedClients: Array<{
      clientId: string
      hits: number
    }>
  } {
    const totalClients = this.rateLimits.size
    let totalRateLimitHits = 0
    const clientHits: Array<{ clientId: string; hits: number }> = []

    // This is simplified - in a real implementation, you'd track rate limit hits
    for (const [clientId, limits] of this.rateLimits.entries()) {
      const hits = 0 // Would track actual rate limit hits
      totalRateLimitHits += hits
      
      if (hits > 0) {
        clientHits.push({ clientId, hits })
      }
    }

    const topRateLimitedClients = clientHits
      .sort((a, b) => b.hits - a.hits)
      .slice(0, 10)

    return {
      totalClients,
      rateLimitHits: totalRateLimitHits,
      topRateLimitedClients
    }
  }

  /**
   * Check for alerts
   */
  private checkAlerts(): void {
    const metrics = usageAnalyticsService.getRealTimeMetrics()
    const alerts = this.generateAlerts(metrics)

    for (const alert of alerts) {
      logger.warn('ApiMetrics', `Alert: ${alert.type}`, {
        message: alert.message,
        severity: alert.severity
      })
    }
  }

  /**
   * Cleanup old rate limit data
   */
  private cleanupRateLimits(): void {
    const now = Date.now()
    const dayAgo = now - (24 * 60 * 60 * 1000)

    for (const [clientId, limits] of this.rateLimits.entries()) {
      // Remove clients that haven't made requests in 24 hours
      if (limits.hour.windowStart < dayAgo) {
        this.rateLimits.delete(clientId)
      }
    }
  }

  /**
   * Export metrics data
   */
  exportMetrics(): {
    rateLimits: any
    performance: any
    timestamp: string
  } {
    return {
      rateLimits: Object.fromEntries(this.rateLimits),
      performance: this.getPerformanceMetrics(),
      timestamp: new Date().toISOString()
    }
  }

  /**
   * Set alert thresholds
   */
  setAlertThresholds(thresholds: Partial<typeof this.alertThresholds>): void {
    this.alertThresholds = { ...this.alertThresholds, ...thresholds }
    logger.info('ApiMetrics', 'Updated alert thresholds', this.alertThresholds)
  }

  /**
   * Get alert thresholds
   */
  getAlertThresholds(): typeof this.alertThresholds {
    return { ...this.alertThresholds }
  }
}

// Export singleton instance
export const apiMetricsService = new ApiMetricsService()
