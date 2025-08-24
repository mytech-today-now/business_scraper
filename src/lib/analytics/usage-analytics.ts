/**
 * Usage Analytics Service
 * Comprehensive API usage analytics and monitoring
 */

import { ApiUsageAnalytics, IntegrationHealthStatus } from '@/types/integrations'
import { logger } from '@/utils/logger'

/**
 * Usage analytics data structures
 */
interface UsageMetric {
  timestamp: number
  clientId: string
  endpoint: string
  method: string
  statusCode: number
  responseTime: number
  dataTransferred: number
  userAgent?: string
  ip?: string
}

interface ClientUsage {
  clientId: string
  totalRequests: number
  successfulRequests: number
  failedRequests: number
  totalDataTransferred: number
  averageResponseTime: number
  rateLimitHits: number
  firstSeen: string
  lastSeen: string
  endpoints: Map<string, {
    requests: number
    averageResponseTime: number
    errorRate: number
  }>
}

/**
 * Usage Analytics Service implementation
 */
export class UsageAnalyticsService {
  private metrics: UsageMetric[] = []
  private clientUsage: Map<string, ClientUsage> = new Map()
  private endpointStats: Map<string, any> = new Map()
  private healthChecks: Map<string, IntegrationHealthStatus> = new Map()
  private maxMetricsRetention = 100000 // Keep last 100k metrics
  private cleanupInterval: NodeJS.Timeout

  constructor() {
    this.initializeService()
  }

  /**
   * Initialize the analytics service
   */
  private initializeService(): void {
    logger.info('UsageAnalytics', 'Initializing usage analytics service')
    
    // Start periodic cleanup
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldMetrics()
    }, 60 * 60 * 1000) // Cleanup every hour

    // Initialize health checks
    this.initializeHealthChecks()
  }

  /**
   * Record API usage metric
   */
  recordUsage(
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
    const timestamp = Date.now()

    // Record raw metric
    const metric: UsageMetric = {
      timestamp,
      clientId,
      endpoint,
      method,
      statusCode,
      responseTime,
      dataTransferred,
      userAgent: metadata?.userAgent,
      ip: metadata?.ip
    }

    this.metrics.push(metric)

    // Update client usage statistics
    this.updateClientUsage(clientId, endpoint, method, statusCode, responseTime, dataTransferred, metadata?.rateLimitHit)

    // Update endpoint statistics
    this.updateEndpointStats(endpoint, method, statusCode, responseTime)

    // Cleanup if needed
    if (this.metrics.length > this.maxMetricsRetention) {
      this.metrics = this.metrics.slice(-this.maxMetricsRetention)
    }
  }

  /**
   * Update client usage statistics
   */
  private updateClientUsage(
    clientId: string,
    endpoint: string,
    method: string,
    statusCode: number,
    responseTime: number,
    dataTransferred: number,
    rateLimitHit?: boolean
  ): void {
    let clientUsage = this.clientUsage.get(clientId)
    
    if (!clientUsage) {
      clientUsage = {
        clientId,
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        totalDataTransferred: 0,
        averageResponseTime: 0,
        rateLimitHits: 0,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        endpoints: new Map()
      }
    }

    // Update overall statistics
    clientUsage.totalRequests++
    clientUsage.totalDataTransferred += dataTransferred
    clientUsage.lastSeen = new Date().toISOString()

    if (statusCode >= 200 && statusCode < 400) {
      clientUsage.successfulRequests++
    } else {
      clientUsage.failedRequests++
    }

    if (rateLimitHit) {
      clientUsage.rateLimitHits++
    }

    // Update average response time
    clientUsage.averageResponseTime = (
      (clientUsage.averageResponseTime * (clientUsage.totalRequests - 1) + responseTime) / 
      clientUsage.totalRequests
    )

    // Update endpoint-specific statistics
    const endpointKey = `${method}:${endpoint}`
    let endpointStats = clientUsage.endpoints.get(endpointKey)
    
    if (!endpointStats) {
      endpointStats = {
        requests: 0,
        averageResponseTime: 0,
        errorRate: 0
      }
    }

    endpointStats.requests++
    endpointStats.averageResponseTime = (
      (endpointStats.averageResponseTime * (endpointStats.requests - 1) + responseTime) / 
      endpointStats.requests
    )

    const errors = statusCode >= 400 ? 1 : 0
    endpointStats.errorRate = (
      (endpointStats.errorRate * (endpointStats.requests - 1) + errors) / 
      endpointStats.requests
    ) * 100

    clientUsage.endpoints.set(endpointKey, endpointStats)
    this.clientUsage.set(clientId, clientUsage)
  }

  /**
   * Update endpoint statistics
   */
  private updateEndpointStats(
    endpoint: string,
    method: string,
    statusCode: number,
    responseTime: number
  ): void {
    const endpointKey = `${method}:${endpoint}`
    let stats = this.endpointStats.get(endpointKey)
    
    if (!stats) {
      stats = {
        requests: 0,
        averageResponseTime: 0,
        errorRate: 0,
        p95ResponseTime: 0,
        responseTimes: []
      }
    }

    stats.requests++
    stats.responseTimes.push(responseTime)

    // Keep only last 1000 response times for percentile calculation
    if (stats.responseTimes.length > 1000) {
      stats.responseTimes = stats.responseTimes.slice(-1000)
    }

    // Calculate average response time
    stats.averageResponseTime = (
      (stats.averageResponseTime * (stats.requests - 1) + responseTime) / 
      stats.requests
    )

    // Calculate error rate
    const errors = statusCode >= 400 ? 1 : 0
    stats.errorRate = (
      (stats.errorRate * (stats.requests - 1) + errors) / 
      stats.requests
    ) * 100

    // Calculate P95 response time
    const sortedTimes = [...stats.responseTimes].sort((a, b) => a - b)
    const p95Index = Math.floor(sortedTimes.length * 0.95)
    stats.p95ResponseTime = sortedTimes[p95Index] || 0

    this.endpointStats.set(endpointKey, stats)
  }

  /**
   * Get usage analytics for a client
   */
  getClientAnalytics(
    clientId: string,
    period: { start: string; end: string }
  ): ApiUsageAnalytics {
    const startTime = new Date(period.start).getTime()
    const endTime = new Date(period.end).getTime()

    // Filter metrics for the client and period
    const clientMetrics = this.metrics.filter(m => 
      m.clientId === clientId && 
      m.timestamp >= startTime && 
      m.timestamp <= endTime
    )

    const totalRequests = clientMetrics.length
    const successfulRequests = clientMetrics.filter(m => m.statusCode >= 200 && m.statusCode < 400).length
    const failedRequests = totalRequests - successfulRequests
    const averageResponseTime = totalRequests > 0 
      ? clientMetrics.reduce((sum, m) => sum + m.responseTime, 0) / totalRequests 
      : 0
    const dataTransferred = clientMetrics.reduce((sum, m) => sum + m.dataTransferred, 0)
    const rateLimitHits = this.clientUsage.get(clientId)?.rateLimitHits || 0

    // Group by endpoint
    const endpointMap = new Map<string, any>()
    
    for (const metric of clientMetrics) {
      const key = `${metric.method}:${metric.endpoint}`
      let endpointData = endpointMap.get(key)
      
      if (!endpointData) {
        endpointData = {
          path: metric.endpoint,
          method: metric.method,
          requests: 0,
          totalResponseTime: 0,
          errors: 0
        }
      }
      
      endpointData.requests++
      endpointData.totalResponseTime += metric.responseTime
      
      if (metric.statusCode >= 400) {
        endpointData.errors++
      }
      
      endpointMap.set(key, endpointData)
    }

    const endpoints = Array.from(endpointMap.values()).map(data => ({
      path: data.path,
      method: data.method,
      requests: data.requests,
      averageResponseTime: data.requests > 0 ? data.totalResponseTime / data.requests : 0,
      errorRate: data.requests > 0 ? (data.errors / data.requests) * 100 : 0
    }))

    // Get error details
    const errorMetrics = clientMetrics.filter(m => m.statusCode >= 400)
    const errorMap = new Map<string, number>()
    
    for (const metric of errorMetrics) {
      const errorKey = `${metric.endpoint}:${metric.statusCode}`
      errorMap.set(errorKey, (errorMap.get(errorKey) || 0) + 1)
    }

    const errors = Array.from(errorMap.entries()).map(([key, count]) => {
      const [endpoint, statusCode] = key.split(':')
      return {
        timestamp: new Date().toISOString(), // Simplified - would track actual error times
        endpoint,
        error: `HTTP ${statusCode}`,
        count
      }
    })

    return {
      clientId,
      period,
      metrics: {
        totalRequests,
        successfulRequests,
        failedRequests,
        averageResponseTime,
        dataTransferred,
        rateLimitHits
      },
      endpoints,
      errors
    }
  }

  /**
   * Get overall system analytics
   */
  getSystemAnalytics(period: { start: string; end: string }): {
    totalClients: number
    totalRequests: number
    averageResponseTime: number
    errorRate: number
    topEndpoints: Array<{
      endpoint: string
      requests: number
      averageResponseTime: number
      errorRate: number
    }>
    topClients: Array<{
      clientId: string
      requests: number
      dataTransferred: number
    }>
  } {
    const startTime = new Date(period.start).getTime()
    const endTime = new Date(period.end).getTime()

    const periodMetrics = this.metrics.filter(m => 
      m.timestamp >= startTime && m.timestamp <= endTime
    )

    const uniqueClients = new Set(periodMetrics.map(m => m.clientId))
    const totalRequests = periodMetrics.length
    const averageResponseTime = totalRequests > 0 
      ? periodMetrics.reduce((sum, m) => sum + m.responseTime, 0) / totalRequests 
      : 0
    const errorCount = periodMetrics.filter(m => m.statusCode >= 400).length
    const errorRate = totalRequests > 0 ? (errorCount / totalRequests) * 100 : 0

    // Top endpoints
    const endpointMap = new Map<string, any>()
    for (const metric of periodMetrics) {
      const key = `${metric.method}:${metric.endpoint}`
      let data = endpointMap.get(key)
      
      if (!data) {
        data = {
          endpoint: `${metric.method} ${metric.endpoint}`,
          requests: 0,
          totalResponseTime: 0,
          errors: 0
        }
      }
      
      data.requests++
      data.totalResponseTime += metric.responseTime
      if (metric.statusCode >= 400) data.errors++
      
      endpointMap.set(key, data)
    }

    const topEndpoints = Array.from(endpointMap.values())
      .map(data => ({
        endpoint: data.endpoint,
        requests: data.requests,
        averageResponseTime: data.requests > 0 ? data.totalResponseTime / data.requests : 0,
        errorRate: data.requests > 0 ? (data.errors / data.requests) * 100 : 0
      }))
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 10)

    // Top clients
    const clientMap = new Map<string, any>()
    for (const metric of periodMetrics) {
      let data = clientMap.get(metric.clientId)
      
      if (!data) {
        data = {
          clientId: metric.clientId,
          requests: 0,
          dataTransferred: 0
        }
      }
      
      data.requests++
      data.dataTransferred += metric.dataTransferred
      
      clientMap.set(metric.clientId, data)
    }

    const topClients = Array.from(clientMap.values())
      .sort((a, b) => b.requests - a.requests)
      .slice(0, 10)

    return {
      totalClients: uniqueClients.size,
      totalRequests,
      averageResponseTime,
      errorRate,
      topEndpoints,
      topClients
    }
  }

  /**
   * Get health status
   */
  getHealthStatus(): IntegrationHealthStatus[] {
    return Array.from(this.healthChecks.values())
  }

  /**
   * Update health status
   */
  updateHealthStatus(service: string, status: Omit<IntegrationHealthStatus, 'service'>): void {
    this.healthChecks.set(service, {
      service,
      ...status
    })
  }

  /**
   * Initialize health checks
   */
  private initializeHealthChecks(): void {
    const services = ['api-framework', 'oauth2-service', 'webhook-service', 'export-service', 'scheduling-service']
    
    for (const service of services) {
      this.healthChecks.set(service, {
        service,
        status: 'healthy',
        lastCheck: new Date().toISOString(),
        responseTime: 0,
        uptime: process.uptime(),
        errors: [],
        metrics: {}
      })
    }
  }

  /**
   * Cleanup old metrics
   */
  private cleanupOldMetrics(): void {
    const cutoffTime = Date.now() - (7 * 24 * 60 * 60 * 1000) // 7 days
    const originalLength = this.metrics.length
    
    this.metrics = this.metrics.filter(m => m.timestamp > cutoffTime)
    
    const cleaned = originalLength - this.metrics.length
    if (cleaned > 0) {
      logger.info('UsageAnalytics', `Cleaned up ${cleaned} old metrics`)
    }
  }

  /**
   * Get real-time metrics
   */
  getRealTimeMetrics(): {
    requestsPerMinute: number
    averageResponseTime: number
    errorRate: number
    activeClients: number
  } {
    const oneMinuteAgo = Date.now() - (60 * 1000)
    const recentMetrics = this.metrics.filter(m => m.timestamp > oneMinuteAgo)
    
    const requestsPerMinute = recentMetrics.length
    const averageResponseTime = recentMetrics.length > 0 
      ? recentMetrics.reduce((sum, m) => sum + m.responseTime, 0) / recentMetrics.length 
      : 0
    const errorCount = recentMetrics.filter(m => m.statusCode >= 400).length
    const errorRate = recentMetrics.length > 0 ? (errorCount / recentMetrics.length) * 100 : 0
    const activeClients = new Set(recentMetrics.map(m => m.clientId)).size

    return {
      requestsPerMinute,
      averageResponseTime,
      errorRate,
      activeClients
    }
  }

  /**
   * Export analytics data
   */
  exportAnalytics(format: 'json' | 'csv' = 'json'): string {
    if (format === 'csv') {
      const headers = ['timestamp', 'clientId', 'endpoint', 'method', 'statusCode', 'responseTime', 'dataTransferred']
      const rows = this.metrics.map(m => [
        new Date(m.timestamp).toISOString(),
        m.clientId,
        m.endpoint,
        m.method,
        m.statusCode,
        m.responseTime,
        m.dataTransferred
      ])
      
      return [headers, ...rows].map(row => row.join(',')).join('\n')
    } else {
      return JSON.stringify({
        metrics: this.metrics,
        clientUsage: Object.fromEntries(this.clientUsage),
        endpointStats: Object.fromEntries(this.endpointStats),
        healthChecks: Object.fromEntries(this.healthChecks),
        exportedAt: new Date().toISOString()
      }, null, 2)
    }
  }

  /**
   * Cleanup resources
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
    }
  }
}

// Export singleton instance
export const usageAnalyticsService = new UsageAnalyticsService()
