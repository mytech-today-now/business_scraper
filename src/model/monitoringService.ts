/**
 * Performance Monitoring Service
 * Business Scraper Application - Comprehensive Performance Monitoring and Alerting
 */

import { logger } from '@/utils/logger'
import { securityLogger } from '@/lib/securityLogger'

export interface PerformanceMetric {
  id: string
  name: string
  value: number
  unit: string
  timestamp: Date
  tags?: Record<string, string>
  threshold?: {
    warning: number
    critical: number
  }
}

export interface HealthCheck {
  service: string
  status: 'healthy' | 'degraded' | 'unhealthy'
  responseTime: number
  lastCheck: Date
  details?: Record<string, any>
  error?: string
}

export interface Alert {
  id: string
  type: 'performance' | 'error' | 'security' | 'business'
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  metric?: string
  value?: number
  threshold?: number
  timestamp: Date
  resolved: boolean
  resolvedAt?: Date
  acknowledgedBy?: string
  acknowledgedAt?: Date
}

export class MonitoringService {
  private metrics: Map<string, PerformanceMetric[]> = new Map()
  private healthChecks: Map<string, HealthCheck> = new Map()
  private alerts: Alert[] = []
  private alertThresholds: Map<string, any> = new Map()
  private healthCheckInterval: NodeJS.Timeout | null = null

  constructor() {
    this.initializeThresholds()
    this.startHealthChecks()
  }

  /**
   * Record performance metric
   */
  async recordMetric(
    name: string,
    value: number,
    unit: string,
    tags?: Record<string, string>
  ): Promise<void> {
    try {
      const metric: PerformanceMetric = {
        id: this.generateMetricId(),
        name,
        value,
        unit,
        timestamp: new Date(),
        tags,
        threshold: this.alertThresholds.get(name)
      }

      // Store metric
      if (!this.metrics.has(name)) {
        this.metrics.set(name, [])
      }
      this.metrics.get(name)!.push(metric)

      // Keep only last 1000 metrics per type
      const metricArray = this.metrics.get(name)!
      if (metricArray.length > 1000) {
        metricArray.splice(0, metricArray.length - 1000)
      }

      // Check thresholds and create alerts
      await this.checkThresholds(metric)

      // Store in persistent storage
      await this.storeMetric(metric)

      logger.debug('Monitoring', `Metric recorded: ${name} = ${value} ${unit}`)
    } catch (error) {
      logger.error('Monitoring', 'Failed to record metric', error)
    }
  }

  /**
   * Record payment processing time
   */
  async recordPaymentProcessingTime(duration: number, success: boolean): Promise<void> {
    await this.recordMetric('payment_processing_time', duration, 'ms', {
      success: success.toString()
    })

    if (!success) {
      await this.recordMetric('payment_failures', 1, 'count')
    }
  }

  /**
   * Record API response time
   */
  async recordApiResponseTime(endpoint: string, duration: number, statusCode: number): Promise<void> {
    await this.recordMetric('api_response_time', duration, 'ms', {
      endpoint,
      status_code: statusCode.toString()
    })

    if (statusCode >= 400) {
      await this.recordMetric('api_errors', 1, 'count', {
        endpoint,
        status_code: statusCode.toString()
      })
    }
  }

  /**
   * Record database query time
   */
  async recordDatabaseQueryTime(query: string, duration: number): Promise<void> {
    await this.recordMetric('database_query_time', duration, 'ms', {
      query_type: this.getQueryType(query)
    })
  }

  /**
   * Record memory usage
   */
  async recordMemoryUsage(): Promise<void> {
    if (typeof process !== 'undefined') {
      const memUsage = process.memoryUsage()
      await this.recordMetric('memory_heap_used', memUsage.heapUsed, 'bytes')
      await this.recordMetric('memory_heap_total', memUsage.heapTotal, 'bytes')
      await this.recordMetric('memory_rss', memUsage.rss, 'bytes')
    }
  }

  /**
   * Perform health check
   */
  async performHealthCheck(serviceName: string): Promise<HealthCheck> {
    const startTime = Date.now()
    let healthCheck: HealthCheck

    try {
      const result = await this.checkServiceHealth(serviceName)
      const responseTime = Date.now() - startTime

      healthCheck = {
        service: serviceName,
        status: result.healthy ? 'healthy' : 'degraded',
        responseTime,
        lastCheck: new Date(),
        details: result.details
      }

      if (!result.healthy && result.error) {
        healthCheck.error = result.error
        healthCheck.status = 'unhealthy'
      }
    } catch (error) {
      healthCheck = {
        service: serviceName,
        status: 'unhealthy',
        responseTime: Date.now() - startTime,
        lastCheck: new Date(),
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    }

    this.healthChecks.set(serviceName, healthCheck)

    // Create alert if service is unhealthy
    if (healthCheck.status === 'unhealthy') {
      await this.createAlert({
        type: 'performance',
        severity: 'critical',
        title: `Service ${serviceName} is unhealthy`,
        description: `Health check failed: ${healthCheck.error}`,
        metric: `health_check_${serviceName}`,
        value: 0,
        threshold: 1
      })
    }

    return healthCheck
  }

  /**
   * Get system health overview
   */
  getSystemHealth(): {
    overall: 'healthy' | 'degraded' | 'unhealthy'
    services: HealthCheck[]
    activeAlerts: number
    lastUpdated: Date
  } {
    const services = Array.from(this.healthChecks.values())
    const unhealthyServices = services.filter(s => s.status === 'unhealthy')
    const degradedServices = services.filter(s => s.status === 'degraded')

    let overall: 'healthy' | 'degraded' | 'unhealthy' = 'healthy'
    if (unhealthyServices.length > 0) {
      overall = 'unhealthy'
    } else if (degradedServices.length > 0) {
      overall = 'degraded'
    }

    return {
      overall,
      services,
      activeAlerts: this.alerts.filter(a => !a.resolved).length,
      lastUpdated: new Date()
    }
  }

  /**
   * Create alert
   */
  async createAlert(alertData: {
    type: 'performance' | 'error' | 'security' | 'business'
    severity: 'low' | 'medium' | 'high' | 'critical'
    title: string
    description: string
    metric?: string
    value?: number
    threshold?: number
  }): Promise<Alert> {
    const alert: Alert = {
      id: this.generateAlertId(),
      ...alertData,
      timestamp: new Date(),
      resolved: false
    }

    this.alerts.push(alert)

    // Log alert for audit
    securityLogger.logSecurityEvent(
      'ALERT_CREATED',
      alertData.severity === 'critical' ? 'CRITICAL' : 'HIGH',
      'monitoring',
      {
        resourceId: alert.id,
        newValues: alert,
        severity: alert.severity === 'critical' ? 'critical' : 'high',
        category: 'system'
      }
    )

    // Send notifications based on severity
    await this.sendAlertNotifications(alert)

    logger.warn('Monitoring', `Alert created: ${alert.title}`, alert)
    return alert
  }

  /**
   * Resolve alert
   */
  async resolveAlert(alertId: string, resolvedBy: string): Promise<void> {
    const alert = this.alerts.find(a => a.id === alertId)
    if (alert && !alert.resolved) {
      alert.resolved = true
      alert.resolvedAt = new Date()

      securityLogger.logSecurityEvent(
        'ALERT_RESOLVED',
        'MEDIUM',
        'monitoring',
        {
          userId: resolvedBy,
          resourceId: alertId,
          severity: 'medium',
          category: 'system'
        }
      )

      logger.info('Monitoring', `Alert resolved: ${alert.title}`)
    }
  }

  /**
   * Get performance metrics
   */
  getMetrics(metricName?: string, timeRange?: { start: Date, end: Date }): PerformanceMetric[] {
    if (metricName) {
      const metrics = this.metrics.get(metricName) || []
      if (timeRange) {
        return metrics.filter(m =>
          m.timestamp >= timeRange.start && m.timestamp <= timeRange.end
        )
      }
      return metrics
    }

    // Return all metrics
    const allMetrics: PerformanceMetric[] = []
    this.metrics.forEach(metrics => allMetrics.push(...metrics))

    if (timeRange) {
      return allMetrics.filter(m =>
        m.timestamp >= timeRange.start && m.timestamp <= timeRange.end
      )
    }

    return allMetrics
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return this.alerts.filter(a => !a.resolved)
  }

  /**
   * Get all alerts
   */
  getAllAlerts(): Alert[] {
    return [...this.alerts]
  }

  /**
   * Initialize alert thresholds
   */
  private initializeThresholds(): void {
    this.alertThresholds.set('payment_processing_time', {
      warning: 5000, // 5 seconds
      critical: 10000 // 10 seconds
    })

    this.alertThresholds.set('api_response_time', {
      warning: 1000, // 1 second
      critical: 3000 // 3 seconds
    })

    this.alertThresholds.set('database_query_time', {
      warning: 500, // 500ms
      critical: 2000 // 2 seconds
    })

    this.alertThresholds.set('memory_heap_used', {
      warning: 500 * 1024 * 1024, // 500MB
      critical: 1024 * 1024 * 1024 // 1GB
    })
  }

  /**
   * Start periodic health checks
   */
  private startHealthChecks(): void {
    const services = ['database', 'stripe', 'email', 'storage']

    // Check every 30 seconds
    this.healthCheckInterval = setInterval(async () => {
      for (const service of services) {
        await this.performHealthCheck(service)
      }
      await this.recordMemoryUsage()
    }, 30000)
  }

  /**
   * Stop health checks
   */
  stopHealthChecks(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval)
      this.healthCheckInterval = null
    }
  }

  /**
   * Check metric thresholds
   */
  private async checkThresholds(metric: PerformanceMetric): Promise<void> {
    if (!metric.threshold) return

    if (metric.value >= metric.threshold.critical) {
      await this.createAlert({
        type: 'performance',
        severity: 'critical',
        title: `Critical threshold exceeded: ${metric.name}`,
        description: `${metric.name} is ${metric.value} ${metric.unit}, exceeding critical threshold of ${metric.threshold.critical} ${metric.unit}`,
        metric: metric.name,
        value: metric.value,
        threshold: metric.threshold.critical
      })
    } else if (metric.value >= metric.threshold.warning) {
      await this.createAlert({
        type: 'performance',
        severity: 'medium',
        title: `Warning threshold exceeded: ${metric.name}`,
        description: `${metric.name} is ${metric.value} ${metric.unit}, exceeding warning threshold of ${metric.threshold.warning} ${metric.unit}`,
        metric: metric.name,
        value: metric.value,
        threshold: metric.threshold.warning
      })
    }
  }

  /**
   * Check individual service health
   */
  private async checkServiceHealth(serviceName: string): Promise<{ healthy: boolean, details?: any, error?: string }> {
    switch (serviceName) {
      case 'database':
        return this.checkDatabaseHealth()
      case 'stripe':
        return this.checkStripeHealth()
      case 'email':
        return this.checkEmailHealth()
      case 'storage':
        return this.checkStorageHealth()
      default:
        return { healthy: false, error: 'Unknown service' }
    }
  }

  /**
   * Service-specific health checks
   */
  private async checkDatabaseHealth(): Promise<{ healthy: boolean, details?: any, error?: string }> {
    try {
      // Implementation would check database connectivity
      // For now, return healthy status
      return { healthy: true, details: { connection: 'active' } }
    } catch (error) {
      return { healthy: false, error: error instanceof Error ? error.message : 'Database connection failed' }
    }
  }

  private async checkStripeHealth(): Promise<{ healthy: boolean, details?: any, error?: string }> {
    try {
      // Implementation would check Stripe API connectivity
      // For now, return healthy status
      return { healthy: true, details: { api: 'responsive' } }
    } catch (error) {
      return { healthy: false, error: error instanceof Error ? error.message : 'Stripe API unavailable' }
    }
  }

  private async checkEmailHealth(): Promise<{ healthy: boolean, details?: any, error?: string }> {
    try {
      // Implementation would check email service connectivity
      // For now, return healthy status
      return { healthy: true, details: { smtp: 'connected' } }
    } catch (error) {
      return { healthy: false, error: error instanceof Error ? error.message : 'Email service unavailable' }
    }
  }

  private async checkStorageHealth(): Promise<{ healthy: boolean, details?: any, error?: string }> {
    try {
      // Implementation would check storage system
      // For now, return healthy status
      return { healthy: true, details: { storage: 'available' } }
    } catch (error) {
      return { healthy: false, error: error instanceof Error ? error.message : 'Storage system unavailable' }
    }
  }

  /**
   * Send alert notifications
   */
  private async sendAlertNotifications(alert: Alert): Promise<void> {
    if (alert.severity === 'critical') {
      // Send immediate notifications (email, SMS, Slack, etc.)
      logger.error('Monitoring', `CRITICAL ALERT: ${alert.title}`, alert)
    }
  }

  /**
   * Helper methods
   */
  private generateMetricId(): string {
    return `metric_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private getQueryType(query: string): string {
    const lowerQuery = query.toLowerCase().trim()
    if (lowerQuery.startsWith('select')) return 'select'
    if (lowerQuery.startsWith('insert')) return 'insert'
    if (lowerQuery.startsWith('update')) return 'update'
    if (lowerQuery.startsWith('delete')) return 'delete'
    return 'other'
  }

  private async storeMetric(metric: PerformanceMetric): Promise<void> {
    // Implementation would store metric in time-series database
    // For now, just log the metric storage
    logger.debug('Monitoring', 'Metric stored', { metricId: metric.id, name: metric.name })
  }
}

export const monitoringService = new MonitoringService()
