/**
 * Enhanced Health Monitoring Service
 * Provides real-time health monitoring, alerting, and auto-recovery
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'
import { connectionManager } from './connectionManager'

export interface HealthCheckConfig {
  interval: number
  timeout: number
  retries: number
  alertThreshold: number
  recoveryThreshold: number
}

export interface ServiceHealth {
  serviceName: string
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown'
  lastCheck: Date
  responseTime: number
  uptime: number
  errorRate: number
  consecutiveFailures: number
  metadata?: Record<string, any>
}

export interface HealthAlert {
  id: string
  serviceName: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  message: string
  timestamp: Date
  resolved: boolean
  resolvedAt?: Date
}

export class HealthMonitor extends EventEmitter {
  private config: HealthCheckConfig
  private services: Map<string, ServiceHealth> = new Map()
  private alerts: Map<string, HealthAlert> = new Map()
  private healthChecks: Map<string, () => Promise<boolean>> = new Map()
  private monitoringInterval: NodeJS.Timeout | null = null
  private isRunning = false

  constructor(config: Partial<HealthCheckConfig> = {}) {
    super()
    this.config = {
      interval: 10000, // 10 seconds
      timeout: 5000, // 5 seconds
      retries: 3,
      alertThreshold: 3, // consecutive failures before alert
      recoveryThreshold: 2, // consecutive successes before recovery
      ...config,
    }

    logger.info('HealthMonitor', 'Enhanced health monitor initialized', this.config)
  }

  /**
   * Register a service for health monitoring
   */
  registerService(
    serviceName: string,
    healthCheck: () => Promise<boolean>,
    metadata?: Record<string, any>
  ): void {
    this.healthChecks.set(serviceName, healthCheck)
    this.services.set(serviceName, {
      serviceName,
      status: 'unknown',
      lastCheck: new Date(),
      responseTime: 0,
      uptime: 0,
      errorRate: 0,
      consecutiveFailures: 0,
      metadata,
    })

    logger.info('HealthMonitor', `Service ${serviceName} registered for health monitoring`)
  }

  /**
   * Start health monitoring
   */
  start(): void {
    if (this.isRunning) {
      logger.warn('HealthMonitor', 'Health monitoring already running')
      return
    }

    this.isRunning = true
    this.monitoringInterval = setInterval(() => {
      this.performHealthChecks()
    }, this.config.interval)

    // Perform initial health check
    this.performHealthChecks()

    logger.info('HealthMonitor', 'Health monitoring started')
    this.emit('monitoringStarted')
  }

  /**
   * Stop health monitoring
   */
  stop(): void {
    if (!this.isRunning) return

    this.isRunning = false
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval)
      this.monitoringInterval = null
    }

    logger.info('HealthMonitor', 'Health monitoring stopped')
    this.emit('monitoringStopped')
  }

  /**
   * Perform health checks for all registered services
   */
  private async performHealthChecks(): Promise<void> {
    const promises = Array.from(this.healthChecks.entries()).map(([serviceName, healthCheck]) =>
      this.checkServiceHealth(serviceName, healthCheck)
    )

    await Promise.allSettled(promises)
    this.evaluateSystemHealth()
  }

  /**
   * Check health of a specific service
   */
  private async checkServiceHealth(
    serviceName: string,
    healthCheck: () => Promise<boolean>
  ): Promise<void> {
    const service = this.services.get(serviceName)
    if (!service) return

    const startTime = Date.now()
    let isHealthy = false
    let error: Error | null = null

    try {
      // Perform health check with timeout and retries
      isHealthy = await this.executeHealthCheckWithRetries(healthCheck)
      service.responseTime = Date.now() - startTime
    } catch (err) {
      error = err instanceof Error ? err : new Error(String(err))
      service.responseTime = Date.now() - startTime
    }

    // Update service health status
    this.updateServiceHealth(serviceName, isHealthy, error)
  }

  /**
   * Execute health check with retries and timeout
   */
  private async executeHealthCheckWithRetries(healthCheck: () => Promise<boolean>): Promise<boolean> {
    let lastError: Error | null = null

    for (let attempt = 1; attempt <= this.config.retries; attempt++) {
      try {
        const result = await Promise.race([
          healthCheck(),
          new Promise<boolean>((_, reject) =>
            setTimeout(() => reject(new Error('Health check timeout')), this.config.timeout)
          ),
        ])

        return result
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error))
        
        if (attempt < this.config.retries) {
          await this.sleep(1000 * attempt) // Progressive delay
        }
      }
    }

    throw lastError || new Error('Health check failed after retries')
  }

  /**
   * Update service health status and handle alerts
   */
  private updateServiceHealth(serviceName: string, isHealthy: boolean, error: Error | null): void {
    const service = this.services.get(serviceName)
    if (!service) return

    service.lastCheck = new Date()

    if (isHealthy) {
      // Service is healthy
      if (service.status !== 'healthy') {
        service.consecutiveFailures = 0
        
        // Check if service has recovered
        if (service.status === 'unhealthy' || service.status === 'degraded') {
          this.handleServiceRecovery(serviceName)
        }
        
        service.status = 'healthy'
        logger.info('HealthMonitor', `Service ${serviceName} is healthy`, {
          responseTime: service.responseTime,
        })
      }
    } else {
      // Service is unhealthy
      service.consecutiveFailures++
      
      const previousStatus = service.status
      
      if (service.consecutiveFailures >= this.config.alertThreshold) {
        service.status = 'unhealthy'
      } else if (service.consecutiveFailures > 1) {
        service.status = 'degraded'
      }

      // Create alert if status changed to unhealthy
      if (previousStatus !== 'unhealthy' && service.status === 'unhealthy') {
        this.createAlert(serviceName, 'critical', `Service ${serviceName} is unhealthy`, error)
      } else if (previousStatus !== 'degraded' && service.status === 'degraded') {
        this.createAlert(serviceName, 'medium', `Service ${serviceName} is degraded`, error)
      }

      logger.warn('HealthMonitor', `Service ${serviceName} health check failed`, {
        consecutiveFailures: service.consecutiveFailures,
        status: service.status,
        error: error?.message,
      })
    }

    this.services.set(serviceName, service)
    this.emit('serviceHealthUpdated', { serviceName, service })
  }

  /**
   * Handle service recovery
   */
  private handleServiceRecovery(serviceName: string): void {
    // Resolve any active alerts for this service
    for (const [alertId, alert] of this.alerts.entries()) {
      if (alert.serviceName === serviceName && !alert.resolved) {
        alert.resolved = true
        alert.resolvedAt = new Date()
        this.alerts.set(alertId, alert)
        
        logger.info('HealthMonitor', `Alert resolved for service ${serviceName}`, { alertId })
        this.emit('alertResolved', { alertId, alert })
      }
    }

    logger.info('HealthMonitor', `Service ${serviceName} has recovered`)
    this.emit('serviceRecovered', { serviceName })
  }

  /**
   * Create health alert
   */
  private createAlert(
    serviceName: string,
    severity: 'critical' | 'high' | 'medium' | 'low',
    message: string,
    error?: Error | null
  ): void {
    const alertId = `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    
    const alert: HealthAlert = {
      id: alertId,
      serviceName,
      severity,
      message: error ? `${message}: ${error.message}` : message,
      timestamp: new Date(),
      resolved: false,
    }

    this.alerts.set(alertId, alert)
    
    logger.error('HealthMonitor', `Health alert created: ${message}`, {
      alertId,
      serviceName,
      severity,
      error: error?.message,
    })

    this.emit('alertCreated', { alertId, alert })
  }

  /**
   * Evaluate overall system health
   */
  private evaluateSystemHealth(): void {
    const services = Array.from(this.services.values())
    const healthyCount = services.filter(s => s.status === 'healthy').length
    const degradedCount = services.filter(s => s.status === 'degraded').length
    const unhealthyCount = services.filter(s => s.status === 'unhealthy').length

    let systemStatus: 'healthy' | 'degraded' | 'unhealthy'
    
    if (unhealthyCount > 0) {
      systemStatus = 'unhealthy'
    } else if (degradedCount > 0) {
      systemStatus = 'degraded'
    } else {
      systemStatus = 'healthy'
    }

    this.emit('systemHealthEvaluated', {
      status: systemStatus,
      totalServices: services.length,
      healthyCount,
      degradedCount,
      unhealthyCount,
    })
  }

  /**
   * Get current health status
   */
  getHealthStatus(): {
    systemStatus: 'healthy' | 'degraded' | 'unhealthy'
    services: ServiceHealth[]
    activeAlerts: HealthAlert[]
    connectionManagerStatus: any
  } {
    const services = Array.from(this.services.values())
    const activeAlerts = Array.from(this.alerts.values()).filter(a => !a.resolved)
    
    const unhealthyCount = services.filter(s => s.status === 'unhealthy').length
    const degradedCount = services.filter(s => s.status === 'degraded').length
    
    let systemStatus: 'healthy' | 'degraded' | 'unhealthy'
    if (unhealthyCount > 0) {
      systemStatus = 'unhealthy'
    } else if (degradedCount > 0) {
      systemStatus = 'degraded'
    } else {
      systemStatus = 'healthy'
    }

    return {
      systemStatus,
      services,
      activeAlerts,
      connectionManagerStatus: connectionManager.getStatus(),
    }
  }

  /**
   * Get service health by name
   */
  getServiceHealth(serviceName: string): ServiceHealth | null {
    return this.services.get(serviceName) || null
  }

  /**
   * Get all alerts
   */
  getAllAlerts(): HealthAlert[] {
    return Array.from(this.alerts.values())
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): HealthAlert[] {
    return Array.from(this.alerts.values()).filter(a => !a.resolved)
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

// Global health monitor instance
export const healthMonitor = new HealthMonitor()
