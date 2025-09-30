/**
 * Enhanced Connection Manager for Multi-Tiered Resilience
 * Implements connection pooling, circuit breakers, and auto-recovery
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'

export interface ConnectionConfig {
  maxConnections: number
  connectionTimeout: number
  retryAttempts: number
  retryDelay: number
  healthCheckInterval: number
  circuitBreakerThreshold: number
  circuitBreakerTimeout: number
}

export interface ConnectionHealth {
  isHealthy: boolean
  lastCheck: Date
  responseTime: number
  errorCount: number
  consecutiveFailures: number
}

export interface CircuitBreakerState {
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN'
  failureCount: number
  lastFailureTime: number
  nextAttemptTime: number
}

export class ConnectionManager extends EventEmitter {
  private config: ConnectionConfig
  private connections: Map<string, any> = new Map()
  private healthStatus: Map<string, ConnectionHealth> = new Map()
  private circuitBreakers: Map<string, CircuitBreakerState> = new Map()
  private healthCheckInterval: NodeJS.Timeout | null = null
  private isShuttingDown = false

  constructor(config: Partial<ConnectionConfig> = {}) {
    super()
    this.config = {
      maxConnections: 20,
      connectionTimeout: 30000,
      retryAttempts: 5,
      retryDelay: 1000,
      healthCheckInterval: 10000,
      circuitBreakerThreshold: 5,
      circuitBreakerTimeout: 60000,
      ...config,
    }

    this.startHealthChecks()
    logger.info('ConnectionManager', 'Enhanced connection manager initialized', this.config)
  }

  /**
   * Get or create a connection with circuit breaker protection
   */
  async getConnection(
    connectionId: string,
    factory: () => Promise<any>,
    healthCheck?: (connection: any) => Promise<boolean>
  ): Promise<any> {
    // Check circuit breaker
    if (!this.isCircuitClosed(connectionId)) {
      throw new Error(`Circuit breaker is open for connection: ${connectionId}`)
    }

    let connection = this.connections.get(connectionId)

    if (!connection || !(await this.isConnectionHealthy(connection, healthCheck))) {
      connection = await this.createConnection(connectionId, factory)
    }

    return connection
  }

  /**
   * Create a new connection with retry logic
   */
  private async createConnection(connectionId: string, factory: () => Promise<any>): Promise<any> {
    let lastError: Error | null = null

    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        logger.debug('ConnectionManager', `Creating connection ${connectionId} (attempt ${attempt})`)

        const connection = await Promise.race([
          factory(),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Connection timeout')), this.config.connectionTimeout)
          ),
        ])

        this.connections.set(connectionId, connection)
        this.updateHealthStatus(connectionId, true, 0)
        this.resetCircuitBreaker(connectionId)

        logger.info('ConnectionManager', `Connection ${connectionId} created successfully`)
        this.emit('connectionCreated', { connectionId, attempt })

        return connection
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error))
        this.recordFailure(connectionId)

        logger.warn('ConnectionManager', `Connection ${connectionId} failed (attempt ${attempt})`, {
          error: lastError.message,
          attempt,
          maxAttempts: this.config.retryAttempts,
        })

        if (attempt < this.config.retryAttempts) {
          const delay = this.config.retryDelay * Math.pow(2, attempt - 1)
          await this.sleep(delay)
        }
      }
    }

    this.openCircuitBreaker(connectionId)
    throw new Error(`Failed to create connection ${connectionId} after ${this.config.retryAttempts} attempts: ${lastError?.message}`)
  }

  /**
   * Check if connection is healthy
   */
  private async isConnectionHealthy(
    connection: any,
    healthCheck?: (connection: any) => Promise<boolean>
  ): Promise<boolean> {
    if (!connection) return false

    try {
      if (healthCheck) {
        return await healthCheck(connection)
      }

      // Default health check - check if connection is still valid
      return connection && typeof connection === 'object'
    } catch (error) {
      logger.debug('ConnectionManager', 'Connection health check failed', error)
      return false
    }
  }

  /**
   * Circuit breaker management
   */
  private isCircuitClosed(connectionId: string): boolean {
    const breaker = this.circuitBreakers.get(connectionId)
    if (!breaker) return true

    const now = Date.now()

    switch (breaker.state) {
      case 'CLOSED':
        return true
      case 'OPEN':
        if (now >= breaker.nextAttemptTime) {
          breaker.state = 'HALF_OPEN'
          logger.info('ConnectionManager', `Circuit breaker ${connectionId} moved to HALF_OPEN`)
          return true
        }
        return false
      case 'HALF_OPEN':
        return true
      default:
        return true
    }
  }

  private recordFailure(connectionId: string): void {
    const health = this.healthStatus.get(connectionId) || {
      isHealthy: false,
      lastCheck: new Date(),
      responseTime: 0,
      errorCount: 0,
      consecutiveFailures: 0,
    }

    health.errorCount++
    health.consecutiveFailures++
    health.isHealthy = false
    this.healthStatus.set(connectionId, health)

    const breaker = this.circuitBreakers.get(connectionId) || {
      state: 'CLOSED' as const,
      failureCount: 0,
      lastFailureTime: 0,
      nextAttemptTime: 0,
    }

    breaker.failureCount++
    breaker.lastFailureTime = Date.now()

    if (breaker.failureCount >= this.config.circuitBreakerThreshold) {
      this.openCircuitBreaker(connectionId)
    }

    this.circuitBreakers.set(connectionId, breaker)
  }

  private openCircuitBreaker(connectionId: string): void {
    const breaker = this.circuitBreakers.get(connectionId) || {
      state: 'CLOSED' as const,
      failureCount: 0,
      lastFailureTime: Date.now(),
      nextAttemptTime: 0,
    }

    breaker.state = 'OPEN'
    breaker.nextAttemptTime = Date.now() + this.config.circuitBreakerTimeout

    this.circuitBreakers.set(connectionId, breaker)
    logger.warn('ConnectionManager', `Circuit breaker opened for ${connectionId}`, {
      failureCount: breaker.failureCount,
      nextAttemptTime: new Date(breaker.nextAttemptTime),
    })

    this.emit('circuitBreakerOpened', { connectionId, breaker })
  }

  private resetCircuitBreaker(connectionId: string): void {
    const breaker = this.circuitBreakers.get(connectionId)
    if (breaker) {
      breaker.state = 'CLOSED'
      breaker.failureCount = 0
      this.circuitBreakers.set(connectionId, breaker)
    }
  }

  private updateHealthStatus(connectionId: string, isHealthy: boolean, responseTime: number): void {
    const health = this.healthStatus.get(connectionId) || {
      isHealthy: false,
      lastCheck: new Date(),
      responseTime: 0,
      errorCount: 0,
      consecutiveFailures: 0,
    }

    health.isHealthy = isHealthy
    health.lastCheck = new Date()
    health.responseTime = responseTime

    if (isHealthy) {
      health.consecutiveFailures = 0
    }

    this.healthStatus.set(connectionId, health)
  }

  /**
   * Start periodic health checks
   */
  private startHealthChecks(): void {
    this.healthCheckInterval = setInterval(async () => {
      if (this.isShuttingDown) return

      for (const [connectionId, connection] of this.connections.entries()) {
        try {
          const startTime = Date.now()
          const isHealthy = await this.isConnectionHealthy(connection)
          const responseTime = Date.now() - startTime

          this.updateHealthStatus(connectionId, isHealthy, responseTime)

          if (!isHealthy) {
            logger.warn('ConnectionManager', `Connection ${connectionId} failed health check`)
            this.connections.delete(connectionId)
            this.recordFailure(connectionId)
          }
        } catch (error) {
          logger.error('ConnectionManager', `Health check error for ${connectionId}`, error)
          this.recordFailure(connectionId)
        }
      }
    }, this.config.healthCheckInterval)
  }

  /**
   * Get system status
   */
  getStatus(): {
    totalConnections: number
    healthyConnections: number
    circuitBreakers: Record<string, CircuitBreakerState>
    healthStatus: Record<string, ConnectionHealth>
  } {
    const healthyConnections = Array.from(this.healthStatus.values()).filter(h => h.isHealthy).length

    return {
      totalConnections: this.connections.size,
      healthyConnections,
      circuitBreakers: Object.fromEntries(this.circuitBreakers),
      healthStatus: Object.fromEntries(this.healthStatus),
    }
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval)
      this.healthCheckInterval = null
    }

    // Close all connections
    for (const [connectionId, connection] of this.connections.entries()) {
      try {
        if (connection && typeof connection.close === 'function') {
          await connection.close()
        }
        logger.debug('ConnectionManager', `Connection ${connectionId} closed`)
      } catch (error) {
        logger.warn('ConnectionManager', `Error closing connection ${connectionId}`, error)
      }
    }

    this.connections.clear()
    this.healthStatus.clear()
    this.circuitBreakers.clear()

    logger.info('ConnectionManager', 'Connection manager shutdown complete')
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

// Global connection manager instance
export const connectionManager = new ConnectionManager()
