/**
 * Auto-Recovery Service
 * Implements self-healing capabilities and automatic service recovery
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'
import { healthMonitor, HealthAlert } from './healthMonitor'
import { connectionManager } from './connectionManager'

export interface RecoveryAction {
  name: string
  description: string
  execute: () => Promise<boolean>
  rollback?: () => Promise<void>
  timeout: number
  retries: number
}

export interface RecoveryPlan {
  serviceName: string
  actions: RecoveryAction[]
  maxExecutionTime: number
  cooldownPeriod: number
}

export interface RecoveryExecution {
  id: string
  serviceName: string
  startTime: Date
  endTime?: Date
  status: 'running' | 'success' | 'failed' | 'timeout'
  executedActions: string[]
  error?: string
}

export class AutoRecoveryService extends EventEmitter {
  private recoveryPlans: Map<string, RecoveryPlan> = new Map()
  private activeRecoveries: Map<string, RecoveryExecution> = new Map()
  private recoveryHistory: RecoveryExecution[] = []
  private cooldownTimers: Map<string, NodeJS.Timeout> = new Map()
  private isEnabled = true

  constructor() {
    super()
    this.setupEventListeners()
    this.registerDefaultRecoveryPlans()
    logger.info('AutoRecoveryService', 'Auto-recovery service initialized')
  }

  /**
   * Setup event listeners for health monitoring
   */
  private setupEventListeners(): void {
    healthMonitor.on('alertCreated', ({ alert }: { alert: HealthAlert }) => {
      if (alert.severity === 'critical' && this.isEnabled) {
        this.triggerRecovery(alert.serviceName, `Critical alert: ${alert.message}`)
      }
    })

    healthMonitor.on('serviceRecovered', ({ serviceName }: { serviceName: string }) => {
      this.onServiceRecovered(serviceName)
    })

    connectionManager.on('circuitBreakerOpened', ({ connectionId }: { connectionId: string }) => {
      this.triggerRecovery(connectionId, 'Circuit breaker opened')
    })
  }

  /**
   * Register default recovery plans for common services
   */
  private registerDefaultRecoveryPlans(): void {
    // Database recovery plan
    this.registerRecoveryPlan('database', {
      serviceName: 'database',
      maxExecutionTime: 300000, // 5 minutes
      cooldownPeriod: 60000, // 1 minute
      actions: [
        {
          name: 'validateConnection',
          description: 'Validate database connection',
          execute: async () => {
            try {
              const { checkDatabaseConnection } = await import('@/lib/database')
              const result = await checkDatabaseConnection()
              return result.connected
            } catch (error) {
              logger.error('AutoRecovery', 'Database validation failed', error)
              return false
            }
          },
          timeout: 10000,
          retries: 3,
        },
        {
          name: 'recreateConnectionPool',
          description: 'Recreate database connection pool',
          execute: async () => {
            try {
              // Force recreation of database connection
              const { getDatabaseInstance } = await import('@/lib/database-factory')
              await getDatabaseInstance()
              return true
            } catch (error) {
              logger.error('AutoRecovery', 'Connection pool recreation failed', error)
              return false
            }
          },
          timeout: 30000,
          retries: 2,
        },
        {
          name: 'clearConnectionCache',
          description: 'Clear connection cache and reset pools',
          execute: async () => {
            try {
              // Clear any cached connections
              connectionManager.emit('clearCache')
              return true
            } catch (error) {
              logger.error('AutoRecovery', 'Connection cache clear failed', error)
              return false
            }
          },
          timeout: 5000,
          retries: 1,
        },
      ],
    })

    // Streaming service recovery plan
    this.registerRecoveryPlan('streamingService', {
      serviceName: 'streamingService',
      maxExecutionTime: 180000, // 3 minutes
      cooldownPeriod: 30000, // 30 seconds
      actions: [
        {
          name: 'restartStreamingService',
          description: 'Restart streaming search service',
          execute: async () => {
            try {
              const { streamingSearchService } = await import('@/lib/streamingSearchService')
              await streamingSearchService.restart()
              return true
            } catch (error) {
              logger.error('AutoRecovery', 'Streaming service restart failed', error)
              return false
            }
          },
          timeout: 60000,
          retries: 2,
        },
        {
          name: 'clearActiveStreams',
          description: 'Clear all active streaming connections',
          execute: async () => {
            try {
              const { streamingSearchService } = await import('@/lib/streamingSearchService')
              streamingSearchService.stopAllStreams()
              return true
            } catch (error) {
              logger.error('AutoRecovery', 'Stream clearing failed', error)
              return false
            }
          },
          timeout: 10000,
          retries: 1,
        },
      ],
    })

    // WebSocket server recovery plan
    this.registerRecoveryPlan('websocket', {
      serviceName: 'websocket',
      maxExecutionTime: 120000, // 2 minutes
      cooldownPeriod: 30000, // 30 seconds
      actions: [
        {
          name: 'restartWebSocketServer',
          description: 'Restart WebSocket server',
          execute: async () => {
            try {
              const { webSocketServer } = await import('@/lib/websocket-server')
              await webSocketServer.stop()
              await webSocketServer.start()
              return true
            } catch (error) {
              logger.error('AutoRecovery', 'WebSocket server restart failed', error)
              return false
            }
          },
          timeout: 60000,
          retries: 2,
        },
      ],
    })

    // Memory cleanup recovery plan
    this.registerRecoveryPlan('memory', {
      serviceName: 'memory',
      maxExecutionTime: 60000, // 1 minute
      cooldownPeriod: 120000, // 2 minutes
      actions: [
        {
          name: 'forceGarbageCollection',
          description: 'Force garbage collection',
          execute: async () => {
            try {
              if (global.gc) {
                global.gc()
                logger.info('AutoRecovery', 'Forced garbage collection')
                return true
              }
              return false
            } catch (error) {
              logger.error('AutoRecovery', 'Garbage collection failed', error)
              return false
            }
          },
          timeout: 5000,
          retries: 1,
        },
        {
          name: 'clearCaches',
          description: 'Clear application caches',
          execute: async () => {
            try {
              const { cacheService } = await import('@/lib/cache')
              await cacheService.clear()
              return true
            } catch (error) {
              logger.error('AutoRecovery', 'Cache clearing failed', error)
              return false
            }
          },
          timeout: 10000,
          retries: 1,
        },
      ],
    })
  }

  /**
   * Register a recovery plan for a service
   */
  registerRecoveryPlan(serviceName: string, plan: RecoveryPlan): void {
    this.recoveryPlans.set(serviceName, plan)
    logger.info('AutoRecovery', `Recovery plan registered for service: ${serviceName}`)
  }

  /**
   * Trigger recovery for a service
   */
  async triggerRecovery(serviceName: string, reason: string): Promise<boolean> {
    // Check if service is in cooldown
    if (this.cooldownTimers.has(serviceName)) {
      logger.info('AutoRecovery', `Service ${serviceName} is in cooldown, skipping recovery`)
      return false
    }

    // Check if recovery is already running
    if (this.activeRecoveries.has(serviceName)) {
      logger.info('AutoRecovery', `Recovery already running for service: ${serviceName}`)
      return false
    }

    const plan = this.recoveryPlans.get(serviceName)
    if (!plan) {
      logger.warn('AutoRecovery', `No recovery plan found for service: ${serviceName}`)
      return false
    }

    const executionId = `recovery_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    const execution: RecoveryExecution = {
      id: executionId,
      serviceName,
      startTime: new Date(),
      status: 'running',
      executedActions: [],
    }

    this.activeRecoveries.set(serviceName, execution)
    logger.info('AutoRecovery', `Starting recovery for service ${serviceName}`, {
      executionId,
      reason,
      planActions: plan.actions.length,
    })

    this.emit('recoveryStarted', { serviceName, executionId, reason })

    try {
      const success = await this.executeRecoveryPlan(plan, execution)
      
      execution.endTime = new Date()
      execution.status = success ? 'success' : 'failed'
      
      if (success) {
        logger.info('AutoRecovery', `Recovery completed successfully for service: ${serviceName}`)
        this.emit('recoveryCompleted', { serviceName, executionId, success: true })
      } else {
        logger.error('AutoRecovery', `Recovery failed for service: ${serviceName}`)
        this.emit('recoveryCompleted', { serviceName, executionId, success: false })
      }

      // Start cooldown period
      this.startCooldown(serviceName, plan.cooldownPeriod)
      
      return success
    } catch (error) {
      execution.endTime = new Date()
      execution.status = 'failed'
      execution.error = error instanceof Error ? error.message : String(error)
      
      logger.error('AutoRecovery', `Recovery execution failed for service: ${serviceName}`, error)
      this.emit('recoveryFailed', { serviceName, executionId, error })
      
      this.startCooldown(serviceName, plan.cooldownPeriod)
      return false
    } finally {
      this.activeRecoveries.delete(serviceName)
      this.recoveryHistory.push(execution)
      
      // Keep only last 100 recovery executions
      if (this.recoveryHistory.length > 100) {
        this.recoveryHistory = this.recoveryHistory.slice(-100)
      }
    }
  }

  /**
   * Execute recovery plan actions
   */
  private async executeRecoveryPlan(plan: RecoveryPlan, execution: RecoveryExecution): Promise<boolean> {
    const startTime = Date.now()
    
    for (const action of plan.actions) {
      // Check if we've exceeded max execution time
      if (Date.now() - startTime > plan.maxExecutionTime) {
        execution.status = 'timeout'
        logger.warn('AutoRecovery', `Recovery plan timed out for service: ${plan.serviceName}`)
        return false
      }

      logger.info('AutoRecovery', `Executing recovery action: ${action.name}`, {
        serviceName: plan.serviceName,
        description: action.description,
      })

      const actionSuccess = await this.executeRecoveryAction(action)
      execution.executedActions.push(action.name)

      if (!actionSuccess) {
        logger.error('AutoRecovery', `Recovery action failed: ${action.name}`)
        return false
      }

      logger.info('AutoRecovery', `Recovery action completed: ${action.name}`)
    }

    return true
  }

  /**
   * Execute a single recovery action with retries
   */
  private async executeRecoveryAction(action: RecoveryAction): Promise<boolean> {
    for (let attempt = 1; attempt <= action.retries; attempt++) {
      try {
        const result = await Promise.race([
          action.execute(),
          new Promise<boolean>((_, reject) =>
            setTimeout(() => reject(new Error('Action timeout')), action.timeout)
          ),
        ])

        if (result) {
          return true
        }
      } catch (error) {
        logger.warn('AutoRecovery', `Recovery action attempt ${attempt} failed: ${action.name}`, error)
        
        if (attempt < action.retries) {
          await this.sleep(1000 * attempt) // Progressive delay
        }
      }
    }

    return false
  }

  /**
   * Start cooldown period for a service
   */
  private startCooldown(serviceName: string, cooldownPeriod: number): void {
    const timer = setTimeout(() => {
      this.cooldownTimers.delete(serviceName)
      logger.info('AutoRecovery', `Cooldown period ended for service: ${serviceName}`)
    }, cooldownPeriod)

    this.cooldownTimers.set(serviceName, timer)
    logger.info('AutoRecovery', `Started cooldown period for service: ${serviceName}`, {
      cooldownMs: cooldownPeriod,
    })
  }

  /**
   * Handle service recovery event
   */
  private onServiceRecovered(serviceName: string): void {
    // Clear cooldown if service has recovered
    const timer = this.cooldownTimers.get(serviceName)
    if (timer) {
      clearTimeout(timer)
      this.cooldownTimers.delete(serviceName)
      logger.info('AutoRecovery', `Cooldown cleared for recovered service: ${serviceName}`)
    }
  }

  /**
   * Get recovery status
   */
  getRecoveryStatus(): {
    isEnabled: boolean
    activeRecoveries: RecoveryExecution[]
    recentHistory: RecoveryExecution[]
    registeredPlans: string[]
    servicesInCooldown: string[]
  } {
    return {
      isEnabled: this.isEnabled,
      activeRecoveries: Array.from(this.activeRecoveries.values()),
      recentHistory: this.recoveryHistory.slice(-10),
      registeredPlans: Array.from(this.recoveryPlans.keys()),
      servicesInCooldown: Array.from(this.cooldownTimers.keys()),
    }
  }

  /**
   * Enable/disable auto-recovery
   */
  setEnabled(enabled: boolean): void {
    this.isEnabled = enabled
    logger.info('AutoRecovery', `Auto-recovery ${enabled ? 'enabled' : 'disabled'}`)
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

// Global auto-recovery service instance
export const autoRecoveryService = new AutoRecoveryService()
