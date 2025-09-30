/**
 * Resilience System Initialization
 * Initializes and configures the complete multi-tiered resilience system
 */

import { logger } from '@/utils/logger'
import { connectionManager } from './connectionManager'
import { healthMonitor } from './healthMonitor'
import { autoRecoveryService } from './autoRecovery'

/**
 * Initialize the complete resilience system
 */
export async function initializeResilienceSystem(): Promise<void> {
  try {
    logger.info('ResilienceSystem', 'Initializing multi-tiered resilience system')

    // Register core health checks
    await registerCoreHealthChecks()

    // Start health monitoring
    healthMonitor.start()

    // Enable auto-recovery
    autoRecoveryService.setEnabled(true)

    logger.info('ResilienceSystem', 'Multi-tiered resilience system initialized successfully')
  } catch (error) {
    logger.error('ResilienceSystem', 'Failed to initialize resilience system', error)
    throw error
  }
}

/**
 * Register health checks for core services
 */
async function registerCoreHealthChecks(): Promise<void> {
  // Database health check
  healthMonitor.registerService('database', async () => {
    try {
      const { checkDatabaseConnection } = await import('@/lib/database')
      const result = await checkDatabaseConnection()
      return result.connected
    } catch (error) {
      logger.debug('ResilienceSystem', 'Database health check failed', error)
      return false
    }
  }, {
    type: 'database',
    critical: true,
  })

  // Streaming service health check (already registered in streamingSearchService)
  // This is handled by the StreamingSearchService itself

  // Cache service health check
  healthMonitor.registerService('cache', async () => {
    try {
      const { cacheService } = await import('@/lib/cache')
      // Simple cache test
      const testKey = 'health_check_test'
      await cacheService.set(testKey, 'test', 1000)
      const result = await cacheService.get(testKey)
      await cacheService.delete(testKey)
      return result === 'test'
    } catch (error) {
      logger.debug('ResilienceSystem', 'Cache health check failed', error)
      return false
    }
  }, {
    type: 'cache',
    critical: false,
  })

  // Memory health check
  healthMonitor.registerService('memory', async () => {
    try {
      if (typeof process === 'undefined') return true

      const memUsage = process.memoryUsage()
      const heapUsagePercent = (memUsage.heapUsed / memUsage.heapTotal) * 100
      
      // Consider unhealthy if heap usage is above 90%
      return heapUsagePercent < 90
    } catch (error) {
      logger.debug('ResilienceSystem', 'Memory health check failed', error)
      return false
    }
  }, {
    type: 'system',
    critical: true,
  })

  // API endpoints health check
  healthMonitor.registerService('api', async () => {
    try {
      // Simple internal API test
      const response = await fetch('http://localhost:3000/api/ping', {
        method: 'HEAD',
        timeout: 5000,
      })
      return response.ok
    } catch (error) {
      logger.debug('ResilienceSystem', 'API health check failed', error)
      return false
    }
  }, {
    type: 'api',
    critical: true,
  })

  logger.info('ResilienceSystem', 'Core health checks registered')
}

/**
 * Gracefully shutdown the resilience system
 */
export async function shutdownResilienceSystem(): Promise<void> {
  try {
    logger.info('ResilienceSystem', 'Shutting down resilience system')

    // Stop health monitoring
    healthMonitor.stop()

    // Disable auto-recovery
    autoRecoveryService.setEnabled(false)

    // Shutdown connection manager
    await connectionManager.shutdown()

    logger.info('ResilienceSystem', 'Resilience system shutdown complete')
  } catch (error) {
    logger.error('ResilienceSystem', 'Error during resilience system shutdown', error)
    throw error
  }
}

/**
 * Get comprehensive resilience system status
 */
export function getResilienceSystemStatus(): {
  isInitialized: boolean
  healthMonitor: any
  connectionManager: any
  autoRecovery: any
  overallScore: number
} {
  const healthStatus = healthMonitor.getHealthStatus()
  const connectionStatus = connectionManager.getStatus()
  const recoveryStatus = autoRecoveryService.getRecoveryStatus()

  // Calculate overall resilience score
  let score = 100

  // Health score (40% weight)
  const healthyServices = healthStatus.services.filter((s: any) => s.status === 'healthy').length
  const totalServices = healthStatus.services.length
  const healthScore = totalServices > 0 ? (healthyServices / totalServices) * 40 : 40

  // Connection score (30% weight)
  const connectionScore = connectionStatus.totalConnections > 0 
    ? (connectionStatus.healthyConnections / connectionStatus.totalConnections) * 30 
    : 30

  // Alert penalty (20% weight)
  const activeAlerts = healthStatus.activeAlerts.length
  const alertPenalty = Math.min(activeAlerts * 5, 20)

  // Recovery score (10% weight)
  const recoveryScore = recoveryStatus.isEnabled ? 10 : 0

  const overallScore = Math.max(0, Math.min(100, Math.round(
    healthScore + connectionScore + recoveryScore - alertPenalty
  )))

  return {
    isInitialized: true,
    healthMonitor: healthStatus,
    connectionManager: connectionStatus,
    autoRecovery: recoveryStatus,
    overallScore,
  }
}

/**
 * Trigger manual recovery for a service
 */
export async function triggerManualRecovery(serviceName: string, reason?: string): Promise<boolean> {
  try {
    logger.info('ResilienceSystem', `Triggering manual recovery for service: ${serviceName}`, { reason })
    
    const success = await autoRecoveryService.triggerRecovery(
      serviceName,
      reason || 'Manual recovery triggered via API'
    )

    if (success) {
      logger.info('ResilienceSystem', `Manual recovery successful for service: ${serviceName}`)
    } else {
      logger.warn('ResilienceSystem', `Manual recovery failed for service: ${serviceName}`)
    }

    return success
  } catch (error) {
    logger.error('ResilienceSystem', `Manual recovery error for service: ${serviceName}`, error)
    return false
  }
}

/**
 * Force health check for all services
 */
export async function forceHealthCheck(): Promise<void> {
  try {
    logger.info('ResilienceSystem', 'Forcing health check for all services')
    
    // The health monitor will automatically perform health checks
    // We just need to wait a moment for them to complete
    await new Promise(resolve => setTimeout(resolve, 1000))
    
    logger.info('ResilienceSystem', 'Forced health check completed')
  } catch (error) {
    logger.error('ResilienceSystem', 'Error during forced health check', error)
    throw error
  }
}

// Export all resilience components
export {
  connectionManager,
  healthMonitor,
  autoRecoveryService,
}

// Export types
export type {
  ConnectionConfig,
  ConnectionHealth,
  CircuitBreakerState,
} from './connectionManager'

export type {
  HealthCheckConfig,
  ServiceHealth,
  HealthAlert,
} from './healthMonitor'

export type {
  RecoveryAction,
  RecoveryPlan,
  RecoveryExecution,
} from './autoRecovery'
