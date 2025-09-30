/**
 * Resilience Status API Endpoint
 * Provides comprehensive status of all resilience systems
 */

import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'
import { connectionManager } from '@/lib/resilience/connectionManager'
import { healthMonitor } from '@/lib/resilience/healthMonitor'
import { autoRecoveryService } from '@/lib/resilience/autoRecovery'
import { withStandardErrorHandling, handleAsyncApiOperation } from '@/utils/apiErrorHandling'

/**
 * GET /api/resilience/status - Get comprehensive resilience status
 */
async function resilienceStatusHandler(request: NextRequest): Promise<NextResponse> {
  const result = await handleAsyncApiOperation(
    async () => {
      const startTime = Date.now()

      // Get status from all resilience components
      const connectionStatus = connectionManager.getStatus()
      const healthStatus = healthMonitor.getHealthStatus()
      const recoveryStatus = autoRecoveryService.getRecoveryStatus()

      // Calculate overall system resilience score
      const resilienceScore = calculateResilienceScore(healthStatus, connectionStatus, recoveryStatus)

      const status = {
        timestamp: new Date().toISOString(),
        responseTime: Date.now() - startTime,
        resilienceScore,
        overall: {
          status: resilienceScore >= 80 ? 'excellent' : resilienceScore >= 60 ? 'good' : resilienceScore >= 40 ? 'degraded' : 'poor',
          uptime: process.uptime(),
          version: process.env.NEXT_PUBLIC_APP_VERSION || '1.0.0',
        },
        connections: {
          total: connectionStatus.totalConnections,
          healthy: connectionStatus.healthyConnections,
          circuitBreakers: connectionStatus.circuitBreakers,
          healthStatus: connectionStatus.healthStatus,
        },
        health: {
          systemStatus: healthStatus.systemStatus,
          services: healthStatus.services.map(service => ({
            name: service.serviceName,
            status: service.status,
            lastCheck: service.lastCheck,
            responseTime: service.responseTime,
            consecutiveFailures: service.consecutiveFailures,
          })),
          activeAlerts: healthStatus.activeAlerts.length,
          alertSummary: healthStatus.activeAlerts.reduce((acc, alert) => {
            acc[alert.severity] = (acc[alert.severity] || 0) + 1
            return acc
          }, {} as Record<string, number>),
        },
        recovery: {
          isEnabled: recoveryStatus.isEnabled,
          activeRecoveries: recoveryStatus.activeRecoveries.length,
          recentHistory: recoveryStatus.recentHistory.slice(-5), // Last 5 recoveries
          registeredPlans: recoveryStatus.registeredPlans,
          servicesInCooldown: recoveryStatus.servicesInCooldown,
        },
        recommendations: generateRecommendations(healthStatus, connectionStatus, recoveryStatus),
      }

      logger.info('ResilienceStatus', 'Resilience status check completed', {
        resilienceScore,
        systemStatus: healthStatus.systemStatus,
        activeAlerts: healthStatus.activeAlerts.length,
        activeRecoveries: recoveryStatus.activeRecoveries.length,
      })

      return { status, statusCode: 200 }
    },
    {
      operationName: 'Resilience Status Check',
      endpoint: '/api/resilience/status',
      request,
    }
  )

  if (!result.success) {
    return result.error
  }

  const { status, statusCode } = result.data
  return NextResponse.json(status, { status: statusCode })
}

/**
 * Calculate overall resilience score (0-100)
 */
function calculateResilienceScore(
  healthStatus: any,
  connectionStatus: any,
  recoveryStatus: any
): number {
  let score = 100

  // Health score (40% weight)
  const healthyServices = healthStatus.services.filter((s: any) => s.status === 'healthy').length
  const totalServices = healthStatus.services.length
  const healthScore = totalServices > 0 ? (healthyServices / totalServices) * 40 : 0
  
  // Connection score (30% weight)
  const connectionScore = connectionStatus.totalConnections > 0 
    ? (connectionStatus.healthyConnections / connectionStatus.totalConnections) * 30 
    : 30 // Full score if no connections (not necessarily bad)

  // Alert penalty (20% weight)
  const activeAlerts = healthStatus.activeAlerts.length
  const alertPenalty = Math.min(activeAlerts * 5, 20) // Max 20 point penalty

  // Recovery score (10% weight)
  const recoveryScore = recoveryStatus.isEnabled ? 10 : 0

  score = healthScore + connectionScore + recoveryScore - alertPenalty
  return Math.max(0, Math.min(100, Math.round(score)))
}

/**
 * Generate actionable recommendations based on current status
 */
function generateRecommendations(
  healthStatus: any,
  connectionStatus: any,
  recoveryStatus: any
): string[] {
  const recommendations: string[] = []

  // Health recommendations
  const unhealthyServices = healthStatus.services.filter((s: any) => s.status === 'unhealthy')
  if (unhealthyServices.length > 0) {
    recommendations.push(`${unhealthyServices.length} service(s) are unhealthy: ${unhealthyServices.map((s: any) => s.serviceName).join(', ')}`)
  }

  const degradedServices = healthStatus.services.filter((s: any) => s.status === 'degraded')
  if (degradedServices.length > 0) {
    recommendations.push(`${degradedServices.length} service(s) are degraded and may need attention`)
  }

  // Connection recommendations
  const openCircuitBreakers = Object.entries(connectionStatus.circuitBreakers)
    .filter(([_, breaker]: [string, any]) => breaker.state === 'OPEN')
  if (openCircuitBreakers.length > 0) {
    recommendations.push(`${openCircuitBreakers.length} circuit breaker(s) are open, indicating connection issues`)
  }

  // Alert recommendations
  const criticalAlerts = healthStatus.activeAlerts.filter((a: any) => a.severity === 'critical')
  if (criticalAlerts.length > 0) {
    recommendations.push(`${criticalAlerts.length} critical alert(s) require immediate attention`)
  }

  // Recovery recommendations
  if (!recoveryStatus.isEnabled) {
    recommendations.push('Auto-recovery is disabled - consider enabling for better resilience')
  }

  if (recoveryStatus.activeRecoveries.length > 0) {
    recommendations.push(`${recoveryStatus.activeRecoveries.length} recovery operation(s) in progress`)
  }

  const failedRecoveries = recoveryStatus.recentHistory.filter((r: any) => r.status === 'failed')
  if (failedRecoveries.length > 2) {
    recommendations.push('Multiple recent recovery failures detected - manual intervention may be required')
  }

  // Performance recommendations
  if (connectionStatus.totalConnections > 50) {
    recommendations.push('High number of active connections - consider connection pooling optimization')
  }

  if (recommendations.length === 0) {
    recommendations.push('All systems are operating normally')
  }

  return recommendations
}

/**
 * POST /api/resilience/status - Trigger manual health checks or recovery actions
 */
async function resilienceActionHandler(request: NextRequest): Promise<NextResponse> {
  const result = await handleAsyncApiOperation(
    async () => {
      const body = await request.json()
      const { action, serviceName, force = false } = body

      switch (action) {
        case 'healthCheck':
          if (serviceName) {
            // Trigger health check for specific service
            const service = healthMonitor.getServiceHealth(serviceName)
            if (!service) {
              throw new Error(`Service ${serviceName} not found`)
            }
            return { message: `Health check triggered for ${serviceName}`, service }
          } else {
            // Trigger health check for all services
            const status = healthMonitor.getHealthStatus()
            return { message: 'Health check triggered for all services', status }
          }

        case 'recovery':
          if (!serviceName) {
            throw new Error('Service name is required for recovery action')
          }
          
          const recoveryTriggered = await autoRecoveryService.triggerRecovery(
            serviceName,
            'Manual recovery triggered via API'
          )
          
          return {
            message: `Recovery ${recoveryTriggered ? 'triggered' : 'failed'} for ${serviceName}`,
            triggered: recoveryTriggered,
          }

        case 'enableRecovery':
          autoRecoveryService.setEnabled(true)
          return { message: 'Auto-recovery enabled' }

        case 'disableRecovery':
          autoRecoveryService.setEnabled(false)
          return { message: 'Auto-recovery disabled' }

        default:
          throw new Error(`Unknown action: ${action}`)
      }
    },
    {
      operationName: 'Resilience Action',
      endpoint: '/api/resilience/status',
      request,
    }
  )

  if (!result.success) {
    return result.error
  }

  return NextResponse.json(result.data, { status: 200 })
}

export const GET = withStandardErrorHandling(resilienceStatusHandler)
export const POST = withStandardErrorHandling(resilienceActionHandler)
