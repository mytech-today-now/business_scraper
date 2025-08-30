/**
 * Health check endpoint for monitoring and deployment
 */

import { NextRequest, NextResponse } from 'next/server'
import { checkDatabaseConnection } from '@/lib/database'
import { performConfigHealthCheck } from '@/lib/config-validator'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'
import { monitoringService } from '@/model/monitoringService'
import {
  withStandardErrorHandling,
  createSuccessResponse,
  handleAsyncApiOperation,
} from '@/utils/apiErrorHandling'

/**
 * Interface for health check response
 */
interface HealthCheckResponse {
  status: string
  timestamp: string
  uptime: number
  environment: string
  version: string
  checks: {
    database: string
    configuration: string
    memory: string
    disk: string
  }
  responseTime?: number
  memory?: {
    rss: number
    heapTotal: number
    heapUsed: number
    external: number
    arrayBuffers: number
  }
}

async function healthCheckHandler(request: NextRequest): Promise<NextResponse> {
  const result = await handleAsyncApiOperation(
    async () => {
      const startTime = Date.now()
      // Get configuration
      const config = getConfig()

      // Basic health check data
      const healthCheck: HealthCheckResponse = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: config.app.environment,
        version: config.app.version,
        checks: {
          database: 'unknown',
          configuration: 'unknown',
          memory: 'unknown',
          disk: 'unknown',
        },
        responseTime: 0,
      }

      // Configuration health check
      try {
        const configHealth = await performConfigHealthCheck()
        healthCheck.checks.configuration =
          configHealth.status === 'healthy'
            ? 'healthy'
            : configHealth.status === 'warning'
              ? 'warning'
              : 'unhealthy'
      } catch (error) {
        healthCheck.checks.configuration = 'unhealthy'
        logger.warn('Health', 'Configuration health check failed', error)
      }

      // Database connectivity check
      try {
        const dbStatus = await checkDatabaseConnection()
        healthCheck.checks.database = dbStatus.connected ? 'healthy' : 'unhealthy'
      } catch (error) {
        // If using IndexedDB on server side, mark as healthy since it's client-side only
        const errorMessage = error instanceof Error ? error.message : 'Unknown error'
        if (errorMessage.includes('IndexedDB not supported')) {
          healthCheck.checks.database = 'healthy' // IndexedDB is client-side only
          logger.info('Health', 'Database check skipped - IndexedDB is client-side only')
        } else {
          healthCheck.checks.database = 'unhealthy'
          logger.warn('Health', 'Database health check failed', error)
        }
      }

      // Memory usage check
      try {
        const memUsage = process.memoryUsage()
        const memUsageMB = {
          rss: Math.round(memUsage.rss / 1024 / 1024),
          heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
          heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
          external: Math.round(memUsage.external / 1024 / 1024),
        }

        // Consider unhealthy if heap usage is over 90% of total
        const heapUsagePercent = (memUsageMB.heapUsed / memUsageMB.heapTotal) * 100
        healthCheck.checks.memory = heapUsagePercent > 90 ? 'warning' : 'healthy'

        // Add memory info to response
        healthCheck.memory = memUsageMB
      } catch (error) {
        healthCheck.checks.memory = 'unknown'
        logger.warn('Health', 'Memory check failed', error)
      }

      // Calculate response time
      healthCheck.responseTime = Date.now() - startTime

      // Get monitoring service health data
      const systemHealth = monitoringService.getSystemHealth()

      // Add monitoring service data to health check
      const monitoringData = {
        overall: systemHealth.overall,
        services: systemHealth.services.length,
        activeAlerts: systemHealth.activeAlerts,
        lastUpdated: systemHealth.lastUpdated
      }

      // Record health check metric
      await monitoringService.recordMetric('health_check_response_time', healthCheck.responseTime, 'ms', {
        status: healthCheck.status
      })

      // Determine overall status (combine existing checks with monitoring service)
      const checks = Object.values(healthCheck.checks)
      if (checks.includes('unhealthy') || systemHealth.overall === 'unhealthy') {
        healthCheck.status = 'unhealthy'
      } else if (checks.includes('warning') || systemHealth.overall === 'degraded') {
        healthCheck.status = 'warning'
      }

      // Return appropriate status code
      const statusCode =
        healthCheck.status === 'healthy' ? 200 : healthCheck.status === 'warning' ? 200 : 503

      return { healthCheck: { ...healthCheck, monitoring: monitoringData }, statusCode }
    },
    {
      operationName: 'Health Check',
      endpoint: '/api/health',
      request,
    }
  )

  if (!result.success) {
    return result.error
  }

  const { healthCheck, statusCode } = result.data
  return NextResponse.json(healthCheck, { status: statusCode })
}

export const GET = withStandardErrorHandling(healthCheckHandler)
