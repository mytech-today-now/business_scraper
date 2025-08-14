/**
 * Health check endpoint for monitoring and deployment
 */

import { NextRequest, NextResponse } from 'next/server'
import { checkDatabaseConnection } from '@/lib/database'
import { performConfigHealthCheck } from '@/lib/config-validator'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'

export async function GET(_request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now()
  
  try {
    // Get configuration
    const config = getConfig()

    // Basic health check data
    const healthCheck = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: config.app.environment,
      version: config.app.version,
      checks: {
        database: 'unknown',
        configuration: 'unknown',
        memory: 'unknown',
        disk: 'unknown'
      },
      responseTime: 0
    }

    // Configuration health check
    try {
      const configHealth = await performConfigHealthCheck()
      healthCheck.checks.configuration = configHealth.status === 'healthy' ? 'healthy' :
                                        configHealth.status === 'warning' ? 'warning' : 'unhealthy'
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
        external: Math.round(memUsage.external / 1024 / 1024)
      }
      
      // Consider unhealthy if heap usage is over 90% of total
      const heapUsagePercent = (memUsageMB.heapUsed / memUsageMB.heapTotal) * 100
      healthCheck.checks.memory = heapUsagePercent > 90 ? 'warning' : 'healthy'
      
      // Add memory info to response
      ;(healthCheck as any).memory = memUsageMB
    } catch (error) {
      healthCheck.checks.memory = 'unknown'
      logger.warn('Health', 'Memory check failed', error)
    }

    // Calculate response time
    healthCheck.responseTime = Date.now() - startTime

    // Determine overall status
    const checks = Object.values(healthCheck.checks)
    if (checks.includes('unhealthy')) {
      healthCheck.status = 'unhealthy'
    } else if (checks.includes('warning')) {
      healthCheck.status = 'warning'
    }

    // Return appropriate status code
    const statusCode = healthCheck.status === 'healthy' ? 200 : 
                      healthCheck.status === 'warning' ? 200 : 503

    return NextResponse.json(healthCheck, { status: statusCode })

  } catch (error) {
    logger.error('Health', 'Health check failed', error)
    
    return NextResponse.json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
      responseTime: Date.now() - startTime
    }, { status: 503 })
  }
}
