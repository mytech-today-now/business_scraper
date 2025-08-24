/**
 * API v1 - Analytics Endpoint
 * RESTful API for usage analytics and metrics
 */

import { NextRequest } from 'next/server'
import { apiFramework } from '@/lib/integrations/api-framework'
import { usageAnalyticsService } from '@/lib/analytics/usage-analytics'
import { apiMetricsService } from '@/lib/analytics/api-metrics'
import { ApiResponse, ApiRequestContext } from '@/types/integrations'
import { logger } from '@/utils/logger'

/**
 * GET /api/v1/analytics - Get usage analytics
 */
export const GET = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    const { searchParams } = new URL(request.url)
    const clientId = searchParams.get('clientId') || context.clientId
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    const type = searchParams.get('type') || 'client' // 'client', 'system', 'realtime'

    try {
      // Default to last 24 hours if no dates provided
      const defaultEnd = new Date()
      const defaultStart = new Date(defaultEnd.getTime() - 24 * 60 * 60 * 1000)

      const period = {
        start: startDate || defaultStart.toISOString(),
        end: endDate || defaultEnd.toISOString()
      }

      let analyticsData: any

      switch (type) {
        case 'client':
          if (!clientId) {
            throw new Error('Client ID is required for client analytics')
          }
          analyticsData = usageAnalyticsService.getClientAnalytics(clientId, period)
          break

        case 'system':
          analyticsData = usageAnalyticsService.getSystemAnalytics(period)
          break

        case 'realtime':
          analyticsData = {
            realTime: usageAnalyticsService.getRealTimeMetrics(),
            performance: apiMetricsService.getPerformanceMetrics(),
            health: usageAnalyticsService.getHealthStatus()
          }
          break

        default:
          throw new Error('Invalid analytics type. Use: client, system, or realtime')
      }

      return {
        success: true,
        data: {
          type,
          period: type !== 'realtime' ? period : undefined,
          analytics: analyticsData
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('AnalyticsAPI', 'Failed to get analytics', error)
      throw error
    }
  },
  {
    permissions: ['read:analytics']
  }
)

/**
 * GET /api/v1/analytics/export - Export analytics data
 */
export const exportAnalytics = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    const { searchParams } = new URL(request.url)
    const format = searchParams.get('format') || 'json' // 'json' or 'csv'
    const type = searchParams.get('type') || 'usage' // 'usage' or 'metrics'

    try {
      let exportData: string

      if (type === 'usage') {
        exportData = usageAnalyticsService.exportAnalytics(format as any)
      } else if (type === 'metrics') {
        const metricsData = apiMetricsService.exportMetrics()
        exportData = format === 'csv' 
          ? this.convertMetricsToCSV(metricsData)
          : JSON.stringify(metricsData, null, 2)
      } else {
        throw new Error('Invalid export type. Use: usage or metrics')
      }

      const timestamp = new Date().toISOString().split('T')[0]
      const filename = `${type}-analytics-${timestamp}.${format}`

      return {
        success: true,
        data: {
          filename,
          format,
          size: exportData.length,
          data: Buffer.from(exportData).toString('base64')
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('AnalyticsAPI', 'Failed to export analytics', error)
      throw error
    }
  },
  {
    permissions: ['read:analytics'],
    rateLimit: {
      requestsPerMinute: 5,
      requestsPerHour: 20
    }
  }
)

/**
 * GET /api/v1/analytics/health - Get system health status
 */
export const health = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const healthStatus = usageAnalyticsService.getHealthStatus()
      const performanceMetrics = apiMetricsService.getPerformanceMetrics()
      const alertThresholds = apiMetricsService.getAlertThresholds()

      const overallStatus = healthStatus.every(h => h.status === 'healthy') 
        ? 'healthy' 
        : healthStatus.some(h => h.status === 'unhealthy') 
          ? 'unhealthy' 
          : 'degraded'

      return {
        success: true,
        data: {
          status: overallStatus,
          timestamp: new Date().toISOString(),
          services: healthStatus,
          performance: performanceMetrics,
          thresholds: alertThresholds,
          uptime: process.uptime(),
          memory: process.memoryUsage()
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('AnalyticsAPI', 'Failed to get health status', error)
      throw error
    }
  },
  {
    permissions: ['read:analytics']
  }
)

/**
 * POST /api/v1/analytics/thresholds - Update alert thresholds
 */
export const updateThresholds = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    try {
      const body = await request.json()
      const { errorRate, responseTime, rateLimitHits } = body

      const thresholds: any = {}
      if (typeof errorRate === 'number' && errorRate > 0) thresholds.errorRate = errorRate
      if (typeof responseTime === 'number' && responseTime > 0) thresholds.responseTime = responseTime
      if (typeof rateLimitHits === 'number' && rateLimitHits > 0) thresholds.rateLimitHits = rateLimitHits

      if (Object.keys(thresholds).length === 0) {
        throw new Error('No valid thresholds provided')
      }

      apiMetricsService.setAlertThresholds(thresholds)

      logger.info('AnalyticsAPI', 'Updated alert thresholds', {
        requestId: context.requestId,
        thresholds,
        clientId: context.clientId
      })

      return {
        success: true,
        data: {
          message: 'Alert thresholds updated successfully',
          thresholds: apiMetricsService.getAlertThresholds()
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('AnalyticsAPI', 'Failed to update thresholds', error)
      throw error
    }
  },
  {
    permissions: ['admin:all'],
    rateLimit: {
      requestsPerMinute: 5,
      requestsPerHour: 20
    }
  }
)

/**
 * GET /api/v1/analytics/rate-limits - Get rate limit status
 */
export const rateLimits = apiFramework.createHandler(
  async (request: NextRequest, context: ApiRequestContext): Promise<ApiResponse> => {
    const { searchParams } = new URL(request.url)
    const targetClientId = searchParams.get('clientId')

    try {
      // Only allow clients to see their own rate limits unless they have admin permissions
      const clientId = context.permissions.includes('admin:all') 
        ? (targetClientId || context.clientId)
        : context.clientId

      if (!clientId) {
        throw new Error('Client ID is required')
      }

      const rateLimitStatus = apiMetricsService.getRateLimitStatus(clientId)
      
      if (!rateLimitStatus) {
        return {
          success: true,
          data: {
            clientId,
            status: 'No rate limit data found',
            limits: null
          },
          metadata: {
            requestId: context.requestId,
            timestamp: new Date().toISOString(),
            version: 'v1'
          }
        }
      }

      return {
        success: true,
        data: {
          clientId,
          limits: rateLimitStatus,
          resetTimes: {
            minute: new Date(rateLimitStatus.minute.resetTime * 1000).toISOString(),
            hour: new Date(rateLimitStatus.hour.resetTime * 1000).toISOString(),
            day: new Date(rateLimitStatus.day.resetTime * 1000).toISOString()
          }
        },
        metadata: {
          requestId: context.requestId,
          timestamp: new Date().toISOString(),
          version: 'v1'
        }
      }

    } catch (error) {
      logger.error('AnalyticsAPI', 'Failed to get rate limit status', error)
      throw error
    }
  },
  {
    permissions: ['read:analytics']
  }
)

/**
 * Helper function to convert metrics to CSV
 */
function convertMetricsToCSV(metricsData: any): string {
  const headers = ['timestamp', 'type', 'value', 'details']
  const rows: string[][] = [headers]

  // Add performance data
  const performance = metricsData.performance
  if (performance.realTime) {
    rows.push([
      metricsData.timestamp,
      'requests_per_minute',
      performance.realTime.requestsPerMinute.toString(),
      'Real-time metric'
    ])
    rows.push([
      metricsData.timestamp,
      'average_response_time',
      performance.realTime.averageResponseTime.toString(),
      'Real-time metric'
    ])
    rows.push([
      metricsData.timestamp,
      'error_rate',
      performance.realTime.errorRate.toString(),
      'Real-time metric'
    ])
    rows.push([
      metricsData.timestamp,
      'active_clients',
      performance.realTime.activeClients.toString(),
      'Real-time metric'
    ])
  }

  return rows.map(row => row.join(',')).join('\n')
}

// Export named functions for specific endpoints
export { 
  exportAnalytics as GET_export, 
  health as GET_health, 
  updateThresholds as POST_thresholds,
  rateLimits as GET_rateLimits
}
