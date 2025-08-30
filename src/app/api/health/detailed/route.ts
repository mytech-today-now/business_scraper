/**
 * Detailed Health Check API Endpoint
 * Business Scraper Application - Comprehensive System Health and Monitoring
 */

import { NextRequest, NextResponse } from 'next/server'
import { monitoringService } from '@/model/monitoringService'
import { logger } from '@/utils/logger'
import { withStandardErrorHandling, handleAsyncApiOperation } from '@/utils/apiErrorHandling'

/**
 * Detailed health check with comprehensive monitoring data
 */
async function detailedHealthCheckHandler(request: NextRequest): Promise<NextResponse> {
  const result = await handleAsyncApiOperation(
    async () => {
      const startTime = Date.now()
      const { searchParams } = new URL(request.url)
      const timeWindow = parseInt(searchParams.get('timeWindow') || '24') // hours
      const includeMetrics = searchParams.get('metrics') === 'true'
      const includeAlerts = searchParams.get('alerts') === 'true'

      // Get system health overview
      const systemHealth = monitoringService.getSystemHealth()
      const responseTime = Date.now() - startTime

      // Base response
      let detailedHealth: any = {
        status: systemHealth.overall,
        timestamp: new Date().toISOString(),
        responseTime,
        uptime: process.uptime(),
        version: process.env.NEXT_PUBLIC_APP_VERSION || '1.0.0',
        environment: process.env.NODE_ENV || 'development',
        overview: {
          totalServices: systemHealth.services.length,
          healthyServices: systemHealth.services.filter(s => s.status === 'healthy').length,
          degradedServices: systemHealth.services.filter(s => s.status === 'degraded').length,
          unhealthyServices: systemHealth.services.filter(s => s.status === 'unhealthy').length,
          activeAlerts: systemHealth.activeAlerts,
          lastUpdated: systemHealth.lastUpdated
        },
        services: systemHealth.services.map(service => ({
          name: service.service,
          status: service.status,
          responseTime: service.responseTime,
          lastCheck: service.lastCheck,
          error: service.error,
          details: service.details
        }))
      }

      // Include metrics if requested
      if (includeMetrics) {
        const endTime = new Date()
        const startTimeMetrics = new Date(endTime.getTime() - (timeWindow * 60 * 60 * 1000))
        
        const allMetrics = monitoringService.getMetrics(undefined, {
          start: startTimeMetrics,
          end: endTime
        })

        // Group metrics by name for summary
        const metricsSummary: Record<string, any> = {}
        allMetrics.forEach(metric => {
          if (!metricsSummary[metric.name]) {
            metricsSummary[metric.name] = {
              name: metric.name,
              unit: metric.unit,
              count: 0,
              latest: null,
              average: 0,
              min: Number.MAX_VALUE,
              max: Number.MIN_VALUE,
              values: []
            }
          }
          
          const summary = metricsSummary[metric.name]
          summary.count++
          summary.latest = metric
          summary.values.push(metric.value)
          summary.min = Math.min(summary.min, metric.value)
          summary.max = Math.max(summary.max, metric.value)
        })

        // Calculate averages
        Object.values(metricsSummary).forEach((summary: any) => {
          summary.average = summary.values.reduce((a: number, b: number) => a + b, 0) / summary.values.length
          delete summary.values // Remove raw values to reduce response size
        })

        detailedHealth.metrics = {
          timeWindow: `${timeWindow} hours`,
          totalMetrics: allMetrics.length,
          uniqueMetrics: Object.keys(metricsSummary).length,
          summary: metricsSummary
        }
      }

      // Include alerts if requested
      if (includeAlerts) {
        const activeAlerts = monitoringService.getActiveAlerts()
        const allAlerts = monitoringService.getAllAlerts()

        detailedHealth.alerts = {
          active: activeAlerts.map(alert => ({
            id: alert.id,
            type: alert.type,
            severity: alert.severity,
            title: alert.title,
            description: alert.description,
            timestamp: alert.timestamp,
            metric: alert.metric,
            value: alert.value,
            threshold: alert.threshold
          })),
          summary: {
            total: allAlerts.length,
            active: activeAlerts.length,
            resolved: allAlerts.filter(a => a.resolved).length,
            bySeverity: {
              critical: activeAlerts.filter(a => a.severity === 'critical').length,
              high: activeAlerts.filter(a => a.severity === 'high').length,
              medium: activeAlerts.filter(a => a.severity === 'medium').length,
              low: activeAlerts.filter(a => a.severity === 'low').length
            },
            byType: {
              performance: activeAlerts.filter(a => a.type === 'performance').length,
              error: activeAlerts.filter(a => a.type === 'error').length,
              security: activeAlerts.filter(a => a.type === 'security').length,
              business: activeAlerts.filter(a => a.type === 'business').length
            }
          }
        }
      }

      // Memory usage details
      if (typeof process !== 'undefined') {
        const memUsage = process.memoryUsage()
        detailedHealth.memory = {
          rss: Math.round(memUsage.rss / 1024 / 1024), // MB
          heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024), // MB
          heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
          external: Math.round(memUsage.external / 1024 / 1024), // MB
          heapUsagePercent: Math.round((memUsage.heapUsed / memUsage.heapTotal) * 100)
        }
      }

      // Record detailed health check metric
      await monitoringService.recordMetric('detailed_health_check_response_time', responseTime, 'ms', {
        status: systemHealth.overall,
        includeMetrics: includeMetrics.toString(),
        includeAlerts: includeAlerts.toString(),
        timeWindow: timeWindow.toString()
      })

      // Determine HTTP status
      const httpStatus = systemHealth.overall === 'unhealthy' ? 503 : 200

      logger.info('DetailedHealthCheck', 'Detailed health check completed', {
        status: systemHealth.overall,
        responseTime,
        includeMetrics,
        includeAlerts,
        timeWindow
      })

      return { detailedHealth, statusCode: httpStatus }
    },
    {
      operationName: 'Detailed Health Check',
      endpoint: '/api/health/detailed',
      request,
    }
  )

  if (!result.success) {
    return result.error
  }

  const { detailedHealth, statusCode } = result.data
  return NextResponse.json(detailedHealth, { status: statusCode })
}

export const GET = withStandardErrorHandling(detailedHealthCheckHandler)

/**
 * POST endpoint for health check with custom parameters
 */
async function customHealthCheckHandler(request: NextRequest): Promise<NextResponse> {
  const result = await handleAsyncApiOperation(
    async () => {
      const body = await request.json()
      const { 
        includeMetrics = false, 
        includeAlerts = false, 
        timeWindow = 24,
        services = [],
        metricNames = []
      } = body

      const startTime = Date.now()
      const systemHealth = monitoringService.getSystemHealth()
      const responseTime = Date.now() - startTime

      let customHealth: any = {
        status: systemHealth.overall,
        timestamp: new Date().toISOString(),
        responseTime,
        requestedParameters: {
          includeMetrics,
          includeAlerts,
          timeWindow,
          services,
          metricNames
        }
      }

      // Filter services if specific services requested
      if (services.length > 0) {
        customHealth.services = systemHealth.services.filter(service => 
          services.includes(service.service)
        )
      } else {
        customHealth.services = systemHealth.services
      }

      // Include specific metrics if requested
      if (includeMetrics && metricNames.length > 0) {
        const endTime = new Date()
        const startTimeMetrics = new Date(endTime.getTime() - (timeWindow * 60 * 60 * 1000))
        
        const specificMetrics: Record<string, any> = {}
        metricNames.forEach((metricName: string) => {
          const metrics = monitoringService.getMetrics(metricName, {
            start: startTimeMetrics,
            end: endTime
          })
          
          if (metrics.length > 0) {
            specificMetrics[metricName] = {
              count: metrics.length,
              latest: metrics[metrics.length - 1],
              average: metrics.reduce((sum, m) => sum + m.value, 0) / metrics.length,
              min: Math.min(...metrics.map(m => m.value)),
              max: Math.max(...metrics.map(m => m.value))
            }
          }
        })

        customHealth.metrics = specificMetrics
      }

      // Include alerts if requested
      if (includeAlerts) {
        customHealth.alerts = monitoringService.getActiveAlerts()
      }

      const httpStatus = systemHealth.overall === 'unhealthy' ? 503 : 200

      return { customHealth, statusCode: httpStatus }
    },
    {
      operationName: 'Custom Health Check',
      endpoint: '/api/health/detailed',
      request,
    }
  )

  if (!result.success) {
    return result.error
  }

  const { customHealth, statusCode } = result.data
  return NextResponse.json(customHealth, { status: statusCode })
}

export const POST = withStandardErrorHandling(customHealthCheckHandler)
