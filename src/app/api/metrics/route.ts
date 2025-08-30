import { NextRequest, NextResponse } from 'next/server'
import { metrics } from '@/lib/metrics'
import { monitoringService } from '@/model/monitoringService'
import { logger } from '@/utils/logger'

/**
 * GET /api/metrics
 * Prometheus metrics endpoint
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const startTime = Date.now()
    const { searchParams } = new URL(request.url)
    const format = searchParams.get('format') || 'prometheus' // prometheus, json
    const includeMonitoring = searchParams.get('monitoring') !== 'false'

    // Initialize metrics if not already done
    await metrics.initialize()

    if (format === 'json') {
      // Return JSON format with monitoring data
      const systemHealth = monitoringService.getSystemHealth()
      const allMetrics = monitoringService.getMetrics()
      const activeAlerts = monitoringService.getActiveAlerts()

      const jsonResponse = {
        timestamp: new Date().toISOString(),
        system: {
          status: systemHealth.overall,
          services: systemHealth.services,
          activeAlerts: systemHealth.activeAlerts
        },
        metrics: includeMonitoring ? allMetrics.slice(-100) : [], // Last 100 metrics
        alerts: includeMonitoring ? activeAlerts : [],
        prometheus: await metrics.getMetrics()
      }

      // Record metrics API access
      const responseTime = Date.now() - startTime
      await monitoringService.recordMetric('metrics_api_response_time', responseTime, 'ms', {
        format: 'json',
        include_monitoring: includeMonitoring.toString()
      })

      return NextResponse.json(jsonResponse, {
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          Pragma: 'no-cache',
          Expires: '0',
        }
      })
    }

    // Get metrics in Prometheus format
    let metricsData = await metrics.getMetrics()

    // Add monitoring service metrics to Prometheus output if requested
    if (includeMonitoring) {
      const monitoringMetrics = formatMonitoringMetricsForPrometheus()
      metricsData += '\n' + monitoringMetrics
    }

    // Record metrics API access
    const responseTime = Date.now() - startTime
    await monitoringService.recordMetric('metrics_api_response_time', responseTime, 'ms', {
      format: 'prometheus',
      include_monitoring: includeMonitoring.toString()
    })

    return new NextResponse(metricsData, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        Pragma: 'no-cache',
        Expires: '0',
      },
    })
  } catch (error) {
    logger.error('Metrics API', 'Failed to get metrics', error)

    return NextResponse.json(
      {
        error: 'Failed to retrieve metrics',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * POST /api/metrics/reset
 * Reset all metrics (for testing purposes)
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const { action } = await request.json()

    if (action === 'reset') {
      metrics.clear()
      await metrics.initialize()

      logger.info('Metrics API', 'Metrics reset successfully')

      return NextResponse.json({
        success: true,
        message: 'Metrics reset successfully',
      })
    }

    return NextResponse.json(
      {
        error: 'Invalid action',
        message: 'Only "reset" action is supported',
      },
      { status: 400 }
    )
  } catch (error) {
    logger.error('Metrics API', 'Failed to reset metrics', error)

    return NextResponse.json(
      {
        error: 'Failed to reset metrics',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Helper function to format monitoring service metrics for Prometheus
 */
function formatMonitoringMetricsForPrometheus(): string {
  const lines: string[] = []
  const allMetrics = monitoringService.getMetrics()
  const systemHealth = monitoringService.getSystemHealth()

  // Add system health metrics
  lines.push('# HELP system_health Overall system health status')
  lines.push('# TYPE system_health gauge')
  const healthValue = systemHealth.overall === 'healthy' ? 1 : systemHealth.overall === 'degraded' ? 0.5 : 0
  lines.push(`system_health ${healthValue}`)

  lines.push('# HELP active_alerts Number of active alerts')
  lines.push('# TYPE active_alerts gauge')
  lines.push(`active_alerts ${systemHealth.activeAlerts}`)

  // Add service health metrics
  lines.push('# HELP service_health Health status of individual services')
  lines.push('# TYPE service_health gauge')
  systemHealth.services.forEach(service => {
    const serviceValue = service.status === 'healthy' ? 1 : service.status === 'degraded' ? 0.5 : 0
    lines.push(`service_health{service="${service.service}"} ${serviceValue}`)
  })

  // Group metrics by name for Prometheus format
  const metricGroups: Record<string, any[]> = {}
  allMetrics.slice(-100).forEach(metric => { // Last 100 metrics to avoid overwhelming output
    if (!metricGroups[metric.name]) {
      metricGroups[metric.name] = []
    }
    metricGroups[metric.name].push(metric)
  })

  // Format each metric group
  Object.entries(metricGroups).forEach(([metricName, metricList]) => {
    const sanitizedName = metricName.replace(/[^a-zA-Z0-9_]/g, '_')
    lines.push(`# HELP ${sanitizedName} Performance metric from monitoring service`)
    lines.push(`# TYPE ${sanitizedName} gauge`)

    metricList.forEach(metric => {
      const labels = metric.tags ?
        Object.entries(metric.tags).map(([key, value]) => `${key}="${value}"`).join(',') : ''
      const labelString = labels ? `{${labels}}` : ''
      const timestamp = new Date(metric.timestamp).getTime()

      lines.push(`${sanitizedName}${labelString} ${metric.value} ${timestamp}`)
    })
  })

  return lines.join('\n')
}
