/**
 * Real-time Analytics API Endpoint
 * Provides real-time metrics and live updates
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { Permission } from '@/lib/auth'
import { AnalyticsService } from '@/lib/analytics-service'
import { collaborationWS } from '@/lib/collaboration-websocket'
import { AuditService } from '@/lib/audit-service'
import { database } from '@/lib/postgresql-database'
import { logger } from '@/utils/logger'

/**
 * GET /api/analytics/realtime - Get real-time metrics
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      const workspaceId = searchParams.get('workspaceId') || 'default-workspace'

      // Get real-time metrics
      const realtimeMetrics = await AnalyticsService.getRealtimeMetrics(workspaceId)

      // Get collaboration metrics
      const collaborationMetrics = {
        activeCollaborators: workspaceId ? collaborationWS.getWorkspaceClientCount(workspaceId) : 0,
        activeLocks: workspaceId ? collaborationWS.getWorkspaceLocks(workspaceId).length : 0,
      }

      // Get current system status
      const systemStatus = await getCurrentSystemStatus()

      const metrics = {
        ...realtimeMetrics,
        collaboration: collaborationMetrics,
        system: systemStatus,
        timestamp: new Date().toISOString(),
      }

      // Log real-time metrics access (but don't spam the logs)
      const shouldLog = Math.random() < 0.1 // Log 10% of requests
      if (shouldLog) {
        await AuditService.log({
          action: 'data.exported',
          resourceType: 'realtime_metrics',
          details: {
            workspaceId,
            activeUsers: metrics.activeUsers,
            activeSessions: metrics.activeSessions,
          },
          context: AuditService.extractContextFromRequest(
            request,
            context.session.user.id,
            undefined
          ),
        })
      }

      return NextResponse.json({
        success: true,
        data: metrics,
      })
    } catch (error) {
      logger.error('Real-time Analytics API', 'Error retrieving real-time metrics', error)
      return NextResponse.json({ error: 'Failed to retrieve real-time metrics' }, { status: 500 })
    }
  },
  { permissions: [Permission.DATA_VIEW] }
)

/**
 * POST /api/analytics/realtime - Update real-time metrics (for system monitoring)
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { metricType, value, workspaceId, metadata } = body

      // Validate required fields
      if (!metricType || value === undefined) {
        return NextResponse.json({ error: 'Metric type and value are required' }, { status: 400 })
      }

      // Validate metric type
      const validMetricTypes = [
        'cpu_usage',
        'memory_usage',
        'active_sessions',
        'response_time',
        'error_rate',
        'throughput',
      ]

      if (!validMetricTypes.includes(metricType)) {
        return NextResponse.json(
          { error: `Metric type must be one of: ${validMetricTypes.join(', ')}` },
          { status: 400 }
        )
      }

      // Store metric in database for historical tracking
      await database.executeQuery(
        `
        INSERT INTO performance_metrics (
          workspace_id, metric_type, value, metadata, timestamp
        ) VALUES ($1, $2, $3, $4, $5)
      `,
        [
          workspaceId || null,
          metricType,
          parseFloat(value),
          JSON.stringify(metadata || {}),
          new Date(),
        ]
      )

      // Log metric update
      await AuditService.log({
        action: 'data.validated',
        resourceType: 'performance_metric',
        details: {
          metricType,
          value,
          workspaceId,
          metadata,
        },
        context: AuditService.extractContextFromRequest(
          request,
          context.session.user.id,
          undefined
        ),
      })

      logger.info('Real-time Analytics API', 'Metric updated', {
        metricType,
        value,
        workspaceId,
        updatedBy: context.session.user.id,
      })

      return NextResponse.json({
        success: true,
        message: 'Metric updated successfully',
      })
    } catch (error) {
      logger.error('Real-time Analytics API', 'Error updating metric', error)
      return NextResponse.json({ error: 'Failed to update metric' }, { status: 500 })
    }
  },
  { permissions: [Permission.DATA_MODIFY] }
)

/**
 * Get current system status
 */
async function getCurrentSystemStatus(): Promise<{
  uptime: number
  memoryUsage: NodeJS.MemoryUsage
  cpuUsage: number
  activeConnections: number
  systemHealth: 'healthy' | 'warning' | 'critical'
}> {
  try {
    // Get Node.js process metrics
    const memoryUsage = process.memoryUsage()
    const uptime = process.uptime()

    // Calculate CPU usage (simplified)
    const cpuUsage = process.cpuUsage()
    const cpuPercent = ((cpuUsage.user + cpuUsage.system) / 1000000 / uptime) * 100

    // Get active connections (simplified)
    const activeConnections = 0 // Would need to track this separately

    // Determine system health
    let systemHealth: 'healthy' | 'warning' | 'critical' = 'healthy'

    if (memoryUsage.heapUsed / memoryUsage.heapTotal > 0.9) {
      systemHealth = 'critical'
    } else if (memoryUsage.heapUsed / memoryUsage.heapTotal > 0.7 || cpuPercent > 80) {
      systemHealth = 'warning'
    }

    return {
      uptime,
      memoryUsage,
      cpuUsage: cpuPercent,
      activeConnections,
      systemHealth,
    }
  } catch (error) {
    logger.error('Real-time Analytics API', 'Error getting system status', error)
    return {
      uptime: 0,
      memoryUsage: process.memoryUsage(),
      cpuUsage: 0,
      activeConnections: 0,
      systemHealth: 'critical',
    }
  }
}
