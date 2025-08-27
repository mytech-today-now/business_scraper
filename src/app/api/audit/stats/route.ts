/**
 * Audit Statistics API Endpoint
 * Provides audit statistics and analytics
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { AuditService } from '@/lib/audit-service'
import { logger } from '@/utils/logger'

/**
 * GET /api/audit/stats - Get audit statistics
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)

      // Extract filter parameters
      const filters = {
        userId: searchParams.get('userId') || undefined,
        workspaceId: searchParams.get('workspaceId') || context.workspaceId,
        teamId: searchParams.get('teamId') || context.teamId,
        startDate: searchParams.get('startDate')
          ? new Date(searchParams.get('startDate')!)
          : undefined,
        endDate: searchParams.get('endDate') ? new Date(searchParams.get('endDate')!) : undefined,
      }

      // Default to last 30 days if no date range specified
      if (!filters.startDate && !filters.endDate) {
        filters.endDate = new Date()
        filters.startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
      }

      // Validate date range
      if (filters.startDate && filters.endDate && filters.startDate > filters.endDate) {
        return NextResponse.json({ error: 'Start date must be before end date' }, { status: 400 })
      }

      // Get audit statistics
      const stats = await AuditService.getAuditStats(filters)

      // Get additional time-based statistics
      const timeStats = await getTimeBasedStats(filters, context.database)

      // Log stats access
      await AuditService.log({
        action: 'audit.stats_viewed',
        resourceType: 'audit_stats',
        details: {
          filters,
          totalEvents: stats.totalEvents,
        },
        context: AuditService.extractContextFromRequest(
          request,
          context.user.id,
          context.sessionId
        ),
      })

      logger.info('Audit Stats API', 'Audit statistics retrieved', {
        userId: context.user.id,
        filters,
        totalEvents: stats.totalEvents,
      })

      return NextResponse.json({
        success: true,
        data: {
          ...stats,
          timeStats,
          period: {
            startDate: filters.startDate?.toISOString(),
            endDate: filters.endDate?.toISOString(),
          },
        },
      })
    } catch (error) {
      logger.error('Audit Stats API', 'Error retrieving audit statistics', error)
      return NextResponse.json({ error: 'Failed to retrieve audit statistics' }, { status: 500 })
    }
  },
  { permissions: ['audit.view'] }
)

/**
 * Get time-based statistics
 */
async function getTimeBasedStats(
  filters: any,
  database: any
): Promise<{
  dailyActivity: Array<{ date: string; count: number }>
  hourlyActivity: Array<{ hour: number; count: number }>
  weeklyTrend: Array<{ week: string; count: number }>
}> {
  const conditions: string[] = ['1=1']
  const values: any[] = []
  let paramIndex = 1

  // Build WHERE conditions
  if (filters.userId) {
    conditions.push(`user_id = $${paramIndex++}`)
    values.push(filters.userId)
  }

  if (filters.workspaceId) {
    conditions.push(`workspace_id = $${paramIndex++}`)
    values.push(filters.workspaceId)
  }

  if (filters.teamId) {
    conditions.push(`team_id = $${paramIndex++}`)
    values.push(filters.teamId)
  }

  if (filters.startDate) {
    conditions.push(`timestamp >= $${paramIndex++}`)
    values.push(filters.startDate)
  }

  if (filters.endDate) {
    conditions.push(`timestamp <= $${paramIndex++}`)
    values.push(filters.endDate)
  }

  const whereClause = `WHERE ${conditions.join(' AND ')}`

  // Daily activity
  const dailyResult = await database.query(
    `
    SELECT 
      DATE(timestamp) as date,
      COUNT(*) as count
    FROM audit_logs 
    ${whereClause}
    GROUP BY DATE(timestamp)
    ORDER BY date DESC
    LIMIT 30
  `,
    values
  )

  const dailyActivity = dailyResult.rows.map(row => ({
    date: row.date,
    count: parseInt(row.count),
  }))

  // Hourly activity
  const hourlyResult = await database.query(
    `
    SELECT 
      EXTRACT(HOUR FROM timestamp) as hour,
      COUNT(*) as count
    FROM audit_logs 
    ${whereClause}
    GROUP BY EXTRACT(HOUR FROM timestamp)
    ORDER BY hour
  `,
    values
  )

  const hourlyActivity = Array.from({ length: 24 }, (_, hour) => {
    const found = hourlyResult.rows.find(row => parseInt(row.hour) === hour)
    return {
      hour,
      count: found ? parseInt(found.count) : 0,
    }
  })

  // Weekly trend
  const weeklyResult = await database.query(
    `
    SELECT 
      DATE_TRUNC('week', timestamp) as week,
      COUNT(*) as count
    FROM audit_logs 
    ${whereClause}
    GROUP BY DATE_TRUNC('week', timestamp)
    ORDER BY week DESC
    LIMIT 12
  `,
    values
  )

  const weeklyTrend = weeklyResult.rows.map(row => ({
    week: row.week,
    count: parseInt(row.count),
  }))

  return {
    dailyActivity,
    hourlyActivity,
    weeklyTrend,
  }
}
