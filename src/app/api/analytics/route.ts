/**
 * Analytics API Endpoint
 * Provides comprehensive analytics and dashboard metrics
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { AnalyticsService, AnalyticsFilters } from '@/lib/analytics-service'
import { AuditService } from '@/lib/audit-service'
import { logger } from '@/utils/logger'

/**
 * GET /api/analytics - Get comprehensive dashboard metrics
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      
      // Extract filter parameters
      const filters: AnalyticsFilters = {
        workspaceId: searchParams.get('workspaceId') || context.workspaceId,
        teamId: searchParams.get('teamId') || context.teamId,
        userId: searchParams.get('userId') || undefined,
        startDate: searchParams.get('startDate') ? new Date(searchParams.get('startDate')!) : undefined,
        endDate: searchParams.get('endDate') ? new Date(searchParams.get('endDate')!) : undefined,
        period: (searchParams.get('period') as any) || 'day'
      }

      // Validate date range
      if (filters.startDate && filters.endDate && filters.startDate > filters.endDate) {
        return NextResponse.json(
          { error: 'Start date must be before end date' },
          { status: 400 }
        )
      }

      // Validate period
      const validPeriods = ['hour', 'day', 'week', 'month']
      if (filters.period && !validPeriods.includes(filters.period)) {
        return NextResponse.json(
          { error: `Period must be one of: ${validPeriods.join(', ')}` },
          { status: 400 }
        )
      }

      // Get dashboard metrics
      const metrics = await AnalyticsService.getDashboardMetrics(filters)

      // Log analytics access
      await AuditService.log({
        action: 'analytics.view',
        resourceType: 'analytics_dashboard',
        details: {
          filters,
          metricsRequested: Object.keys(metrics)
        },
        context: AuditService.extractContextFromRequest(request, context.user.id, context.sessionId)
      })

      logger.info('Analytics API', 'Dashboard metrics retrieved', {
        userId: context.user.id,
        filters,
        totalUsers: metrics.overview.totalUsers,
        totalCampaigns: metrics.overview.totalCampaigns
      })

      return NextResponse.json({
        success: true,
        data: metrics,
        filters,
        generatedAt: new Date().toISOString()
      })
    } catch (error) {
      logger.error('Analytics API', 'Error retrieving dashboard metrics', error)
      return NextResponse.json(
        { error: 'Failed to retrieve analytics data' },
        { status: 500 }
      )
    }
  },
  { permissions: ['analytics.view'] }
)

/**
 * POST /api/analytics - Generate custom analytics report
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const { 
        reportType, 
        filters, 
        metrics, 
        groupBy, 
        sortBy, 
        limit 
      } = body

      // Validate required fields
      if (!reportType || !metrics || !Array.isArray(metrics)) {
        return NextResponse.json(
          { error: 'Report type and metrics array are required' },
          { status: 400 }
        )
      }

      // Validate report type
      const validReportTypes = [
        'user_activity', 
        'team_performance', 
        'workspace_analytics', 
        'data_quality', 
        'performance_metrics',
        'custom'
      ]
      if (!validReportTypes.includes(reportType)) {
        return NextResponse.json(
          { error: `Report type must be one of: ${validReportTypes.join(', ')}` },
          { status: 400 }
        )
      }

      // Build analytics filters
      const analyticsFilters: AnalyticsFilters = {
        workspaceId: filters?.workspaceId || context.workspaceId,
        teamId: filters?.teamId || context.teamId,
        userId: filters?.userId,
        startDate: filters?.startDate ? new Date(filters.startDate) : undefined,
        endDate: filters?.endDate ? new Date(filters.endDate) : undefined,
        period: filters?.period || 'day'
      }

      let reportData: any

      // Generate report based on type
      switch (reportType) {
        case 'user_activity':
          reportData = await AnalyticsService.getUserActivitySummary(analyticsFilters)
          break

        case 'team_performance':
          reportData = await AnalyticsService.getTeamPerformance(analyticsFilters)
          break

        case 'workspace_analytics':
          reportData = await AnalyticsService.getWorkspaceAnalytics(analyticsFilters)
          break

        case 'data_quality':
          reportData = await AnalyticsService.getDataQualityMetrics(analyticsFilters)
          break

        case 'performance_metrics':
          reportData = await AnalyticsService.getPerformanceMetrics(analyticsFilters)
          break

        case 'custom':
          // For custom reports, get full dashboard metrics and filter
          const fullMetrics = await AnalyticsService.getDashboardMetrics(analyticsFilters)
          reportData = this.filterMetrics(fullMetrics, metrics)
          break

        default:
          return NextResponse.json(
            { error: 'Invalid report type' },
            { status: 400 }
          )
      }

      // Apply sorting and limiting if specified
      if (Array.isArray(reportData) && sortBy) {
        // Validate sortBy field to prevent object injection
        const allowedSortFields = ['name', 'industry', 'location', 'phone', 'email', 'website', 'confidence_score', 'created_at']
        if (!allowedSortFields.includes(sortBy)) {
          return NextResponse.json({ error: 'Invalid sort field' }, { status: 400 })
        }

        reportData.sort((a: Record<string, unknown>, b: Record<string, unknown>) => {
          const aVal = a[sortBy]
          const bVal = b[sortBy]
          return typeof aVal === 'number' ? (bVal as number) - (aVal as number) : String(bVal).localeCompare(String(aVal))
        })
      }

      if (Array.isArray(reportData) && limit) {
        reportData = reportData.slice(0, parseInt(limit))
      }

      // Log report generation
      await AuditService.log({
        action: 'analytics.report_generated',
        resourceType: 'analytics_report',
        details: {
          reportType,
          filters: analyticsFilters,
          metrics,
          recordCount: Array.isArray(reportData) ? reportData.length : 1
        },
        context: AuditService.extractContextFromRequest(request, context.user.id, context.sessionId)
      })

      logger.info('Analytics API', 'Custom report generated', {
        userId: context.user.id,
        reportType,
        recordCount: Array.isArray(reportData) ? reportData.length : 1
      })

      return NextResponse.json({
        success: true,
        data: reportData,
        reportType,
        filters: analyticsFilters,
        generatedAt: new Date().toISOString(),
        recordCount: Array.isArray(reportData) ? reportData.length : 1
      })
    } catch (error) {
      logger.error('Analytics API', 'Error generating custom report', error)
      return NextResponse.json(
        { error: 'Failed to generate analytics report' },
        { status: 500 }
      )
    }
  },
  { permissions: ['analytics.view'] }
)

/**
 * Filter metrics based on requested fields
 */
function filterMetrics(fullMetrics: Record<string, unknown>, requestedMetrics: string[]): Record<string, unknown> {
  const filtered: Record<string, unknown> = {}

  // Define allowed metrics to prevent object injection
  const allowedMetrics = [
    'totalBusinesses', 'totalSearches', 'successRate', 'averageResponseTime',
    'topIndustries', 'topLocations', 'searchVolume', 'errorRate'
  ]

  requestedMetrics.forEach(metric => {
    if (allowedMetrics.includes(metric) && Object.prototype.hasOwnProperty.call(fullMetrics, metric)) {
      filtered[metric] = fullMetrics[metric]
    }
  })

  return filtered
}
