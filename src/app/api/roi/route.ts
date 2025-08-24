/**
 * ROI (Return on Investment) API Endpoint
 * Provides ROI calculations, reports, and business value analytics
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { ROIService, ROICalculationInput } from '@/lib/roi-service'
import { AuditService } from '@/lib/audit-service'
import { logger } from '@/utils/logger'

/**
 * GET /api/roi - Calculate ROI metrics
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const { searchParams } = new URL(request.url)
      
      // Extract parameters
      const workspaceId = searchParams.get('workspaceId') || context.workspaceId
      const period = (searchParams.get('period') as any) || 'month'
      const startDate = searchParams.get('startDate') ? new Date(searchParams.get('startDate')!) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
      const endDate = searchParams.get('endDate') ? new Date(searchParams.get('endDate')!) : new Date()
      const costPerHour = searchParams.get('costPerHour') ? parseFloat(searchParams.get('costPerHour')!) : 50
      const estimatedLeadValue = searchParams.get('estimatedLeadValue') ? parseFloat(searchParams.get('estimatedLeadValue')!) : 100

      // Validate parameters
      if (!workspaceId) {
        return NextResponse.json(
          { error: 'Workspace ID is required' },
          { status: 400 }
        )
      }

      if (startDate >= endDate) {
        return NextResponse.json(
          { error: 'Start date must be before end date' },
          { status: 400 }
        )
      }

      const validPeriods = ['day', 'week', 'month', 'quarter', 'year']
      if (!validPeriods.includes(period)) {
        return NextResponse.json(
          { error: `Period must be one of: ${validPeriods.join(', ')}` },
          { status: 400 }
        )
      }

      // Build ROI calculation input
      const input: ROICalculationInput = {
        workspaceId,
        period,
        startDate,
        endDate,
        costPerHour,
        estimatedLeadValue
      }

      // Add conversion data if provided
      const leadsContacted = searchParams.get('leadsContacted')
      const responseRate = searchParams.get('responseRate')
      const conversionRate = searchParams.get('conversionRate')
      const avgDealValue = searchParams.get('avgDealValue')

      if (leadsContacted && responseRate && conversionRate && avgDealValue) {
        input.conversionData = {
          leadsContacted: parseInt(leadsContacted),
          responseRate: parseFloat(responseRate),
          conversionRate: parseFloat(conversionRate),
          avgDealValue: parseFloat(avgDealValue)
        }
      }

      // Calculate ROI metrics
      const metrics = await ROIService.calculateROI(input)

      // Log ROI calculation
      await AuditService.log({
        action: 'roi.calculated',
        resourceType: 'roi_metrics',
        resourceId: workspaceId,
        details: {
          period,
          startDate: startDate.toISOString(),
          endDate: endDate.toISOString(),
          roi: metrics.roi,
          totalCosts: metrics.totalCosts,
          estimatedValue: metrics.estimatedValue
        },
        context: AuditService.extractContextFromRequest(request, context.user.id, context.sessionId)
      })

      logger.info('ROI API', 'ROI metrics calculated', {
        userId: context.user.id,
        workspaceId,
        period,
        roi: metrics.roi,
        totalBusinesses: metrics.totalBusinessesFound
      })

      return NextResponse.json({
        success: true,
        data: metrics,
        calculatedAt: new Date().toISOString()
      })
    } catch (error) {
      logger.error('ROI API', 'Error calculating ROI metrics', error)
      return NextResponse.json(
        { error: 'Failed to calculate ROI metrics' },
        { status: 500 }
      )
    }
  },
  { permissions: ['analytics.view'] }
)

/**
 * POST /api/roi - Generate comprehensive ROI report
 */
export const POST = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const {
        workspaceId,
        period = 'month',
        startDate,
        endDate,
        costPerHour = 50,
        estimatedLeadValue = 100,
        conversionData,
        includeBreakdown = true,
        includeTrends = true,
        includeRecommendations = true
      } = body

      // Validate required fields
      if (!workspaceId || !startDate || !endDate) {
        return NextResponse.json(
          { error: 'Workspace ID, start date, and end date are required' },
          { status: 400 }
        )
      }

      // Build ROI calculation input
      const input: ROICalculationInput = {
        workspaceId: workspaceId || context.workspaceId,
        period,
        startDate: new Date(startDate),
        endDate: new Date(endDate),
        costPerHour,
        estimatedLeadValue,
        conversionData
      }

      // Validate dates
      if (input.startDate >= input.endDate) {
        return NextResponse.json(
          { error: 'Start date must be before end date' },
          { status: 400 }
        )
      }

      // Generate comprehensive ROI report
      const report = await ROIService.generateROIReport(input)

      // Filter report sections based on request
      const filteredReport = {
        metrics: report.metrics,
        ...(includeBreakdown && { breakdown: report.breakdown }),
        ...(includeTrends && { trends: report.trends }),
        ...(includeRecommendations && { recommendations: report.recommendations })
      }

      // Log report generation
      await AuditService.log({
        action: 'roi.report_generated',
        resourceType: 'roi_report',
        resourceId: workspaceId,
        details: {
          period,
          startDate: input.startDate.toISOString(),
          endDate: input.endDate.toISOString(),
          includeBreakdown,
          includeTrends,
          includeRecommendations,
          roi: report.metrics.roi
        },
        context: AuditService.extractContextFromRequest(request, context.user.id, context.sessionId)
      })

      logger.info('ROI API', 'ROI report generated', {
        userId: context.user.id,
        workspaceId,
        period,
        roi: report.metrics.roi,
        recommendationCount: report.recommendations.length
      })

      return NextResponse.json({
        success: true,
        data: filteredReport,
        generatedAt: new Date().toISOString()
      })
    } catch (error) {
      logger.error('ROI API', 'Error generating ROI report', error)
      return NextResponse.json(
        { error: 'Failed to generate ROI report' },
        { status: 500 }
      )
    }
  },
  { permissions: ['analytics.view'] }
)

/**
 * PUT /api/roi - Update conversion data for ROI tracking
 */
export const PUT = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const body = await request.json()
      const {
        workspaceId,
        campaignId,
        conversionData,
        actualRevenue,
        notes
      } = body

      // Validate required fields
      if (!workspaceId || !conversionData) {
        return NextResponse.json(
          { error: 'Workspace ID and conversion data are required' },
          { status: 400 }
        )
      }

      // Validate conversion data structure
      const requiredFields = ['leadsContacted', 'responseRate', 'conversionRate', 'avgDealValue']
      for (const field of requiredFields) {
        if (conversionData[field] === undefined || conversionData[field] === null) {
          return NextResponse.json(
            { error: `Conversion data must include ${field}` },
            { status: 400 }
          )
        }
      }

      // Store conversion data in database
      await context.database.query(`
        INSERT INTO roi_tracking (
          workspace_id, campaign_id, leads_contacted, response_rate, 
          conversion_rate, avg_deal_value, actual_revenue, notes, 
          created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (workspace_id, campaign_id) 
        DO UPDATE SET
          leads_contacted = EXCLUDED.leads_contacted,
          response_rate = EXCLUDED.response_rate,
          conversion_rate = EXCLUDED.conversion_rate,
          avg_deal_value = EXCLUDED.avg_deal_value,
          actual_revenue = EXCLUDED.actual_revenue,
          notes = EXCLUDED.notes,
          updated_at = EXCLUDED.updated_at
      `, [
        workspaceId,
        campaignId || null,
        conversionData.leadsContacted,
        conversionData.responseRate,
        conversionData.conversionRate,
        conversionData.avgDealValue,
        actualRevenue || null,
        notes || null,
        context.user.id,
        new Date(),
        new Date()
      ])

      // Log conversion data update
      await AuditService.log({
        action: 'roi.conversion_updated',
        resourceType: 'roi_tracking',
        resourceId: workspaceId,
        details: {
          campaignId,
          conversionData,
          actualRevenue,
          updatedBy: context.user.id
        },
        context: AuditService.extractContextFromRequest(request, context.user.id, context.sessionId)
      })

      logger.info('ROI API', 'Conversion data updated', {
        userId: context.user.id,
        workspaceId,
        campaignId,
        leadsContacted: conversionData.leadsContacted,
        conversionRate: conversionData.conversionRate
      })

      return NextResponse.json({
        success: true,
        message: 'Conversion data updated successfully'
      })
    } catch (error) {
      logger.error('ROI API', 'Error updating conversion data', error)
      return NextResponse.json(
        { error: 'Failed to update conversion data' },
        { status: 500 }
      )
    }
  },
  { permissions: ['analytics.manage'] }
)
