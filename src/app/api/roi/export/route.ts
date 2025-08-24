/**
 * ROI Export API Endpoint
 * Handles exporting ROI reports in various formats (CSV, JSON, PDF)
 */

import { NextRequest, NextResponse } from 'next/server'
import { withRBAC } from '@/lib/rbac-middleware'
import { ROIService, ROICalculationInput } from '@/lib/roi-service'
import { AuditService } from '@/lib/audit-service'
import { logger } from '@/utils/logger'

/**
 * POST /api/roi/export - Export ROI report in specified format
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
        format = 'json'
      } = body

      // Validate required fields
      if (!workspaceId || !startDate || !endDate) {
        return NextResponse.json(
          { error: 'Workspace ID, start date, and end date are required' },
          { status: 400 }
        )
      }

      // Validate format
      const validFormats = ['json', 'csv', 'pdf']
      if (!validFormats.includes(format)) {
        return NextResponse.json(
          { error: `Format must be one of: ${validFormats.join(', ')}` },
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

      // Generate comprehensive ROI report
      const report = await ROIService.generateROIReport(input)

      // Export report in requested format
      const exportResult = await ROIService.exportROIReport(report, format)

      // Log export
      await AuditService.log({
        action: 'roi.exported',
        resourceType: 'roi_report',
        resourceId: workspaceId,
        details: {
          format,
          period,
          startDate: input.startDate.toISOString(),
          endDate: input.endDate.toISOString(),
          filename: exportResult.filename,
          roi: report.metrics.roi
        },
        context: AuditService.extractContextFromRequest(request, context.user.id, context.sessionId)
      })

      logger.info('ROI Export API', 'ROI report exported', {
        userId: context.user.id,
        workspaceId,
        format,
        filename: exportResult.filename,
        roi: report.metrics.roi
      })

      // Return file for download
      return new NextResponse(exportResult.data, {
        status: 200,
        headers: {
          'Content-Type': exportResult.mimeType,
          'Content-Disposition': `attachment; filename="${exportResult.filename}"`,
          'Cache-Control': 'no-cache'
        }
      })
    } catch (error) {
      logger.error('ROI Export API', 'Error exporting ROI report', error)
      return NextResponse.json(
        { error: 'Failed to export ROI report' },
        { status: 500 }
      )
    }
  },
  { permissions: ['analytics.view'] }
)

/**
 * GET /api/roi/export - Get available export formats and options
 */
export const GET = withRBAC(
  async (request: NextRequest, context) => {
    try {
      const exportOptions = {
        formats: [
          {
            format: 'json',
            description: 'JSON format with complete report data',
            mimeType: 'application/json',
            extension: '.json'
          },
          {
            format: 'csv',
            description: 'CSV format with key metrics and trends',
            mimeType: 'text/csv',
            extension: '.csv'
          },
          {
            format: 'pdf',
            description: 'PDF format with formatted report (coming soon)',
            mimeType: 'application/pdf',
            extension: '.pdf',
            available: false
          }
        ],
        periods: ['day', 'week', 'month', 'quarter', 'year'],
        defaultSettings: {
          costPerHour: 50,
          estimatedLeadValue: 100,
          period: 'month'
        },
        maxDateRange: {
          days: 365,
          description: 'Maximum date range is 1 year'
        }
      }

      return NextResponse.json({
        success: true,
        data: exportOptions
      })
    } catch (error) {
      logger.error('ROI Export API', 'Error getting export options', error)
      return NextResponse.json(
        { error: 'Failed to get export options' },
        { status: 500 }
      )
    }
  },
  { permissions: ['analytics.view'] }
)
