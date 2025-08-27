/**
 * Virtualized Export API Endpoint
 * Handles large dataset exports with progress tracking and streaming
 */

import { NextRequest, NextResponse } from 'next/server'
import { virtualizedExportService, ExportOptions } from '@/lib/virtualizedExportService'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'
import { z } from 'zod'

/**
 * Request validation schema
 */
const ExportRequestSchema = z.object({
  format: z.enum(['csv', 'xlsx', 'json', 'pdf']),
  includeAIScores: z.boolean().default(false),
  includeHeaders: z.boolean().default(true),
  customFields: z.array(z.string()).optional(),
  maxRecords: z.number().min(1).max(100000).optional(),
  batchSize: z.number().min(100).max(5000).default(1000),
  filters: z
    .object({
      fullTextSearch: z.string().optional(),
      businessNameSearch: z.string().optional(),
      industrySearch: z.string().optional(),
      locationSearch: z.string().optional(),
      hasEmail: z.boolean().optional(),
      hasPhone: z.boolean().optional(),
      hasWebsite: z.boolean().optional(),
      emailDomain: z.string().optional(),
      confidenceScore: z
        .object({
          min: z.number().min(0).max(1).optional(),
          max: z.number().min(0).max(1).optional(),
        })
        .optional(),
      scrapedDateRange: z
        .object({
          start: z.string().optional(),
          end: z.string().optional(),
        })
        .optional(),
      zipCodes: z.array(z.string()).optional(),
      states: z.array(z.string()).optional(),
      cities: z.array(z.string()).optional(),
    })
    .optional(),
  sorting: z
    .object({
      field: z.enum(['name', 'industry', 'confidence_score', 'scraped_at', 'data_completeness']),
      order: z.enum(['asc', 'desc']),
    })
    .optional(),
})

/**
 * POST /api/export/virtualized - Start a new virtualized export
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('VirtualizedExportAPI', `Export request from IP: ${ip}`)

    // Parse and validate request body
    const body = await request.json()
    const validatedData = ExportRequestSchema.parse(body)

    // Generate unique export ID
    const exportId = `export-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`

    // Prepare export options
    const exportOptions: ExportOptions = {
      format: validatedData.format,
      includeAIScores: validatedData.includeAIScores,
      includeHeaders: validatedData.includeHeaders,
      customFields: validatedData.customFields,
      maxRecords: validatedData.maxRecords,
      batchSize: validatedData.batchSize,
      filters: validatedData.filters,
      sorting: validatedData.sorting,
    }

    // Start the export process
    const result = await virtualizedExportService.startExport(exportId, exportOptions)

    logger.info(
      'VirtualizedExportAPI',
      `Started export ${exportId} with estimated duration ${result.estimatedDuration}s`
    )

    return NextResponse.json({
      success: true,
      exportId: result.exportId,
      estimatedDuration: result.estimatedDuration,
      message: 'Export started successfully',
      progressUrl: `/api/export/virtualized/${result.exportId}/progress`,
    })
  } catch (error) {
    logger.error('VirtualizedExportAPI', 'Failed to start export', error)

    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid request parameters',
          details: error.errors,
        },
        { status: 400 }
      )
    }

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to start export',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * GET /api/export/virtualized - Get list of recent exports
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('VirtualizedExportAPI', `Export list request from IP: ${ip}`)

    // For now, return empty list - would be implemented with database storage
    return NextResponse.json({
      success: true,
      exports: [],
      message: 'Export list retrieved successfully',
    })
  } catch (error) {
    logger.error('VirtualizedExportAPI', 'Failed to get export list', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to retrieve export list',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}
