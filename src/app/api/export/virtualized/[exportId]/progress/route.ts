/**
 * Export Progress API Endpoint
 * Provides real-time progress updates for virtualized exports
 */

import { NextRequest, NextResponse } from 'next/server'
import { virtualizedExportService } from '@/lib/virtualizedExportService'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

interface RouteParams {
  params: {
    exportId: string
  }
}

/**
 * GET /api/export/virtualized/[exportId]/progress - Get export progress
 */
export async function GET(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const ip = getClientIP(request)
  const { exportId } = params

  try {
    logger.info('ExportProgressAPI', `Progress request for export ${exportId} from IP: ${ip}`)

    // Validate export ID format
    if (!exportId || !exportId.startsWith('export-')) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid export ID format',
        },
        { status: 400 }
      )
    }

    // Get progress from service
    const progress = virtualizedExportService.getExportProgress(exportId)

    if (!progress) {
      return NextResponse.json(
        {
          success: false,
          error: 'Export not found',
          message: 'The specified export ID does not exist or has expired',
        },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      exportId,
      progress,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('ExportProgressAPI', `Failed to get progress for export ${exportId}`, error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to retrieve export progress',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/export/virtualized/[exportId]/progress - Cancel export
 */
export async function DELETE(request: NextRequest, { params }: RouteParams): Promise<NextResponse> {
  const ip = getClientIP(request)
  const { exportId } = params

  try {
    logger.info('ExportProgressAPI', `Cancel request for export ${exportId} from IP: ${ip}`)

    // Validate export ID format
    if (!exportId || !exportId.startsWith('export-')) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid export ID format',
        },
        { status: 400 }
      )
    }

    // Cancel the export
    const cancelled = await virtualizedExportService.cancelExport(exportId)

    if (!cancelled) {
      return NextResponse.json(
        {
          success: false,
          error: 'Export not found or already completed',
          message: 'The specified export ID does not exist, has expired, or is already completed',
        },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      exportId,
      message: 'Export cancelled successfully',
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('ExportProgressAPI', `Failed to cancel export ${exportId}`, error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to cancel export',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}
