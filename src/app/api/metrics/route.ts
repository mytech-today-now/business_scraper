import { NextRequest, NextResponse } from 'next/server'
import { metrics } from '@/lib/metrics'
import { logger } from '@/utils/logger'

/**
 * GET /api/metrics
 * Prometheus metrics endpoint
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // Initialize metrics if not already done
    await metrics.initialize()

    // Get metrics in Prometheus format
    const metricsData = await metrics.getMetrics()

    return new NextResponse(metricsData, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    })
  } catch (error) {
    logger.error('Metrics API', 'Failed to get metrics', error)
    
    return NextResponse.json({
      error: 'Failed to retrieve metrics',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
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
        message: 'Metrics reset successfully'
      })
    }

    return NextResponse.json({
      error: 'Invalid action',
      message: 'Only "reset" action is supported'
    }, { status: 400 })
  } catch (error) {
    logger.error('Metrics API', 'Failed to reset metrics', error)
    
    return NextResponse.json({
      error: 'Failed to reset metrics',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
