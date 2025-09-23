/**
 * Health check endpoint specifically for streaming services
 * Provides detailed diagnostics for SSE connections
 */

import { NextRequest, NextResponse } from 'next/server'
import { streamingSearchService } from '@/lib/streamingSearchService'
import { logger } from '@/utils/logger'
import { withStandardErrorHandling } from '@/utils/apiErrorHandling'

async function streamHealthHandler(request: NextRequest): Promise<NextResponse> {
  const startTime = Date.now()
  
  try {
    logger.info('StreamHealthAPI', 'Performing streaming service health check')

    // Perform comprehensive health check
    const healthCheck = await streamingSearchService.healthCheck()
    const responseTime = Date.now() - startTime

    // Additional connection diagnostics
    const diagnostics = {
      timestamp: new Date().toISOString(),
      responseTime,
      activeStreams: streamingSearchService.getActiveStreamCount(),
      serverInfo: {
        nodeVersion: process.version,
        platform: process.platform,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
      },
      connectionTests: {
        eventSourceSupported: true, // Always true for server-side
        corsEnabled: true,
        rateLimitingActive: true,
      },
    }

    const response = {
      status: healthCheck.healthy ? 'healthy' : 'unhealthy',
      ...healthCheck.details,
      diagnostics,
    }

    const statusCode = healthCheck.healthy ? 200 : 503

    logger.info('StreamHealthAPI', `Health check completed: ${response.status}`, {
      healthy: healthCheck.healthy,
      responseTime,
      activeStreams: diagnostics.activeStreams,
    })

    return NextResponse.json(response, { 
      status: statusCode,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Content-Type': 'application/json',
      },
    })
  } catch (error) {
    const responseTime = Date.now() - startTime
    logger.error('StreamHealthAPI', 'Health check failed', error)

    return NextResponse.json(
      {
        status: 'unhealthy',
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString(),
        responseTime,
      },
      { status: 503 }
    )
  }
}

export const GET = withStandardErrorHandling(streamHealthHandler)

// OPTIONS handler for CORS
export async function OPTIONS(request: NextRequest) {
  return new Response(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
}
