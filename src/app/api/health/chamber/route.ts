import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'

/**
 * GET /api/health/chamber - Health check for Chamber of Commerce processing
 */
export async function GET(request: NextRequest) {
  try {
    logger.info('Health Check', 'Chamber of Commerce service health check requested')

    // Import Chamber of Commerce scraping service
    const { chamberOfCommerceScrapingService } = await import('@/lib/chamberOfCommerceScrapingService')

    // Get service status
    const status = chamberOfCommerceScrapingService.getStatus()
    
    // Perform health check
    const healthCheck = await chamberOfCommerceScrapingService.healthCheck()

    const response = {
      service: 'Chamber of Commerce Processing',
      timestamp: new Date().toISOString(),
      status: status,
      healthCheck: healthCheck,
      overall: healthCheck.healthy ? 'healthy' : 'unhealthy'
    }

    logger.info('Health Check', `Chamber service health: ${response.overall}`)

    return NextResponse.json(response, { 
      status: healthCheck.healthy ? 200 : 503 
    })

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    logger.error('Health Check', `Chamber health check failed: ${errorMessage}`, error)
    
    return NextResponse.json({
      service: 'Chamber of Commerce Processing',
      timestamp: new Date().toISOString(),
      overall: 'unhealthy',
      error: errorMessage
    }, { status: 503 })
  }
}
