/**
 * API route for cleaning up expired rate limit entries
 * Replaces setInterval cleanup for Edge Runtime compatibility
 */

import { NextRequest, NextResponse } from 'next/server'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { logger } from '@/utils/logger'

/**
 * POST /api/cleanup/rate-limits
 * Manually trigger rate limit cleanup
 */
export async function POST(request: NextRequest) {
  try {
    // Verify this is an internal request or has proper authorization
    const authHeader = request.headers.get('authorization')
    const internalKey = process.env.INTERNAL_API_KEY
    
    if (!internalKey || authHeader !== `Bearer ${internalKey}`) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // Get current count before cleanup
    const beforeCount = advancedRateLimitService.getAllRateLimits().size
    
    // Trigger cleanup by calling a rate limit check with a dummy key
    // This will trigger the performCleanupIfNeeded method
    advancedRateLimitService.checkRateLimit('cleanup-trigger', {
      windowMs: 1000,
      maxRequests: 1
    })
    
    const afterCount = advancedRateLimitService.getAllRateLimits().size
    const cleanedCount = beforeCount - afterCount
    
    logger.info('Cleanup API', `Rate limit cleanup completed, removed ${cleanedCount} expired entries`)
    
    return NextResponse.json({
      success: true,
      message: 'Rate limit cleanup completed',
      cleanedCount,
      remainingEntries: afterCount,
      timestamp: new Date().toISOString()
    })
    
  } catch (error) {
    logger.error('Cleanup API', 'Rate limit cleanup failed', error)
    
    return NextResponse.json(
      { 
        error: 'Cleanup failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * GET /api/cleanup/rate-limits
 * Get rate limit cleanup status and information
 */
export async function GET() {
  try {
    const currentEntries = advancedRateLimitService.getAllRateLimits().size
    
    return NextResponse.json({
      available: true,
      currentEntries,
      lastRun: 'Manual trigger required',
      message: 'Rate limit cleanup is available via POST request'
    })
  } catch (error) {
    logger.error('Cleanup API', 'Failed to get rate limit cleanup status', error)
    
    return NextResponse.json(
      { error: 'Failed to get status' },
      { status: 500 }
    )
  }
}
