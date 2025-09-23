/**
 * API route for cleaning up expired CSRF tokens
 * Replaces setInterval cleanup for Edge Runtime compatibility
 */

import { NextRequest, NextResponse } from 'next/server'
import { csrfProtectionService } from '@/lib/csrfProtection'
import { logger } from '@/utils/logger'

/**
 * POST /api/cleanup/csrf-tokens
 * Manually trigger CSRF token cleanup
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

    // Perform CSRF token cleanup
    const cleanedCount = csrfProtectionService.cleanupExpiredTokens()
    
    logger.info('Cleanup API', `CSRF token cleanup completed, removed ${cleanedCount} expired tokens`)
    
    return NextResponse.json({
      success: true,
      message: 'CSRF token cleanup completed',
      cleanedCount,
      timestamp: new Date().toISOString()
    })
    
  } catch (error) {
    logger.error('Cleanup API', 'CSRF token cleanup failed', error)
    
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
 * GET /api/cleanup/csrf-tokens
 * Get CSRF token cleanup status and information
 */
export async function GET() {
  try {
    // Get current token count (if available)
    const tokenCount = csrfProtectionService.getTokenCount?.() || 'Unknown'
    
    return NextResponse.json({
      available: true,
      currentTokenCount: tokenCount,
      lastRun: 'Manual trigger required',
      message: 'CSRF token cleanup is available via POST request'
    })
  } catch (error) {
    logger.error('Cleanup API', 'Failed to get CSRF cleanup status', error)
    
    return NextResponse.json(
      { error: 'Failed to get status' },
      { status: 500 }
    )
  }
}
