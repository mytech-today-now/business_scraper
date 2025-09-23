/**
 * API route for cleaning up expired sessions
 * Replaces setInterval cleanup for Edge Runtime compatibility
 */

import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'

// Import the cleanup function from security module
// Note: We'll need to export this function from security.ts
let cleanupExpiredSessions: () => void

try {
  // Dynamic import to handle potential Edge Runtime issues
  const securityModule = require('@/lib/security')
  cleanupExpiredSessions = securityModule.cleanupExpiredSessions
} catch (error) {
  logger.error('Cleanup API', 'Failed to import security module', error)
}

/**
 * POST /api/cleanup/sessions
 * Manually trigger session cleanup
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

    if (!cleanupExpiredSessions) {
      return NextResponse.json(
        { error: 'Cleanup function not available' },
        { status: 500 }
      )
    }

    // Perform cleanup
    cleanupExpiredSessions()
    
    logger.info('Cleanup API', 'Session cleanup completed successfully')
    
    return NextResponse.json({
      success: true,
      message: 'Session cleanup completed',
      timestamp: new Date().toISOString()
    })
    
  } catch (error) {
    logger.error('Cleanup API', 'Session cleanup failed', error)
    
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
 * GET /api/cleanup/sessions
 * Get cleanup status and information
 */
export async function GET() {
  try {
    return NextResponse.json({
      available: !!cleanupExpiredSessions,
      lastRun: 'Manual trigger required',
      message: 'Session cleanup is available via POST request'
    })
  } catch (error) {
    logger.error('Cleanup API', 'Failed to get cleanup status', error)
    
    return NextResponse.json(
      { error: 'Failed to get status' },
      { status: 500 }
    )
  }
}
