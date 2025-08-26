/**
 * CCPA Opt-Out API Route
 * Handles "Do Not Sell My Info" requests
 */

import { NextRequest, NextResponse } from 'next/server'
import { ccpaComplianceService } from '@/lib/ccpa-compliance'
import { logger } from '@/utils/logger'

/**
 * POST /api/compliance/ccpa/opt-out
 * Process "Do Not Sell My Info" opt-out request
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const {
      consumerEmail,
      consumerName,
      phone,
      address,
      verificationMethod,
      requestDetails
    } = body

    // Validate required fields
    if (!consumerEmail || !consumerName) {
      return NextResponse.json(
        { error: 'Consumer email and name are required' },
        { status: 400 }
      )
    }

    // Get client information
    const clientIP = getClientIP(request)
    const userAgent = request.headers.get('user-agent') || 'Unknown'

    // Process the opt-out request
    const result = await ccpaComplianceService.processOptOutRequest(
      consumerEmail,
      clientIP,
      userAgent
    )

    if (result.success) {
      logger.info('CCPA Opt-Out API', 'Opt-out request processed successfully', {
        consumerEmail,
        clientIP
      })

      return NextResponse.json({
        success: true,
        message: 'Your opt-out request has been processed successfully',
        requestId: crypto.randomUUID(), // Generate a request ID for tracking
        effectiveDate: new Date().toISOString()
      })
    } else {
      return NextResponse.json(
        { error: result.error },
        { status: 400 }
      )
    }

  } catch (error) {
    logger.error('CCPA Opt-Out API', 'Failed to process opt-out request', error)
    return NextResponse.json(
      { error: 'Failed to process opt-out request' },
      { status: 500 }
    )
  }
}

/**
 * GET /api/compliance/ccpa/opt-out
 * Check opt-out status for a consumer
 */
export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url)
    const email = url.searchParams.get('email')

    if (!email) {
      return NextResponse.json(
        { error: 'Email parameter is required' },
        { status: 400 }
      )
    }

    const clientIP = getClientIP(request)

    // Get privacy dashboard data which includes opt-out status
    const result = await ccpaComplianceService.getPrivacyDashboard(email, clientIP)

    if (result.success && result.data) {
      const optOutStatus = {
        isOptedOut: result.data.privacySettings?.doNotSell || false,
        optOutDate: result.data.privacySettings?.doNotSellDate,
        lastUpdated: result.data.lastUpdated
      }

      return NextResponse.json({
        success: true,
        optOutStatus
      })
    } else {
      return NextResponse.json(
        { error: result.error || 'Failed to get opt-out status' },
        { status: 400 }
      )
    }

  } catch (error) {
    logger.error('CCPA Opt-Out API', 'Failed to get opt-out status', error)
    return NextResponse.json(
      { error: 'Failed to get opt-out status' },
      { status: 500 }
    )
  }
}

/**
 * Get client IP address
 */
function getClientIP(request: NextRequest): string {
  return request.headers.get('x-forwarded-for') ||
         request.headers.get('x-real-ip') ||
         'unknown'
}
