/**
 * CSP Violation Reporting Endpoint
 * Business Scraper Application - Security Monitoring
 */

import { NextRequest, NextResponse } from 'next/server'
import { logCSPViolation, CSPViolationReport } from '@/lib/cspConfig'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * Handle CSP violation reports
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Get client IP for logging
    const clientIP = getClientIP(request)

    logger.info('CSP Report', `Received CSP violation report from IP: ${clientIP}`)

    // Parse the CSP violation report
    let report: CSPViolationReport
    try {
      report = await request.json()
    } catch (parseError) {
      logger.error('CSP Report', 'Failed to parse CSP report JSON', { clientIP, error: parseError })
      return NextResponse.json({ error: 'Invalid JSON format' }, { status: 400 })
    }

    // Validate the report structure
    if (!report['csp-report']) {
      logger.warn('CSP Report', 'Invalid CSP report structure received', { clientIP, report })
      return NextResponse.json({ error: 'Invalid report structure' }, { status: 400 })
    }

    // Log the violation
    logCSPViolation(report)

    // Additional logging with client context
    logger.info('CSP Report', 'CSP violation reported', {
      clientIP,
      userAgent: request.headers.get('user-agent'),
      timestamp: new Date().toISOString(),
      violation: {
        directive: report['csp-report']['violated-directive'],
        blockedUri: report['csp-report']['blocked-uri'],
        documentUri: report['csp-report']['document-uri'],
      },
    })

    // In production, you might want to:
    // 1. Store violations in a database for analysis
    // 2. Send alerts for critical violations
    // 3. Rate limit reporting to prevent spam

    return NextResponse.json({ status: 'received' }, { status: 200 })
  } catch (error) {
    logger.error('CSP Report', 'Error processing CSP violation report', {
      error: error instanceof Error ? error.message : 'Unknown error',
      clientIP: getClientIP(request),
    })

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

/**
 * Handle preflight requests for CORS
 */
export async function OPTIONS(_request: NextRequest): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  })
}

/**
 * Reject other HTTP methods
 */
export async function GET(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
}

export async function PUT(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
}

export async function DELETE(): Promise<NextResponse> {
  return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
}
