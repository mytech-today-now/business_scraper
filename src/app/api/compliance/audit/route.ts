/**
 * Audit Logging API
 * Handles client-side audit event submission
 */

import { NextRequest, NextResponse } from 'next/server'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'
import { logger } from '@/utils/logger'

/**
 * POST /api/compliance/audit
 * Submit audit event from client
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const {
      eventType,
      severity,
      resource,
      action,
      details,
      userId,
      sessionId,
      correlationId,
      complianceFlags
    } = body

    // Validate required fields
    if (!eventType || !severity || !details) {
      return NextResponse.json(
        { error: 'Missing required fields: eventType, severity, details' },
        { status: 400 }
      )
    }

    // Validate event type
    if (!Object.values(AuditEventType).includes(eventType)) {
      return NextResponse.json(
        { error: 'Invalid event type' },
        { status: 400 }
      )
    }

    // Validate severity
    if (!Object.values(AuditSeverity).includes(severity)) {
      return NextResponse.json(
        { error: 'Invalid severity level' },
        { status: 400 }
      )
    }

    const clientIP = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const userAgent = request.headers.get('user-agent') || 'unknown'

    // Log audit event
    await auditService.logEvent({
      eventType,
      severity,
      userId,
      sessionId,
      ipAddress: clientIP,
      userAgent,
      resource,
      action,
      details: {
        ...details,
        clientSubmitted: true,
        submittedAt: new Date().toISOString()
      },
      timestamp: new Date(),
      correlationId,
      complianceFlags: complianceFlags || {
        gdprRelevant: false,
        ccpaRelevant: false,
        soc2Relevant: true
      }
    })

    logger.info('Audit API', `Client audit event logged: ${eventType}`, {
      userId,
      sessionId,
      severity,
      correlationId
    })

    return NextResponse.json({
      success: true,
      eventType,
      severity,
      message: 'Audit event logged successfully'
    })

  } catch (error) {
    logger.error('Audit API', 'Failed to log audit event', error)
    return NextResponse.json(
      { error: 'Failed to log audit event' },
      { status: 500 }
    )
  }
}

/**
 * GET /api/compliance/audit
 * Query audit events (admin only)
 */
export async function GET(request: NextRequest) {
  try {
    // TODO: Add authentication check for admin/compliance officer roles
    
    const { searchParams } = new URL(request.url)
    const eventTypes = searchParams.get('eventTypes')?.split(',') as AuditEventType[]
    const userId = searchParams.get('userId')
    const startDate = searchParams.get('startDate')
    const endDate = searchParams.get('endDate')
    const severity = searchParams.get('severity') as AuditSeverity
    const correlationId = searchParams.get('correlationId')
    const limit = parseInt(searchParams.get('limit') || '50')
    const offset = parseInt(searchParams.get('offset') || '0')

    // Build filters
    const filters: any = {}
    
    if (eventTypes?.length) {
      filters.eventTypes = eventTypes
    }
    
    if (userId) {
      filters.userId = userId
    }
    
    if (startDate) {
      filters.startDate = new Date(startDate)
    }
    
    if (endDate) {
      filters.endDate = new Date(endDate)
    }
    
    if (severity) {
      filters.severity = severity
    }
    
    if (correlationId) {
      filters.correlationId = correlationId
    }
    
    filters.limit = limit
    filters.offset = offset

    // Query audit events
    const events = await auditService.queryEvents(filters)

    return NextResponse.json({
      success: true,
      events,
      filters,
      count: events.length
    })

  } catch (error) {
    logger.error('Audit API', 'Failed to query audit events', error)
    return NextResponse.json(
      { error: 'Failed to query audit events' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/compliance/audit/report
 * Generate compliance report
 */
export async function PUT(request: NextRequest) {
  try {
    // TODO: Add authentication check for admin/compliance officer roles
    
    const body = await request.json()
    const { startDate, endDate, complianceType } = body

    // Validate required fields
    if (!startDate || !endDate || !complianceType) {
      return NextResponse.json(
        { error: 'Missing required fields: startDate, endDate, complianceType' },
        { status: 400 }
      )
    }

    // Validate compliance type
    const validTypes = ['gdpr', 'ccpa', 'soc2']
    if (!validTypes.includes(complianceType)) {
      return NextResponse.json(
        { error: 'Invalid compliance type. Must be: gdpr, ccpa, or soc2' },
        { status: 400 }
      )
    }

    // Generate compliance report
    const report = await auditService.generateComplianceReport(
      new Date(startDate),
      new Date(endDate),
      complianceType
    )

    logger.info('Audit API', `Compliance report generated: ${complianceType}`, {
      startDate,
      endDate,
      totalEvents: report.totalEvents
    })

    return NextResponse.json({
      success: true,
      report,
      complianceType,
      period: { startDate, endDate }
    })

  } catch (error) {
    logger.error('Audit API', 'Failed to generate compliance report', error)
    return NextResponse.json(
      { error: 'Failed to generate compliance report' },
      { status: 500 }
    )
  }
}
