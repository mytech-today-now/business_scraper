/**
 * Security Monitoring API
 * Provides access to security events, statistics, and monitoring data
 */

import { NextRequest, NextResponse } from 'next/server'
import { securityMonitoringService, SecurityEventType, SecuritySeverity } from '@/lib/securityMonitoring'
import { getClientIP, getSession } from '@/lib/security'
import { logger } from '@/utils/logger'

/**
 * Interface for security event filter
 */
interface SecurityEventFilter {
  type?: SecurityEventType
  severity?: SecuritySeverity
  ip?: string
  since?: number
  limit?: number
}

/**
 * Interface for security event
 */
interface SecurityEvent {
  id: string
  type: SecurityEventType
  severity: SecuritySeverity
  ip: string
  timestamp: Date
  message: string
  details?: Record<string, unknown>
  userAgent?: string
  endpoint?: string
}

/**
 * GET /api/security - Get security monitoring data
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    // Check authentication
    const sessionId = request.cookies.get('session-id')?.value
    if (!sessionId) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const session = getSession(sessionId)
    if (!session || !session.isValid) {
      return NextResponse.json(
        { error: 'Invalid session' },
        { status: 401 }
      )
    }

    const url = new URL(request.url)
    const action = url.searchParams.get('action') || 'stats'
    
    logger.info('Security API', `Security monitoring request: ${action} from IP: ${ip}`)

    switch (action) {
      case 'stats':
        // Get security statistics
        const stats = securityMonitoringService.getSecurityStats()
        return NextResponse.json({
          success: true,
          stats
        })

      case 'events':
        // Get security events with optional filtering
        const type = url.searchParams.get('type') as SecurityEventType | null
        const severity = url.searchParams.get('severity') as SecuritySeverity | null
        const filterIP = url.searchParams.get('ip')
        const since = url.searchParams.get('since')
        const limit = url.searchParams.get('limit')

        const filter: SecurityEventFilter = {}
        if (type) filter.type = type
        if (severity) filter.severity = severity
        if (filterIP) filter.ip = filterIP
        if (since) filter.since = parseInt(since, 10)
        if (limit) filter.limit = parseInt(limit, 10)

        const events = securityMonitoringService.getSecurityEvents(filter)
        
        return NextResponse.json({
          success: true,
          events,
          total: events.length
        })

      case 'suspicious-ips':
        // Get list of suspicious IPs
        const recentEvents = securityMonitoringService.getSecurityEvents({
          severity: 'high',
          since: Date.now() - 24 * 60 * 60 * 1000 // Last 24 hours
        })

        const suspiciousIPs = Array.from(
          new Set(recentEvents.map(event => event.ip))
        ).map(suspiciousIP => ({
          ip: suspiciousIP,
          isSuspicious: securityMonitoringService.isSuspiciousIP(suspiciousIP),
          eventCount: recentEvents.filter(event => event.ip === suspiciousIP).length,
          lastSeen: Math.max(...recentEvents
            .filter(event => event.ip === suspiciousIP)
            .map(event => event.timestamp))
        }))

        return NextResponse.json({
          success: true,
          suspiciousIPs
        })

      case 'threat-summary':
        // Get threat summary for dashboard
        const now = Date.now()
        const oneHour = 60 * 60 * 1000
        const oneDay = 24 * oneHour

        const hourlyEvents = securityMonitoringService.getSecurityEvents({
          since: now - oneHour
        })

        const dailyEvents = securityMonitoringService.getSecurityEvents({
          since: now - oneDay
        })

        const criticalEvents = securityMonitoringService.getSecurityEvents({
          severity: 'critical',
          since: now - oneDay
        })

        const highSeverityEvents = securityMonitoringService.getSecurityEvents({
          severity: 'high',
          since: now - oneDay
        })

        return NextResponse.json({
          success: true,
          summary: {
            hourlyEvents: hourlyEvents.length,
            dailyEvents: dailyEvents.length,
            criticalEvents: criticalEvents.length,
            highSeverityEvents: highSeverityEvents.length,
            topThreats: this.getTopThreats(dailyEvents),
            recentBlocked: dailyEvents.filter(event => event.blocked).length
          }
        })

      case 'export':
        // Export security events as CSV
        const exportEvents = securityMonitoringService.getSecurityEvents({
          since: Date.now() - 7 * 24 * 60 * 60 * 1000 // Last 7 days
        })

        const csv = this.generateCSVReport(exportEvents)
        
        return new NextResponse(csv, {
          headers: {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename="security-events.csv"'
          }
        })

      default:
        return NextResponse.json(
          { error: 'Invalid action parameter' },
          { status: 400 }
        )
    }

  } catch (error) {
    logger.error('Security API', `Error processing security request from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/security - Manual security operations
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    // Check authentication
    const sessionId = request.cookies.get('session-id')?.value
    if (!sessionId) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const session = getSession(sessionId)
    if (!session || !session.isValid) {
      return NextResponse.json(
        { error: 'Invalid session' },
        { status: 401 }
      )
    }

    const body = await request.json()
    const { action, ...params } = body

    logger.info('Security API', `Security action request: ${action} from IP: ${ip}`)

    switch (action) {
      case 'cleanup':
        // Manual cleanup of old events
        securityMonitoringService.cleanup()
        return NextResponse.json({
          success: true,
          message: 'Security monitoring data cleaned up'
        })

      case 'analyze-request':
        // Analyze a specific request for threats
        const { url: targetUrl, method, headers, requestBody } = params
        
        if (!targetUrl) {
          return NextResponse.json(
            { error: 'URL parameter is required' },
            { status: 400 }
          )
        }

        // Create a mock request for analysis
        const mockRequest = {
          nextUrl: new URL(targetUrl),
          method: method || 'GET',
          headers: new Map(Object.entries(headers || {})),
          cookies: { get: () => undefined }
        } as NextRequest

        const threats = securityMonitoringService.analyzeRequest(mockRequest, requestBody)
        
        return NextResponse.json({
          success: true,
          threats,
          threatCount: threats.length
        })

      default:
        return NextResponse.json(
          { error: 'Invalid action parameter' },
          { status: 400 }
        )
    }

  } catch (error) {
    logger.error('Security API', `Error processing security action from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

/**
 * Helper function to get top threats
 */
function getTopThreats(events: SecurityEvent[]): Array<{ type: string; count: number }> {
  const threatCounts: Record<string, number> = {}
  
  for (const event of events) {
    threatCounts[event.type] = (threatCounts[event.type] || 0) + 1
  }

  return Object.entries(threatCounts)
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
}

/**
 * Helper function to generate CSV report
 */
function generateCSVReport(events: SecurityEvent[]): string {
  const headers = [
    'Timestamp',
    'Type',
    'Severity',
    'IP',
    'Endpoint',
    'Method',
    'User Agent',
    'Blocked',
    'Details'
  ]

  const rows = events.map(event => [
    new Date(event.timestamp).toISOString(),
    event.type,
    event.severity,
    event.ip,
    event.endpoint || '',
    event.method || '',
    event.userAgent || '',
    event.blocked ? 'Yes' : 'No',
    JSON.stringify(event.details)
  ])

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
  ].join('\n')

  return csvContent
}
