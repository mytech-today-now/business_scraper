/**
 * Security Monitoring Dashboard API
 * Business Scraper Application - Real-time Security Metrics & Alerts
 */

import { NextRequest, NextResponse } from 'next/server'
import { securityLogger } from '@/lib/securityLogger'
import { authenticationMonitor } from '@/lib/authenticationMonitor'
import { securityAlertManager } from '@/lib/securityAlerts'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

/**
 * Get security monitoring dashboard data
 */
export async function GET(request: NextRequest) {
  try {
    const clientIP = getClientIP(request)
    const { searchParams } = new URL(request.url)
    const timeWindow = parseInt(searchParams.get('timeWindow') || '24') // hours
    const includeDetails = searchParams.get('details') === 'true'

    // Log access to security monitoring
    logger.info('SecurityMonitoring', 'Dashboard accessed', {
      clientIP,
      timeWindow,
      includeDetails
    })

    // Get security metrics
    const securityMetrics = securityLogger.getSecurityMetrics(timeWindow)
    const authStats = authenticationMonitor.getAuthStats(timeWindow)
    const alertStats = securityAlertManager.getAlertStats(timeWindow)

    // Get recent events if details requested
    let recentEvents = []
    let recentAlerts = []
    let authPatterns = []

    if (includeDetails) {
      recentEvents = securityLogger.getRecentEvents(50)
      recentAlerts = securityAlertManager.getRecentAlerts(25)
      authPatterns = authenticationMonitor.getAuthPatterns().slice(0, 20)
    }

    // Calculate overall security score
    const securityScore = calculateSecurityScore(securityMetrics, authStats, alertStats)

    const dashboardData = {
      timestamp: new Date().toISOString(),
      timeWindow: `${timeWindow} hours`,
      securityScore,
      overview: {
        totalSecurityEvents: securityMetrics.totalEvents,
        blockedEvents: securityMetrics.blockedEvents,
        averageRiskScore: securityMetrics.averageRiskScore,
        uniqueThreats: securityMetrics.uniqueIPs,
        totalAlerts: alertStats.totalAlerts,
        criticalAlerts: alertStats.alertsBySeverity.CRITICAL || 0,
        authenticationAttempts: authStats.totalAttempts,
        failedLogins: authStats.failedLogins,
        blockedIPs: authStats.blockedIPs
      },
      metrics: {
        security: securityMetrics,
        authentication: authStats,
        alerts: alertStats
      },
      ...(includeDetails && {
        details: {
          recentEvents: recentEvents.map(event => ({
            id: event.id,
            timestamp: event.timestamp,
            type: event.type,
            severity: event.severity,
            source: event.source,
            ip: event.ip,
            blocked: event.blocked,
            riskScore: event.riskScore
          })),
          recentAlerts: recentAlerts.map(alert => ({
            id: alert.id,
            timestamp: alert.timestamp,
            severity: alert.severity,
            title: alert.title,
            acknowledged: alert.acknowledged,
            resolved: alert.resolved
          })),
          authPatterns: authPatterns.map(pattern => ({
            ip: pattern.ip,
            attempts: pattern.attempts,
            failedLogins: pattern.failedLogins,
            riskScore: pattern.riskScore,
            isBlocked: pattern.isBlocked,
            usernames: pattern.usernames.size,
            userAgents: pattern.userAgents.size
          }))
        }
      })
    }

    return NextResponse.json(dashboardData)

  } catch (error) {
    logger.error('SecurityMonitoring', 'Dashboard error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      clientIP: getClientIP(request)
    })

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

/**
 * Get security alerts
 */
export async function POST(request: NextRequest) {
  try {
    const clientIP = getClientIP(request)
    const body = await request.json()
    const { action, alertId, acknowledgedBy, resolvedBy } = body

    logger.info('SecurityMonitoring', 'Alert action requested', {
      clientIP,
      action,
      alertId
    })

    let result = false

    switch (action) {
      case 'acknowledge':
        if (alertId && acknowledgedBy) {
          result = securityAlertManager.acknowledgeAlert(alertId, acknowledgedBy)
        }
        break

      case 'resolve':
        if (alertId && resolvedBy) {
          result = securityAlertManager.resolveAlert(alertId, resolvedBy)
        }
        break

      default:
        return NextResponse.json(
          { error: 'Invalid action' },
          { status: 400 }
        )
    }

    if (result) {
      return NextResponse.json({ success: true })
    } else {
      return NextResponse.json(
        { error: 'Action failed' },
        { status: 400 }
      )
    }

  } catch (error) {
    logger.error('SecurityMonitoring', 'Alert action error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      clientIP: getClientIP(request)
    })

    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

/**
 * Calculate overall security score
 */
function calculateSecurityScore(
  securityMetrics: any,
  authStats: any,
  alertStats: any
): {
  score: number
  level: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' | 'CRITICAL'
  factors: Array<{ factor: string; impact: number; description: string }>
} {
  let score = 100
  const factors: Array<{ factor: string; impact: number; description: string }> = []

  // Factor 1: Average risk score
  if (securityMetrics.averageRiskScore > 7) {
    const impact = -20
    score += impact
    factors.push({
      factor: 'High Risk Events',
      impact,
      description: `Average risk score is ${securityMetrics.averageRiskScore}/10`
    })
  } else if (securityMetrics.averageRiskScore > 5) {
    const impact = -10
    score += impact
    factors.push({
      factor: 'Medium Risk Events',
      impact,
      description: `Average risk score is ${securityMetrics.averageRiskScore}/10`
    })
  }

  // Factor 2: Blocked events ratio
  const blockedRatio = securityMetrics.totalEvents > 0 
    ? securityMetrics.blockedEvents / securityMetrics.totalEvents 
    : 0

  if (blockedRatio > 0.1) {
    const impact = -15
    score += impact
    factors.push({
      factor: 'High Block Rate',
      impact,
      description: `${(blockedRatio * 100).toFixed(1)}% of events were blocked`
    })
  }

  // Factor 3: Failed login ratio
  const failedLoginRatio = authStats.totalAttempts > 0 
    ? authStats.failedLogins / authStats.totalAttempts 
    : 0

  if (failedLoginRatio > 0.5) {
    const impact = -15
    score += impact
    factors.push({
      factor: 'High Failed Login Rate',
      impact,
      description: `${(failedLoginRatio * 100).toFixed(1)}% of login attempts failed`
    })
  }

  // Factor 4: Critical alerts
  const criticalAlerts = alertStats.alertsBySeverity.CRITICAL || 0
  if (criticalAlerts > 0) {
    const impact = -25
    score += impact
    factors.push({
      factor: 'Critical Alerts',
      impact,
      description: `${criticalAlerts} critical security alerts`
    })
  }

  // Factor 5: Blocked IPs
  if (authStats.blockedIPs > 10) {
    const impact = -10
    score += impact
    factors.push({
      factor: 'Many Blocked IPs',
      impact,
      description: `${authStats.blockedIPs} IP addresses are currently blocked`
    })
  }

  // Factor 6: Suspicious patterns
  if (authStats.suspiciousPatterns > 5) {
    const impact = -10
    score += impact
    factors.push({
      factor: 'Suspicious Activity',
      impact,
      description: `${authStats.suspiciousPatterns} suspicious authentication patterns detected`
    })
  }

  // Ensure score is within bounds
  score = Math.max(0, Math.min(100, score))

  // Determine security level
  let level: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' | 'CRITICAL'
  if (score >= 90) level = 'EXCELLENT'
  else if (score >= 75) level = 'GOOD'
  else if (score >= 60) level = 'FAIR'
  else if (score >= 40) level = 'POOR'
  else level = 'CRITICAL'

  return { score, level, factors }
}

/**
 * Handle OPTIONS requests for CORS
 */
export async function OPTIONS() {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  })
}
