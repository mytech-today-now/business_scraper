/**
 * Comprehensive Security Audit Service
 * Implements security logging, monitoring, and alerting for authentication events
 */

import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'

export interface SecurityEvent {
  id: string
  timestamp: Date
  eventType: SecurityEventType
  severity: SecuritySeverity
  userId?: string
  sessionId?: string
  ipAddress?: string
  userAgent?: string
  resource?: string
  action?: string
  details: Record<string, any>
  riskScore: number
  geolocation?: {
    country?: string
    region?: string
    city?: string
    coordinates?: [number, number]
  }
}

export enum SecurityEventType {
  // Authentication events
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  LOGOUT = 'logout',
  MFA_SUCCESS = 'mfa_success',
  MFA_FAILURE = 'mfa_failure',
  PASSWORD_CHANGE = 'password_change',
  PASSWORD_RESET = 'password_reset',
  
  // Session events
  SESSION_CREATED = 'session_created',
  SESSION_EXPIRED = 'session_expired',
  SESSION_INVALIDATED = 'session_invalidated',
  SESSION_HIJACKING_ATTEMPT = 'session_hijacking_attempt',
  
  // Access control events
  ACCESS_GRANTED = 'access_granted',
  ACCESS_DENIED = 'access_denied',
  PRIVILEGE_ESCALATION_ATTEMPT = 'privilege_escalation_attempt',
  
  // Security violations
  BRUTE_FORCE_ATTACK = 'brute_force_attack',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  IP_BLOCKED = 'ip_blocked',
  
  // Data access events
  DATA_ACCESS = 'data_access',
  DATA_EXPORT = 'data_export',
  DATA_MODIFICATION = 'data_modification',
  DATA_DELETION = 'data_deletion',
  
  // System events
  SYSTEM_ERROR = 'system_error',
  CONFIGURATION_CHANGE = 'configuration_change',
  SECURITY_POLICY_VIOLATION = 'security_policy_violation'
}

export enum SecuritySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface SecurityAlert {
  id: string
  timestamp: Date
  alertType: string
  severity: SecuritySeverity
  title: string
  description: string
  events: SecurityEvent[]
  riskScore: number
  actionRequired: boolean
  acknowledged: boolean
  acknowledgedBy?: string
  acknowledgedAt?: Date
}

export interface SecurityMetrics {
  totalEvents: number
  eventsByType: Record<SecurityEventType, number>
  eventsBySeverity: Record<SecuritySeverity, number>
  riskScore: number
  alertsGenerated: number
  activeThreats: number
  blockedIPs: number
  failedLogins: number
  successfulLogins: number
  timeRange: {
    start: Date
    end: Date
  }
}

// In-memory stores (in production, these should be in database)
const securityEvents = new Map<string, SecurityEvent>()
const securityAlerts = new Map<string, SecurityAlert>()
const blockedIPs = new Set<string>()
const suspiciousIPs = new Map<string, { count: number; lastSeen: Date; riskScore: number }>()

export class SecurityAuditService {
  private static instance: SecurityAuditService

  static getInstance(): SecurityAuditService {
    if (!SecurityAuditService.instance) {
      SecurityAuditService.instance = new SecurityAuditService()
    }
    return SecurityAuditService.instance
  }

  /**
   * Log security event
   */
  async logSecurityEvent(
    eventType: SecurityEventType,
    details: Record<string, any>,
    request?: NextRequest
  ): Promise<SecurityEvent> {
    try {
      const eventId = this.generateEventId()
      const timestamp = new Date()
      
      // Extract request information if available
      let ipAddress: string | undefined
      let userAgent: string | undefined
      let geolocation: SecurityEvent['geolocation'] | undefined

      if (request) {
        ipAddress = this.getClientIP(request)
        userAgent = request.headers.get('user-agent') || undefined
        
        // Extract geolocation if available
        if (request.geo) {
          geolocation = {
            country: request.geo.country,
            region: request.geo.region,
            city: request.geo.city,
            coordinates: request.geo.latitude && request.geo.longitude 
              ? [parseFloat(request.geo.latitude), parseFloat(request.geo.longitude)]
              : undefined
          }
        }
      }

      // Calculate risk score
      const riskScore = this.calculateRiskScore(eventType, details, ipAddress)

      // Determine severity
      const severity = this.determineSeverity(eventType, riskScore, details)

      const event: SecurityEvent = {
        id: eventId,
        timestamp,
        eventType,
        severity,
        userId: details.userId,
        sessionId: details.sessionId,
        ipAddress,
        userAgent,
        resource: details.resource,
        action: details.action,
        details,
        riskScore,
        geolocation
      }

      // Store event
      securityEvents.set(eventId, event)

      // Log to application logger
      logger.info('SecurityAudit', `Security event: ${eventType}`, {
        eventId,
        severity,
        riskScore,
        userId: details.userId,
        ipAddress
      })

      // Check for suspicious activity patterns
      await this.analyzeSecurityPatterns(event)

      // Generate alerts if necessary
      await this.checkForAlerts(event)

      return event
    } catch (error) {
      logger.error('SecurityAudit', 'Failed to log security event', error)
      throw new Error('Security event logging failed')
    }
  }

  /**
   * Generate security alert
   */
  async generateAlert(
    alertType: string,
    title: string,
    description: string,
    events: SecurityEvent[],
    severity: SecuritySeverity = SecuritySeverity.MEDIUM
  ): Promise<SecurityAlert> {
    const alertId = this.generateEventId()
    const timestamp = new Date()
    
    // Calculate combined risk score
    const riskScore = events.reduce((sum, event) => sum + event.riskScore, 0) / events.length

    const alert: SecurityAlert = {
      id: alertId,
      timestamp,
      alertType,
      severity,
      title,
      description,
      events,
      riskScore,
      actionRequired: severity === SecuritySeverity.HIGH || severity === SecuritySeverity.CRITICAL,
      acknowledged: false
    }

    securityAlerts.set(alertId, alert)

    logger.warn('SecurityAudit', `Security alert generated: ${title}`, {
      alertId,
      alertType,
      severity,
      riskScore,
      eventCount: events.length
    })

    // Send notifications for high/critical alerts
    if (alert.actionRequired) {
      await this.sendSecurityNotification(alert)
    }

    return alert
  }

  /**
   * Analyze security patterns and detect threats
   */
  private async analyzeSecurityPatterns(event: SecurityEvent): Promise<void> {
    const ipAddress = event.ipAddress
    if (!ipAddress) return

    // Track suspicious IP activity
    const suspiciousActivity = suspiciousIPs.get(ipAddress) || { count: 0, lastSeen: new Date(), riskScore: 0 }
    
    // Update suspicious activity tracking
    if (this.isSuspiciousEvent(event)) {
      suspiciousActivity.count++
      suspiciousActivity.lastSeen = event.timestamp
      suspiciousActivity.riskScore = Math.min(100, suspiciousActivity.riskScore + event.riskScore)
      
      suspiciousIPs.set(ipAddress, suspiciousActivity)

      // Check for brute force attacks
      if (event.eventType === SecurityEventType.LOGIN_FAILURE) {
        await this.checkForBruteForceAttack(ipAddress, event)
      }

      // Check for session hijacking attempts
      if (event.eventType === SecurityEventType.SESSION_HIJACKING_ATTEMPT) {
        await this.handleSessionHijackingAttempt(event)
      }

      // Auto-block IPs with high risk scores
      if (suspiciousActivity.riskScore >= 80) {
        await this.blockIP(ipAddress, 'High risk score threshold exceeded')
      }
    }
  }

  /**
   * Check for brute force attacks
   */
  private async checkForBruteForceAttack(ipAddress: string, event: SecurityEvent): Promise<void> {
    const recentEvents = this.getRecentEventsByIP(ipAddress, 15 * 60 * 1000) // Last 15 minutes
    const failedLogins = recentEvents.filter(e => e.eventType === SecurityEventType.LOGIN_FAILURE)

    if (failedLogins.length >= 5) {
      await this.generateAlert(
        'brute_force_attack',
        'Brute Force Attack Detected',
        `Multiple failed login attempts detected from IP ${ipAddress}`,
        failedLogins,
        SecuritySeverity.HIGH
      )

      // Auto-block IP
      await this.blockIP(ipAddress, 'Brute force attack detected')
    }
  }

  /**
   * Handle session hijacking attempts
   */
  private async handleSessionHijackingAttempt(event: SecurityEvent): Promise<void> {
    await this.generateAlert(
      'session_hijacking',
      'Session Hijacking Attempt',
      'Potential session hijacking attempt detected',
      [event],
      SecuritySeverity.CRITICAL
    )

    // Immediately invalidate the session
    if (event.sessionId) {
      // This would integrate with session management
      logger.warn('SecurityAudit', `Session ${event.sessionId} should be invalidated due to hijacking attempt`)
    }
  }

  /**
   * Block IP address
   */
  async blockIP(ipAddress: string, reason: string): Promise<void> {
    blockedIPs.add(ipAddress)
    
    await this.logSecurityEvent(SecurityEventType.IP_BLOCKED, {
      ipAddress,
      reason,
      timestamp: new Date()
    })

    logger.warn('SecurityAudit', `Blocked IP address: ${ipAddress} - ${reason}`)
  }

  /**
   * Check if IP is blocked
   */
  isIPBlocked(ipAddress: string): boolean {
    return blockedIPs.has(ipAddress)
  }

  /**
   * Get recent events by IP
   */
  private getRecentEventsByIP(ipAddress: string, timeWindowMs: number): SecurityEvent[] {
    const cutoffTime = new Date(Date.now() - timeWindowMs)
    return Array.from(securityEvents.values())
      .filter(event => event.ipAddress === ipAddress && event.timestamp > cutoffTime)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
  }

  /**
   * Calculate risk score for event
   */
  private calculateRiskScore(
    eventType: SecurityEventType,
    details: Record<string, any>,
    ipAddress?: string
  ): number {
    let baseScore = 0

    // Base scores by event type
    switch (eventType) {
      case SecurityEventType.LOGIN_FAILURE:
        baseScore = 20
        break
      case SecurityEventType.MFA_FAILURE:
        baseScore = 30
        break
      case SecurityEventType.SESSION_HIJACKING_ATTEMPT:
        baseScore = 90
        break
      case SecurityEventType.BRUTE_FORCE_ATTACK:
        baseScore = 80
        break
      case SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT:
        baseScore = 85
        break
      case SecurityEventType.LOGIN_SUCCESS:
        baseScore = 5
        break
      default:
        baseScore = 10
    }

    // Adjust based on IP reputation
    if (ipAddress) {
      const suspiciousActivity = suspiciousIPs.get(ipAddress)
      if (suspiciousActivity) {
        baseScore += Math.min(30, suspiciousActivity.count * 5)
      }
    }

    // Adjust based on details
    if (details.failedAttempts && details.failedAttempts > 1) {
      baseScore += Math.min(40, details.failedAttempts * 10)
    }

    return Math.min(100, baseScore)
  }

  /**
   * Determine event severity
   */
  private determineSeverity(
    eventType: SecurityEventType,
    riskScore: number,
    details: Record<string, any>
  ): SecuritySeverity {
    // Critical events
    if ([
      SecurityEventType.SESSION_HIJACKING_ATTEMPT,
      SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT
    ].includes(eventType)) {
      return SecuritySeverity.CRITICAL
    }

    // High severity based on risk score
    if (riskScore >= 70) {
      return SecuritySeverity.HIGH
    }

    // Medium severity events
    if ([
      SecurityEventType.LOGIN_FAILURE,
      SecurityEventType.MFA_FAILURE,
      SecurityEventType.ACCESS_DENIED
    ].includes(eventType) || riskScore >= 40) {
      return SecuritySeverity.MEDIUM
    }

    return SecuritySeverity.LOW
  }

  /**
   * Check if event is suspicious
   */
  private isSuspiciousEvent(event: SecurityEvent): boolean {
    return [
      SecurityEventType.LOGIN_FAILURE,
      SecurityEventType.MFA_FAILURE,
      SecurityEventType.SESSION_HIJACKING_ATTEMPT,
      SecurityEventType.ACCESS_DENIED,
      SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT,
      SecurityEventType.RATE_LIMIT_EXCEEDED
    ].includes(event.eventType)
  }

  /**
   * Get client IP address
   */
  private getClientIP(request: NextRequest): string {
    return request.headers.get('x-forwarded-for')?.split(',')[0] ||
           request.headers.get('x-real-ip') ||
           request.ip ||
           'unknown'
  }

  /**
   * Check for alerts based on event patterns
   */
  private async checkForAlerts(event: SecurityEvent): Promise<void> {
    // This would implement various alert conditions
    // For now, we'll generate alerts for high-severity events
    if (event.severity === SecuritySeverity.HIGH || event.severity === SecuritySeverity.CRITICAL) {
      await this.generateAlert(
        event.eventType,
        `${event.severity.toUpperCase()} Security Event`,
        `Security event of type ${event.eventType} detected`,
        [event],
        event.severity
      )
    }
  }

  /**
   * Generate event ID
   */
  private generateEventId(): string {
    // Use a combination of timestamp and random number for unique ID
    const timestamp = Date.now().toString(36)
    const random = Math.random().toString(36).substring(2)
    return `${timestamp}-${random}`
  }

  /**
   * Send security notification
   */
  private async sendSecurityNotification(alert: SecurityAlert): Promise<void> {
    // This would integrate with notification systems (email, Slack, etc.)
    logger.warn('SecurityAudit', `Security notification should be sent for alert: ${alert.title}`)
  }

  /**
   * Get security metrics
   */
  getSecurityMetrics(timeRangeMs: number = 24 * 60 * 60 * 1000): SecurityMetrics {
    const now = new Date()
    const startTime = new Date(now.getTime() - timeRangeMs)
    
    const recentEvents = Array.from(securityEvents.values())
      .filter(event => event.timestamp >= startTime)

    const eventsByType = {} as Record<SecurityEventType, number>
    const eventsBySeverity = {} as Record<SecuritySeverity, number>

    // Initialize counters
    Object.values(SecurityEventType).forEach(type => {
      eventsByType[type] = 0
    })
    Object.values(SecuritySeverity).forEach(severity => {
      eventsBySeverity[severity] = 0
    })

    // Count events
    recentEvents.forEach(event => {
      eventsByType[event.eventType]++
      eventsBySeverity[event.severity]++
    })

    // Calculate average risk score
    const totalRiskScore = recentEvents.reduce((sum, event) => sum + event.riskScore, 0)
    const avgRiskScore = recentEvents.length > 0 ? totalRiskScore / recentEvents.length : 0

    return {
      totalEvents: recentEvents.length,
      eventsByType,
      eventsBySeverity,
      riskScore: avgRiskScore,
      alertsGenerated: Array.from(securityAlerts.values())
        .filter(alert => alert.timestamp >= startTime).length,
      activeThreats: suspiciousIPs.size,
      blockedIPs: blockedIPs.size,
      failedLogins: eventsByType[SecurityEventType.LOGIN_FAILURE] || 0,
      successfulLogins: eventsByType[SecurityEventType.LOGIN_SUCCESS] || 0,
      timeRange: {
        start: startTime,
        end: now
      }
    }
  }
}

// Export singleton instance
export const securityAuditService = SecurityAuditService.getInstance()
