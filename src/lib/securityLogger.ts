/**
 * Enhanced Security Logging & Monitoring System
 * Business Scraper Application - Comprehensive Security Event Tracking
 */

import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import { getClientIP } from './security'
import crypto from 'crypto'

/**
 * Security event types for comprehensive monitoring
 */
export enum SecurityEventType {
  // Authentication Events
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGIN_BLOCKED = 'LOGIN_BLOCKED',
  SESSION_CREATED = 'SESSION_CREATED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_HIJACK_ATTEMPT = 'SESSION_HIJACK_ATTEMPT',

  // Authorization Events
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION',
  FORBIDDEN_RESOURCE = 'FORBIDDEN_RESOURCE',

  // Input Validation Events
  SQL_INJECTION_ATTEMPT = 'SQL_INJECTION_ATTEMPT',
  XSS_ATTEMPT = 'XSS_ATTEMPT',
  CSRF_VIOLATION = 'CSRF_VIOLATION',
  MALICIOUS_INPUT = 'MALICIOUS_INPUT',

  // Rate Limiting Events
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  BRUTE_FORCE_ATTEMPT = 'BRUTE_FORCE_ATTEMPT',

  // Data Access Events
  SENSITIVE_DATA_ACCESS = 'SENSITIVE_DATA_ACCESS',
  DATA_EXPORT = 'DATA_EXPORT',
  BULK_DATA_ACCESS = 'BULK_DATA_ACCESS',
  UNAUTHORIZED_DATA_ACCESS = 'UNAUTHORIZED_DATA_ACCESS',

  // System Events
  CONFIGURATION_CHANGE = 'CONFIGURATION_CHANGE',
  SECURITY_POLICY_VIOLATION = 'SECURITY_POLICY_VIOLATION',
  ANOMALOUS_BEHAVIOR = 'ANOMALOUS_BEHAVIOR',
  SYSTEM_COMPROMISE_INDICATOR = 'SYSTEM_COMPROMISE_INDICATOR',
}

/**
 * Security event severity levels
 */
export enum SecuritySeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

/**
 * Security event interface
 */
export interface SecurityEvent {
  id: string
  timestamp: Date
  type: SecurityEventType
  severity: SecuritySeverity
  source: string
  ip: string
  userAgent?: string
  sessionId?: string
  userId?: string
  endpoint?: string
  method?: string
  details: Record<string, any>
  blocked: boolean
  riskScore: number
}

/**
 * Alert configuration
 */
export interface AlertConfig {
  enabled: boolean
  thresholds: {
    [key in SecuritySeverity]: number
  }
  timeWindow: number // minutes
  cooldown: number // minutes
}

/**
 * Security metrics for monitoring
 */
export interface SecurityMetrics {
  totalEvents: number
  eventsByType: Record<SecurityEventType, number>
  eventsBySeverity: Record<SecuritySeverity, number>
  blockedEvents: number
  uniqueIPs: number
  averageRiskScore: number
  topThreats: Array<{ type: SecurityEventType; count: number }>
  recentAlerts: number
}

/**
 * Enhanced Security Logger Service
 */
export class SecurityLogger {
  private events: SecurityEvent[] = []
  private alerts: Array<{ timestamp: Date; message: string; severity: SecuritySeverity }> = []
  private suspiciousIPs = new Set<string>()
  private blockedIPs = new Set<string>()
  private maxEvents = 10000
  private maxAlerts = 1000

  private alertConfig: AlertConfig = {
    enabled: true,
    thresholds: {
      [SecuritySeverity.LOW]: 50,
      [SecuritySeverity.MEDIUM]: 20,
      [SecuritySeverity.HIGH]: 10,
      [SecuritySeverity.CRITICAL]: 3,
    },
    timeWindow: 60, // 1 hour
    cooldown: 15, // 15 minutes
  }

  private lastAlertTime = new Map<string, Date>()

  /**
   * Log a security event with comprehensive details
   */
  logSecurityEvent(
    type: SecurityEventType,
    severity: SecuritySeverity,
    source: string,
    details: Record<string, any> = {},
    request?: NextRequest,
    blocked: boolean = false
  ): SecurityEvent {
    const event: SecurityEvent = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      type,
      severity,
      source,
      ip: request ? getClientIP(request) : details.ip || 'unknown',
      userAgent: request?.headers.get('user-agent') || details.userAgent,
      sessionId: request?.cookies.get('session-id')?.value || details.sessionId,
      userId: details.userId,
      endpoint: request?.nextUrl.pathname || details.endpoint,
      method: request?.method || details.method,
      details,
      blocked,
      riskScore: this.calculateRiskScore(type, severity, details),
    }

    // Store event
    this.events.push(event)
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(-this.maxEvents)
    }

    // Track suspicious IPs
    if (severity === SecuritySeverity.HIGH || severity === SecuritySeverity.CRITICAL) {
      this.suspiciousIPs.add(event.ip)
    }

    // Track blocked IPs
    if (blocked) {
      this.blockedIPs.add(event.ip)
    }

    // Log to application logger
    const logLevel = this.getLogLevel(severity)
    logger[logLevel]('SecurityLogger', `${type}: ${details.message || 'Security event'}`, {
      eventId: event.id,
      ip: event.ip,
      endpoint: event.endpoint,
      severity,
      blocked,
      riskScore: event.riskScore,
      details: this.sanitizeDetails(details),
    })

    // Check for alerts
    this.checkAlerts(event)

    return event
  }

  /**
   * Log authentication events
   */
  logAuthEvent(
    type:
      | SecurityEventType.LOGIN_SUCCESS
      | SecurityEventType.LOGIN_FAILURE
      | SecurityEventType.LOGIN_BLOCKED,
    request: NextRequest,
    details: { username?: string; reason?: string } = {}
  ): SecurityEvent {
    const severity =
      type === SecurityEventType.LOGIN_SUCCESS
        ? SecuritySeverity.LOW
        : type === SecurityEventType.LOGIN_BLOCKED
          ? SecuritySeverity.HIGH
          : SecuritySeverity.MEDIUM

    return this.logSecurityEvent(
      type,
      severity,
      'authentication',
      {
        ...details,
        message: `Authentication ${type.toLowerCase().replace('_', ' ')}`,
      },
      request,
      type === SecurityEventType.LOGIN_BLOCKED
    )
  }

  /**
   * Log failed authentication attempts with enhanced tracking
   */
  logFailedAuth(request: NextRequest, username: string, reason: string): SecurityEvent {
    const ip = getClientIP(request)
    const recentFailures = this.getRecentEventsByIP(ip, SecurityEventType.LOGIN_FAILURE, 15) // Last 15 minutes

    const severity =
      recentFailures.length >= 5
        ? SecuritySeverity.CRITICAL
        : recentFailures.length >= 3
          ? SecuritySeverity.HIGH
          : SecuritySeverity.MEDIUM

    return this.logSecurityEvent(
      SecurityEventType.LOGIN_FAILURE,
      severity,
      'authentication',
      {
        username,
        reason,
        failureCount: recentFailures.length + 1,
        message: `Failed login attempt for user: ${username}`,
      },
      request
    )
  }

  /**
   * Log suspicious activity patterns
   */
  logSuspiciousActivity(
    type: SecurityEventType,
    request: NextRequest,
    details: Record<string, any>
  ): SecurityEvent {
    const ip = getClientIP(request)
    const recentEvents = this.getRecentEventsByIP(ip, type, 60) // Last hour

    const severity =
      recentEvents.length >= 10
        ? SecuritySeverity.CRITICAL
        : recentEvents.length >= 5
          ? SecuritySeverity.HIGH
          : SecuritySeverity.MEDIUM

    return this.logSecurityEvent(
      type,
      severity,
      'suspicious_activity',
      {
        ...details,
        eventCount: recentEvents.length + 1,
        message: `Suspicious activity detected: ${type}`,
      },
      request,
      severity === SecuritySeverity.CRITICAL
    )
  }

  /**
   * Log data access events
   */
  logDataAccess(
    type:
      | SecurityEventType.SENSITIVE_DATA_ACCESS
      | SecurityEventType.DATA_EXPORT
      | SecurityEventType.BULK_DATA_ACCESS,
    request: NextRequest,
    details: { dataType?: string; recordCount?: number; query?: string } = {}
  ): SecurityEvent {
    const severity =
      type === SecurityEventType.BULK_DATA_ACCESS && (details.recordCount || 0) > 1000
        ? SecuritySeverity.HIGH
        : type === SecurityEventType.SENSITIVE_DATA_ACCESS
          ? SecuritySeverity.MEDIUM
          : SecuritySeverity.LOW

    return this.logSecurityEvent(
      type,
      severity,
      'data_access',
      {
        ...details,
        message: `Data access: ${type.toLowerCase().replace('_', ' ')}`,
      },
      request
    )
  }

  /**
   * Calculate risk score for an event
   */
  private calculateRiskScore(
    type: SecurityEventType,
    severity: SecuritySeverity,
    details: Record<string, any>
  ): number {
    let baseScore = 0

    // Base score by severity
    switch (severity) {
      case SecuritySeverity.LOW:
        baseScore = 1
        break
      case SecuritySeverity.MEDIUM:
        baseScore = 3
        break
      case SecuritySeverity.HIGH:
        baseScore = 7
        break
      case SecuritySeverity.CRITICAL:
        baseScore = 10
        break
    }

    // Adjust by event type
    const typeMultipliers: Partial<Record<SecurityEventType, number>> = {
      [SecurityEventType.SQL_INJECTION_ATTEMPT]: 2.0,
      [SecurityEventType.SYSTEM_COMPROMISE_INDICATOR]: 2.0,
      [SecurityEventType.PRIVILEGE_ESCALATION]: 1.8,
      [SecurityEventType.SESSION_HIJACK_ATTEMPT]: 1.8,
      [SecurityEventType.BRUTE_FORCE_ATTEMPT]: 1.5,
      [SecurityEventType.UNAUTHORIZED_DATA_ACCESS]: 1.5,
    }

    const multiplier = typeMultipliers[type] || 1.0
    let score = baseScore * multiplier

    // Adjust by frequency
    if (details.eventCount && details.eventCount > 1) {
      score *= Math.min(details.eventCount * 0.2 + 1, 3.0)
    }

    return Math.min(Math.round(score * 10) / 10, 10.0)
  }

  /**
   * Get recent events by IP address
   */
  private getRecentEventsByIP(
    ip: string,
    type?: SecurityEventType,
    minutes: number = 60
  ): SecurityEvent[] {
    const cutoff = new Date(Date.now() - minutes * 60 * 1000)
    return this.events.filter(
      event => event.ip === ip && event.timestamp >= cutoff && (!type || event.type === type)
    )
  }

  /**
   * Check for alert conditions
   */
  private checkAlerts(event: SecurityEvent): void {
    if (!this.alertConfig.enabled) return

    const now = new Date()
    const windowStart = new Date(now.getTime() - this.alertConfig.timeWindow * 60 * 1000)

    // Count recent events by severity
    const recentEvents = this.events.filter(e => e.timestamp >= windowStart)
    const eventsBySeverity = recentEvents.reduce(
      (acc, e) => {
        acc[e.severity] = (acc[e.severity] || 0) + 1
        return acc
      },
      {} as Record<SecuritySeverity, number>
    )

    // Check thresholds
    for (const [severity, threshold] of Object.entries(this.alertConfig.thresholds)) {
      const count = eventsBySeverity[severity as SecuritySeverity] || 0

      if (count >= threshold) {
        const alertKey = `${severity}_threshold`
        const lastAlert = this.lastAlertTime.get(alertKey)

        // Check cooldown
        if (
          !lastAlert ||
          now.getTime() - lastAlert.getTime() > this.alertConfig.cooldown * 60 * 1000
        ) {
          this.triggerAlert(
            `High volume of ${severity} security events: ${count} in ${this.alertConfig.timeWindow} minutes`,
            severity as SecuritySeverity
          )
          this.lastAlertTime.set(alertKey, now)
        }
      }
    }

    // Check for critical individual events
    if (event.severity === SecuritySeverity.CRITICAL) {
      this.triggerAlert(
        `Critical security event: ${event.type} from IP ${event.ip}`,
        SecuritySeverity.CRITICAL
      )
    }
  }

  /**
   * Trigger security alert
   */
  private triggerAlert(message: string, severity: SecuritySeverity): void {
    const alert = {
      timestamp: new Date(),
      message,
      severity,
    }

    this.alerts.push(alert)
    if (this.alerts.length > this.maxAlerts) {
      this.alerts = this.alerts.slice(-this.maxAlerts)
    }

    // Log alert
    logger.error('SecurityAlert', message, { severity, timestamp: alert.timestamp })

    // In production, you might want to:
    // - Send email notifications
    // - Post to Slack/Teams
    // - Trigger incident response
    // - Update monitoring dashboards
  }

  /**
   * Get log level for severity
   */
  private getLogLevel(severity: SecuritySeverity): 'debug' | 'info' | 'warn' | 'error' {
    switch (severity) {
      case SecuritySeverity.LOW:
        return 'info'
      case SecuritySeverity.MEDIUM:
        return 'warn'
      case SecuritySeverity.HIGH:
        return 'error'
      case SecuritySeverity.CRITICAL:
        return 'error'
      default:
        return 'info'
    }
  }

  /**
   * Sanitize details for logging (remove sensitive data)
   */
  private sanitizeDetails(details: Record<string, any>): Record<string, any> {
    return sanitizeLogData(details)
  }

  /**
   * Get security metrics
   */
  getSecurityMetrics(timeWindow: number = 24): SecurityMetrics {
    const cutoff = new Date(Date.now() - timeWindow * 60 * 60 * 1000)
    const recentEvents = this.events.filter(e => e.timestamp >= cutoff)

    const eventsByType = recentEvents.reduce(
      (acc, e) => {
        acc[e.type] = (acc[e.type] || 0) + 1
        return acc
      },
      {} as Record<SecurityEventType, number>
    )

    const eventsBySeverity = recentEvents.reduce(
      (acc, e) => {
        acc[e.severity] = (acc[e.severity] || 0) + 1
        return acc
      },
      {} as Record<SecuritySeverity, number>
    )

    const topThreats = Object.entries(eventsByType)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([type, count]) => ({ type: type as SecurityEventType, count }))

    const uniqueIPs = new Set(recentEvents.map(e => e.ip)).size
    const averageRiskScore =
      recentEvents.length > 0
        ? recentEvents.reduce((sum, e) => sum + e.riskScore, 0) / recentEvents.length
        : 0

    const recentAlerts = this.alerts.filter(a => a.timestamp >= cutoff).length

    return {
      totalEvents: recentEvents.length,
      eventsByType,
      eventsBySeverity,
      blockedEvents: recentEvents.filter(e => e.blocked).length,
      uniqueIPs,
      averageRiskScore: Math.round(averageRiskScore * 10) / 10,
      topThreats,
      recentAlerts,
    }
  }

  /**
   * Get recent security events
   */
  getRecentEvents(limit: number = 100, severity?: SecuritySeverity): SecurityEvent[] {
    let events = [...this.events].reverse()

    if (severity) {
      events = events.filter(e => e.severity === severity)
    }

    return events.slice(0, limit)
  }

  /**
   * Get recent alerts
   */
  getRecentAlerts(
    limit: number = 50
  ): Array<{ timestamp: Date; message: string; severity: SecuritySeverity }> {
    return [...this.alerts].reverse().slice(0, limit)
  }

  /**
   * Check if IP is suspicious
   */
  isSuspiciousIP(ip: string): boolean {
    return this.suspiciousIPs.has(ip)
  }

  /**
   * Check if IP is blocked
   */
  isBlockedIP(ip: string): boolean {
    return this.blockedIPs.has(ip)
  }

  /**
   * Clear old events and alerts
   */
  cleanup(retentionDays: number = 30): void {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000)

    this.events = this.events.filter(e => e.timestamp >= cutoff)
    this.alerts = this.alerts.filter(a => a.timestamp >= cutoff)

    logger.info(
      'SecurityLogger',
      `Cleanup completed. Retained ${this.events.length} events and ${this.alerts.length} alerts`
    )
  }

  /**
   * Export security events as JSON
   */
  exportEvents(timeWindow: number = 24): string {
    const cutoff = new Date(Date.now() - timeWindow * 60 * 60 * 1000)
    const events = this.events.filter(e => e.timestamp >= cutoff)

    return JSON.stringify(
      {
        exportTimestamp: new Date().toISOString(),
        timeWindow: `${timeWindow} hours`,
        eventCount: events.length,
        events: events.map(e => ({
          ...e,
          timestamp: e.timestamp.toISOString(),
        })),
      },
      null,
      2
    )
  }
}

/**
 * Sanitize log data to prevent sensitive information exposure
 */
export function sanitizeLogData(data: any): any {
  if (data === null || data === undefined) {
    return data
  }

  if (typeof data === 'string') {
    return sanitizeString(data)
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeLogData(item))
  }

  if (typeof data === 'object') {
    const sanitized: Record<string, any> = {}

    for (const [key, value] of Object.entries(data)) {
      // Check if field name indicates sensitive data
      if (isSensitiveField(key)) {
        sanitized[key] = '[REDACTED]'
      } else {
        sanitized[key] = sanitizeLogData(value)
      }
    }

    return sanitized
  }

  return data
}

/**
 * Check if field name indicates sensitive data
 */
function isSensitiveField(fieldName: string): boolean {
  const sensitivePatterns = [
    /password/i,
    /passwd/i,
    /pwd/i,
    /secret/i,
    /token/i,
    /key/i,
    /credential/i,
    /auth/i,
    /session/i,
    /cookie/i,
    /api[_-]?key/i,
    /access[_-]?token/i,
    /refresh[_-]?token/i,
    /private[_-]?key/i,
    /public[_-]?key/i,
    /cert/i,
    /certificate/i,
    /ssn/i,
    /social[_-]?security/i,
    /credit[_-]?card/i,
    /card[_-]?number/i,
    /cvv/i,
    /cvc/i,
    /pin/i,
    /email/i,
    /phone/i,
    /address/i,
    /zip/i,
    /postal/i,
  ]

  return sensitivePatterns.some(pattern => pattern.test(fieldName))
}

/**
 * Sanitize string data
 */
function sanitizeString(str: string): string {
  // Truncate very long strings
  if (str.length > 1000) {
    return str.substring(0, 1000) + '...[TRUNCATED]'
  }

  // Mask potential sensitive patterns in strings
  let sanitized = str

  // Mask email addresses
  sanitized = sanitized.replace(
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    '[EMAIL_REDACTED]'
  )

  // Mask phone numbers
  sanitized = sanitized.replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[PHONE_REDACTED]')

  // Mask credit card numbers
  sanitized = sanitized.replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[CARD_REDACTED]')

  // Mask SSN
  sanitized = sanitized.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]')

  // Mask potential API keys (long alphanumeric strings)
  sanitized = sanitized.replace(/\b[A-Za-z0-9]{32,}\b/g, '[KEY_REDACTED]')

  // Mask JWT tokens
  sanitized = sanitized.replace(
    /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/g,
    '[JWT_REDACTED]'
  )

  return sanitized
}

/**
 * Validate log data for security compliance
 */
export function validateLogData(data: any): {
  isValid: boolean
  issues: string[]
  sanitizedData: any
} {
  const issues: string[] = []
  const sanitizedData = sanitizeLogData(data)

  // Check for potential sensitive data leakage
  const dataString = JSON.stringify(data)

  if (dataString.includes('password')) {
    issues.push('Potential password field detected in log data')
  }

  if (dataString.includes('secret')) {
    issues.push('Potential secret field detected in log data')
  }

  if (dataString.includes('token')) {
    issues.push('Potential token field detected in log data')
  }

  // Check for PII patterns
  if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(dataString)) {
    issues.push('Email address detected in log data')
  }

  if (/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/.test(dataString)) {
    issues.push('Phone number detected in log data')
  }

  if (/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/.test(dataString)) {
    issues.push('Credit card number detected in log data')
  }

  return {
    isValid: issues.length === 0,
    issues,
    sanitizedData,
  }
}

// Export singleton instance
export const securityLogger = new SecurityLogger()
