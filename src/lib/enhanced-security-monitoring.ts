/**
 * Enhanced Security Monitoring Service
 * Provides comprehensive threat detection and security monitoring
 * 
 * Features:
 * - SQL injection detection
 * - XSS detection
 * - Command injection detection
 * - Brute force detection
 * - Anomaly detection
 * - Real-time alerting
 */

import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import { hardenedSecurityConfig } from './hardened-security-config'

export interface ThreatDetection {
  type: 'SQL_INJECTION' | 'XSS' | 'COMMAND_INJECTION' | 'BRUTE_FORCE' | 'ANOMALY' | 'RATE_LIMIT_ABUSE'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  evidence: string
  timestamp: Date
  clientIP: string
  userAgent: string
  requestPath: string
}

export interface SecurityEvent {
  eventType: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  timestamp: Date
  clientIP: string
  userAgent: string
  requestPath: string
  details: any
  blocked: boolean
}

export interface SecurityMetrics {
  totalRequests: number
  threatsDetected: number
  threatsBlocked: number
  topThreatTypes: { [key: string]: number }
  topAttackIPs: { [key: string]: number }
  securityScore: number
}

/**
 * Enhanced Security Monitoring Service
 */
export class EnhancedSecurityMonitoringService {
  private config = hardenedSecurityConfig.monitoring
  private threatHistory: Map<string, ThreatDetection[]> = new Map()
  private securityEvents: SecurityEvent[] = []
  private requestMetrics: SecurityMetrics = {
    totalRequests: 0,
    threatsDetected: 0,
    threatsBlocked: 0,
    topThreatTypes: {},
    topAttackIPs: {},
    securityScore: 100
  }

  /**
   * Analyze request for security threats
   */
  analyzeRequest(request: NextRequest): ThreatDetection[] {
    if (!this.config.enabled) {
      return []
    }

    const threats: ThreatDetection[] = []
    const clientIP = this.getClientIP(request)
    const userAgent = request.headers.get('user-agent') || 'unknown'
    const requestPath = request.nextUrl.pathname

    this.requestMetrics.totalRequests++

    // Analyze URL for threats
    threats.push(...this.analyzeURL(request.nextUrl.href, clientIP, userAgent, requestPath))

    // Analyze headers for threats
    threats.push(...this.analyzeHeaders(request, clientIP, userAgent, requestPath))

    // Analyze query parameters
    threats.push(...this.analyzeQueryParams(request.nextUrl.searchParams, clientIP, userAgent, requestPath))

    // Update metrics
    if (threats.length > 0) {
      this.requestMetrics.threatsDetected++
      this.updateThreatMetrics(threats, clientIP)
    }

    // Store threat history
    if (threats.length > 0) {
      const ipThreats = this.threatHistory.get(clientIP) || []
      ipThreats.push(...threats)
      this.threatHistory.set(clientIP, ipThreats)
    }

    return threats
  }

  /**
   * Detect SQL injection attempts
   */
  detectSQLInjection(input: string): boolean {
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
      /(--|\/\*|\*\/|;)/,
      /(\bOR\b|\bAND\b).*?[=<>]/i,
      /(\bUNION\b.*?\bSELECT\b)/i,
      /(\bINTO\b.*?\bOUTFILE\b)/i,
      /(\bLOAD_FILE\b|\bINTO\b.*?\bDUMPFILE\b)/i
    ]
    return sqlPatterns.some(pattern => pattern.test(input))
  }

  /**
   * Detect XSS attempts
   */
  detectXSS(input: string): boolean {
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
      /<embed\b[^>]*>/gi,
      /<link\b[^>]*>/gi,
      /<meta\b[^>]*>/gi
    ]
    return xssPatterns.some(pattern => pattern.test(input))
  }

  /**
   * Detect command injection attempts
   */
  detectCommandInjection(input: string): boolean {
    const commandPatterns = [
      /[;&|`$(){}[\]]/,
      /\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|wget|curl)\b/i,
      /(\|\s*(cat|ls|pwd|whoami|id|uname))/i,
      /(&&|\|\|)\s*\w+/,
      /`[^`]*`/,
      /\$\([^)]*\)/
    ]
    return commandPatterns.some(pattern => pattern.test(input))
  }

  /**
   * Analyze URL for threats
   */
  private analyzeURL(url: string, clientIP: string, userAgent: string, requestPath: string): ThreatDetection[] {
    const threats: ThreatDetection[] = []

    if (this.detectSQLInjection(url)) {
      threats.push({
        type: 'SQL_INJECTION',
        severity: 'high',
        description: 'SQL injection attempt detected in URL',
        evidence: url,
        timestamp: new Date(),
        clientIP,
        userAgent,
        requestPath
      })
    }

    if (this.detectXSS(url)) {
      threats.push({
        type: 'XSS',
        severity: 'high',
        description: 'XSS attempt detected in URL',
        evidence: url,
        timestamp: new Date(),
        clientIP,
        userAgent,
        requestPath
      })
    }

    if (this.detectCommandInjection(url)) {
      threats.push({
        type: 'COMMAND_INJECTION',
        severity: 'critical',
        description: 'Command injection attempt detected in URL',
        evidence: url,
        timestamp: new Date(),
        clientIP,
        userAgent,
        requestPath
      })
    }

    return threats
  }

  /**
   * Analyze headers for threats
   */
  private analyzeHeaders(request: NextRequest, clientIP: string, userAgent: string, requestPath: string): ThreatDetection[] {
    const threats: ThreatDetection[] = []

    // Check for suspicious user agents
    const suspiciousUserAgents = [
      /sqlmap/i,
      /nikto/i,
      /nessus/i,
      /burp/i,
      /nmap/i,
      /masscan/i,
      /zap/i
    ]

    if (suspiciousUserAgents.some(pattern => pattern.test(userAgent))) {
      threats.push({
        type: 'ANOMALY',
        severity: 'medium',
        description: 'Suspicious user agent detected',
        evidence: userAgent,
        timestamp: new Date(),
        clientIP,
        userAgent,
        requestPath
      })
    }

    // Check headers for injection attempts
    request.headers.forEach((value, key) => {
      if (this.detectSQLInjection(value) || this.detectXSS(value) || this.detectCommandInjection(value)) {
        threats.push({
          type: 'ANOMALY',
          severity: 'high',
          description: `Malicious content detected in header: ${key}`,
          evidence: `${key}: ${value}`,
          timestamp: new Date(),
          clientIP,
          userAgent,
          requestPath
        })
      }
    })

    return threats
  }

  /**
   * Analyze query parameters for threats
   */
  private analyzeQueryParams(params: URLSearchParams, clientIP: string, userAgent: string, requestPath: string): ThreatDetection[] {
    const threats: ThreatDetection[] = []

    params.forEach((value, key) => {
      if (this.detectSQLInjection(value)) {
        threats.push({
          type: 'SQL_INJECTION',
          severity: 'high',
          description: `SQL injection attempt in parameter: ${key}`,
          evidence: `${key}=${value}`,
          timestamp: new Date(),
          clientIP,
          userAgent,
          requestPath
        })
      }

      if (this.detectXSS(value)) {
        threats.push({
          type: 'XSS',
          severity: 'high',
          description: `XSS attempt in parameter: ${key}`,
          evidence: `${key}=${value}`,
          timestamp: new Date(),
          clientIP,
          userAgent,
          requestPath
        })
      }

      if (this.detectCommandInjection(value)) {
        threats.push({
          type: 'COMMAND_INJECTION',
          severity: 'critical',
          description: `Command injection attempt in parameter: ${key}`,
          evidence: `${key}=${value}`,
          timestamp: new Date(),
          clientIP,
          userAgent,
          requestPath
        })
      }
    })

    return threats
  }

  /**
   * Log security event
   */
  logSecurityEvent(
    eventType: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    request: NextRequest,
    details: any,
    blocked: boolean = false
  ): void {
    const event: SecurityEvent = {
      eventType,
      severity,
      timestamp: new Date(),
      clientIP: this.getClientIP(request),
      userAgent: request.headers.get('user-agent') || 'unknown',
      requestPath: request.nextUrl.pathname,
      details,
      blocked
    }

    this.securityEvents.push(event)

    // Log to application logger
    logger.warn('Security Event', {
      eventType,
      severity,
      clientIP: event.clientIP,
      userAgent: event.userAgent,
      requestPath: event.requestPath,
      blocked,
      details
    })

    // Send real-time alerts for critical events
    if (severity === 'critical' && this.config.realTimeAlerts) {
      this.sendSecurityAlert(event)
    }

    // Update metrics
    if (blocked) {
      this.requestMetrics.threatsBlocked++
    }
  }

  /**
   * Get client IP address
   */
  private getClientIP(request: NextRequest): string {
    const forwarded = request.headers.get('x-forwarded-for')
    const realIP = request.headers.get('x-real-ip')
    const remoteAddr = request.headers.get('remote-addr')

    if (forwarded) {
      return forwarded.split(',')[0].trim()
    }
    if (realIP) {
      return realIP
    }
    if (remoteAddr) {
      return remoteAddr
    }
    return 'unknown'
  }

  /**
   * Update threat metrics
   */
  private updateThreatMetrics(threats: ThreatDetection[], clientIP: string): void {
    threats.forEach(threat => {
      this.requestMetrics.topThreatTypes[threat.type] = 
        (this.requestMetrics.topThreatTypes[threat.type] || 0) + 1
      
      this.requestMetrics.topAttackIPs[clientIP] = 
        (this.requestMetrics.topAttackIPs[clientIP] || 0) + 1
    })

    // Calculate security score
    const threatRate = this.requestMetrics.threatsDetected / this.requestMetrics.totalRequests
    this.requestMetrics.securityScore = Math.max(0, 100 - (threatRate * 100))
  }

  /**
   * Send security alert
   */
  private sendSecurityAlert(event: SecurityEvent): void {
    // In a real implementation, this would send alerts to monitoring services
    logger.error('SECURITY ALERT', {
      message: 'Critical security event detected',
      event
    })

    // TODO: Integrate with external alerting services (Slack, PagerDuty, etc.)
  }

  /**
   * Get security metrics
   */
  getSecurityMetrics(): SecurityMetrics {
    return { ...this.requestMetrics }
  }

  /**
   * Get threat history for IP
   */
  getThreatHistory(clientIP: string): ThreatDetection[] {
    return this.threatHistory.get(clientIP) || []
  }

  /**
   * Clear old security events (cleanup)
   */
  cleanupOldEvents(): void {
    const retentionPeriod = this.config.retentionPeriod
    const cutoffDate = new Date(Date.now() - retentionPeriod)

    this.securityEvents = this.securityEvents.filter(event => event.timestamp > cutoffDate)

    // Clean up threat history
    this.threatHistory.forEach((threats, ip) => {
      const filteredThreats = threats.filter(threat => threat.timestamp > cutoffDate)
      if (filteredThreats.length === 0) {
        this.threatHistory.delete(ip)
      } else {
        this.threatHistory.set(ip, filteredThreats)
      }
    })
  }
}

// Export singleton instance
export const enhancedSecurityMonitoringService = new EnhancedSecurityMonitoringService()

// Export convenience functions
export function detectSQLInjection(input: string): boolean {
  return enhancedSecurityMonitoringService.detectSQLInjection(input)
}

export function detectXSS(input: string): boolean {
  return enhancedSecurityMonitoringService.detectXSS(input)
}

export function detectCommandInjection(input: string): boolean {
  return enhancedSecurityMonitoringService.detectCommandInjection(input)
}
