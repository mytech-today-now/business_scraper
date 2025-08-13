/**
 * Security Monitoring and Logging System
 * Comprehensive security event tracking, request monitoring, and threat detection
 */

import { NextRequest } from 'next/server'
import { getClientIP } from './security'
import { logger } from '@/utils/logger'

export interface SecurityEvent {
  id: string
  timestamp: number
  type: SecurityEventType
  severity: SecuritySeverity
  ip: string
  userAgent?: string
  sessionId?: string
  endpoint?: string
  method?: string
  details: Record<string, any>
  blocked: boolean
}

export type SecurityEventType = 
  | 'rate_limit_exceeded'
  | 'invalid_csrf_token'
  | 'suspicious_input'
  | 'failed_authentication'
  | 'account_lockout'
  | 'malicious_request'
  | 'file_upload_blocked'
  | 'sql_injection_attempt'
  | 'xss_attempt'
  | 'path_traversal_attempt'
  | 'command_injection_attempt'
  | 'unusual_request_pattern'
  | 'security_header_violation'

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical'

export interface RequestSignature {
  ip: string
  userAgent: string
  timestamp: number
  endpoint: string
  method: string
  headers: Record<string, string>
  bodyHash?: string
}

export interface ThreatPattern {
  name: string
  pattern: RegExp
  severity: SecuritySeverity
  description: string
}

/**
 * Security Monitoring Service
 */
export class SecurityMonitoringService {
  private events: SecurityEvent[] = []
  private requestSignatures = new Map<string, RequestSignature[]>()
  private suspiciousIPs = new Set<string>()
  private maxEvents = 10000
  private maxSignaturesPerIP = 100

  // Threat detection patterns
  private threatPatterns: ThreatPattern[] = [
    {
      name: 'SQL Injection',
      pattern: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b.*(\b(OR|AND)\b.*=|--|\/\*|\*\/|;))/i,
      severity: 'high',
      description: 'Potential SQL injection attempt detected'
    },
    {
      name: 'XSS Attack',
      pattern: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|javascript:|on\w+\s*=/i,
      severity: 'high',
      description: 'Potential XSS attack detected'
    },
    {
      name: 'Path Traversal',
      pattern: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c/i,
      severity: 'medium',
      description: 'Path traversal attempt detected'
    },
    {
      name: 'Command Injection',
      pattern: /[;&|`$(){}[\]]|\b(cat|ls|dir|type|echo|curl|wget|nc|netcat|rm|del|mv|cp|chmod|chown)\b/i,
      severity: 'high',
      description: 'Command injection attempt detected'
    },
    {
      name: 'LDAP Injection',
      pattern: /(\(|\)|&|\||!|=|\*|<|>|~)/,
      severity: 'medium',
      description: 'Potential LDAP injection detected'
    },
    {
      name: 'XML Injection',
      pattern: /<\?xml|<!DOCTYPE|<!ENTITY/i,
      severity: 'medium',
      description: 'XML injection attempt detected'
    }
  ]

  /**
   * Log a security event
   */
  logSecurityEvent(
    type: SecurityEventType,
    severity: SecuritySeverity,
    request: NextRequest,
    details: Record<string, any> = {},
    blocked: boolean = false
  ): void {
    const event: SecurityEvent = {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      type,
      severity,
      ip: getClientIP(request),
      userAgent: request.headers.get('user-agent') || undefined,
      sessionId: request.cookies.get('session-id')?.value,
      endpoint: request.nextUrl.pathname,
      method: request.method,
      details,
      blocked
    }

    this.events.push(event)

    // Maintain event limit
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(-this.maxEvents)
    }

    // Log to application logger
    const logLevel = severity === 'critical' ? 'error' : severity === 'high' ? 'warn' : 'info'
    logger[logLevel]('Security', `${type}: ${details.message || 'Security event'}`, {
      eventId: event.id,
      ip: event.ip,
      endpoint: event.endpoint,
      severity,
      blocked
    })

    // Track suspicious IPs
    if (severity === 'high' || severity === 'critical') {
      this.suspiciousIPs.add(event.ip)
    }
  }

  /**
   * Analyze request for threats
   */
  analyzeRequest(request: NextRequest, body?: string): SecurityEvent[] {
    const events: SecurityEvent[] = []
    const ip = getClientIP(request)
    const url = request.nextUrl.toString()
    const userAgent = request.headers.get('user-agent') || ''

    // Check URL for threats
    for (const pattern of this.threatPatterns) {
      if (pattern.pattern.test(url)) {
        this.logSecurityEvent(
          'malicious_request',
          pattern.severity,
          request,
          {
            message: pattern.description,
            pattern: pattern.name,
            matchedContent: url
          },
          true
        )
        events.push(this.events[this.events.length - 1])
      }
    }

    // Check body for threats if provided
    if (body) {
      for (const pattern of this.threatPatterns) {
        if (pattern.pattern.test(body)) {
          this.logSecurityEvent(
            'suspicious_input',
            pattern.severity,
            request,
            {
              message: pattern.description,
              pattern: pattern.name,
              inputLength: body.length
            },
            true
          )
          events.push(this.events[this.events.length - 1])
        }
      }
    }

    // Check for unusual request patterns
    this.checkRequestPattern(request)

    return events
  }

  /**
   * Generate request signature for pattern analysis
   */
  generateRequestSignature(request: NextRequest, body?: string): RequestSignature {
    const signature: RequestSignature = {
      ip: getClientIP(request),
      userAgent: request.headers.get('user-agent') || '',
      timestamp: Date.now(),
      endpoint: request.nextUrl.pathname,
      method: request.method,
      headers: Object.fromEntries(request.headers.entries())
    }

    if (body) {
      signature.bodyHash = crypto.createHash('sha256').update(body).digest('hex')
    }

    return signature
  }

  /**
   * Track and analyze request patterns
   */
  trackRequestSignature(request: NextRequest, body?: string): void {
    const signature = this.generateRequestSignature(request, body)
    const ip = signature.ip

    if (!this.requestSignatures.has(ip)) {
      this.requestSignatures.set(ip, [])
    }

    const signatures = this.requestSignatures.get(ip)!
    signatures.push(signature)

    // Maintain signature limit per IP
    if (signatures.length > this.maxSignaturesPerIP) {
      signatures.splice(0, signatures.length - this.maxSignaturesPerIP)
    }

    // Analyze patterns
    this.analyzeRequestPatterns(ip, signatures)
  }

  /**
   * Check for unusual request patterns
   */
  private checkRequestPattern(request: NextRequest): void {
    const ip = getClientIP(request)
    const userAgent = request.headers.get('user-agent') || ''

    // Check for suspicious user agents
    const suspiciousUserAgents = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /java/i,
      /go-http-client/i
    ]

    if (suspiciousUserAgents.some(pattern => pattern.test(userAgent))) {
      this.logSecurityEvent(
        'unusual_request_pattern',
        'low',
        request,
        {
          message: 'Suspicious user agent detected',
          userAgent
        }
      )
    }

    // Check for missing common headers
    const commonHeaders = ['accept', 'accept-language', 'accept-encoding']
    const missingHeaders = commonHeaders.filter(header => !request.headers.has(header))

    if (missingHeaders.length >= 2) {
      this.logSecurityEvent(
        'unusual_request_pattern',
        'low',
        request,
        {
          message: 'Unusual header pattern detected',
          missingHeaders
        }
      )
    }
  }

  /**
   * Analyze request patterns for anomalies
   */
  private analyzeRequestPatterns(ip: string, signatures: RequestSignature[]): void {
    if (signatures.length < 5) return

    const recent = signatures.slice(-10)
    const now = Date.now()
    const fiveMinutesAgo = now - 5 * 60 * 1000

    // Check for rapid requests
    const recentRequests = recent.filter(sig => sig.timestamp > fiveMinutesAgo)
    if (recentRequests.length > 20) {
      this.logSecurityEvent(
        'unusual_request_pattern',
        'medium',
        { nextUrl: { pathname: '/pattern-analysis' } } as NextRequest,
        {
          message: 'Rapid request pattern detected',
          requestCount: recentRequests.length,
          timeWindow: '5 minutes'
        }
      )
    }

    // Check for identical requests (potential replay attack)
    const bodyHashes = recent.map(sig => sig.bodyHash).filter(Boolean)
    const uniqueHashes = new Set(bodyHashes)
    if (bodyHashes.length > 0 && uniqueHashes.size < bodyHashes.length / 2) {
      this.logSecurityEvent(
        'unusual_request_pattern',
        'medium',
        { nextUrl: { pathname: '/pattern-analysis' } } as NextRequest,
        {
          message: 'Potential replay attack detected',
          duplicateRequests: bodyHashes.length - uniqueHashes.size
        }
      )
    }
  }

  /**
   * Get security events with filtering
   */
  getSecurityEvents(filter?: {
    type?: SecurityEventType
    severity?: SecuritySeverity
    ip?: string
    since?: number
    limit?: number
  }): SecurityEvent[] {
    let filtered = this.events

    if (filter) {
      if (filter.type) {
        filtered = filtered.filter(event => event.type === filter.type)
      }
      if (filter.severity) {
        filtered = filtered.filter(event => event.severity === filter.severity)
      }
      if (filter.ip) {
        filtered = filtered.filter(event => event.ip === filter.ip)
      }
      if (filter.since) {
        filtered = filtered.filter(event => event.timestamp >= filter.since)
      }
    }

    // Sort by timestamp (newest first)
    filtered.sort((a, b) => b.timestamp - a.timestamp)

    if (filter?.limit) {
      filtered = filtered.slice(0, filter.limit)
    }

    return filtered
  }

  /**
   * Get security statistics
   */
  getSecurityStats(): {
    totalEvents: number
    eventsByType: Record<SecurityEventType, number>
    eventsBySeverity: Record<SecuritySeverity, number>
    suspiciousIPs: number
    recentEvents: number
  } {
    const now = Date.now()
    const oneHourAgo = now - 60 * 60 * 1000

    const eventsByType = {} as Record<SecurityEventType, number>
    const eventsBySeverity = {} as Record<SecuritySeverity, number>

    for (const event of this.events) {
      eventsByType[event.type] = (eventsByType[event.type] || 0) + 1
      eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1
    }

    return {
      totalEvents: this.events.length,
      eventsByType,
      eventsBySeverity,
      suspiciousIPs: this.suspiciousIPs.size,
      recentEvents: this.events.filter(event => event.timestamp > oneHourAgo).length
    }
  }

  /**
   * Check if IP is suspicious
   */
  isSuspiciousIP(ip: string): boolean {
    return this.suspiciousIPs.has(ip)
  }

  /**
   * Clear old events and signatures
   */
  cleanup(): void {
    const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000

    // Clean old events
    this.events = this.events.filter(event => event.timestamp > oneWeekAgo)

    // Clean old signatures
    for (const [ip, signatures] of this.requestSignatures.entries()) {
      const recentSignatures = signatures.filter(sig => sig.timestamp > oneWeekAgo)
      if (recentSignatures.length === 0) {
        this.requestSignatures.delete(ip)
      } else {
        this.requestSignatures.set(ip, recentSignatures)
      }
    }
  }
}

/**
 * Default security monitoring service instance
 */
export const securityMonitoringService = new SecurityMonitoringService()

// Cleanup interval (every hour)
if (typeof window === 'undefined') {
  setInterval(() => {
    securityMonitoringService.cleanup()
  }, 60 * 60 * 1000)
}
