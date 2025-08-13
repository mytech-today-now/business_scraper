/**
 * Authentication Monitoring System
 * Business Scraper Application - Enhanced Authentication Security Monitoring
 */

import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import { getClientIP } from './security'
import { securityLogger, SecurityEventType, SecuritySeverity } from './securityLogger'

/**
 * Authentication attempt details
 */
export interface AuthAttempt {
  id: string
  timestamp: Date
  ip: string
  userAgent: string
  username?: string
  success: boolean
  failureReason?: string
  sessionId?: string
  geoLocation?: {
    country?: string
    region?: string
    city?: string
  }
  deviceFingerprint?: string
}

/**
 * Authentication pattern analysis
 */
export interface AuthPattern {
  ip: string
  attempts: number
  successfulLogins: number
  failedLogins: number
  firstAttempt: Date
  lastAttempt: Date
  usernames: Set<string>
  userAgents: Set<string>
  isBlocked: boolean
  riskScore: number
}

/**
 * Suspicious authentication indicators
 */
export interface SuspiciousIndicators {
  rapidFireAttempts: boolean
  multipleUsernames: boolean
  unusualUserAgent: boolean
  geoLocationAnomaly: boolean
  timePatternAnomaly: boolean
  credentialStuffing: boolean
}

/**
 * Authentication monitoring configuration
 */
export interface AuthMonitorConfig {
  maxFailedAttempts: number
  lockoutDuration: number // minutes
  rapidFireThreshold: number // attempts per minute
  suspiciousUsernameCount: number
  geoLocationTracking: boolean
  deviceFingerprintTracking: boolean
  alertThresholds: {
    failedAttempts: number
    suspiciousPatterns: number
    blockedIPs: number
  }
}

/**
 * Enhanced Authentication Monitor
 */
export class AuthenticationMonitor {
  private attempts: AuthAttempt[] = []
  private patterns = new Map<string, AuthPattern>()
  private blockedIPs = new Map<string, Date>()
  private suspiciousUsernames = new Set<string>()
  private maxAttempts = 10000

  private config: AuthMonitorConfig = {
    maxFailedAttempts: 5,
    lockoutDuration: 15, // 15 minutes
    rapidFireThreshold: 10, // 10 attempts per minute
    suspiciousUsernameCount: 5,
    geoLocationTracking: false, // Disabled by default (requires external service)
    deviceFingerprintTracking: true,
    alertThresholds: {
      failedAttempts: 20,
      suspiciousPatterns: 5,
      blockedIPs: 10
    }
  }

  /**
   * Record authentication attempt
   */
  recordAuthAttempt(
    request: NextRequest,
    username: string | undefined,
    success: boolean,
    failureReason?: string,
    sessionId?: string
  ): AuthAttempt {
    const ip = getClientIP(request)
    const userAgent = request.headers.get('user-agent') || 'unknown'
    
    const attempt: AuthAttempt = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      ip,
      userAgent,
      username,
      success,
      failureReason,
      sessionId,
      deviceFingerprint: this.generateDeviceFingerprint(request)
    }

    // Store attempt
    this.attempts.push(attempt)
    if (this.attempts.length > this.maxAttempts) {
      this.attempts = this.attempts.slice(-this.maxAttempts)
    }

    // Update patterns
    this.updateAuthPattern(attempt)

    // Analyze for suspicious activity
    const indicators = this.analyzeSuspiciousActivity(ip)
    
    // Log security event
    if (success) {
      securityLogger.logAuthEvent(SecurityEventType.LOGIN_SUCCESS, request, { username })
    } else {
      securityLogger.logFailedAuth(request, username || 'unknown', failureReason || 'invalid_credentials')
    }

    // Check for blocking conditions
    if (!success && this.shouldBlockIP(ip, indicators)) {
      this.blockIP(ip)
      securityLogger.logSecurityEvent(
        SecurityEventType.LOGIN_BLOCKED,
        SecuritySeverity.HIGH,
        'authentication_monitor',
        {
          ip,
          username,
          reason: 'Excessive failed attempts',
          indicators: this.indicatorsToObject(indicators),
          message: `IP ${ip} blocked due to suspicious authentication activity`
        },
        request,
        true
      )
    }

    // Check for alerts
    this.checkAlertConditions()

    logger.info('AuthMonitor', `Authentication attempt recorded`, {
      ip,
      username,
      success,
      failureReason,
      indicators: this.indicatorsToObject(indicators)
    })

    return attempt
  }

  /**
   * Update authentication pattern for IP
   */
  private updateAuthPattern(attempt: AuthAttempt): void {
    const pattern = this.patterns.get(attempt.ip) || {
      ip: attempt.ip,
      attempts: 0,
      successfulLogins: 0,
      failedLogins: 0,
      firstAttempt: attempt.timestamp,
      lastAttempt: attempt.timestamp,
      usernames: new Set(),
      userAgents: new Set(),
      isBlocked: false,
      riskScore: 0
    }

    pattern.attempts++
    pattern.lastAttempt = attempt.timestamp
    
    if (attempt.success) {
      pattern.successfulLogins++
    } else {
      pattern.failedLogins++
    }

    if (attempt.username) {
      pattern.usernames.add(attempt.username)
    }
    
    pattern.userAgents.add(attempt.userAgent)
    pattern.riskScore = this.calculateRiskScore(pattern)

    this.patterns.set(attempt.ip, pattern)
  }

  /**
   * Calculate risk score for authentication pattern
   */
  private calculateRiskScore(pattern: AuthPattern): number {
    let score = 0

    // Failed login ratio
    const failureRate = pattern.failedLogins / pattern.attempts
    score += failureRate * 3

    // Multiple usernames (credential stuffing indicator)
    if (pattern.usernames.size > this.config.suspiciousUsernameCount) {
      score += 2
    }

    // Rapid fire attempts
    const timeSpan = pattern.lastAttempt.getTime() - pattern.firstAttempt.getTime()
    const attemptsPerMinute = pattern.attempts / (timeSpan / 60000)
    if (attemptsPerMinute > this.config.rapidFireThreshold) {
      score += 3
    }

    // Multiple user agents (distributed attack indicator)
    if (pattern.userAgents.size > 3) {
      score += 1
    }

    // High volume of attempts
    if (pattern.attempts > 50) {
      score += 2
    }

    return Math.min(score, 10)
  }

  /**
   * Analyze suspicious activity indicators
   */
  private analyzeSuspiciousActivity(ip: string): SuspiciousIndicators {
    const pattern = this.patterns.get(ip)
    const recentAttempts = this.getRecentAttempts(ip, 5) // Last 5 minutes

    if (!pattern) {
      return {
        rapidFireAttempts: false,
        multipleUsernames: false,
        unusualUserAgent: false,
        geoLocationAnomaly: false,
        timePatternAnomaly: false,
        credentialStuffing: false
      }
    }

    return {
      rapidFireAttempts: recentAttempts.length > this.config.rapidFireThreshold,
      multipleUsernames: pattern.usernames.size > this.config.suspiciousUsernameCount,
      unusualUserAgent: this.isUnusualUserAgent(Array.from(pattern.userAgents)),
      geoLocationAnomaly: false, // Would require geo-location service
      timePatternAnomaly: this.hasTimePatternAnomaly(recentAttempts),
      credentialStuffing: pattern.usernames.size > 10 && pattern.failedLogins > pattern.successfulLogins * 5
    }
  }

  /**
   * Check if user agent is unusual/suspicious
   */
  private isUnusualUserAgent(userAgents: string[]): boolean {
    const suspiciousPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /java/i,
      /^$/,
      /test/i
    ]

    return userAgents.some(ua => 
      suspiciousPatterns.some(pattern => pattern.test(ua)) ||
      ua.length < 10 ||
      ua.length > 500
    )
  }

  /**
   * Check for time pattern anomalies
   */
  private hasTimePatternAnomaly(attempts: AuthAttempt[]): boolean {
    if (attempts.length < 3) return false

    // Check for perfectly regular intervals (bot behavior)
    const intervals = []
    for (let i = 1; i < attempts.length; i++) {
      const interval = attempts[i].timestamp.getTime() - attempts[i-1].timestamp.getTime()
      intervals.push(interval)
    }

    // Check if intervals are suspiciously regular
    const avgInterval = intervals.reduce((sum, interval) => sum + interval, 0) / intervals.length
    const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length
    const standardDeviation = Math.sqrt(variance)

    // If standard deviation is very low, intervals are too regular (bot-like)
    return standardDeviation < avgInterval * 0.1 && avgInterval < 5000 // Less than 5 seconds
  }

  /**
   * Check if IP should be blocked
   */
  private shouldBlockIP(ip: string, indicators: SuspiciousIndicators): boolean {
    const pattern = this.patterns.get(ip)
    if (!pattern) return false

    // Already blocked
    if (this.isIPBlocked(ip)) return false

    // Too many failed attempts
    if (pattern.failedLogins >= this.config.maxFailedAttempts) return true

    // High risk score with suspicious indicators
    if (pattern.riskScore >= 7 && (indicators.rapidFireAttempts || indicators.credentialStuffing)) {
      return true
    }

    // Credential stuffing attack
    if (indicators.credentialStuffing && pattern.failedLogins >= 10) return true

    return false
  }

  /**
   * Block IP address
   */
  private blockIP(ip: string): void {
    const blockUntil = new Date(Date.now() + this.config.lockoutDuration * 60 * 1000)
    this.blockedIPs.set(ip, blockUntil)

    const pattern = this.patterns.get(ip)
    if (pattern) {
      pattern.isBlocked = true
    }

    logger.warn('AuthMonitor', `IP blocked due to suspicious activity`, {
      ip,
      blockUntil: blockUntil.toISOString(),
      pattern: pattern ? {
        attempts: pattern.attempts,
        failedLogins: pattern.failedLogins,
        riskScore: pattern.riskScore
      } : null
    })
  }

  /**
   * Check if IP is currently blocked
   */
  isIPBlocked(ip: string): boolean {
    const blockUntil = this.blockedIPs.get(ip)
    if (!blockUntil) return false

    if (new Date() > blockUntil) {
      // Block expired
      this.blockedIPs.delete(ip)
      const pattern = this.patterns.get(ip)
      if (pattern) {
        pattern.isBlocked = false
      }
      return false
    }

    return true
  }

  /**
   * Get recent authentication attempts for IP
   */
  private getRecentAttempts(ip: string, minutes: number = 60): AuthAttempt[] {
    const cutoff = new Date(Date.now() - minutes * 60 * 1000)
    return this.attempts.filter(attempt => 
      attempt.ip === ip && attempt.timestamp >= cutoff
    )
  }

  /**
   * Generate device fingerprint
   */
  private generateDeviceFingerprint(request: NextRequest): string {
    if (!this.config.deviceFingerprintTracking) return ''

    const components = [
      request.headers.get('user-agent') || '',
      request.headers.get('accept-language') || '',
      request.headers.get('accept-encoding') || '',
      request.headers.get('accept') || ''
    ]

    return crypto.createHash('sha256')
      .update(components.join('|'))
      .digest('hex')
      .substring(0, 16)
  }

  /**
   * Convert indicators to plain object for logging
   */
  private indicatorsToObject(indicators: SuspiciousIndicators): Record<string, boolean> {
    return {
      rapidFireAttempts: indicators.rapidFireAttempts,
      multipleUsernames: indicators.multipleUsernames,
      unusualUserAgent: indicators.unusualUserAgent,
      geoLocationAnomaly: indicators.geoLocationAnomaly,
      timePatternAnomaly: indicators.timePatternAnomaly,
      credentialStuffing: indicators.credentialStuffing
    }
  }

  /**
   * Check alert conditions
   */
  private checkAlertConditions(): void {
    const now = new Date()
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000)
    
    // Count recent failed attempts
    const recentFailedAttempts = this.attempts.filter(attempt => 
      !attempt.success && attempt.timestamp >= oneHourAgo
    ).length

    // Count blocked IPs
    const blockedIPCount = Array.from(this.blockedIPs.values()).filter(blockUntil => 
      now < blockUntil
    ).length

    // Count suspicious patterns
    const suspiciousPatternCount = Array.from(this.patterns.values()).filter(pattern => 
      pattern.riskScore >= 5
    ).length

    // Trigger alerts if thresholds exceeded
    if (recentFailedAttempts >= this.config.alertThresholds.failedAttempts) {
      securityLogger.logSecurityEvent(
        SecurityEventType.BRUTE_FORCE_ATTEMPT,
        SecuritySeverity.HIGH,
        'authentication_monitor',
        {
          failedAttempts: recentFailedAttempts,
          timeWindow: '1 hour',
          message: `High volume of failed authentication attempts: ${recentFailedAttempts} in the last hour`
        }
      )
    }

    if (blockedIPCount >= this.config.alertThresholds.blockedIPs) {
      securityLogger.logSecurityEvent(
        SecurityEventType.SUSPICIOUS_ACTIVITY,
        SecuritySeverity.HIGH,
        'authentication_monitor',
        {
          blockedIPs: blockedIPCount,
          message: `High number of blocked IPs: ${blockedIPCount}`
        }
      )
    }
  }

  /**
   * Get authentication statistics
   */
  getAuthStats(timeWindow: number = 24): {
    totalAttempts: number
    successfulLogins: number
    failedLogins: number
    blockedIPs: number
    suspiciousPatterns: number
    topFailureReasons: Array<{ reason: string; count: number }>
    hourlyDistribution: Array<{ hour: number; attempts: number }>
  } {
    const cutoff = new Date(Date.now() - timeWindow * 60 * 60 * 1000)
    const recentAttempts = this.attempts.filter(attempt => attempt.timestamp >= cutoff)

    const successfulLogins = recentAttempts.filter(attempt => attempt.success).length
    const failedLogins = recentAttempts.filter(attempt => !attempt.success).length

    // Count failure reasons
    const failureReasons = recentAttempts
      .filter(attempt => !attempt.success && attempt.failureReason)
      .reduce((acc, attempt) => {
        const reason = attempt.failureReason!
        acc[reason] = (acc[reason] || 0) + 1
        return acc
      }, {} as Record<string, number>)

    const topFailureReasons = Object.entries(failureReasons)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([reason, count]) => ({ reason, count }))

    // Hourly distribution
    const hourlyDistribution = Array.from({ length: 24 }, (_, hour) => ({
      hour,
      attempts: recentAttempts.filter(attempt => 
        attempt.timestamp.getHours() === hour
      ).length
    }))

    const now = new Date()
    const blockedIPs = Array.from(this.blockedIPs.values()).filter(blockUntil => 
      now < blockUntil
    ).length

    const suspiciousPatterns = Array.from(this.patterns.values()).filter(pattern => 
      pattern.riskScore >= 5
    ).length

    return {
      totalAttempts: recentAttempts.length,
      successfulLogins,
      failedLogins,
      blockedIPs,
      suspiciousPatterns,
      topFailureReasons,
      hourlyDistribution
    }
  }

  /**
   * Get recent authentication attempts
   */
  getRecentAttempts(limit: number = 100): AuthAttempt[] {
    return [...this.attempts].reverse().slice(0, limit)
  }

  /**
   * Get authentication patterns
   */
  getAuthPatterns(): AuthPattern[] {
    return Array.from(this.patterns.values())
      .sort((a, b) => b.riskScore - a.riskScore)
  }

  /**
   * Clear old data
   */
  cleanup(retentionDays: number = 30): void {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000)
    
    // Clean old attempts
    this.attempts = this.attempts.filter(attempt => attempt.timestamp >= cutoff)
    
    // Clean old patterns
    for (const [ip, pattern] of this.patterns.entries()) {
      if (pattern.lastAttempt < cutoff) {
        this.patterns.delete(ip)
      }
    }
    
    // Clean expired blocks
    const now = new Date()
    for (const [ip, blockUntil] of this.blockedIPs.entries()) {
      if (now > blockUntil) {
        this.blockedIPs.delete(ip)
      }
    }

    logger.info('AuthMonitor', `Cleanup completed. Retained ${this.attempts.length} attempts and ${this.patterns.size} patterns`)
  }
}

// Export singleton instance
export const authenticationMonitor = new AuthenticationMonitor()
