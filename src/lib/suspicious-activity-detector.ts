/**
 * Suspicious Activity Detector
 * Advanced threat detection and monitoring for authentication systems
 */

import { NextRequest } from 'next/server'
import { getClientIP } from './security'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

export interface SuspiciousEvent {
  id: string
  timestamp: number
  ip: string
  eventType: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  details: any
  userAgent?: string
  sessionId?: string
  riskScore: number
}

export interface ThreatPattern {
  name: string
  description: string
  indicators: string[]
  riskScore: number
  autoBlock: boolean
}

export interface IPRiskProfile {
  ip: string
  riskScore: number
  events: SuspiciousEvent[]
  firstSeen: number
  lastSeen: number
  isBlocked: boolean
  blockReason?: string
  geolocation?: {
    country?: string
    region?: string
    city?: string
  }
}

// Threat patterns for detection
const THREAT_PATTERNS: ThreatPattern[] = [
  {
    name: 'credential_stuffing',
    description: 'Multiple failed login attempts with different credentials',
    indicators: ['high_failure_rate', 'multiple_usernames', 'rapid_attempts'],
    riskScore: 8,
    autoBlock: true
  },
  {
    name: 'session_hijacking',
    description: 'Session used from multiple IP addresses',
    indicators: ['ip_change', 'session_reuse', 'geolocation_jump'],
    riskScore: 9,
    autoBlock: true
  },
  {
    name: 'bot_activity',
    description: 'Automated bot-like behavior patterns',
    indicators: ['consistent_timing', 'missing_headers', 'suspicious_user_agent'],
    riskScore: 7,
    autoBlock: true
  },
  {
    name: 'brute_force',
    description: 'Systematic password guessing attempts',
    indicators: ['sequential_attempts', 'password_patterns', 'high_frequency'],
    riskScore: 8,
    autoBlock: true
  },
  {
    name: 'token_manipulation',
    description: 'Attempts to manipulate or forge authentication tokens',
    indicators: ['invalid_jwt', 'token_tampering', 'signature_mismatch'],
    riskScore: 9,
    autoBlock: true
  }
]

export class SuspiciousActivityDetector {
  private static instance: SuspiciousActivityDetector
  private events = new Map<string, SuspiciousEvent[]>()
  private ipProfiles = new Map<string, IPRiskProfile>()
  private blockedIPs = new Set<string>()
  private eventCounter = 0

  static getInstance(): SuspiciousActivityDetector {
    if (!SuspiciousActivityDetector.instance) {
      SuspiciousActivityDetector.instance = new SuspiciousActivityDetector()
    }
    return SuspiciousActivityDetector.instance
  }

  /**
   * Analyze request for suspicious patterns
   */
  async analyzeRequest(
    request: NextRequest,
    eventType: string,
    details: any = {},
    sessionId?: string
  ): Promise<{ suspicious: boolean; riskScore: number; threats: string[] }> {
    const ip = getClientIP(request)
    const userAgent = request.headers.get('user-agent') || ''
    const now = Date.now()

    // Check if IP is already blocked
    if (this.blockedIPs.has(ip)) {
      return { suspicious: true, riskScore: 10, threats: ['blocked_ip'] }
    }

    // Create suspicious event
    const event: SuspiciousEvent = {
      id: `evt_${++this.eventCounter}_${now}`,
      timestamp: now,
      ip,
      eventType,
      severity: 'low',
      details,
      userAgent,
      sessionId,
      riskScore: 0
    }

    // Get or create IP risk profile
    let profile = this.ipProfiles.get(ip)
    if (!profile) {
      profile = {
        ip,
        riskScore: 0,
        events: [],
        firstSeen: now,
        lastSeen: now,
        isBlocked: false
      }
      this.ipProfiles.set(ip, profile)
    }

    profile.lastSeen = now
    profile.events.push(event)

    // Keep only recent events (last 24 hours)
    const dayAgo = now - 24 * 60 * 60 * 1000
    profile.events = profile.events.filter(e => e.timestamp > dayAgo)

    // Analyze patterns
    const analysis = await this.analyzePatterns(profile, event)
    event.riskScore = analysis.riskScore
    event.severity = this.calculateSeverity(analysis.riskScore)

    // Update profile risk score
    profile.riskScore = Math.max(profile.riskScore, analysis.riskScore)

    // Auto-block if risk is too high
    if (analysis.riskScore >= 8 && analysis.threats.some(threat => 
      THREAT_PATTERNS.find(p => p.name === threat)?.autoBlock
    )) {
      await this.blockIP(ip, `High risk activity detected: ${analysis.threats.join(', ')}`)
    }

    // Log suspicious activity
    if (analysis.suspicious) {
      await this.logSuspiciousActivity(event, analysis.threats)
    }

    return analysis
  }

  /**
   * Analyze patterns in IP activity
   */
  private async analyzePatterns(
    profile: IPRiskProfile,
    currentEvent: SuspiciousEvent
  ): Promise<{ suspicious: boolean; riskScore: number; threats: string[] }> {
    const threats: string[] = []
    let riskScore = 0

    const recentEvents = profile.events.slice(-50) // Last 50 events
    const lastHour = currentEvent.timestamp - 60 * 60 * 1000
    const recentHourEvents = recentEvents.filter(e => e.timestamp > lastHour)

    // Pattern 1: High frequency of requests
    if (recentHourEvents.length > 100) {
      threats.push('high_frequency')
      riskScore += 3
    }

    // Pattern 2: High failure rate
    const failedEvents = recentEvents.filter(e => 
      e.eventType.includes('failed') || e.eventType.includes('invalid')
    )
    const failureRate = failedEvents.length / Math.max(recentEvents.length, 1)
    if (failureRate > 0.7) {
      threats.push('high_failure_rate')
      riskScore += 4
    }

    // Pattern 3: Rapid sequential attempts
    const rapidAttempts = this.detectRapidAttempts(recentEvents)
    if (rapidAttempts > 10) {
      threats.push('rapid_attempts')
      riskScore += 3
    }

    // Pattern 4: Suspicious user agent patterns
    const userAgentRisk = this.analyzeUserAgent(currentEvent.userAgent || '')
    if (userAgentRisk > 0) {
      threats.push('suspicious_user_agent')
      riskScore += userAgentRisk
    }

    // Pattern 5: Session manipulation
    if (currentEvent.eventType.includes('session') && currentEvent.details) {
      const sessionRisk = this.analyzeSessionActivity(currentEvent.details)
      if (sessionRisk > 0) {
        threats.push('session_manipulation')
        riskScore += sessionRisk
      }
    }

    // Pattern 6: JWT/Token manipulation
    if (currentEvent.eventType.includes('jwt') || currentEvent.eventType.includes('token')) {
      threats.push('token_manipulation')
      riskScore += 5
    }

    // Pattern 7: IP geolocation jumps (simplified)
    if (this.detectGeolocationJump(profile)) {
      threats.push('geolocation_jump')
      riskScore += 4
    }

    // Pattern 8: Consistent timing (bot behavior)
    const timingConsistency = this.analyzeTimingPatterns(recentEvents)
    if (timingConsistency > 0.8) {
      threats.push('bot_timing')
      riskScore += 3
    }

    return {
      suspicious: riskScore > 3,
      riskScore: Math.min(riskScore, 10),
      threats
    }
  }

  /**
   * Detect rapid sequential attempts
   */
  private detectRapidAttempts(events: SuspiciousEvent[]): number {
    let rapidCount = 0
    for (let i = 1; i < events.length; i++) {
      const timeDiff = events[i].timestamp - events[i - 1].timestamp
      if (timeDiff < 1000) { // Less than 1 second apart
        rapidCount++
      }
    }
    return rapidCount
  }

  /**
   * Analyze user agent for suspicious patterns
   */
  private analyzeUserAgent(userAgent: string): number {
    let risk = 0

    // Empty or missing user agent
    if (!userAgent || userAgent.length < 10) {
      risk += 2
    }

    // Known bot patterns
    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /java/i
    ]
    
    if (botPatterns.some(pattern => pattern.test(userAgent))) {
      risk += 3
    }

    // Suspicious patterns
    if (userAgent.includes('Mozilla/5.0') && userAgent.length < 50) {
      risk += 1 // Minimal user agent
    }

    return risk
  }

  /**
   * Analyze session activity for manipulation
   */
  private analyzeSessionActivity(details: any): number {
    let risk = 0

    if (details.error) {
      if (details.error.includes('signature') || details.error.includes('tampering')) {
        risk += 5
      }
      if (details.error.includes('expired') && details.attemptCount > 5) {
        risk += 2
      }
    }

    if (details.ipMismatch || details.deviceMismatch) {
      risk += 4
    }

    return risk
  }

  /**
   * Detect geolocation jumps (simplified implementation)
   */
  private detectGeolocationJump(profile: IPRiskProfile): boolean {
    // This is a simplified implementation
    // In a real system, you would use a geolocation service
    const recentEvents = profile.events.slice(-10)
    
    // Look for rapid changes in IP patterns that might indicate VPN/proxy hopping
    const ipPrefixes = recentEvents.map(e => e.ip.split('.').slice(0, 2).join('.'))
    const uniquePrefixes = new Set(ipPrefixes)
    
    return uniquePrefixes.size > 3 // Multiple IP ranges in short time
  }

  /**
   * Analyze timing patterns for bot detection
   */
  private analyzeTimingPatterns(events: SuspiciousEvent[]): number {
    if (events.length < 5) return 0

    const intervals: number[] = []
    for (let i = 1; i < events.length; i++) {
      intervals.push(events[i].timestamp - events[i - 1].timestamp)
    }

    // Calculate coefficient of variation (consistency measure)
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length
    const variance = intervals.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / intervals.length
    const stdDev = Math.sqrt(variance)
    const cv = stdDev / mean

    // Lower CV indicates more consistent timing (bot-like)
    return cv < 0.3 ? 1 - cv : 0
  }

  /**
   * Calculate severity based on risk score
   */
  private calculateSeverity(riskScore: number): 'low' | 'medium' | 'high' | 'critical' {
    if (riskScore >= 9) return 'critical'
    if (riskScore >= 7) return 'high'
    if (riskScore >= 4) return 'medium'
    return 'low'
  }

  /**
   * Block IP address
   */
  private async blockIP(ip: string, reason: string): Promise<void> {
    this.blockedIPs.add(ip)
    
    const profile = this.ipProfiles.get(ip)
    if (profile) {
      profile.isBlocked = true
      profile.blockReason = reason
    }

    await auditService.logSecurityEvent(
      'ip_auto_blocked',
      {
        ip,
        reason,
        riskScore: profile?.riskScore || 0,
        eventCount: profile?.events.length || 0
      },
      ip
    )

    logger.error('SuspiciousActivityDetector', `Auto-blocked IP ${ip}: ${reason}`)
  }

  /**
   * Log suspicious activity
   */
  private async logSuspiciousActivity(event: SuspiciousEvent, threats: string[]): Promise<void> {
    await auditService.logSecurityEvent(
      'suspicious_activity_detected',
      {
        eventId: event.id,
        eventType: event.eventType,
        threats,
        riskScore: event.riskScore,
        severity: event.severity,
        details: event.details,
        userAgent: event.userAgent,
        sessionId: event.sessionId
      },
      event.ip
    )

    logger.warn('SuspiciousActivityDetector', 
      `Suspicious activity detected from ${event.ip}: ${threats.join(', ')} (risk: ${event.riskScore})`
    )
  }

  /**
   * Get IP risk profile
   */
  getIPProfile(ip: string): IPRiskProfile | null {
    return this.ipProfiles.get(ip) || null
  }

  /**
   * Manually unblock IP
   */
  unblockIP(ip: string, reason: string = 'manual unblock'): boolean {
    if (this.blockedIPs.has(ip)) {
      this.blockedIPs.delete(ip)
      
      const profile = this.ipProfiles.get(ip)
      if (profile) {
        profile.isBlocked = false
        profile.blockReason = undefined
        profile.riskScore = Math.max(0, profile.riskScore - 3) // Reduce risk score
      }

      logger.info('SuspiciousActivityDetector', `Unblocked IP ${ip}: ${reason}`)
      return true
    }
    return false
  }

  /**
   * Clean up old data
   */
  cleanup(): void {
    const now = Date.now()
    const weekAgo = now - 7 * 24 * 60 * 60 * 1000

    // Clean up old IP profiles
    for (const [ip, profile] of this.ipProfiles.entries()) {
      if (profile.lastSeen < weekAgo && !profile.isBlocked) {
        this.ipProfiles.delete(ip)
      } else {
        // Clean up old events within profile
        profile.events = profile.events.filter(e => e.timestamp > weekAgo)
      }
    }

    logger.info('SuspiciousActivityDetector', 'Completed cleanup of old suspicious activity data')
  }
}

// Export singleton instance
export const suspiciousActivityDetector = SuspiciousActivityDetector.getInstance()

// Schedule periodic cleanup
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    suspiciousActivityDetector.cleanup()
  }, 6 * 60 * 60 * 1000) // Clean up every 6 hours
}
