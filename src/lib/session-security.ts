/**
 * Enhanced Session Security Management
 * Implements secure session management with fingerprinting, IP validation, and session hijacking protection
 */

import crypto from 'crypto'
import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

export interface SessionSecurityConfig {
  sessionTimeout: number // in milliseconds
  absoluteTimeout: number // in milliseconds
  renewalThreshold: number // percentage of session lifetime
  maxRenewals: number
  strictIPBinding: boolean
  deviceFingerprintRequired: boolean
  suspiciousActivityThreshold: number
}

export interface SecureSession {
  id: string
  userId: string
  csrfToken: string
  fingerprint: string
  ipAddress: string
  userAgent: string
  createdAt: Date
  lastAccessedAt: Date
  expiresAt: Date
  absoluteExpiresAt: Date
  renewalCount: number
  isValid: boolean
  securityFlags: {
    ipValidated: boolean
    deviceValidated: boolean
    jwtVerified: boolean
    suspiciousActivity: boolean
    highRisk: boolean
  }
  metadata: {
    loginMethod: string
    mfaVerified: boolean
    deviceTrusted: boolean
    geoLocation?: string
  }
}

export interface SessionValidationResult {
  valid: boolean
  session?: SecureSession
  renewed?: boolean
  newTokens?: {
    sessionId: string
    csrfToken: string
  }
  error?: string
  securityAlert?: string
}

export interface DeviceFingerprint {
  hash: string
  components: {
    userAgent: string
    acceptLanguage: string
    acceptEncoding: string
    screenResolution?: string
    timezone?: string
    platform?: string
  }
  risk: 'low' | 'medium' | 'high'
}

// Session security configuration
export const sessionSecurityConfig: SessionSecurityConfig = {
  sessionTimeout: 30 * 60 * 1000, // 30 minutes
  absoluteTimeout: 8 * 60 * 60 * 1000, // 8 hours
  renewalThreshold: 0.75, // Renew when 75% of session lifetime has passed
  maxRenewals: 10,
  strictIPBinding: true,
  deviceFingerprintRequired: true,
  suspiciousActivityThreshold: 3
}

// In-memory session store (in production, this should be in database)
const sessions = new Map<string, SecureSession>()
const deviceFingerprints = new Map<string, DeviceFingerprint>()
const suspiciousActivities = new Map<string, number>()

export class SecureSessionManager {
  private static instance: SecureSessionManager

  static getInstance(): SecureSessionManager {
    if (!SecureSessionManager.instance) {
      SecureSessionManager.instance = new SecureSessionManager()
    }
    return SecureSessionManager.instance
  }

  /**
   * Create a new secure session
   */
  async createSession(
    userId: string,
    request: NextRequest,
    loginMethod: string = 'password',
    mfaVerified: boolean = false
  ): Promise<SecureSession> {
    try {
      const sessionId = this.generateSessionId()
      const csrfToken = this.generateCSRFToken()
      const ipAddress = this.getClientIP(request)
      const userAgent = request.headers.get('user-agent') || ''
      
      // Generate device fingerprint
      const fingerprint = this.generateDeviceFingerprint(request)
      deviceFingerprints.set(sessionId, fingerprint)

      const now = new Date()
      const expiresAt = new Date(now.getTime() + sessionSecurityConfig.sessionTimeout)
      const absoluteExpiresAt = new Date(now.getTime() + sessionSecurityConfig.absoluteTimeout)

      const session: SecureSession = {
        id: sessionId,
        userId,
        csrfToken,
        fingerprint: fingerprint.hash,
        ipAddress,
        userAgent,
        createdAt: now,
        lastAccessedAt: now,
        expiresAt,
        absoluteExpiresAt,
        renewalCount: 0,
        isValid: true,
        securityFlags: {
          ipValidated: true,
          deviceValidated: fingerprint.risk === 'low',
          jwtVerified: false,
          suspiciousActivity: false,
          highRisk: fingerprint.risk === 'high'
        },
        metadata: {
          loginMethod,
          mfaVerified,
          deviceTrusted: fingerprint.risk === 'low',
          geoLocation: request.geo?.city || undefined
        }
      }

      sessions.set(sessionId, session)

      // Log session creation
      await auditService.logSecurityEvent('session_created', {
        sessionId,
        userId,
        ipAddress,
        userAgent,
        loginMethod,
        mfaVerified,
        deviceRisk: fingerprint.risk,
        timestamp: now
      })

      logger.info('SessionSecurity', `Created secure session ${sessionId} for user ${userId}`)

      return session
    } catch (error) {
      logger.error('SessionSecurity', 'Failed to create session', error)
      throw new Error('Session creation failed')
    }
  }

  /**
   * Validate session with enhanced security checks
   */
  async validateSession(
    sessionId: string,
    request: NextRequest
  ): Promise<SessionValidationResult> {
    try {
      const session = sessions.get(sessionId)
      if (!session) {
        return { valid: false, error: 'Session not found' }
      }

      const now = new Date()
      const ipAddress = this.getClientIP(request)

      // Check if session is expired
      if (now > session.expiresAt || now > session.absoluteExpiresAt) {
        sessions.delete(sessionId)
        deviceFingerprints.delete(sessionId)
        
        await auditService.logSecurityEvent('session_expired', {
          sessionId,
          userId: session.userId,
          expiredAt: now
        })

        return { valid: false, error: 'Session expired' }
      }

      // Check if session is marked as invalid
      if (!session.isValid) {
        return { valid: false, error: 'Session invalidated' }
      }

      // Strict IP binding check
      if (sessionSecurityConfig.strictIPBinding && session.ipAddress !== ipAddress) {
        await this.handleSuspiciousActivity(sessionId, 'ip_address_change', {
          originalIP: session.ipAddress,
          currentIP: ipAddress
        })
        
        return { 
          valid: false, 
          error: 'Session invalid',
          securityAlert: 'IP address mismatch detected'
        }
      }

      // Device fingerprint validation
      if (sessionSecurityConfig.deviceFingerprintRequired) {
        const currentFingerprint = this.generateDeviceFingerprint(request)
        const storedFingerprint = deviceFingerprints.get(sessionId)

        if (storedFingerprint && currentFingerprint.hash !== storedFingerprint.hash) {
          await this.handleSuspiciousActivity(sessionId, 'device_fingerprint_mismatch', {
            storedFingerprint: storedFingerprint.hash,
            currentFingerprint: currentFingerprint.hash
          })

          return {
            valid: false,
            error: 'Session invalid',
            securityAlert: 'Device fingerprint mismatch detected'
          }
        }
      }

      // Update last accessed time
      session.lastAccessedAt = now

      // Check if session needs renewal
      const sessionAge = now.getTime() - session.createdAt.getTime()
      const sessionLifetime = session.expiresAt.getTime() - session.createdAt.getTime()
      const renewalThreshold = sessionLifetime * sessionSecurityConfig.renewalThreshold

      if (sessionAge > renewalThreshold && session.renewalCount < sessionSecurityConfig.maxRenewals) {
        // Renew session
        const renewedSession = await this.renewSession(session)
        sessions.set(sessionId, renewedSession)

        return {
          valid: true,
          session: renewedSession,
          renewed: true,
          newTokens: {
            sessionId: renewedSession.id,
            csrfToken: renewedSession.csrfToken
          }
        }
      }

      // Update session
      sessions.set(sessionId, session)

      return { valid: true, session }
    } catch (error) {
      logger.error('SessionSecurity', 'Session validation failed', error)
      return { valid: false, error: 'Session validation error' }
    }
  }

  /**
   * Invalidate session
   */
  async invalidateSession(sessionId: string, reason: string = 'logout'): Promise<void> {
    const session = sessions.get(sessionId)
    if (session) {
      sessions.delete(sessionId)
      deviceFingerprints.delete(sessionId)
      suspiciousActivities.delete(sessionId)

      await auditService.logSecurityEvent('session_invalidated', {
        sessionId,
        userId: session.userId,
        reason,
        timestamp: new Date()
      })

      logger.info('SessionSecurity', `Invalidated session ${sessionId} - ${reason}`)
    }
  }

  /**
   * Generate device fingerprint
   */
  private generateDeviceFingerprint(request: NextRequest): DeviceFingerprint {
    const userAgent = request.headers.get('user-agent') || ''
    const acceptLanguage = request.headers.get('accept-language') || ''
    const acceptEncoding = request.headers.get('accept-encoding') || ''
    
    const components = {
      userAgent,
      acceptLanguage,
      acceptEncoding,
      platform: this.extractPlatform(userAgent),
      timezone: request.headers.get('x-timezone') || undefined,
      screenResolution: request.headers.get('x-screen-resolution') || undefined
    }

    // Create fingerprint hash
    const fingerprintData = Object.values(components).filter(Boolean).join('|')
    const hash = crypto.createHash('sha256').update(fingerprintData).digest('hex')

    // Assess risk based on fingerprint characteristics
    const risk = this.assessDeviceRisk(components)

    return { hash, components, risk }
  }

  /**
   * Assess device risk level
   */
  private assessDeviceRisk(components: DeviceFingerprint['components']): 'low' | 'medium' | 'high' {
    let riskScore = 0

    // Check for suspicious user agents
    if (!components.userAgent || components.userAgent.length < 50) {
      riskScore += 2
    }

    // Check for automation indicators
    if (components.userAgent.includes('bot') || 
        components.userAgent.includes('crawler') ||
        components.userAgent.includes('headless')) {
      riskScore += 3
    }

    // Check for missing standard headers
    if (!components.acceptLanguage) riskScore += 1
    if (!components.acceptEncoding) riskScore += 1

    if (riskScore >= 4) return 'high'
    if (riskScore >= 2) return 'medium'
    return 'low'
  }

  /**
   * Extract platform from user agent
   */
  private extractPlatform(userAgent: string): string {
    if (userAgent.includes('Windows')) return 'Windows'
    if (userAgent.includes('Mac')) return 'macOS'
    if (userAgent.includes('Linux')) return 'Linux'
    if (userAgent.includes('Android')) return 'Android'
    if (userAgent.includes('iOS')) return 'iOS'
    return 'Unknown'
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
   * Renew session
   */
  private async renewSession(session: SecureSession): Promise<SecureSession> {
    const now = new Date()
    const newCsrfToken = this.generateCSRFToken()

    session.csrfToken = newCsrfToken
    session.expiresAt = new Date(now.getTime() + sessionSecurityConfig.sessionTimeout)
    session.renewalCount++
    session.lastAccessedAt = now

    await auditService.logSecurityEvent('session_renewed', {
      sessionId: session.id,
      userId: session.userId,
      renewalCount: session.renewalCount,
      timestamp: now
    })

    return session
  }

  /**
   * Handle suspicious activity
   */
  private async handleSuspiciousActivity(
    sessionId: string,
    activityType: string,
    details: Record<string, any>
  ): Promise<void> {
    const session = sessions.get(sessionId)
    if (!session) return

    // Track suspicious activity count
    const currentCount = suspiciousActivities.get(sessionId) || 0
    suspiciousActivities.set(sessionId, currentCount + 1)

    // Mark session as having suspicious activity
    session.securityFlags.suspiciousActivity = true
    sessions.set(sessionId, session)

    // Log security event
    await auditService.logSecurityEvent('suspicious_activity_detected', {
      sessionId,
      userId: session.userId,
      activityType,
      details,
      count: currentCount + 1,
      timestamp: new Date()
    })

    // If threshold exceeded, invalidate session
    if (currentCount + 1 >= sessionSecurityConfig.suspiciousActivityThreshold) {
      await this.invalidateSession(sessionId, 'suspicious_activity')
    }

    logger.warn('SessionSecurity', `Suspicious activity detected for session ${sessionId}: ${activityType}`)
  }

  /**
   * Generate session ID
   */
  private generateSessionId(): string {
    const timestamp = Date.now().toString(36)
    const random = Math.random().toString(36).substring(2)
    return `sess_${timestamp}_${random}`
  }

  /**
   * Generate CSRF token
   */
  private generateCSRFToken(): string {
    const bytes = new Uint8Array(32)
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(bytes)
    } else {
      // Fallback for environments without crypto.getRandomValues
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Math.floor(Math.random() * 256)
      }
    }
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Get session statistics
   */
  getSessionStatistics(): {
    totalSessions: number
    activeSessions: number
    expiredSessions: number
    suspiciousSessions: number
  } {
    const now = new Date()
    let activeSessions = 0
    let expiredSessions = 0
    let suspiciousSessions = 0

    for (const session of sessions.values()) {
      if (now > session.expiresAt || now > session.absoluteExpiresAt) {
        expiredSessions++
      } else if (session.isValid) {
        activeSessions++
      }

      if (session.securityFlags.suspiciousActivity) {
        suspiciousSessions++
      }
    }

    return {
      totalSessions: sessions.size,
      activeSessions,
      expiredSessions,
      suspiciousSessions
    }
  }
}

// Export singleton instance
export const secureSessionManager = SecureSessionManager.getInstance()
