/**
 * JWT Session Service
 * Integrates JWT token validation with enhanced session management
 */

import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'
import { NextRequest } from 'next/server'
import { 
  Session, 
  createSecureSession, 
  validateSecureSession, 
  invalidateSession,
  generateDeviceFingerprint,
  logSuspiciousActivity,
  isIpLockedOut,
  recordFailedLogin,
  clearFailedLogins
} from './security'
import { getClientIP } from './security'
import { logger } from '@/utils/logger'

// JWT Configuration for session tokens
const JWT_SESSION_CONFIG = {
  secret: process.env.JWT_SESSION_SECRET || 'your-super-secure-session-secret-key',
  algorithm: 'HS256' as const,
  issuer: 'business-scraper-auth',
  audience: 'business-scraper-app',
  sessionTokenLifetime: 24 * 60 * 60, // 24 hours in seconds
  renewalTokenLifetime: 7 * 24 * 60 * 60, // 7 days in seconds
}

export interface JWTSessionPayload {
  iss: string // issuer
  sub: string // subject (user ID)
  aud: string // audience
  exp: number // expiration time
  iat: number // issued at
  jti: string // JWT ID (session ID)
  sessionId: string
  ipHash: string
  deviceFingerprint?: string
  tokenType: 'session' | 'renewal'
  securityLevel: 'basic' | 'enhanced'
}

export interface SessionValidationResult {
  valid: boolean
  session?: Session
  error?: string
  needsRenewal?: boolean
  securityFlags?: {
    ipValidated: boolean
    deviceValidated: boolean
    jwtVerified: boolean
    suspiciousActivity: boolean
  }
}

export class JWTSessionService {
  private static instance: JWTSessionService

  static getInstance(): JWTSessionService {
    if (!JWTSessionService.instance) {
      JWTSessionService.instance = new JWTSessionService()
    }
    return JWTSessionService.instance
  }

  /**
   * Create a new JWT-secured session
   */
  async createJWTSession(
    request: NextRequest,
    userId: string = 'admin'
  ): Promise<{ session: Session; jwtToken: string; renewalToken: string }> {
    const ipAddress = getClientIP(request)
    
    // Check if IP is locked out
    if (isIpLockedOut(ipAddress)) {
      throw new Error('IP address is temporarily locked due to suspicious activity')
    }

    const sessionId = uuidv4()
    const now = Math.floor(Date.now() / 1000)
    
    // Generate device fingerprint
    const deviceFingerprint = generateDeviceFingerprint(request)
    
    // Create session JWT payload
    const sessionPayload: JWTSessionPayload = {
      iss: JWT_SESSION_CONFIG.issuer,
      sub: userId,
      aud: JWT_SESSION_CONFIG.audience,
      exp: now + JWT_SESSION_CONFIG.sessionTokenLifetime,
      iat: now,
      jti: sessionId,
      sessionId,
      ipHash: await this.hashIP(ipAddress),
      deviceFingerprint: deviceFingerprint.hash,
      tokenType: 'session',
      securityLevel: 'enhanced'
    }

    // Create renewal JWT payload
    const renewalPayload: JWTSessionPayload = {
      ...sessionPayload,
      jti: uuidv4(),
      exp: now + JWT_SESSION_CONFIG.renewalTokenLifetime,
      tokenType: 'renewal'
    }

    // Sign JWT tokens
    const jwtToken = jwt.sign(sessionPayload, JWT_SESSION_CONFIG.secret, {
      algorithm: JWT_SESSION_CONFIG.algorithm
    })

    const renewalToken = jwt.sign(renewalPayload, JWT_SESSION_CONFIG.secret, {
      algorithm: JWT_SESSION_CONFIG.algorithm
    })

    // Create secure session
    const session = await createSecureSession(ipAddress, request, jwtToken)
    
    // Update session with JWT signature
    session.jwtSignature = await this.generateJWTSignature(jwtToken, sessionId)
    
    // Clear any previous failed login attempts
    clearFailedLogins(ipAddress)
    
    logger.info('JWTSessionService', `Created JWT session ${sessionId} for user ${userId} from IP ${ipAddress}`)

    return { session, jwtToken, renewalToken }
  }

  /**
   * Validate JWT session with comprehensive security checks
   */
  async validateJWTSession(
    request: NextRequest,
    sessionId: string,
    jwtToken: string
  ): Promise<SessionValidationResult> {
    const ipAddress = getClientIP(request)

    try {
      // Verify JWT token signature and decode payload
      const payload = jwt.verify(jwtToken, JWT_SESSION_CONFIG.secret, {
        algorithm: JWT_SESSION_CONFIG.algorithm,
        issuer: JWT_SESSION_CONFIG.issuer,
        audience: JWT_SESSION_CONFIG.audience
      }) as JWTSessionPayload

      // Validate JWT payload structure
      if (!payload.sessionId || payload.sessionId !== sessionId) {
        await logSuspiciousActivity(ipAddress, 'jwt_session_id_mismatch', {
          providedSessionId: sessionId,
          jwtSessionId: payload.sessionId
        })
        return { valid: false, error: 'Session ID mismatch in JWT' }
      }

      // Validate token type
      if (payload.tokenType !== 'session') {
        return { valid: false, error: 'Invalid token type for session validation' }
      }

      // Validate IP hash (if available in JWT)
      if (payload.ipHash) {
        const currentIpHash = await this.hashIP(ipAddress)
        if (payload.ipHash !== currentIpHash) {
          await logSuspiciousActivity(ipAddress, 'jwt_ip_hash_mismatch', {
            sessionId,
            expectedHash: payload.ipHash,
            actualHash: currentIpHash
          })
          return { valid: false, error: 'IP address validation failed' }
        }
      }

      // Validate session using enhanced security checks
      const sessionValidation = await validateSecureSession(
        sessionId,
        ipAddress,
        request,
        jwtToken
      )

      if (!sessionValidation.valid) {
        return {
          valid: false,
          error: sessionValidation.error,
          securityFlags: sessionValidation.session?.securityFlags
        }
      }

      const session = sessionValidation.session!

      // Check if session needs renewal (within renewal threshold)
      const now = new Date()
      const timeUntilExpiry = session.expiresAt.getTime() - now.getTime()
      const needsRenewal = timeUntilExpiry <= session.renewalThreshold

      return {
        valid: true,
        session,
        needsRenewal,
        securityFlags: session.securityFlags
      }

    } catch (error) {
      // Log JWT validation errors
      if (error instanceof jwt.JsonWebTokenError) {
        await logSuspiciousActivity(ipAddress, 'jwt_validation_error', {
          sessionId,
          error: error.message,
          tokenProvided: !!jwtToken
        })
        
        logger.warn('JWTSessionService', `JWT validation failed for session ${sessionId}`, error)
        return { valid: false, error: 'Invalid JWT token' }
      }

      logger.error('JWTSessionService', `Session validation error for ${sessionId}`, error)
      return { valid: false, error: 'Session validation failed' }
    }
  }

  /**
   * Renew JWT session using renewal token
   */
  async renewJWTSession(
    request: NextRequest,
    sessionId: string,
    renewalToken: string
  ): Promise<{ session: Session; jwtToken: string; renewalToken: string } | null> {
    const ipAddress = getClientIP(request)

    try {
      // Verify renewal token
      const payload = jwt.verify(renewalToken, JWT_SESSION_CONFIG.secret, {
        algorithm: JWT_SESSION_CONFIG.algorithm,
        issuer: JWT_SESSION_CONFIG.issuer,
        audience: JWT_SESSION_CONFIG.audience
      }) as JWTSessionPayload

      if (payload.tokenType !== 'renewal') {
        return null
      }

      // Validate session exists and can be renewed
      const sessionValidation = await validateSecureSession(sessionId, ipAddress, request)
      if (!sessionValidation.valid || !sessionValidation.session) {
        return null
      }

      const session = sessionValidation.session

      // Check renewal limits
      if (session.renewalCount >= session.maxRenewals) {
        logger.warn('JWTSessionService', `Session ${sessionId} exceeded max renewals`)
        return null
      }

      // Create new JWT session
      const newSession = await this.createJWTSession(request, payload.sub)
      
      // Update renewal count
      newSession.session.renewalCount = session.renewalCount + 1
      newSession.session.lastRenewal = new Date()

      // Invalidate old session
      invalidateSession(sessionId)

      logger.info('JWTSessionService', `Renewed session ${sessionId} -> ${newSession.session.id}`)

      return newSession

    } catch (error) {
      logger.warn('JWTSessionService', `Session renewal failed for ${sessionId}`, error)
      return null
    }
  }

  /**
   * Invalidate JWT session
   */
  async invalidateJWTSession(sessionId: string, reason: string = 'logout'): Promise<void> {
    invalidateSession(sessionId)
    logger.info('JWTSessionService', `Invalidated session ${sessionId}: ${reason}`)
  }

  /**
   * Generate JWT signature for additional verification
   */
  private async generateJWTSignature(jwtToken: string, sessionId: string): Promise<string> {
    const crypto = globalThis.crypto || require('crypto').webcrypto
    const encoder = new TextEncoder()
    const data = encoder.encode(`${jwtToken}:${sessionId}`)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = new Uint8Array(hashBuffer)
    return Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Hash IP address for JWT payload
   */
  private async hashIP(ipAddress: string): Promise<string> {
    const crypto = globalThis.crypto || require('crypto').webcrypto
    const encoder = new TextEncoder()
    const data = encoder.encode(ipAddress)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = new Uint8Array(hashBuffer)
    return Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('')
  }
}

// Export singleton instance
export const jwtSessionService = JWTSessionService.getInstance()
