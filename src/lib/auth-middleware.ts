/**
 * Authentication Middleware for API Routes
 * Provides consistent authentication checks across all protected endpoints
 */

import { NextRequest, NextResponse } from 'next/server'
import { getSession, getClientIP, validateSecureSession, isIpLockedOut, recordFailedLogin } from '@/lib/security'
import { jwtSessionService, SessionValidationResult } from '@/lib/jwt-session-service'
import { authRateLimiter } from '@/lib/auth-rate-limiter'
import { suspiciousActivityDetector } from '@/lib/suspicious-activity-detector'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

export interface AuthConfig {
  required?: boolean
  allowPublic?: boolean
  roles?: string[]
  permissions?: string[]
  // Enhanced security options
  requireJWT?: boolean
  strictIPBinding?: boolean
  requireDeviceFingerprint?: boolean
  maxFailedAttempts?: number
}

/**
 * Authentication middleware wrapper
 */
export function withAuth(
  handler: (request: NextRequest, context?: AuthContext) => Promise<NextResponse>,
  config: AuthConfig = {}
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const { required = true, allowPublic = false } = config
    const ip = getClientIP(request)
    const pathname = request.nextUrl.pathname

    try {
      // Analyze request for suspicious activity
      const suspiciousAnalysis = await suspiciousActivityDetector.analyzeRequest(
        request,
        'auth_middleware_check',
        { endpoint: pathname, method: request.method }
      )

      if (suspiciousAnalysis.suspicious && suspiciousAnalysis.riskScore >= 8) {
        await auditService.logSecurityEvent(
          'suspicious_auth_attempt_blocked',
          {
            endpoint: pathname,
            method: request.method,
            userAgent: request.headers.get('user-agent'),
            riskScore: suspiciousAnalysis.riskScore,
            threats: suspiciousAnalysis.threats,
            message: `High-risk authentication attempt blocked`
          },
          ip
        )

        logger.error('Auth Middleware', `Blocked high-risk auth attempt from ${ip}. Risk: ${suspiciousAnalysis.riskScore}, Threats: ${suspiciousAnalysis.threats.join(', ')}`)
        return NextResponse.json({
          error: 'Access denied due to suspicious activity',
          riskScore: suspiciousAnalysis.riskScore
        }, { status: 403 })
      }

      // Check rate limiting for authentication attempts
      const rateLimitResult = authRateLimiter.checkRateLimit(request, 'session_validation')
      if (!rateLimitResult.allowed) {
        await auditService.logSecurityEvent(
          'rate_limit_exceeded',
          {
            endpoint: pathname,
            method: request.method,
            userAgent: request.headers.get('user-agent'),
            message: `Rate limit exceeded: ${rateLimitResult.reason}`,
            remaining: rateLimitResult.remaining,
            resetTime: rateLimitResult.resetTime,
            lockoutUntil: rateLimitResult.lockoutUntil
          },
          ip
        )

        logger.warn('Auth Middleware', `Rate limit exceeded for ${ip}: ${rateLimitResult.reason}`)

        const response = NextResponse.json({
          error: 'Rate limit exceeded',
          details: rateLimitResult.reason,
          retryAfter: rateLimitResult.resetTime
        }, { status: 429 })

        // Add rate limit headers
        response.headers.set('X-RateLimit-Limit', '50')
        response.headers.set('X-RateLimit-Remaining', rateLimitResult.remaining.toString())
        response.headers.set('X-RateLimit-Reset', rateLimitResult.resetTime.toString())
        if (rateLimitResult.lockoutUntil) {
          response.headers.set('X-RateLimit-LockoutUntil', rateLimitResult.lockoutUntil.toString())
        }

        return response
      }

      // Check if IP is locked out due to failed attempts (legacy check)
      if (isIpLockedOut(ip)) {
        await auditService.logSecurityEvent(
          'ip_lockout_access_attempt',
          {
            endpoint: pathname,
            method: request.method,
            userAgent: request.headers.get('user-agent'),
            message: `Access attempt from locked IP: ${ip}`,
          },
          ip
        )

        logger.warn('Auth Middleware', `Access attempt from locked IP: ${ip}`)
        return NextResponse.json({ error: 'Access temporarily restricted' }, { status: 429 })
      }

      // If public access is allowed and no session is provided, proceed
      const sessionId = request.cookies.get('session-id')?.value
      const jwtToken = request.headers.get('authorization')?.replace('Bearer ', '') ||
                      request.cookies.get('jwt-token')?.value

      if (!sessionId) {
        if (allowPublic || !required) {
          return handler(request, { authenticated: false })
        }

        // Record failed authentication attempt
        recordFailedLogin(ip)

        // Log unauthorized access attempt
        await auditService.logSecurityEvent(
          'unauthorized_access_attempt',
          {
            endpoint: pathname,
            method: request.method,
            userAgent: request.headers.get('user-agent'),
            message: `Authentication required for ${pathname}`,
          },
          ip
        )

        logger.warn('Auth Middleware', `Authentication required for ${pathname} from IP: ${ip}`)
        return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
      }

      // Enhanced session validation with JWT and security checks
      let sessionValidation: SessionValidationResult

      if (jwtToken && config.requireJWT !== false) {
        // Use JWT-based validation for enhanced security
        sessionValidation = await jwtSessionService.validateJWTSession(request, sessionId, jwtToken)
      } else {
        // Use enhanced session validation with IP and device checks
        const validation = await validateSecureSession(sessionId, ip, request, jwtToken)
        sessionValidation = {
          valid: validation.valid,
          session: validation.session,
          error: validation.error,
          securityFlags: validation.session?.securityFlags
        }
      }

      if (!sessionValidation.valid || !sessionValidation.session) {
        // Analyze failed authentication for suspicious patterns
        await suspiciousActivityDetector.analyzeRequest(
          request,
          'auth_validation_failed',
          {
            endpoint: pathname,
            error: sessionValidation.error,
            sessionId: sessionId,
            jwtProvided: !!jwtToken
          },
          sessionId
        )

        // Record failed authentication attempt with rate limiter
        authRateLimiter.recordAttempt(request, 'session_validation', false, sessionId)
        recordFailedLogin(ip) // Legacy tracking

        // Log invalid session attempt with enhanced details
        await auditService.logSecurityEvent(
          'invalid_session_access',
          {
            endpoint: pathname,
            method: request.method,
            sessionId: sessionId,
            userAgent: request.headers.get('user-agent'),
            message: `Invalid session for ${pathname}`,
            error: sessionValidation.error,
            securityFlags: sessionValidation.securityFlags,
            jwtProvided: !!jwtToken
          },
          ip
        )

        logger.warn('Auth Middleware', `Invalid session for ${pathname} from IP: ${ip}. Error: ${sessionValidation.error}`)
        const response = NextResponse.json({
          error: 'Invalid session',
          details: sessionValidation.error
        }, { status: 401 })
        response.cookies.delete('session-id')
        response.cookies.delete('jwt-token')
        return response
      }

      // Analyze successful authentication
      await suspiciousActivityDetector.analyzeRequest(
        request,
        'auth_validation_success',
        {
          endpoint: pathname,
          sessionId: sessionId,
          jwtProvided: !!jwtToken,
          securityFlags: sessionValidation.session.securityFlags
        },
        sessionId
      )

      // Record successful authentication attempt
      authRateLimiter.recordAttempt(request, 'session_validation', true, sessionId)

      const session = sessionValidation.session

      // Check for session renewal requirement
      if (sessionValidation.needsRenewal && jwtToken) {
        logger.info('Auth Middleware', `Session ${sessionId} requires renewal`)
        // Could implement automatic renewal here or return a specific header
      }

      // Log successful authentication with enhanced security details
      await auditService.logAuditEvent('session_validated', 'authentication', {
        userId: 'admin',
        sessionId: session.id,
        ipAddress: ip,
        userAgent: request.headers.get('user-agent'),
        severity: 'low',
        category: 'security',
        complianceFlags: ['SOC2'],
        securityFlags: session.securityFlags,
        jwtVerified: !!jwtToken,
        deviceFingerprint: session.deviceFingerprint,
        renewalCount: session.renewalCount
      })

      // Create enhanced auth context
      const authContext: AuthContext = {
        authenticated: true,
        sessionId: session.id,
        userId: 'admin', // Single user system
        csrfToken: session.csrfToken,
        // Enhanced security context
        securityFlags: session.securityFlags,
        jwtVerified: !!jwtToken,
        ipValidated: session.securityFlags.ipValidated,
        deviceValidated: session.securityFlags.deviceValidated
      }

      // Call handler with enhanced auth context
      return handler(request, authContext)
    } catch (error) {
      logger.error('Auth Middleware', `Authentication error for ${pathname}`, error)
      return NextResponse.json({ error: 'Authentication error' }, { status: 500 })
    }
  }
}

/**
 * Enhanced authentication context passed to handlers
 */
export interface AuthContext {
  authenticated: boolean
  sessionId?: string
  userId?: string
  csrfToken?: string
  // Enhanced security context
  securityFlags?: {
    ipValidated: boolean
    deviceValidated: boolean
    jwtVerified: boolean
    suspiciousActivity: boolean
  }
  jwtVerified?: boolean
  ipValidated?: boolean
  deviceValidated?: boolean
  renewalCount?: number
  lastRenewal?: Date
}

/**
 * Check if request has valid authentication
 */
export function isAuthenticated(request: NextRequest): boolean {
  const sessionId = request.cookies.get('session-id')?.value
  if (!sessionId) return false

  const session = getSession(sessionId)
  return session !== null && session.isValid
}

/**
 * Get enhanced authentication context from request with cryptographic verification
 */
export async function getAuthContext(request: NextRequest): Promise<AuthContext | null> {
  const sessionId = request.cookies.get('session-id')?.value
  if (!sessionId) return null

  const ip = getClientIP(request)
  const jwtToken = request.headers.get('authorization')?.replace('Bearer ', '') ||
                  request.cookies.get('jwt-token')?.value

  // Check if IP is locked out
  if (isIpLockedOut(ip)) {
    logger.warn('Auth Context', `Blocked auth context request from locked IP: ${ip}`)
    return null
  }

  try {
    let sessionValidation: SessionValidationResult

    if (jwtToken) {
      // Use JWT-based validation for enhanced security
      sessionValidation = await jwtSessionService.validateJWTSession(request, sessionId, jwtToken)
    } else {
      // Use enhanced session validation with IP and device checks
      const validation = await validateSecureSession(sessionId, ip, request, jwtToken)
      sessionValidation = {
        valid: validation.valid,
        session: validation.session,
        error: validation.error,
        securityFlags: validation.session?.securityFlags
      }
    }

    if (!sessionValidation.valid || !sessionValidation.session) {
      logger.warn('Auth Context', `Invalid session context for ${sessionId} from IP: ${ip}. Error: ${sessionValidation.error}`)
      return null
    }

    const session = sessionValidation.session

    return {
      authenticated: true,
      sessionId: session.id,
      userId: 'admin',
      csrfToken: session.csrfToken,
      securityFlags: session.securityFlags,
      jwtVerified: !!jwtToken,
      ipValidated: session.securityFlags.ipValidated,
      deviceValidated: session.securityFlags.deviceValidated,
      renewalCount: session.renewalCount,
      lastRenewal: session.lastRenewal
    }
  } catch (error) {
    logger.error('Auth Context', `Error getting auth context for session ${sessionId}`, error)
    return null
  }
}

/**
 * Get authentication context from request (legacy synchronous version)
 */
export function getAuthContextSync(request: NextRequest): AuthContext | null {
  const sessionId = request.cookies.get('session-id')?.value
  if (!sessionId) return null

  const session = getSession(sessionId)
  if (!session || !session.isValid) return null

  return {
    authenticated: true,
    sessionId: session.id,
    userId: 'admin',
    csrfToken: session.csrfToken,
    securityFlags: session.securityFlags,
    jwtVerified: false,
    ipValidated: session.securityFlags?.ipValidated || false,
    deviceValidated: session.securityFlags?.deviceValidated || false,
    renewalCount: session.renewalCount,
    lastRenewal: session.lastRenewal
  }
}

/**
 * Require authentication for API endpoint
 */
export function requireAuth(request: NextRequest): NextResponse | null {
  const sessionId = request.cookies.get('session-id')?.value
  const ip = getClientIP(request)

  if (!sessionId) {
    logger.warn('Auth Check', `No session provided from IP: ${ip}`)
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
  }

  const session = getSession(sessionId)
  if (!session || !session.isValid) {
    logger.warn('Auth Check', `Invalid session from IP: ${ip}`)
    const response = NextResponse.json({ error: 'Invalid session' }, { status: 401 })
    response.cookies.delete('session-id')
    return response
  }

  return null
}

/**
 * Optional authentication with IP address validation - allows both authenticated and public access
 */
export async function optionalAuth(request: NextRequest): Promise<AuthContext> {
  const sessionId = request.cookies.get('session-id')?.value
  if (!sessionId) {
    return { authenticated: false }
  }

  const ip = getClientIP(request)
  const jwtToken = request.headers.get('authorization')?.replace('Bearer ', '') ||
                  request.cookies.get('jwt-token')?.value

  // Check if IP is locked out (but don't block for optional auth)
  if (isIpLockedOut(ip)) {
    logger.warn('Optional Auth', `Optional auth request from locked IP: ${ip}`)
    return { authenticated: false }
  }

  try {
    let sessionValidation: SessionValidationResult

    if (jwtToken) {
      // Use JWT-based validation for enhanced security
      sessionValidation = await jwtSessionService.validateJWTSession(request, sessionId, jwtToken)
    } else {
      // Use enhanced session validation with IP and device checks
      const validation = await validateSecureSession(sessionId, ip, request, jwtToken)
      sessionValidation = {
        valid: validation.valid,
        session: validation.session,
        error: validation.error,
        securityFlags: validation.session?.securityFlags
      }
    }

    if (!sessionValidation.valid || !sessionValidation.session) {
      logger.info('Optional Auth', `Invalid optional session for ${sessionId} from IP: ${ip}. Error: ${sessionValidation.error}`)
      return { authenticated: false }
    }

    const session = sessionValidation.session

    return {
      authenticated: true,
      sessionId: session.id,
      userId: 'admin',
      csrfToken: session.csrfToken,
      securityFlags: session.securityFlags,
      jwtVerified: !!jwtToken,
      ipValidated: session.securityFlags.ipValidated,
      deviceValidated: session.securityFlags.deviceValidated,
      renewalCount: session.renewalCount,
      lastRenewal: session.lastRenewal
    }
  } catch (error) {
    logger.warn('Optional Auth', `Error in optional auth for session ${sessionId}`, error)
    return { authenticated: false }
  }
}

/**
 * Optional authentication (legacy synchronous version)
 */
export function optionalAuthSync(request: NextRequest): AuthContext {
  const sessionId = request.cookies.get('session-id')?.value
  if (!sessionId) {
    return { authenticated: false }
  }

  const session = getSession(sessionId)
  if (!session || !session.isValid) {
    return { authenticated: false }
  }

  return {
    authenticated: true,
    sessionId: session.id,
    userId: 'admin',
    csrfToken: session.csrfToken,
    securityFlags: session.securityFlags,
    jwtVerified: false,
    ipValidated: session.securityFlags?.ipValidated || false,
    deviceValidated: session.securityFlags?.deviceValidated || false,
    renewalCount: session.renewalCount,
    lastRenewal: session.lastRenewal
  }
}

/**
 * Create authentication headers for response
 */
export function addAuthHeaders(response: NextResponse, authContext: AuthContext): NextResponse {
  if (authContext.authenticated && authContext.csrfToken) {
    response.headers.set('X-CSRF-Token', authContext.csrfToken)
  }

  response.headers.set('X-Authenticated', authContext.authenticated ? 'true' : 'false')

  return response
}

/**
 * Middleware for endpoints that require admin privileges
 */
export function requireAdmin(request: NextRequest): NextResponse | null {
  // In a single-user system, any authenticated user is admin
  return requireAuth(request)
}

/**
 * Check if the current session has admin privileges
 */
export function isAdmin(authContext: AuthContext): boolean {
  // In a single-user system, any authenticated user is admin
  return authContext.authenticated
}

/**
 * Validate session and refresh if needed with enhanced security and automatic renewal
 */
export async function validateAndRefreshSession(request: NextRequest): Promise<{
  valid: boolean
  response?: NextResponse
  authContext?: AuthContext
  renewed?: boolean
  newTokens?: { jwtToken: string; renewalToken: string }
}> {
  const sessionId = request.cookies.get('session-id')?.value
  const jwtToken = request.headers.get('authorization')?.replace('Bearer ', '') ||
                  request.cookies.get('jwt-token')?.value
  const renewalToken = request.cookies.get('renewal-token')?.value

  if (!sessionId) {
    return { valid: false }
  }

  const ip = getClientIP(request)

  // Check if IP is locked out
  if (isIpLockedOut(ip)) {
    logger.warn('Session Validation', `Session validation blocked for locked IP: ${ip}`)
    const response = NextResponse.json({ error: 'Access temporarily restricted' }, { status: 429 })
    return { valid: false, response }
  }

  try {
    let sessionValidation: SessionValidationResult

    if (jwtToken) {
      // Use JWT-based validation for enhanced security
      sessionValidation = await jwtSessionService.validateJWTSession(request, sessionId, jwtToken)
    } else {
      // Use enhanced session validation with IP and device checks
      const validation = await validateSecureSession(sessionId, ip, request, jwtToken)
      sessionValidation = {
        valid: validation.valid,
        session: validation.session,
        error: validation.error,
        securityFlags: validation.session?.securityFlags
      }
    }

    if (!sessionValidation.valid || !sessionValidation.session) {
      logger.warn('Session Validation', `Invalid session ${sessionId} from IP: ${ip}. Error: ${sessionValidation.error}`)

      const response = NextResponse.json({
        error: 'Session expired',
        details: sessionValidation.error
      }, { status: 401 })
      response.cookies.delete('session-id')
      response.cookies.delete('jwt-token')
      response.cookies.delete('renewal-token')

      return { valid: false, response }
    }

    const session = sessionValidation.session

    // Check if session needs renewal
    if (sessionValidation.needsRenewal && renewalToken && jwtToken) {
      try {
        const renewalResult = await jwtSessionService.renewJWTSession(request, sessionId, renewalToken)

        if (renewalResult) {
          logger.info('Session Validation', `Successfully renewed session ${sessionId} -> ${renewalResult.session.id}`)

          // Create response with new tokens
          const response = NextResponse.json({
            message: 'Session renewed',
            sessionId: renewalResult.session.id
          })

          // Set new session cookies
          response.cookies.set('session-id', renewalResult.session.id, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 // 24 hours
          })

          response.cookies.set('jwt-token', renewalResult.jwtToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 // 24 hours
          })

          response.cookies.set('renewal-token', renewalResult.renewalToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 // 7 days
          })

          const authContext: AuthContext = {
            authenticated: true,
            sessionId: renewalResult.session.id,
            userId: 'admin',
            csrfToken: renewalResult.session.csrfToken,
            securityFlags: renewalResult.session.securityFlags,
            jwtVerified: true,
            ipValidated: renewalResult.session.securityFlags.ipValidated,
            deviceValidated: renewalResult.session.securityFlags.deviceValidated,
            renewalCount: renewalResult.session.renewalCount,
            lastRenewal: renewalResult.session.lastRenewal
          }

          return {
            valid: true,
            authContext,
            renewed: true,
            newTokens: {
              jwtToken: renewalResult.jwtToken,
              renewalToken: renewalResult.renewalToken
            }
          }
        }
      } catch (error) {
        logger.warn('Session Validation', `Session renewal failed for ${sessionId}`, error)
        // Continue with existing session if renewal fails
      }
    }

    // Session is valid, create enhanced auth context
    const authContext: AuthContext = {
      authenticated: true,
      sessionId: session.id,
      userId: 'admin',
      csrfToken: session.csrfToken,
      securityFlags: session.securityFlags,
      jwtVerified: !!jwtToken,
      ipValidated: session.securityFlags.ipValidated,
      deviceValidated: session.securityFlags.deviceValidated,
      renewalCount: session.renewalCount,
      lastRenewal: session.lastRenewal
    }

    return { valid: true, authContext }

  } catch (error) {
    logger.error('Session Validation', `Error validating session ${sessionId}`, error)

    const response = NextResponse.json({ error: 'Session validation failed' }, { status: 500 })
    return { valid: false, response }
  }
}

/**
 * Validate session and refresh if needed (legacy synchronous version)
 */
export function validateAndRefreshSessionSync(request: NextRequest): {
  valid: boolean
  response?: NextResponse
  authContext?: AuthContext
} {
  const sessionId = request.cookies.get('session-id')?.value

  if (!sessionId) {
    return { valid: false }
  }

  const session = getSession(sessionId)

  if (!session || !session.isValid) {
    const response = NextResponse.json({ error: 'Session expired' }, { status: 401 })
    response.cookies.delete('session-id')
    return { valid: false, response }
  }

  // Session is valid, create auth context
  const authContext: AuthContext = {
    authenticated: true,
    sessionId: session.id,
    userId: 'admin',
    csrfToken: session.csrfToken,
    securityFlags: session.securityFlags,
    jwtVerified: false,
    ipValidated: session.securityFlags?.ipValidated || false,
    deviceValidated: session.securityFlags?.deviceValidated || false,
    renewalCount: session.renewalCount,
    lastRenewal: session.lastRenewal
  }

  return { valid: true, authContext }
}

/**
 * Create a protected API route handler with enhanced security
 */
export function createProtectedHandler(
  handler: (request: NextRequest, authContext: AuthContext) => Promise<NextResponse>
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const authCheck = requireAuth(request)
    if (authCheck) {
      return authCheck
    }

    const authContext = await getAuthContext(request)
    if (!authContext) {
      return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
    }

    return handler(request, authContext)
  }
}

/**
 * Create a public API route handler with optional enhanced auth
 */
export function createPublicHandler(
  handler: (request: NextRequest, authContext: AuthContext) => Promise<NextResponse>
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const authContext = await optionalAuth(request)
    return handler(request, authContext)
  }
}
