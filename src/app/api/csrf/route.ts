/**
 * CSRF Token Management API
 * Provides CSRF tokens for authentication and form protection
 * Separated from NextAuth.js to avoid route conflicts
 *
 * This endpoint handles both session-based and temporary CSRF tokens:
 * - Session-based tokens for authenticated users
 * - Temporary tokens for unauthenticated requests (e.g., login page)
 */

import { NextRequest, NextResponse } from 'next/server'
import {
  createSession,
  getSession,
  generateSecureToken,
  getClientIP,
  defaultSecurityConfig,
} from '@/lib/security'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

// Store for temporary CSRF tokens (for unauthenticated requests)
// These tokens are short-lived and only valid for login attempts
const temporaryCSRFTokens = new Map<string, {
  token: string
  expiresAt: number
  ipAddress: string
  createdAt: number
}>()

// Cleanup interval for expired temporary tokens
const TEMP_TOKEN_EXPIRY = 10 * 60 * 1000 // 10 minutes
const CLEANUP_INTERVAL = 5 * 60 * 1000 // 5 minutes

// Cleanup expired tokens periodically
if (typeof window === 'undefined') {
  setInterval(() => {
    const now = Date.now()
    for (const [key, tokenInfo] of Array.from(temporaryCSRFTokens.entries())) {
      if (tokenInfo.expiresAt < now) {
        temporaryCSRFTokens.delete(key)
      }
    }
  }, CLEANUP_INTERVAL)
}

/**
 * GET /api/csrf - Get CSRF token for session protection
 * This endpoint provides CSRF tokens for both authenticated and unauthenticated users
 * Priority: Session-based tokens for authenticated users, temporary tokens for unauthenticated
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const ip = getClientIP(request)
    const userAgent = request.headers.get('user-agent') || 'unknown'
    const sessionId = request.cookies.get('session-id')?.value

    // Check if user has an existing session (authenticated user)
    if (sessionId) {
      const session = getSession(sessionId)

      if (session && session.isValid) {
        // Valid session exists - return session-based CSRF token
        logger.info('CSRF', `Returning session-based CSRF token for valid session from IP: ${ip}`)

        const response = NextResponse.json({
          authenticated: true,
          sessionId: session.id,
          csrfToken: session.csrfToken,
          expiresAt: new Date(
            session.lastAccessed.getTime() + defaultSecurityConfig.sessionTimeout
          ).toISOString(),
          temporary: false
        })

        // Set CSRF token as a cookie (double-submit pattern)
        response.cookies.set('csrf-token', session.csrfToken, {
          httpOnly: false, // Needs to be accessible to JavaScript
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: Math.floor(defaultSecurityConfig.sessionTimeout / 1000),
          path: '/'
        })

        // Add CSRF token to response headers
        response.headers.set('X-CSRF-Token', session.csrfToken)
        response.headers.set('X-CSRF-Expires', String(session.lastAccessed.getTime() + defaultSecurityConfig.sessionTimeout))
        response.headers.set('X-CSRF-Temporary', 'false')

        return response
      } else if (sessionId) {
        // Invalid session - create new session
        logger.info('CSRF', `Invalid session detected, creating new session for IP: ${ip}`)

        const newSession = createSession()

        const response = NextResponse.json({
          authenticated: false,
          sessionId: newSession.id,
          csrfToken: newSession.csrfToken,
          expiresAt: new Date(Date.now() + defaultSecurityConfig.sessionTimeout).toISOString(),
          temporary: false
        })

        // Replace the invalid session cookie
        response.cookies.set('session-id', newSession.id, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: defaultSecurityConfig.sessionTimeout / 1000,
          path: '/',
        })

        // Set CSRF token as a cookie
        response.cookies.set('csrf-token', newSession.csrfToken, {
          httpOnly: false,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: Math.floor(defaultSecurityConfig.sessionTimeout / 1000),
          path: '/'
        })

        // Add CSRF token to response headers
        response.headers.set('X-CSRF-Token', newSession.csrfToken)
        response.headers.set('X-CSRF-Expires', String(Date.now() + defaultSecurityConfig.sessionTimeout))
        response.headers.set('X-CSRF-Temporary', 'false')

        return response
      }
    }

    // No session exists - create new session for unauthenticated user
    logger.info('CSRF', `Creating new session for CSRF token from IP: ${ip}`)

    const newSession = createSession()

    const response = NextResponse.json({
      authenticated: false,
      sessionId: newSession.id,
      csrfToken: newSession.csrfToken,
      expiresAt: new Date(Date.now() + defaultSecurityConfig.sessionTimeout).toISOString(),
      temporary: false
    })

    // Set session cookie for the new session
    response.cookies.set('session-id', newSession.id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: defaultSecurityConfig.sessionTimeout / 1000,
      path: '/',
    })

    // Set CSRF token as a cookie (double-submit pattern)
    response.cookies.set('csrf-token', newSession.csrfToken, {
      httpOnly: false, // Needs to be accessible to JavaScript
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: Math.floor(defaultSecurityConfig.sessionTimeout / 1000),
      path: '/'
    })

    // Add CSRF token to response headers for AJAX requests
    response.headers.set('X-CSRF-Token', newSession.csrfToken)
    response.headers.set('X-CSRF-Expires', String(Date.now() + defaultSecurityConfig.sessionTimeout))
    response.headers.set('X-CSRF-Temporary', 'false')

    // Log CSRF token creation for audit
    await auditService.logAuditEvent('csrf_token_created', 'security', {
      sessionId: newSession.id,
      ipAddress: ip,
      userAgent,
      severity: 'low',
      category: 'security',
      complianceFlags: ['SOC2'],
    })

    return response
  } catch (error) {
    logger.error('CSRF', 'CSRF token fetch error', error)

    // Determine error type and appropriate response
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    const isDatabaseError = errorMessage.includes('ECONNREFUSED') ||
                           errorMessage.includes('connection') ||
                           errorMessage.includes('database')

    // Try to log error for audit (but don't fail if audit service is also down)
    try {
      const ip = getClientIP(request)
      const userAgent = request.headers.get('user-agent') || 'unknown'

      await auditService.logSecurityEvent(
        'csrf_token_error',
        {
          error: errorMessage,
          userAgent,
          message: 'Failed to fetch CSRF token',
          isDatabaseError,
        },
        ip
      )
    } catch (auditError) {
      logger.warn('CSRF', 'Failed to log audit event due to database issues', auditError)
    }

    // Return appropriate error response
    if (isDatabaseError) {
      return NextResponse.json({
        error: 'Database connection failed. Please try again later.',
        type: 'database_error',
        retryable: true
      }, { status: 500 })
    } else {
      return NextResponse.json({
        error: 'Internal server error',
        type: 'server_error',
        retryable: false
      }, { status: 500 })
    }
  }
}

/**
 * POST /api/csrf - Refresh CSRF token
 * Allows clients to refresh their CSRF token if needed
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const ip = getClientIP(request)
    const sessionId = request.cookies.get('session-id')?.value

    if (!sessionId) {
      logger.warn('CSRF', `CSRF refresh attempted without session from IP: ${ip}`)
      return NextResponse.json({ error: 'No session found' }, { status: 401 })
    }

    const session = getSession(sessionId)

    if (!session || !session.isValid) {
      logger.warn('CSRF', `CSRF refresh attempted with invalid session from IP: ${ip}`)
      return NextResponse.json({ error: 'Invalid session' }, { status: 401 })
    }

    // Generate new CSRF token for the existing session
    const newSession = createSession()

    // Copy session data but with new CSRF token
    session.csrfToken = newSession.csrfToken
    session.lastAccessed = new Date()

    logger.info('CSRF', `CSRF token refreshed for session from IP: ${ip}`)

    const response = NextResponse.json({
      authenticated: true,
      sessionId: session.id,
      csrfToken: session.csrfToken,
      expiresAt: new Date(
        session.lastAccessed.getTime() + defaultSecurityConfig.sessionTimeout
      ).toISOString(),
      temporary: false
    })

    // Update CSRF token cookie
    response.cookies.set('csrf-token', session.csrfToken, {
      httpOnly: false,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: Math.floor(defaultSecurityConfig.sessionTimeout / 1000),
      path: '/'
    })

    // Add CSRF token to response headers
    response.headers.set('X-CSRF-Token', session.csrfToken)
    response.headers.set('X-CSRF-Expires', String(session.lastAccessed.getTime() + defaultSecurityConfig.sessionTimeout))
    response.headers.set('X-CSRF-Temporary', 'false')

    // Log CSRF refresh for audit
    await auditService.logAuditEvent('csrf_token_refreshed', 'security', {
      sessionId: session.id,
      ipAddress: ip,
      userAgent: request.headers.get('user-agent') || undefined,
      severity: 'low',
      category: 'security',
      complianceFlags: ['SOC2'],
    })

    return response
  } catch (error) {
    logger.error('CSRF', 'CSRF token refresh error', error)

    // Log error for audit
    await auditService.logSecurityEvent(
      'csrf_refresh_error',
      {
        error: error instanceof Error ? error.message : 'Unknown error',
        userAgent: request.headers.get('user-agent'),
        message: 'Failed to refresh CSRF token',
      },
      getClientIP(request)
    )

    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

/**
 * Validate a temporary CSRF token
 * This function is exported for use by the authentication middleware
 */
export function validateTemporaryCSRFToken(
  tokenId: string,
  token: string,
  ipAddress: string
): { isValid: boolean; error?: string } {
  const tokenInfo = temporaryCSRFTokens.get(tokenId)

  if (!tokenInfo) {
    return { isValid: false, error: 'CSRF token not found' }
  }

  // Check if token is expired
  if (tokenInfo.expiresAt < Date.now()) {
    temporaryCSRFTokens.delete(tokenId)
    return { isValid: false, error: 'CSRF token expired' }
  }

  // Check if token matches
  if (tokenInfo.token !== token) {
    return { isValid: false, error: 'Invalid CSRF token' }
  }

  // Check if IP address matches (optional security measure)
  if (tokenInfo.ipAddress !== ipAddress) {
    logger.warn('CSRF', `IP address mismatch for temporary CSRF token. Expected: ${tokenInfo.ipAddress}, Got: ${ipAddress}`)
    // Note: We might want to be more lenient here for users behind NAT/proxies
    // For now, we'll log but not reject
  }

  return { isValid: true }
}

/**
 * Invalidate a temporary CSRF token after successful use
 */
export function invalidateTemporaryCSRFToken(tokenId: string): void {
  temporaryCSRFTokens.delete(tokenId)
  logger.info('CSRF', `Invalidated temporary CSRF token: ${tokenId}`)
}

/**
 * Get statistics about temporary CSRF tokens (for monitoring)
 */
export function getTemporaryCSRFTokenStats(): {
  totalTokens: number
  expiredTokens: number
  activeTokens: number
} {
  const now = Date.now()
  let expiredTokens = 0
  let activeTokens = 0
  
  for (const tokenInfo of Array.from(temporaryCSRFTokens.values())) {
    if (tokenInfo.expiresAt < now) {
      expiredTokens++
    } else {
      activeTokens++
    }
  }
  
  return {
    totalTokens: temporaryCSRFTokens.size,
    expiredTokens,
    activeTokens
  }
}
