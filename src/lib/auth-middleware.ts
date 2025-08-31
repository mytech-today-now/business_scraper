/**
 * Authentication Middleware for API Routes
 * Provides consistent authentication checks across all protected endpoints
 */

import { NextRequest, NextResponse } from 'next/server'
import { getSession, getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

export interface AuthConfig {
  required?: boolean
  allowPublic?: boolean
  roles?: string[]
  permissions?: string[]
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
      // If public access is allowed and no session is provided, proceed
      const sessionId = request.cookies.get('session-id')?.value

      if (!sessionId) {
        if (allowPublic || !required) {
          return handler(request, { authenticated: false })
        }

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

      // Validate session
      const session = getSession(sessionId)

      if (!session || !session.isValid) {
        // Log invalid session attempt
        await auditService.logSecurityEvent(
          'invalid_session_access',
          {
            endpoint: pathname,
            method: request.method,
            sessionId: sessionId,
            userAgent: request.headers.get('user-agent'),
            message: `Invalid session for ${pathname}`,
          },
          ip
        )

        logger.warn('Auth Middleware', `Invalid session for ${pathname} from IP: ${ip}`)
        const response = NextResponse.json({ error: 'Invalid session' }, { status: 401 })
        response.cookies.delete('session-id')
        return response
      }

      // Log successful authentication
      await auditService.logAuditEvent('session_validated', 'authentication', {
        userId: 'admin',
        sessionId: session.id,
        ipAddress: ip,
        userAgent: request.headers.get('user-agent'),
        severity: 'low',
        category: 'security',
        complianceFlags: ['SOC2'],
      })

      // Create auth context
      const authContext: AuthContext = {
        authenticated: true,
        sessionId: session.id,
        userId: 'admin', // Single user system
        csrfToken: session.csrfToken,
      }

      // Call handler with auth context
      return handler(request, authContext)
    } catch (error) {
      logger.error('Auth Middleware', `Authentication error for ${pathname}`, error)
      return NextResponse.json({ error: 'Authentication error' }, { status: 500 })
    }
  }
}

/**
 * Authentication context passed to handlers
 */
export interface AuthContext {
  authenticated: boolean
  sessionId?: string
  userId?: string
  csrfToken?: string
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
 * Get authentication context from request
 */
export function getAuthContext(request: NextRequest): AuthContext | null {
  const sessionId = request.cookies.get('session-id')?.value
  if (!sessionId) return null

  const session = getSession(sessionId)
  if (!session || !session.isValid) return null

  return {
    authenticated: true,
    sessionId: session.id,
    userId: 'admin',
    csrfToken: session.csrfToken,
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
 * Optional authentication - allows both authenticated and public access
 */
export function optionalAuth(request: NextRequest): AuthContext {
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
 * Validate session and refresh if needed
 */
export function validateAndRefreshSession(request: NextRequest): {
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
  }

  return { valid: true, authContext }
}

/**
 * Create a protected API route handler
 */
export function createProtectedHandler(
  handler: (request: NextRequest, authContext: AuthContext) => Promise<NextResponse>
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const authCheck = requireAuth(request)
    if (authCheck) {
      return authCheck
    }

    const authContext = getAuthContext(request)!
    return handler(request, authContext)
  }
}

/**
 * Create a public API route handler with optional auth
 */
export function createPublicHandler(
  handler: (request: NextRequest, authContext: AuthContext) => Promise<NextResponse>
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const authContext = optionalAuth(request)
    return handler(request, authContext)
  }
}
