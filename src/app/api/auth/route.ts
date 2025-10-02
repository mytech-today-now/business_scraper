/**
 * Authentication API endpoints
 * Handles multi-user authentication, session management, and security
 * Enhanced with comprehensive data sanitization and security controls
 */

import { NextRequest, NextResponse } from 'next/server'
import {
  createSession,
  getSession,
  invalidateSession,
  verifyPassword,
  trackLoginAttempt,
  getClientIP,
  sanitizeInput,
  validateInput,
  defaultSecurityConfig,
} from '@/lib/security'
import { getOAuthContext } from '@/lib/oauth/oauth-middleware'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'
import { invalidateTemporaryCSRFToken } from '../csrf/route'
import { createSecureErrorResponse, ErrorContext, sanitizeErrorForLogging } from '@/lib/error-handling'
import { piiDetectionService } from '@/lib/pii-detection'
import { sanitizeErrorMessage, sanitizeSessionData, createSecureApiResponse } from '@/lib/response-sanitization'

// Legacy single user credentials (for backward compatibility)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin'
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || ''
const ADMIN_PASSWORD_SALT = process.env.ADMIN_PASSWORD_SALT || ''

// If no hash is provided, use a default password (for development only)
const DEFAULT_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'

/**
 * GET /api/auth - Get or create session with CSRF token
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const sessionId = request.cookies.get('session-id')?.value
    const ip = getClientIP(request)

    let session = null
    let authenticated = false

    if (sessionId) {
      session = getSession(sessionId)
      if (session && session.isValid) {
        authenticated = true
      }
    }

    // If no valid session, create a new one for CSRF token purposes
    if (!session || !session.isValid) {
      session = createSession()
      authenticated = false
    }

    // Return sanitized session info (remove ALL sensitive details)
    const sessionResponse = {
      authenticated,
      // Enhanced: Never expose actual session ID in any environment
      sessionId: authenticated ? '[SESSION_ACTIVE]' : '[NO_SESSION]',
      csrfToken: session.csrfToken,
      expiresAt: new Date(Date.now() + defaultSecurityConfig.sessionTimeout).toISOString(),
    }

    // Use enhanced sanitization for the response
    const response = createSecureApiResponse(sessionResponse, 200, {
      sanitizeSession: true,
      context: 'Auth Session Check'
    })

    // Set session cookie if it's a new session or invalid session was replaced
    if (!authenticated || !sessionId) {
      response.cookies.set('session-id', session.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: defaultSecurityConfig.sessionTimeout / 1000,
        path: '/',
      })
    }

    return response
  } catch (error) {
    const errorContext: ErrorContext = {
      endpoint: '/api/auth',
      method: 'GET',
      ip: getClientIP(request),
      userAgent: request.headers.get('user-agent') || undefined,
    }

    return createSecureErrorResponse(error, errorContext, {
      customMessage: sanitizeErrorMessage(error, 'Auth Session Check'),
      statusCode: 500,
      sanitizeResponse: true,
    })
  }
}

/**
 * POST /api/auth - Login endpoint
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const ip = getClientIP(request)

    // Parse request body with error handling
    let body
    try {
      body = await request.json()
    } catch (parseError) {
      logger.error('Auth', 'Failed to parse request body', parseError)
      return NextResponse.json({ error: 'Invalid request format' }, { status: 400 })
    }

    // Validate and sanitize input
    const username = sanitizeInput(body.username || '')
    const password = body.password || ''

    // Log authentication attempt with sanitized details
    logger.info('Auth', `Authentication attempt from IP: ${ip}`, {
      username: sanitizeErrorForLogging(username),
      hasPassword: !!password,
      bodyKeys: Object.keys(body).filter(key => !['password', 'secret', 'token'].includes(key.toLowerCase())),
    })

    // Validate input format
    try {
      const usernameValidation = validateInput(username)
      if (!usernameValidation.isValid) {
        logger.warn('Auth', `Invalid username format from IP: ${ip}`)
        return NextResponse.json({ error: 'Invalid input format' }, { status: 400 })
      }
    } catch (validationError) {
      logger.error('Auth', 'Error during input validation', validationError)
      return NextResponse.json({ error: 'Validation error' }, { status: 500 })
    }

    // Check required fields
    if (!username || !password) {
      trackLoginAttempt(ip, false)
      return NextResponse.json({ error: 'Username and password are required' }, { status: 400 })
    }

    // Verify credentials
    let isValidCredentials = false

    try {
      // Secure authentication logging (no sensitive data)
      logger.info('Auth', `Authentication attempt for user`, {
        hasUsername: !!username,
        hasPassword: !!password,
        hasHashConfig: !!(ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT),
        environment: process.env.NODE_ENV,
      })

      if (ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT) {
        // Use hashed password from environment
        try {
          const hashVerificationResult = await verifyPassword(password, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT)
          isValidCredentials = username === ADMIN_USERNAME && hashVerificationResult
        } catch (hashError) {
          logger.error('Auth', 'Password hash verification failed', {
            error: sanitizeErrorForLogging(hashError instanceof Error ? hashError.message : String(hashError))
          })
          // Continue to fallback methods
        }
      } else {
        // Use plain text password (development only)
        isValidCredentials = username === ADMIN_USERNAME && password === DEFAULT_PASSWORD

        if (process.env.NODE_ENV === 'production') {
          logger.error('Auth', 'Plain text password authentication in production - security risk!')
        }
      }

      // Additional fallback: try plain text comparison if hash fails
      if (!isValidCredentials && username === ADMIN_USERNAME) {
        if (password === process.env.ADMIN_PASSWORD) {
          isValidCredentials = true
        }
      }

      logger.info('Auth', `Authentication completed`, {
        success: isValidCredentials,
        method: (ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT) ? 'hash' : 'plaintext'
      })
    } catch (credentialError) {
      const errorContext: ErrorContext = {
        endpoint: '/api/auth',
        method: 'POST',
        ip,
        userAgent: request.headers.get('user-agent') || undefined,
      }

      return createSecureErrorResponse(credentialError, errorContext, {
        customMessage: sanitizeErrorMessage(credentialError, 'Auth Credential Verification'),
        statusCode: 500,
        sanitizeResponse: true,
      })
    }

    // Track login attempt
    if (!trackLoginAttempt(ip, isValidCredentials)) {
      return NextResponse.json(
        {
          error: 'Account temporarily locked due to too many failed attempts',
          retryAfter: Math.ceil(defaultSecurityConfig.lockoutDuration / 1000),
        },
        { status: 429 }
      )
    }

    if (!isValidCredentials) {
      // Log failed authentication attempt
      await auditService.logSecurityEvent(
        'login_failure',
        {
          username,
          reason: 'invalid_credentials',
          userAgent: request.headers.get('user-agent'),
          message: `Failed login attempt for username: ${username}`,
        },
        ip
      )

      logger.warn('Auth', `Failed login attempt from IP: ${ip} for username: ${username}`)
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 })
    }

    // Create session
    let session
    try {
      session = createSession()
      logger.info('Auth', `Created session: ${session.id}`)
    } catch (sessionError) {
      logger.error('Auth', 'Error creating session', sessionError)
      return NextResponse.json({ error: 'Session creation failed' }, { status: 500 })
    }

    // Invalidate temporary CSRF token if it was used for login
    try {
      const tempTokenId = request.headers.get('x-csrf-token-id')
      if (tempTokenId) {
        invalidateTemporaryCSRFToken(tempTokenId)
        logger.info('Auth', `Invalidated temporary CSRF token: ${tempTokenId}`)
      }
    } catch (csrfError) {
      logger.warn('Auth', 'Error invalidating temporary CSRF token', csrfError)
      // Continue with login process
    }

    // Set session cookie with enhanced sanitization
    try {
      const loginResponse = {
        success: true,
        // Enhanced: Never expose actual session ID in any environment
        sessionId: '[SESSION_CREATED]',
        csrfToken: session.csrfToken,
        expiresAt: new Date(Date.now() + defaultSecurityConfig.sessionTimeout).toISOString(),
      }

      // Use enhanced sanitization for the response
      const response = createSecureApiResponse(loginResponse, 200, {
        sanitizeSession: true,
        context: 'Auth Login Success'
      })

      response.cookies.set('session-id', session.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: defaultSecurityConfig.sessionTimeout / 1000,
        path: '/',
      })

      // Log successful authentication
      try {
        await auditService.logAuditEvent('login_success', 'authentication', {
          userId: username,
          sessionId: session.id,
          ipAddress: ip,
          userAgent: request.headers.get('user-agent') || undefined,
          severity: 'medium',
          category: 'security',
          complianceFlags: ['SOC2', 'GDPR'],
        })
      } catch (auditError) {
        logger.warn('Auth', 'Error logging audit event', auditError)
        // Continue with successful login
      }

      logger.info('Auth', `Successful login from IP: ${ip}`)
      return response
    } catch (responseError) {
      logger.error('Auth', 'Error creating response', responseError)
      return NextResponse.json({ error: 'Response creation failed' }, { status: 500 })
    }
  } catch (error) {
    const errorContext: ErrorContext = {
      endpoint: '/api/auth',
      method: 'POST',
      ip,
      userAgent: request.headers.get('user-agent') || undefined,
    }

    return createSecureErrorResponse(error, errorContext, {
      customMessage: sanitizeErrorMessage(error, 'Auth Request Processing'),
      statusCode: 500,
      sanitizeResponse: true,
    })
  }
}

/**
 * DELETE /api/auth - Logout endpoint
 */
export async function DELETE(request: NextRequest): Promise<NextResponse> {
  try {
    const sessionId = request.cookies.get('session-id')?.value
    const ip = getClientIP(request)

    if (sessionId) {
      // Log logout event before invalidating session
      await auditService.logAuditEvent('logout', 'authentication', {
        userId: 'admin',
        sessionId: sessionId,
        ipAddress: ip,
        userAgent: request.headers.get('user-agent') || undefined,
        severity: 'low',
        category: 'security',
        complianceFlags: ['SOC2'],
      })

      invalidateSession(sessionId)
    }

    const response = NextResponse.json({ success: true })
    response.cookies.delete('session-id')

    logger.info('Auth', 'User logged out')
    return response
  } catch (error) {
    logger.error('Auth', 'Logout error', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}


