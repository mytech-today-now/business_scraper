/**
 * Authentication API endpoints
 * Handles multi-user authentication, session management, and security
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

    // Return session info
    const response = NextResponse.json({
      authenticated,
      sessionId: session.id,
      csrfToken: session.csrfToken,
      expiresAt: new Date(Date.now() + defaultSecurityConfig.sessionTimeout).toISOString(),
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
    logger.error('Auth', 'Session check error', error)
    return NextResponse.json({ authenticated: false, error: 'Session check failed' }, { status: 500 })
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

    // Log authentication attempt details for debugging
    logger.info('Auth', `Authentication attempt from IP: ${ip}`, {
      username: username,
      hasPassword: !!password,
      bodyKeys: Object.keys(body),
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
      // Log authentication attempt for debugging
      logger.info('Auth', `Authentication attempt for username: ${username}`)
      logger.info('Auth', `ADMIN_USERNAME: ${ADMIN_USERNAME}`)
      logger.info('Auth', `Has ADMIN_PASSWORD_HASH: ${!!ADMIN_PASSWORD_HASH}`)
      logger.info('Auth', `Has ADMIN_PASSWORD_SALT: ${!!ADMIN_PASSWORD_SALT}`)
      logger.info('Auth', `DEFAULT_PASSWORD: ${DEFAULT_PASSWORD}`)

      if (ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT) {
        // Use hashed password from environment
        logger.info('Auth', 'Using hashed password verification')
        try {
          const hashVerificationResult = verifyPassword(password, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT)
          logger.info('Auth', `Hash verification result: ${hashVerificationResult}`)
          isValidCredentials = username === ADMIN_USERNAME && hashVerificationResult
        } catch (hashError) {
          logger.error('Auth', 'Error during password hash verification', hashError)
          // Continue to fallback methods
        }
      } else {
        // Use plain text password (development only)
        logger.info('Auth', 'Using plain text password verification')
        isValidCredentials = username === ADMIN_USERNAME && password === DEFAULT_PASSWORD

        if (process.env.NODE_ENV === 'production') {
          logger.error('Auth', 'Using plain text password in production is not secure!')
        }
      }

      // Additional fallback: try plain text comparison if hash fails
      if (!isValidCredentials && username === ADMIN_USERNAME) {
        logger.info('Auth', 'Hash verification failed, trying plain text fallback')
        if (password === process.env.ADMIN_PASSWORD) {
          logger.info('Auth', 'Plain text fallback succeeded')
          isValidCredentials = true
        }
      }

      logger.info('Auth', `Final authentication result: ${isValidCredentials}`)
    } catch (credentialError) {
      logger.error('Auth', 'Error during credential verification', credentialError)
      return NextResponse.json({ error: 'Authentication system error' }, { status: 500 })
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

    // Set session cookie
    try {
      const response = NextResponse.json({
        success: true,
        sessionId: session.id,
        csrfToken: session.csrfToken,
        expiresAt: new Date(Date.now() + defaultSecurityConfig.sessionTimeout).toISOString(),
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
          userAgent: request.headers.get('user-agent'),
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
    logger.error('Auth', 'Login error', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
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
        userAgent: request.headers.get('user-agent'),
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


