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
  defaultSecurityConfig
} from '@/lib/security'
import { UserManagementService } from '@/lib/user-management'
import { AuditService } from '@/lib/audit-service'
import { logger } from '@/utils/logger'

// Legacy single user credentials (for backward compatibility)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin'
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || ''
const ADMIN_PASSWORD_SALT = process.env.ADMIN_PASSWORD_SALT || ''

// If no hash is provided, use a default password (for development only)
const DEFAULT_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'

/**
 * POST /api/auth - Login endpoint
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const ip = getClientIP(request)
    const body = await request.json()
    
    // Validate and sanitize input
    const username = sanitizeInput(body.username || '')
    const password = body.password || ''
    
    // Validate input format
    const usernameValidation = validateInput(username)
    if (!usernameValidation.isValid) {
      logger.warn('Auth', `Invalid username format from IP: ${ip}`)
      return NextResponse.json(
        { error: 'Invalid input format' },
        { status: 400 }
      )
    }
    
    // Check required fields
    if (!username || !password) {
      trackLoginAttempt(ip, false)
      return NextResponse.json(
        { error: 'Username and password are required' },
        { status: 400 }
      )
    }
    
    // Verify credentials
    let isValidCredentials = false
    
    if (ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT) {
      // Use hashed password from environment
      isValidCredentials = username === ADMIN_USERNAME && 
                          verifyPassword(password, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT)
    } else {
      // Use plain text password (development only)
      isValidCredentials = username === ADMIN_USERNAME && password === DEFAULT_PASSWORD
      
      if (process.env.NODE_ENV === 'production') {
        logger.error('Auth', 'Using plain text password in production is not secure!')
      }
    }
    
    // Track login attempt
    if (!trackLoginAttempt(ip, isValidCredentials)) {
      return NextResponse.json(
        { 
          error: 'Account temporarily locked due to too many failed attempts',
          retryAfter: Math.ceil(defaultSecurityConfig.lockoutDuration / 1000)
        },
        { status: 429 }
      )
    }
    
    if (!isValidCredentials) {
      logger.warn('Auth', `Failed login attempt from IP: ${ip} for username: ${username}`)
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      )
    }
    
    // Create session
    const session = createSession()
    
    // Set session cookie
    const response = NextResponse.json({
      success: true,
      sessionId: session.id,
      csrfToken: session.csrfToken,
      expiresAt: new Date(Date.now() + defaultSecurityConfig.sessionTimeout).toISOString()
    })
    
    response.cookies.set('session-id', session.id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: defaultSecurityConfig.sessionTimeout / 1000,
      path: '/'
    })
    
    logger.info('Auth', `Successful login from IP: ${ip}`)
    return response
    
  } catch (error) {
    logger.error('Auth', 'Login error', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/auth - Logout endpoint
 */
export async function DELETE(request: NextRequest): Promise<NextResponse> {
  try {
    const sessionId = request.cookies.get('session-id')?.value
    
    if (sessionId) {
      invalidateSession(sessionId)
    }
    
    const response = NextResponse.json({ success: true })
    response.cookies.delete('session-id')
    
    logger.info('Auth', 'User logged out')
    return response
    
  } catch (error) {
    logger.error('Auth', 'Logout error', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}

/**
 * GET /api/auth - Check session status
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const sessionId = request.cookies.get('session-id')?.value
    
    if (!sessionId) {
      return NextResponse.json(
        { authenticated: false },
        { status: 401 }
      )
    }
    
    const session = getSession(sessionId)
    
    if (!session || !session.isValid) {
      const response = NextResponse.json(
        { authenticated: false },
        { status: 401 }
      )
      response.cookies.delete('session-id')
      return response
    }
    
    return NextResponse.json({
      authenticated: true,
      sessionId: session.id,
      csrfToken: session.csrfToken,
      expiresAt: new Date(session.lastAccessed.getTime() + defaultSecurityConfig.sessionTimeout).toISOString()
    })
    
  } catch (error) {
    logger.error('Auth', 'Session check error', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
