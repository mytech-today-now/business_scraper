/**
 * Multi-User Authentication API Endpoint
 * Handles multi-user login, logout, registration, and session management
 */

import { NextRequest, NextResponse } from 'next/server'
import { UserManagementService } from '@/lib/user-management'
import { AuditService } from '@/lib/audit-service'
import { 
  getClientIP,
  sanitizeInput,
  validateInput,
  trackLoginAttempt,
  defaultSecurityConfig
} from '@/lib/security'
import { logger } from '@/utils/logger'

/**
 * POST /api/auth/multi-user - Multi-user authentication endpoint
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    const body = await request.json()
    const { action, username, password, email, firstName, lastName } = body

    switch (action) {
      case 'login':
        return await handleLogin(request, { username, password }, ip)
      
      case 'logout':
        return await handleLogout(request, ip)
      
      case 'register':
        return await handleRegister(request, { 
          username, 
          password, 
          email, 
          firstName, 
          lastName 
        }, ip)
      
      default:
        return NextResponse.json(
          { error: 'Invalid action. Supported actions: login, logout, register' },
          { status: 400 }
        )
    }
  } catch (error) {
    logger.error('Multi-User Auth API', `Error processing request from IP: ${ip}`, error)
    return NextResponse.json(
      { error: 'Authentication request failed' },
      { status: 500 }
    )
  }
}

/**
 * Handle user login
 */
async function handleLogin(
  request: NextRequest, 
  credentials: { username: string; password: string }, 
  ip: string
): Promise<NextResponse> {
  const { username, password } = credentials

  // Validate input
  if (!username || !password) {
    logger.warn('Multi-User Auth API', `Missing credentials from IP: ${ip}`)
    return NextResponse.json(
      { error: 'Username and password are required' },
      { status: 400 }
    )
  }

  // Sanitize input
  const sanitizedUsername = sanitizeInput(username)
  const sanitizedPassword = sanitizeInput(password)

  // Validate input format
  const usernameValidation = validateInput(sanitizedUsername)
  if (!usernameValidation.isValid) {
    logger.warn('Multi-User Auth API', `Invalid username format from IP: ${ip}`)
    return NextResponse.json(
      { error: 'Invalid username format' },
      { status: 400 }
    )
  }

  // Track login attempt
  const attemptResult = trackLoginAttempt(ip, sanitizedUsername)
  if (!attemptResult.allowed) {
    logger.warn('Multi-User Auth API', `Rate limited login attempt from IP: ${ip} for user: ${sanitizedUsername}`)
    return NextResponse.json(
      { 
        error: 'Too many login attempts', 
        retryAfter: attemptResult.retryAfter 
      },
      { status: 429 }
    )
  }

  // Authenticate user
  const authResult = await UserManagementService.authenticateUser(
    sanitizedUsername,
    sanitizedPassword,
    ip
  )

  if (!authResult) {
    // Log failed login attempt
    await AuditService.logAuth('user.login_failed', undefined, { 
      ipAddress: ip,
      userAgent: request.headers.get('user-agent') || undefined
    }, { username: sanitizedUsername })
    
    logger.warn('Multi-User Auth API', `Invalid credentials from IP: ${ip} for user: ${sanitizedUsername}`)
    return NextResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    )
  }

  const { user, session } = authResult

  // Log successful login
  await AuditService.logAuth('user.login', user.id, { 
    ipAddress: ip,
    userAgent: request.headers.get('user-agent') || undefined,
    sessionId: session.id
  }, { username: sanitizedUsername })
  
  logger.info('Multi-User Auth API', `User ${sanitizedUsername} logged in from IP: ${ip}`)
  
  const response = NextResponse.json({
    success: true,
    sessionId: session.id,
    csrfToken: session.csrfToken,
    user: {
      id: user.id,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      roles: user.roles?.map(role => ({
        id: role.role.id,
        name: role.role.name,
        displayName: role.role.displayName,
        permissions: role.role.permissions
      })) || [],
      teams: user.teams?.map(team => ({
        id: team.team.id,
        name: team.team.name,
        role: team.role
      })) || [],
      workspaces: user.workspaces?.map(workspace => ({
        id: workspace.workspace.id,
        name: workspace.workspace.name,
        role: workspace.role,
        permissions: workspace.permissions
      })) || [],
      preferences: user.preferences
    },
    expiresAt: session.expiresAt.toISOString()
  })
  
  // Set session cookie
  response.cookies.set('session-id', session.sessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: defaultSecurityConfig.sessionTimeout / 1000
  })
  
  return response
}

/**
 * Handle user logout
 */
async function handleLogout(request: NextRequest, ip: string): Promise<NextResponse> {
  const sessionId = request.cookies.get('session-id')?.value
  
  if (sessionId) {
    // Get session to find user ID for audit log
    try {
      // In a real implementation, you'd get the session from database
      // For now, just log the logout
      await AuditService.logAuth('user.logout', undefined, { 
        ipAddress: ip,
        sessionId
      })
      
      // Invalidate session in database
      // TODO: Implement session invalidation in UserManagementService
      
      logger.info('Multi-User Auth API', `User logged out from IP: ${ip}`)
    } catch (error) {
      logger.error('Multi-User Auth API', 'Error during logout', error)
    }
  }
  
  const response = NextResponse.json({ success: true })
  response.cookies.delete('session-id')
  return response
}

/**
 * Handle user registration
 */
async function handleRegister(
  request: NextRequest,
  userData: {
    username: string
    password: string
    email: string
    firstName: string
    lastName: string
  },
  ip: string
): Promise<NextResponse> {
  const { username, password, email, firstName, lastName } = userData

  // Validate required fields
  if (!username || !password || !email || !firstName || !lastName) {
    return NextResponse.json(
      { error: 'All fields are required: username, password, email, firstName, lastName' },
      { status: 400 }
    )
  }

  // Sanitize input
  const sanitizedData = {
    username: sanitizeInput(username),
    password: sanitizeInput(password),
    email: sanitizeInput(email),
    firstName: sanitizeInput(firstName),
    lastName: sanitizeInput(lastName)
  }

  // Validate input formats
  const usernameValidation = validateInput(sanitizedData.username)
  if (!usernameValidation.isValid) {
    return NextResponse.json(
      { error: 'Invalid username format' },
      { status: 400 }
    )
  }

  // Basic email validation
  if (!sanitizedData.email.includes('@') || sanitizedData.email.length < 5) {
    return NextResponse.json(
      { error: 'Invalid email format' },
      { status: 400 }
    )
  }

  try {
    // Create user
    const { user } = await UserManagementService.createUser(sanitizedData)

    // Log user creation
    await AuditService.logUserManagement(
      'user.created',
      user.id,
      undefined, // No performer for self-registration
      { 
        ipAddress: ip,
        userAgent: request.headers.get('user-agent') || undefined
      },
      { 
        username: sanitizedData.username,
        email: sanitizedData.email,
        selfRegistration: true
      }
    )

    logger.info('Multi-User Auth API', `User registered: ${sanitizedData.username} from IP: ${ip}`)

    return NextResponse.json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      }
    }, { status: 201 })
  } catch (error) {
    logger.error('Multi-User Auth API', 'Error during registration', error)
    
    if (error instanceof Error) {
      return NextResponse.json(
        { error: error.message },
        { status: 400 }
      )
    }
    
    return NextResponse.json(
      { error: 'Registration failed' },
      { status: 500 }
    )
  }
}

/**
 * GET /api/auth/multi-user - Check session status
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
    
    // TODO: Implement session validation with UserManagementService
    // For now, return basic session info
    
    return NextResponse.json({
      authenticated: true,
      sessionId,
      message: 'Multi-user session validation not fully implemented yet'
    })
  } catch (error) {
    logger.error('Multi-User Auth API', 'Error checking session status', error)
    return NextResponse.json(
      { authenticated: false, error: 'Session check failed' },
      { status: 500 }
    )
  }
}
