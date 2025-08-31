/**
 * Authentication Utility Functions
 * Integrates with existing session-based authentication system for API endpoint protection
 */

import { NextRequest } from 'next/server'
import { getSession, getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

/**
 * User context interface for authenticated requests
 */
export interface AuthenticatedUser {
  id: string
  email: string
  name?: string
  sessionId: string
  isAuthenticated: boolean
  permissions?: string[]
  roles?: string[]
}

/**
 * Authentication result interface
 */
export interface AuthResult {
  success: boolean
  user?: AuthenticatedUser
  error?: string
  code?: string
}

/**
 * Authenticate user from request
 * Extracts and validates session from request cookies
 */
export async function authenticateUser(request: NextRequest): Promise<AuthenticatedUser | null> {
  try {
    const sessionId = request.cookies.get('session-id')?.value
    const ip = getClientIP(request)

    if (!sessionId) {
      logger.debug('Auth', `No session ID provided from IP: ${ip}`)
      return null
    }

    // Validate session using existing security system
    const session = getSession(sessionId)

    if (!session || !session.isValid) {
      logger.warn('Auth', `Invalid session: ${sessionId} from IP: ${ip}`)
      return null
    }

    // For this application, we have a single admin user
    // In a multi-user system, this would fetch user data from database
    const user: AuthenticatedUser = {
      id: 'admin',
      email: process.env.ADMIN_EMAIL || 'admin@business-scraper.com',
      name: 'Administrator',
      sessionId: session.id,
      isAuthenticated: true,
      permissions: ['read', 'write', 'admin'],
      roles: ['admin'],
    }

    logger.debug('Auth', `User authenticated: ${user.id} from IP: ${ip}`)
    return user
  } catch (error) {
    logger.error('Auth', 'Authentication failed', error)
    return null
  }
}

/**
 * Authenticate user with detailed result
 * Returns comprehensive authentication result with error details
 */
export async function authenticateUserWithResult(request: NextRequest): Promise<AuthResult> {
  try {
    const user = await authenticateUser(request)

    if (!user) {
      return {
        success: false,
        error: 'Authentication failed',
        code: 'AUTH_FAILED',
      }
    }

    return {
      success: true,
      user,
    }
  } catch (error) {
    logger.error('Auth', 'Authentication error', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown authentication error',
      code: 'AUTH_ERROR',
    }
  }
}

/**
 * Require authentication for API endpoint
 * Throws error if user is not authenticated
 */
export async function requireAuthentication(request: NextRequest): Promise<AuthenticatedUser> {
  const user = await authenticateUser(request)

  if (!user) {
    const ip = getClientIP(request)
    logger.warn('Auth', `Authentication required but not provided from IP: ${ip}`)
    throw new Error('Authentication required')
  }

  return user
}

/**
 * Check if user has specific permission
 */
export function hasPermission(user: AuthenticatedUser, permission: string): boolean {
  return user.permissions?.includes(permission) || user.permissions?.includes('admin') || false
}

/**
 * Check if user has specific role
 */
export function hasRole(user: AuthenticatedUser, role: string): boolean {
  return user.roles?.includes(role) || user.roles?.includes('admin') || false
}

/**
 * Require specific permission
 * Throws error if user doesn't have the required permission
 */
export function requirePermission(user: AuthenticatedUser, permission: string): void {
  if (!hasPermission(user, permission)) {
    logger.warn('Auth', `Permission denied: ${user.id} lacks ${permission}`)
    throw new Error(`Permission denied: ${permission} required`)
  }
}

/**
 * Require specific role
 * Throws error if user doesn't have the required role
 */
export function requireRole(user: AuthenticatedUser, role: string): void {
  if (!hasRole(user, role)) {
    logger.warn('Auth', `Role denied: ${user.id} lacks ${role}`)
    throw new Error(`Role denied: ${role} required`)
  }
}

/**
 * Extract user ID from request
 * Convenience function for getting just the user ID
 */
export async function getUserId(request: NextRequest): Promise<string | null> {
  const user = await authenticateUser(request)
  return user?.id || null
}

/**
 * Check if request is authenticated
 * Simple boolean check for authentication status
 */
export async function isAuthenticated(request: NextRequest): Promise<boolean> {
  const user = await authenticateUser(request)
  return user !== null
}

/**
 * Get session info from request
 * Returns session details if available
 */
export function getSessionInfo(request: NextRequest): { sessionId: string | null; ip: string } {
  const sessionId = request.cookies.get('session-id')?.value || null
  const ip = getClientIP(request)

  return { sessionId, ip }
}

/**
 * Log authentication event
 * Centralized logging for authentication events
 */
export function logAuthEvent(
  event: 'login' | 'logout' | 'auth_success' | 'auth_failure' | 'permission_denied',
  userId?: string,
  ip?: string,
  details?: Record<string, any>
): void {
  logger.info(
    'AuthEvent',
    `${event.toUpperCase()}: ${userId || 'unknown'} from ${ip || 'unknown'}`,
    details
  )
}

/**
 * Validate session token format
 * Basic validation for session token structure
 */
export function isValidSessionToken(token: string): boolean {
  // Session tokens should be UUIDs or similar format
  const sessionTokenRegex = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i
  return sessionTokenRegex.test(token)
}

/**
 * Create authentication error response data
 * Standardized error response for authentication failures
 */
export function createAuthErrorResponse(message: string, code: string = 'AUTH_FAILED') {
  return {
    error: message,
    code,
    timestamp: new Date().toISOString(),
    authenticated: false,
  }
}

/**
 * Create authentication success response data
 * Standardized success response for authentication
 */
export function createAuthSuccessResponse(
  user: AuthenticatedUser,
  message: string = 'Authentication successful'
) {
  return {
    message,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      permissions: user.permissions,
      roles: user.roles,
    },
    timestamp: new Date().toISOString(),
    authenticated: true,
  }
}
