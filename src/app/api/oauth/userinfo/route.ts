/**
 * OAuth 2.0 UserInfo Endpoint
 * Returns user information for valid access tokens
 */

import { NextRequest, NextResponse } from 'next/server'
import { tokenService } from '@/lib/oauth/token-service'
import { logger } from '@/utils/logger'
import { UserInfoResponse, OAuthError } from '@/types/oauth'

/**
 * GET /api/oauth/userinfo - UserInfo endpoint
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // Extract access token from Authorization header
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Missing or invalid Authorization header',
      }, 401)
    }

    const accessToken = authHeader.substring(7) // Remove 'Bearer ' prefix

    // Validate access token
    const tokenValidation = tokenService.validateToken(accessToken)
    
    if (!tokenValidation.valid || !tokenValidation.payload) {
      return createErrorResponse({
        error: 'invalid_token',
        errorDescription: 'Invalid or expired access token',
      }, 401)
    }

    const payload = tokenValidation.payload

    // Verify this is an access token
    if (payload.token_type !== 'access_token') {
      return createErrorResponse({
        error: 'invalid_token',
        errorDescription: 'Token is not an access token',
      }, 401)
    }

    // Check if token has required scopes for userinfo
    const scopes = payload.scope.split(' ')
    if (!scopes.includes('openid') && !scopes.includes('profile')) {
      return createErrorResponse({
        error: 'insufficient_scope',
        errorDescription: 'Token does not have required scope for userinfo',
      }, 403)
    }

    // Build user info response based on scopes
    const userInfo: UserInfoResponse = {
      sub: payload.sub,
    }

    // Add profile information if scope includes 'profile'
    if (scopes.includes('profile')) {
      // In a real implementation, fetch user data from database
      const userData = getUserData(payload.sub)
      
      if (userData) {
        userInfo.name = userData.name
        userInfo.roles = userData.roles
        userInfo.permissions = userData.permissions
      }
    }

    // Add email if scope includes 'email'
    if (scopes.includes('email')) {
      const userData = getUserData(payload.sub)
      if (userData?.email) {
        userInfo.email = userData.email
      }
    }

    logger.info('OAuth', `UserInfo requested for user ${payload.sub}`)
    return NextResponse.json(userInfo)

  } catch (error) {
    logger.error('OAuth', 'UserInfo endpoint error', error)
    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    }, 500)
  }
}

/**
 * POST /api/oauth/userinfo - Alternative userinfo endpoint (token in body)
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const accessToken = body.access_token

    if (!accessToken) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Missing access_token parameter',
      }, 400)
    }

    // Create a new request with Authorization header for reuse
    const newRequest = new NextRequest(request.url, {
      method: 'GET',
      headers: {
        ...Object.fromEntries(request.headers.entries()),
        'Authorization': `Bearer ${accessToken}`,
      },
    })

    return GET(newRequest)

  } catch (error) {
    logger.error('OAuth', 'UserInfo POST endpoint error', error)
    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    }, 500)
  }
}

/**
 * Get user data (mock implementation)
 * In a real implementation, this would fetch from a database
 */
function getUserData(userId: string): {
  name?: string
  email?: string
  roles?: string[]
  permissions?: string[]
} | null {
  // Mock user data - in production, fetch from database
  const users: Record<string, any> = {
    'admin': {
      name: 'Administrator',
      email: 'admin@businessscraper.com',
      roles: ['admin'],
      permissions: ['read', 'write', 'admin'],
    },
    'user': {
      name: 'Regular User',
      email: 'user@businessscraper.com',
      roles: ['user'],
      permissions: ['read'],
    },
  }

  // Handle service users (client credentials)
  if (userId.startsWith('service:')) {
    const clientId = userId.substring(8)
    return {
      name: `Service Account (${clientId})`,
      roles: ['service'],
      permissions: ['read', 'write'],
    }
  }

  return users[userId] || {
    name: 'Unknown User',
    roles: ['user'],
    permissions: ['read'],
  }
}

/**
 * Create error response
 */
function createErrorResponse(error: OAuthError, status: number = 400): NextResponse {
  return NextResponse.json(error, { status })
}
