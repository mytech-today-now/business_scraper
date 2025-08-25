/**
 * OAuth 2.0 Middleware
 * Protects API endpoints with OAuth 2.0 access tokens
 */

import { NextRequest, NextResponse } from 'next/server'
import { tokenService } from './token-service'
import { logger } from '@/utils/logger'

export interface OAuthConfig {
  requiredScopes?: string[]
  allowPublic?: boolean
  requireAuthentication?: boolean
}

export interface OAuthContext {
  authenticated: boolean
  userId?: string
  clientId?: string
  scopes?: string[]
  tokenPayload?: any
}

/**
 * OAuth 2.0 middleware wrapper
 */
export function withOAuth(
  handler: (request: NextRequest, context: OAuthContext) => Promise<NextResponse>,
  config: OAuthConfig = {}
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const { 
      requiredScopes = [], 
      allowPublic = false, 
      requireAuthentication = true 
    } = config

    try {
      // Extract access token from Authorization header
      const authHeader = request.headers.get('Authorization')
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        if (allowPublic || !requireAuthentication) {
          return handler(request, { authenticated: false })
        }
        
        return createUnauthorizedResponse('Missing or invalid Authorization header')
      }

      const accessToken = authHeader.substring(7) // Remove 'Bearer ' prefix

      // Validate access token
      const tokenValidation = tokenService.validateToken(accessToken)
      
      if (!tokenValidation.valid || !tokenValidation.payload) {
        if (allowPublic || !requireAuthentication) {
          return handler(request, { authenticated: false })
        }
        
        return createUnauthorizedResponse('Invalid or expired access token')
      }

      const payload = tokenValidation.payload

      // Verify this is an access token
      if (payload.token_type !== 'access_token') {
        return createUnauthorizedResponse('Token is not an access token')
      }

      // Parse token scopes
      const tokenScopes = payload.scope.split(' ')

      // Check required scopes
      if (requiredScopes.length > 0) {
        const hasRequiredScopes = requiredScopes.every(scope => tokenScopes.includes(scope))
        
        if (!hasRequiredScopes) {
          return createForbiddenResponse(`Insufficient scope. Required: ${requiredScopes.join(', ')}`)
        }
      }

      // Create OAuth context
      const oauthContext: OAuthContext = {
        authenticated: true,
        userId: payload.sub,
        clientId: payload.client_id,
        scopes: tokenScopes,
        tokenPayload: payload,
      }

      // Call handler with OAuth context
      return handler(request, oauthContext)

    } catch (error) {
      logger.error('OAuth Middleware', 'Authentication error', error)
      return createServerErrorResponse('Authentication error')
    }
  }
}

/**
 * Extract OAuth context from request (without enforcing authentication)
 */
export function getOAuthContext(request: NextRequest): OAuthContext | null {
  try {
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null
    }

    const accessToken = authHeader.substring(7)
    const tokenValidation = tokenService.validateToken(accessToken)
    
    if (!tokenValidation.valid || !tokenValidation.payload) {
      return null
    }

    const payload = tokenValidation.payload

    if (payload.token_type !== 'access_token') {
      return null
    }

    return {
      authenticated: true,
      userId: payload.sub,
      clientId: payload.client_id,
      scopes: payload.scope.split(' '),
      tokenPayload: payload,
    }
  } catch (error) {
    logger.warn('OAuth Middleware', 'Failed to extract OAuth context', error)
    return null
  }
}

/**
 * Check if request has valid OAuth authentication
 */
export function isOAuthAuthenticated(request: NextRequest): boolean {
  const context = getOAuthContext(request)
  return context !== null && context.authenticated
}

/**
 * Check if request has required scopes
 */
export function hasRequiredScopes(request: NextRequest, requiredScopes: string[]): boolean {
  const context = getOAuthContext(request)
  
  if (!context || !context.scopes) {
    return false
  }

  return requiredScopes.every(scope => context.scopes!.includes(scope))
}

/**
 * Require OAuth authentication for API endpoint
 */
export function requireOAuth(
  request: NextRequest, 
  requiredScopes: string[] = []
): NextResponse | null {
  const context = getOAuthContext(request)
  
  if (!context) {
    return createUnauthorizedResponse('OAuth authentication required')
  }

  if (requiredScopes.length > 0 && !hasRequiredScopes(request, requiredScopes)) {
    return createForbiddenResponse(`Insufficient scope. Required: ${requiredScopes.join(', ')}`)
  }

  return null
}

/**
 * Create a protected OAuth API route handler
 */
export function createOAuthProtectedHandler(
  handler: (request: NextRequest, context: OAuthContext) => Promise<NextResponse>,
  requiredScopes: string[] = []
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const authCheck = requireOAuth(request, requiredScopes)
    if (authCheck) {
      return authCheck
    }

    const context = getOAuthContext(request)!
    return handler(request, context)
  }
}

/**
 * Create a public OAuth API route handler with optional auth
 */
export function createOAuthPublicHandler(
  handler: (request: NextRequest, context: OAuthContext) => Promise<NextResponse>
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const context = getOAuthContext(request) || { authenticated: false }
    return handler(request, context)
  }
}

/**
 * Validate OAuth scope requirements
 */
export function validateScopes(
  tokenScopes: string[],
  requiredScopes: string[]
): { valid: boolean; missing?: string[] } {
  const missing = requiredScopes.filter(scope => !tokenScopes.includes(scope))
  
  return {
    valid: missing.length === 0,
    missing: missing.length > 0 ? missing : undefined,
  }
}

/**
 * Create unauthorized response
 */
function createUnauthorizedResponse(message: string): NextResponse {
  return NextResponse.json(
    { 
      error: 'unauthorized',
      error_description: message,
    },
    { 
      status: 401,
      headers: {
        'WWW-Authenticate': 'Bearer',
      },
    }
  )
}

/**
 * Create forbidden response
 */
function createForbiddenResponse(message: string): NextResponse {
  return NextResponse.json(
    { 
      error: 'insufficient_scope',
      error_description: message,
    },
    { status: 403 }
  )
}

/**
 * Create server error response
 */
function createServerErrorResponse(message: string): NextResponse {
  return NextResponse.json(
    { 
      error: 'server_error',
      error_description: message,
    },
    { status: 500 }
  )
}
