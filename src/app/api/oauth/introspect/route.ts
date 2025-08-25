/**
 * OAuth 2.0 Token Introspection Endpoint (RFC 7662)
 * Allows resource servers to query token information
 */

import { NextRequest, NextResponse } from 'next/server'
import { tokenService } from '@/lib/oauth/token-service'
import { clientService } from '@/lib/oauth/client-service'
import { logger } from '@/utils/logger'
import { IntrospectionResponse, OAuthError } from '@/types/oauth'

/**
 * POST /api/oauth/introspect - Token introspection endpoint
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Parse request body
    const body = await request.json()
    const token = body.token
    const tokenTypeHint = body.token_type_hint // Optional hint: 'access_token' or 'refresh_token'

    // Validate required parameters
    if (!token) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Missing required parameter: token',
      })
    }

    // Authenticate the client making the introspection request
    const clientId = body.client_id
    const clientSecret = body.client_secret

    if (!clientId) {
      return createErrorResponse({
        error: 'invalid_client',
        errorDescription: 'Client authentication required',
      })
    }

    // Validate client credentials
    const clientValidation = clientService.validateClient(clientId, clientSecret)
    
    if (!clientValidation.valid || !clientValidation.client) {
      return createErrorResponse({
        error: 'invalid_client',
        errorDescription: 'Invalid client credentials',
      })
    }

    const client = clientValidation.client

    // Only confidential clients can perform introspection
    if (client.type !== 'confidential') {
      return createErrorResponse({
        error: 'unauthorized_client',
        errorDescription: 'Only confidential clients can perform token introspection',
      })
    }

    // Introspect the token
    const introspectionResult = tokenService.introspectToken(token)

    // Additional security: Only allow introspection of tokens issued to the same client
    // or if the client has admin privileges
    if (introspectionResult.active && introspectionResult.clientId !== clientId) {
      // Check if the requesting client has admin scope
      if (!client.allowedScopes.includes('admin')) {
        // Return inactive for tokens not belonging to this client
        const response: IntrospectionResponse = { active: false }
        return NextResponse.json(response)
      }
    }

    // Build introspection response
    const response: IntrospectionResponse = {
      active: introspectionResult.active,
    }

    // Add additional information if token is active
    if (introspectionResult.active) {
      response.scope = introspectionResult.scope
      response.clientId = introspectionResult.clientId
      response.username = introspectionResult.username
      response.tokenType = introspectionResult.tokenType
      response.exp = introspectionResult.exp
      response.iat = introspectionResult.iat
      response.sub = introspectionResult.sub
      response.aud = introspectionResult.aud
      response.iss = introspectionResult.iss
      response.jti = introspectionResult.jti
    }

    logger.info('OAuth', `Token introspection performed by client ${clientId}`)
    return NextResponse.json(response)

  } catch (error) {
    logger.error('OAuth', 'Token introspection error', error)
    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    })
  }
}

/**
 * GET /api/oauth/introspect - Not allowed (introspection must use POST)
 */
export async function GET(): Promise<NextResponse> {
  return createErrorResponse({
    error: 'invalid_request',
    errorDescription: 'Token introspection must use POST method',
  }, 405)
}

/**
 * Create error response
 */
function createErrorResponse(error: OAuthError, status: number = 400): NextResponse {
  return NextResponse.json(error, { status })
}
