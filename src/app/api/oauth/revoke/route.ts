/**
 * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
 * Allows clients to revoke access and refresh tokens
 */

import { NextRequest, NextResponse } from 'next/server'
import { tokenService } from '@/lib/oauth/token-service'
import { clientService } from '@/lib/oauth/client-service'
import { logger } from '@/utils/logger'
import { OAuthError } from '@/types/oauth'

/**
 * POST /api/oauth/revoke - Token revocation endpoint
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

    // Authenticate the client making the revocation request
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

    // Validate the token before revocation
    const tokenValidation = tokenService.validateToken(token)

    if (tokenValidation.valid && tokenValidation.payload) {
      // Security check: Only allow revocation of tokens issued to the same client
      // or if the client has admin privileges
      if (tokenValidation.payload.client_id !== clientId) {
        if (!client.allowedScopes.includes('admin')) {
          // For security, we still return success even if the token doesn't belong to this client
          // This prevents token enumeration attacks
          logger.warn('OAuth', `Client ${clientId} attempted to revoke token not issued to them`)
          return NextResponse.json({}, { status: 200 })
        }
      }
    }

    // Attempt to revoke the token
    const revoked = tokenService.revokeToken(token)

    if (revoked) {
      logger.info('OAuth', `Token revoked by client ${clientId}`)
    } else {
      // Even if revocation fails (e.g., token already expired/invalid),
      // we return success as per RFC 7009
      logger.info(
        'OAuth',
        `Token revocation attempted by client ${clientId} (token may have been invalid)`
      )
    }

    // RFC 7009: The authorization server responds with HTTP status code 200
    // regardless of whether the token was successfully revoked or invalid
    return NextResponse.json({}, { status: 200 })
  } catch (error) {
    logger.error('OAuth', 'Token revocation error', error)
    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    })
  }
}

/**
 * GET /api/oauth/revoke - Not allowed (revocation must use POST)
 */
export async function GET(): Promise<NextResponse> {
  return createErrorResponse(
    {
      error: 'invalid_request',
      errorDescription: 'Token revocation must use POST method',
    },
    405
  )
}

/**
 * Create error response
 */
function createErrorResponse(error: OAuthError, status: number = 400): NextResponse {
  return NextResponse.json(error, { status })
}
