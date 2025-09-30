/**
 * OAuth 2.0 Token Endpoint
 * Handles OAuth 2.0 token requests and refresh
 */

import { NextRequest, NextResponse } from 'next/server'
import { oauth2Service } from '@/lib/integrations/oauth2-service'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * POST /api/v1/oauth/token - OAuth 2.0 token endpoint
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    const contentType = request.headers.get('content-type')
    let body: any

    // Parse request body based on content type
    if (contentType?.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData()
      body = Object.fromEntries(formData.entries())
    } else if (contentType?.includes('application/json')) {
      body = await request.json()
    } else {
      return NextResponse.json(
        {
          error: 'invalid_request',
          error_description: 'Unsupported content type',
        },
        { status: 400 }
      )
    }

    const {
      grant_type: grantType,
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      refresh_token: refreshToken,
      code_verifier: codeVerifier,
    } = body

    // Validate grant type
    if (!grantType) {
      return NextResponse.json(
        {
          error: 'invalid_request',
          error_description: 'Missing grant_type parameter',
        },
        { status: 400 }
      )
    }

    if (!['authorization_code', 'refresh_token'].includes(grantType)) {
      return NextResponse.json(
        {
          error: 'unsupported_grant_type',
          error_description: 'Only authorization_code and refresh_token grant types are supported',
        },
        { status: 400 }
      )
    }

    // Validate client credentials
    if (!clientId || !clientSecret) {
      return NextResponse.json(
        {
          error: 'invalid_client',
          error_description: 'Missing client credentials',
        },
        { status: 400 }
      )
    }

    logger.info('OAuth2Token', `Token request from IP: ${ip}`, {
      grantType,
      clientId,
      hasPKCE: !!codeVerifier,
    })

    try {
      if (grantType === 'authorization_code') {
        // Authorization code flow
        if (!code || !redirectUri) {
          return NextResponse.json(
            {
              error: 'invalid_request',
              error_description: 'Missing code or redirect_uri parameter',
            },
            { status: 400 }
          )
        }

        const token = await oauth2Service.exchangeCodeForToken(
          clientId,
          clientSecret,
          code,
          redirectUri,
          codeVerifier
        )

        logger.info('OAuth2Token', `Access token issued for client: ${clientId}`, {
          clientId,
          scope: token.scope,
          expiresIn: token.expiresIn,
        })

        return NextResponse.json({
          access_token: token.accessToken,
          token_type: token.tokenType,
          expires_in: token.expiresIn,
          refresh_token: token.refreshToken,
          scope: token.scope.join(' '),
        })
      } else if (grantType === 'refresh_token') {
        // Refresh token flow
        if (!refreshToken) {
          return NextResponse.json(
            {
              error: 'invalid_request',
              error_description: 'Missing refresh_token parameter',
            },
            { status: 400 }
          )
        }

        const token = await oauth2Service.refreshToken(clientId, clientSecret, refreshToken)

        logger.info('OAuth2Token', `Token refreshed for client: ${clientId}`, {
          clientId,
          scope: token.scope,
          expiresIn: token.expiresIn,
        })

        return NextResponse.json({
          access_token: token.accessToken,
          token_type: token.tokenType,
          expires_in: token.expiresIn,
          refresh_token: token.refreshToken,
          scope: token.scope.join(' '),
        })
      } else {
        // This should never happen due to validation above, but TypeScript requires it
        return NextResponse.json(
          {
            error: 'unsupported_grant_type',
            error_description: 'Unsupported grant type',
          },
          { status: 400 }
        )
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'

      logger.warn('OAuth2Token', `Token request failed for client: ${clientId}`, {
        clientId,
        grantType,
        error: errorMessage,
        ip,
      })

      // Map specific errors to OAuth error codes
      if (errorMessage.includes('not found') || errorMessage.includes('Invalid client')) {
        return NextResponse.json(
          {
            error: 'invalid_client',
            error_description: 'Client authentication failed',
          },
          { status: 401 }
        )
      }

      if (
        errorMessage.includes('Invalid authorization code') ||
        errorMessage.includes('expired') ||
        errorMessage.includes('Invalid refresh token')
      ) {
        return NextResponse.json(
          {
            error: 'invalid_grant',
            error_description: errorMessage,
          },
          { status: 400 }
        )
      }

      if (errorMessage.includes('redirect')) {
        return NextResponse.json(
          {
            error: 'invalid_request',
            error_description: errorMessage,
          },
          { status: 400 }
        )
      }

      if (errorMessage.includes('PKCE') || errorMessage.includes('verifier')) {
        return NextResponse.json(
          {
            error: 'invalid_request',
            error_description: errorMessage,
          },
          { status: 400 }
        )
      }

      // Generic server error
      return NextResponse.json(
        {
          error: 'server_error',
          error_description: 'Token generation failed',
        },
        { status: 500 }
      )
    }
  } catch (error) {
    logger.error('OAuth2Token', `Token endpoint error from IP: ${ip}`, error)

    return NextResponse.json(
      {
        error: 'server_error',
        error_description: 'Internal server error',
      },
      { status: 500 }
    )
  }
}

/**
 * OPTIONS /api/v1/oauth/token - Handle CORS preflight
 */
export async function OPTIONS(request: NextRequest): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    },
  })
}
