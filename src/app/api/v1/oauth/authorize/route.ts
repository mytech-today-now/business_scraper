/**
 * OAuth 2.0 Authorization Endpoint
 * Handles OAuth 2.0 authorization requests
 */

import { NextRequest, NextResponse } from 'next/server'
import { oauth2Service } from '@/lib/integrations/oauth2-service'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * GET /api/v1/oauth/authorize - OAuth 2.0 authorization endpoint
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  const { searchParams } = new URL(request.url)

  try {
    // Extract OAuth parameters
    const clientId = searchParams.get('client_id')
    const redirectUri = searchParams.get('redirect_uri')
    const responseType = searchParams.get('response_type')
    const scope = searchParams.get('scope')?.split(' ') || []
    const state = searchParams.get('state')
    const codeChallenge = searchParams.get('code_challenge')
    const codeChallengeMethod = searchParams.get('code_challenge_method')

    // Validate required parameters
    if (!clientId) {
      return NextResponse.json(
        { error: 'invalid_request', error_description: 'Missing client_id parameter' },
        { status: 400 }
      )
    }

    if (!redirectUri) {
      return NextResponse.json(
        { error: 'invalid_request', error_description: 'Missing redirect_uri parameter' },
        { status: 400 }
      )
    }

    if (responseType !== 'code') {
      return NextResponse.json(
        {
          error: 'unsupported_response_type',
          error_description: 'Only code response type is supported',
        },
        { status: 400 }
      )
    }

    if (scope.length === 0) {
      return NextResponse.json(
        { error: 'invalid_scope', error_description: 'At least one scope is required' },
        { status: 400 }
      )
    }

    logger.info('OAuth2Authorize', `Authorization request from IP: ${ip}`, {
      clientId,
      redirectUri,
      scope,
      hasPKCE: !!codeChallenge,
    })

    // Get client
    const client = await oauth2Service.getClient(clientId)
    if (!client) {
      return NextResponse.json(
        { error: 'invalid_client', error_description: 'Client not found' },
        { status: 400 }
      )
    }

    if (client.status !== 'active') {
      return NextResponse.json(
        { error: 'invalid_client', error_description: 'Client is not active' },
        { status: 400 }
      )
    }

    // Validate redirect URI
    if (redirectUri !== client.config.redirectUri) {
      return NextResponse.json(
        { error: 'invalid_request', error_description: 'Invalid redirect_uri' },
        { status: 400 }
      )
    }

    // Validate scopes
    const invalidScopes = scope.filter(s => !client.config.scopes.includes(s))
    if (invalidScopes.length > 0) {
      return NextResponse.json(
        {
          error: 'invalid_scope',
          error_description: `Invalid scopes: ${invalidScopes.join(', ')}`,
        },
        { status: 400 }
      )
    }

    // For this implementation, we'll auto-approve the authorization
    // In a real implementation, you would redirect to a consent page
    try {
      const authResult = await oauth2Service.generateAuthorizationUrl(
        clientId,
        redirectUri,
        scope,
        state || undefined,
        codeChallenge || undefined,
        codeChallengeMethod || undefined
      )

      // Extract the authorization code from the URL
      const authUrl = new URL(authResult.authorizationUrl, 'http://localhost')
      const code = authUrl.searchParams.get('code')

      if (!code) {
        throw new Error('Failed to generate authorization code')
      }

      // Redirect back to client with authorization code
      const redirectUrl = new URL(redirectUri)
      redirectUrl.searchParams.set('code', code)
      if (state) {
        redirectUrl.searchParams.set('state', state)
      }

      logger.info('OAuth2Authorize', `Authorization granted for client: ${clientId}`, {
        clientId,
        scope,
        redirectUri,
      })

      return NextResponse.redirect(redirectUrl.toString())
    } catch (error) {
      logger.error('OAuth2Authorize', `Authorization failed for client: ${clientId}`, error)

      const redirectUrl = new URL(redirectUri)
      redirectUrl.searchParams.set('error', 'server_error')
      redirectUrl.searchParams.set('error_description', 'Authorization server error')
      if (state) {
        redirectUrl.searchParams.set('state', state)
      }

      return NextResponse.redirect(redirectUrl.toString())
    }
  } catch (error) {
    logger.error('OAuth2Authorize', `Authorization endpoint error from IP: ${ip}`, error)

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
 * POST /api/v1/oauth/authorize - Handle authorization form submission
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    const body = await request.json()
    const { client_id: clientId, redirect_uri: redirectUri, scope, state, approved } = body

    if (!approved) {
      // User denied authorization
      const redirectUrl = new URL(redirectUri)
      redirectUrl.searchParams.set('error', 'access_denied')
      redirectUrl.searchParams.set('error_description', 'User denied authorization')
      if (state) {
        redirectUrl.searchParams.set('state', state)
      }

      return NextResponse.redirect(redirectUrl.toString())
    }

    // Process approved authorization (same logic as GET)
    const client = await oauth2Service.getClient(clientId)
    if (!client) {
      return NextResponse.json(
        { error: 'invalid_client', error_description: 'Client not found' },
        { status: 400 }
      )
    }

    const authResult = await oauth2Service.generateAuthorizationUrl(
      clientId,
      redirectUri,
      scope,
      state
    )

    const authUrl = new URL(authResult.authorizationUrl, 'http://localhost')
    const code = authUrl.searchParams.get('code')

    const redirectUrl = new URL(redirectUri)
    redirectUrl.searchParams.set('code', code!)
    if (state) {
      redirectUrl.searchParams.set('state', state)
    }

    logger.info('OAuth2Authorize', `Authorization approved via POST for client: ${clientId}`, {
      clientId,
      scope,
      ip,
    })

    return NextResponse.redirect(redirectUrl.toString())
  } catch (error) {
    logger.error('OAuth2Authorize', `POST authorization error from IP: ${ip}`, error)

    return NextResponse.json(
      {
        error: 'server_error',
        error_description: 'Internal server error',
      },
      { status: 500 }
    )
  }
}
