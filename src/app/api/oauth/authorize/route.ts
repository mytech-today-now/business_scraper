/**
 * OAuth 2.0 Authorization Endpoint
 * Handles authorization requests and redirects
 */

import { NextRequest, NextResponse } from 'next/server'
import { clientService } from '@/lib/oauth/client-service'
import { authorizationService } from '@/lib/oauth/authorization-service'
import { pkceService } from '@/lib/oauth/pkce-service'
import { getAuthContext } from '@/lib/auth-middleware'
import { logger } from '@/utils/logger'
import { AuthorizationRequest, OAuthError } from '@/types/oauth'

/**
 * GET /api/oauth/authorize - Authorization endpoint
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const { searchParams } = new URL(request.url)
    
    // Parse authorization request
    const authRequest: AuthorizationRequest = {
      responseType: searchParams.get('response_type') as 'code',
      clientId: searchParams.get('client_id') || '',
      redirectUri: searchParams.get('redirect_uri') || '',
      scope: searchParams.get('scope') || undefined,
      state: searchParams.get('state') || undefined,
      codeChallenge: searchParams.get('code_challenge') || undefined,
      codeChallengeMethod: searchParams.get('code_challenge_method') as 'S256' | 'plain' || undefined,
    }

    // Validate required parameters
    if (!authRequest.clientId || !authRequest.redirectUri) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Missing required parameters: client_id and redirect_uri',
      })
    }

    // Validate client
    const clientValidation = clientService.validateClient(authRequest.clientId)
    if (!clientValidation.valid || !clientValidation.client) {
      return createErrorResponse({
        error: 'invalid_client',
        errorDescription: 'Invalid or inactive client',
      })
    }

    const client = clientValidation.client

    // Validate authorization request
    const requestValidation = authorizationService.validateAuthorizationRequest(authRequest, client)
    if (!requestValidation.valid) {
      return createErrorRedirect(authRequest.redirectUri, {
        error: requestValidation.error || 'invalid_request',
        state: authRequest.state,
      })
    }

    // Validate PKCE if present
    if (authRequest.codeChallenge) {
      const pkceValidation = pkceService.validatePKCERequest(
        authRequest.codeChallenge,
        authRequest.codeChallengeMethod,
        client.type === 'public'
      )
      
      if (!pkceValidation.valid) {
        return createErrorRedirect(authRequest.redirectUri, {
          error: 'invalid_request',
          errorDescription: pkceValidation.error,
          state: authRequest.state,
        })
      }
    }

    // Check if user is authenticated
    const authContext = getAuthContext(request)
    if (!authContext || !authContext.authenticated) {
      // Redirect to login with authorization request parameters
      const loginUrl = new URL('/login', request.url)
      loginUrl.searchParams.set('redirect', request.url)
      
      return NextResponse.redirect(loginUrl)
    }

    // For this implementation, we'll auto-approve for the default user
    // In a real implementation, you might show a consent screen here
    const scopes = requestValidation.scopes || ['openid', 'profile']
    
    // Create mock user object (in real implementation, get from auth context)
    const user = {
      id: authContext.userId || 'admin',
      username: 'admin',
      email: 'admin@businessscraper.com',
      roles: ['admin'],
      permissions: ['read', 'write', 'admin'],
      isActive: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    }

    // Generate authorization code
    const { code } = authorizationService.generateAuthorizationCode(
      client,
      user,
      authRequest.redirectUri,
      scopes,
      authRequest.codeChallenge,
      authRequest.codeChallengeMethod
    )

    // Store PKCE challenge if present
    if (authRequest.codeChallenge) {
      pkceService.storePKCEChallenge(code, {
        codeVerifier: '', // Will be provided by client
        codeChallenge: authRequest.codeChallenge,
        codeChallengeMethod: authRequest.codeChallengeMethod || 'S256',
      })
    }

    // Redirect back to client with authorization code
    const redirectUrl = new URL(authRequest.redirectUri)
    redirectUrl.searchParams.set('code', code)
    
    if (authRequest.state) {
      redirectUrl.searchParams.set('state', authRequest.state)
    }

    logger.info('OAuth', `Authorization granted for client ${client.id}`)
    return NextResponse.redirect(redirectUrl)

  } catch (error) {
    logger.error('OAuth', 'Authorization endpoint error', error)
    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    })
  }
}

/**
 * POST /api/oauth/authorize - Handle consent form submission
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const { approve, ...authRequest } = body

    if (!approve) {
      // User denied authorization
      return createErrorRedirect(authRequest.redirectUri, {
        error: 'access_denied',
        errorDescription: 'User denied authorization',
        state: authRequest.state,
      })
    }

    // Process approval (similar to GET logic)
    // This would handle the consent form submission
    // For now, redirect to GET endpoint
    const authUrl = new URL('/api/oauth/authorize', request.url)
    Object.entries(authRequest).forEach(([key, value]) => {
      if (value) authUrl.searchParams.set(key, value as string)
    })

    return NextResponse.redirect(authUrl)

  } catch (error) {
    logger.error('OAuth', 'Authorization POST error', error)
    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    })
  }
}

/**
 * Create error response for invalid requests
 */
function createErrorResponse(error: OAuthError): NextResponse {
  return NextResponse.json(error, { status: 400 })
}

/**
 * Create error redirect for client errors
 */
function createErrorRedirect(redirectUri: string, error: OAuthError): NextResponse {
  try {
    const url = new URL(redirectUri)
    url.searchParams.set('error', error.error)
    
    if (error.errorDescription) {
      url.searchParams.set('error_description', error.errorDescription)
    }
    
    if (error.state) {
      url.searchParams.set('state', error.state)
    }

    return NextResponse.redirect(url)
  } catch {
    // If redirect URI is invalid, return error response
    return createErrorResponse({
      error: 'invalid_request',
      errorDescription: 'Invalid redirect_uri',
    })
  }
}
