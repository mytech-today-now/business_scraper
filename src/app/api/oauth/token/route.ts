/**
 * OAuth 2.0 Token Endpoint
 * Handles token requests and issuance
 */

import { NextRequest, NextResponse } from 'next/server'
import { clientService } from '@/lib/oauth/client-service'
import { authorizationService } from '@/lib/oauth/authorization-service'
import { tokenService } from '@/lib/oauth/token-service'
import { pkceService } from '@/lib/oauth/pkce-service'
import { logger } from '@/utils/logger'
import { TokenRequest, TokenResponse, OAuthError, GrantType } from '@/types/oauth'

/**
 * POST /api/oauth/token - Token endpoint
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Parse request body
    const body = await request.json()
    
    const tokenRequest: TokenRequest = {
      grantType: body.grant_type as GrantType,
      clientId: body.client_id,
      clientSecret: body.client_secret,
      code: body.code,
      redirectUri: body.redirect_uri,
      codeVerifier: body.code_verifier,
      refreshToken: body.refresh_token,
      scope: body.scope,
    }

    // Validate required parameters
    if (!tokenRequest.grantType || !tokenRequest.clientId) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Missing required parameters: grant_type and client_id',
      })
    }

    // Validate client
    const clientValidation = clientService.validateClient(
      tokenRequest.clientId,
      tokenRequest.clientSecret
    )
    
    if (!clientValidation.valid || !clientValidation.client) {
      return createErrorResponse({
        error: 'invalid_client',
        errorDescription: clientValidation.error || 'Invalid client credentials',
      })
    }

    const client = clientValidation.client

    // Check if client supports the requested grant type
    if (!clientService.supportsGrantType(tokenRequest.clientId, tokenRequest.grantType)) {
      return createErrorResponse({
        error: 'unauthorized_client',
        errorDescription: `Client not authorized for grant type: ${tokenRequest.grantType}`,
      })
    }

    // Handle different grant types
    switch (tokenRequest.grantType) {
      case 'authorization_code':
        return handleAuthorizationCodeGrant(tokenRequest, client)
      
      case 'refresh_token':
        return handleRefreshTokenGrant(tokenRequest, client)
      
      case 'client_credentials':
        return handleClientCredentialsGrant(tokenRequest, client)
      
      default:
        return createErrorResponse({
          error: 'unsupported_grant_type',
          errorDescription: `Unsupported grant type: ${tokenRequest.grantType}`,
        })
    }

  } catch (error) {
    logger.error('OAuth', 'Token endpoint error', error)
    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    })
  }
}

/**
 * Handle authorization code grant
 */
async function handleAuthorizationCodeGrant(
  tokenRequest: TokenRequest,
  client: any
): Promise<NextResponse> {
  // Validate required parameters
  if (!tokenRequest.code || !tokenRequest.redirectUri) {
    return createErrorResponse({
      error: 'invalid_request',
      errorDescription: 'Missing required parameters: code and redirect_uri',
    })
  }

  // Validate and consume authorization code
  const codeValidation = authorizationService.validateAndConsumeCode(
    tokenRequest.code,
    tokenRequest.clientId,
    tokenRequest.redirectUri,
    tokenRequest.codeVerifier
  )

  if (!codeValidation.valid || !codeValidation.authCode) {
    return createErrorResponse({
      error: 'invalid_grant',
      errorDescription: codeValidation.error || 'Invalid authorization code',
    })
  }

  const authCode = codeValidation.authCode

  // Create user object (in real implementation, fetch from database)
  const user = {
    id: authCode.userId,
    username: 'admin',
    email: 'admin@businessscraper.com',
    roles: ['admin'],
    permissions: ['read', 'write', 'admin'],
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  }

  // Generate tokens
  const { token: accessToken, expiresAt: accessTokenExpiresAt } = tokenService.generateAccessToken(
    client,
    user,
    authCode.scopes
  )

  const { token: refreshToken } = tokenService.generateRefreshToken(
    client,
    user,
    authCode.scopes,
    accessToken
  )

  const response: TokenResponse = {
    accessToken,
    tokenType: 'Bearer',
    expiresIn: Math.floor((accessTokenExpiresAt.getTime() - Date.now()) / 1000),
    refreshToken,
    scope: authCode.scopes.join(' '),
  }

  logger.info('OAuth', `Issued tokens for client ${client.id}`)
  return NextResponse.json(response)
}

/**
 * Handle refresh token grant
 */
async function handleRefreshTokenGrant(
  tokenRequest: TokenRequest,
  client: any
): Promise<NextResponse> {
  if (!tokenRequest.refreshToken) {
    return createErrorResponse({
      error: 'invalid_request',
      errorDescription: 'Missing required parameter: refresh_token',
    })
  }

  // Validate refresh token
  const tokenValidation = tokenService.validateToken(tokenRequest.refreshToken)
  
  if (!tokenValidation.valid || !tokenValidation.payload) {
    return createErrorResponse({
      error: 'invalid_grant',
      errorDescription: 'Invalid refresh token',
    })
  }

  const payload = tokenValidation.payload

  // Verify client matches
  if (payload.client_id !== client.id) {
    return createErrorResponse({
      error: 'invalid_grant',
      errorDescription: 'Refresh token not issued to this client',
    })
  }

  // Create user object
  const user = {
    id: payload.sub,
    username: 'admin',
    email: 'admin@businessscraper.com',
    roles: ['admin'],
    permissions: ['read', 'write', 'admin'],
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  }

  const scopes = payload.scope.split(' ')

  // Generate new access token
  const { token: accessToken, expiresAt: accessTokenExpiresAt } = tokenService.generateAccessToken(
    client,
    user,
    scopes
  )

  // Optionally rotate refresh token
  const { token: newRefreshToken } = tokenService.generateRefreshToken(
    client,
    user,
    scopes,
    accessToken
  )

  // Revoke old refresh token
  tokenService.revokeToken(tokenRequest.refreshToken)

  const response: TokenResponse = {
    accessToken,
    tokenType: 'Bearer',
    expiresIn: Math.floor((accessTokenExpiresAt.getTime() - Date.now()) / 1000),
    refreshToken: newRefreshToken,
    scope: scopes.join(' '),
  }

  logger.info('OAuth', `Refreshed tokens for client ${client.id}`)
  return NextResponse.json(response)
}

/**
 * Handle client credentials grant
 */
async function handleClientCredentialsGrant(
  tokenRequest: TokenRequest,
  client: any
): Promise<NextResponse> {
  // Client credentials grant is for machine-to-machine communication
  if (client.type !== 'confidential') {
    return createErrorResponse({
      error: 'unauthorized_client',
      errorDescription: 'Client credentials grant requires confidential client',
    })
  }

  // Parse requested scopes
  const requestedScopes = tokenRequest.scope ? tokenRequest.scope.split(' ') : ['read']
  
  // Validate scopes
  if (!clientService.hasScope(client.id, requestedScopes)) {
    return createErrorResponse({
      error: 'invalid_scope',
      errorDescription: 'Requested scope not allowed for this client',
    })
  }

  // Create service user object
  const serviceUser = {
    id: `service:${client.id}`,
    username: client.name,
    email: '',
    roles: ['service'],
    permissions: requestedScopes,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  }

  // Generate access token (no refresh token for client credentials)
  const { token: accessToken, expiresAt: accessTokenExpiresAt } = tokenService.generateAccessToken(
    client,
    serviceUser,
    requestedScopes
  )

  const response: TokenResponse = {
    accessToken,
    tokenType: 'Bearer',
    expiresIn: Math.floor((accessTokenExpiresAt.getTime() - Date.now()) / 1000),
    scope: requestedScopes.join(' '),
  }

  logger.info('OAuth', `Issued client credentials token for client ${client.id}`)
  return NextResponse.json(response)
}

/**
 * Create error response
 */
function createErrorResponse(error: OAuthError): NextResponse {
  return NextResponse.json(error, { status: 400 })
}
