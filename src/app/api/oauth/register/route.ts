/**
 * OAuth 2.0 Dynamic Client Registration Endpoint (RFC 7591)
 * Allows clients to register themselves with the authorization server
 */

import { NextRequest, NextResponse } from 'next/server'
import { clientService } from '@/lib/oauth/client-service'
import { clientRegistrationConfig } from '@/lib/oauth/config'
import { logger } from '@/utils/logger'
import { ClientRegistrationRequest, OAuthError } from '@/types/oauth'

/**
 * POST /api/oauth/register - Client registration endpoint
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Check if dynamic registration is enabled
    if (!clientRegistrationConfig.allowDynamicRegistration) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Dynamic client registration is not enabled',
      }, 403)
    }

    // Parse registration request
    const body = await request.json()
    
    const registrationRequest: ClientRegistrationRequest = {
      clientName: body.client_name,
      clientType: body.client_type || 'public',
      redirectUris: body.redirect_uris || [],
      scope: body.scope,
      grantTypes: body.grant_types,
      responseTypes: body.response_types,
      tokenEndpointAuthMethod: body.token_endpoint_auth_method,
      contacts: body.contacts,
      logoUri: body.logo_uri,
      clientUri: body.client_uri,
      policyUri: body.policy_uri,
      tosUri: body.tos_uri,
    }

    // Validate required fields
    if (!registrationRequest.clientName) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Missing required parameter: client_name',
      })
    }

    if (!registrationRequest.redirectUris || registrationRequest.redirectUris.length === 0) {
      // Allow empty redirect URIs only for client_credentials grant
      const grantTypes = registrationRequest.grantTypes || clientRegistrationConfig.defaultGrantTypes
      if (!grantTypes.includes('client_credentials')) {
        return createErrorResponse({
          error: 'invalid_request',
          errorDescription: 'At least one redirect_uri is required',
        })
      }
    }

    // Validate client type
    if (!['public', 'confidential'].includes(registrationRequest.clientType)) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: 'Invalid client_type. Must be "public" or "confidential"',
      })
    }

    // Validate redirect URIs format
    if (registrationRequest.redirectUris.length > 0) {
      for (const uri of registrationRequest.redirectUris) {
        if (!isValidRedirectUri(uri)) {
          return createErrorResponse({
            error: 'invalid_redirect_uri',
            errorDescription: `Invalid redirect URI: ${uri}`,
          })
        }
      }
    }

    // Validate grant types
    if (registrationRequest.grantTypes) {
      for (const grantType of registrationRequest.grantTypes) {
        if (!['authorization_code', 'refresh_token', 'client_credentials'].includes(grantType)) {
          return createErrorResponse({
            error: 'invalid_request',
            errorDescription: `Unsupported grant type: ${grantType}`,
          })
        }
      }
    }

    // Register the client
    const registrationResponse = clientService.registerClient(registrationRequest)

    logger.info('OAuth', `New client registered: ${registrationResponse.clientId}`)
    
    return NextResponse.json(registrationResponse, { status: 201 })

  } catch (error) {
    logger.error('OAuth', 'Client registration error', error)
    
    if (error instanceof Error) {
      return createErrorResponse({
        error: 'invalid_request',
        errorDescription: error.message,
      })
    }

    return createErrorResponse({
      error: 'server_error',
      errorDescription: 'Internal server error',
    })
  }
}

/**
 * GET /api/oauth/register - Get registration information
 */
export async function GET(): Promise<NextResponse> {
  if (!clientRegistrationConfig.allowDynamicRegistration) {
    return createErrorResponse({
      error: 'invalid_request',
      errorDescription: 'Dynamic client registration is not enabled',
    }, 403)
  }

  const registrationInfo = {
    registration_endpoint: '/api/oauth/register',
    client_types_supported: ['public', 'confidential'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    response_types_supported: ['code'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    scopes_supported: ['openid', 'profile', 'email', 'read', 'write', 'admin'],
    code_challenge_methods_supported: ['S256', 'plain'],
    require_request_uri_registration: false,
    require_signed_request_object: false,
  }

  return NextResponse.json(registrationInfo)
}

/**
 * Validate redirect URI format
 */
function isValidRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri)
    
    // Allow HTTP only for localhost in development
    if (url.protocol === 'http:' && url.hostname !== 'localhost' && process.env.NODE_ENV === 'production') {
      return false
    }

    // Allow HTTPS and custom schemes
    if (!['http:', 'https:'].includes(url.protocol) && !url.protocol.endsWith(':')) {
      return false
    }

    // Reject fragment components
    if (url.hash) {
      return false
    }

    return true
  } catch {
    return false
  }
}

/**
 * Create error response
 */
function createErrorResponse(error: OAuthError, status: number = 400): NextResponse {
  return NextResponse.json(error, { status })
}
