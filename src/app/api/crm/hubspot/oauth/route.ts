/**
 * HubSpot OAuth API Endpoint
 * Handles HubSpot OAuth2 authentication flow
 */

import { NextRequest, NextResponse } from 'next/server'
import { HubSpotOAuth, HubSpotOAuthConfig } from '@/lib/crm/hubspotOAuth'
import { crmServiceRegistry } from '@/lib/crm/crmServiceRegistry'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * GET /api/crm/hubspot/oauth - Initiate OAuth flow or handle callback
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  const url = new URL(request.url)

  try {
    logger.info('HubSpot_OAuth_API', `OAuth request from IP: ${ip}`)

    // Check if this is a callback (has 'code' parameter)
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    const error = url.searchParams.get('error')

    if (error) {
      // OAuth error
      const errorDescription = url.searchParams.get('error_description')
      logger.error('HubSpot_OAuth_API', `OAuth error: ${error}`, { errorDescription })

      return NextResponse.redirect(
        new URL(
          `/crm/hubspot/oauth/error?error=${error}&description=${errorDescription}`,
          request.url
        )
      )
    }

    if (code) {
      // Handle OAuth callback
      return await handleOAuthCallback(request, code, state)
    } else {
      // Initiate OAuth flow
      return await initiateOAuthFlow(request)
    }
  } catch (error) {
    logger.error('HubSpot_OAuth_API', 'OAuth flow failed', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'OAuth flow failed',
      },
      { status: 500 }
    )
  }
}

/**
 * POST /api/crm/hubspot/oauth - Refresh access token
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('HubSpot_OAuth_API', `Token refresh request from IP: ${ip}`)

    const body = await request.json()
    const { refreshToken, providerId } = body

    if (!refreshToken) {
      return NextResponse.json(
        {
          success: false,
          error: 'Refresh token is required',
        },
        { status: 400 }
      )
    }

    // Get OAuth configuration
    const oauthConfig = await getOAuthConfig()
    const hubspotOAuth = new HubSpotOAuth(oauthConfig)

    // Refresh the token
    const tokenResponse = await hubspotOAuth.refreshAccessToken(refreshToken)

    // Update provider configuration if providerId is provided
    if (providerId) {
      await updateProviderTokens(providerId, tokenResponse)
    }

    logger.info('HubSpot_OAuth_API', 'Token refreshed successfully')

    return NextResponse.json({
      success: true,
      data: {
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        expiresIn: tokenResponse.expires_in,
        tokenType: tokenResponse.token_type,
      },
    })
  } catch (error) {
    logger.error('HubSpot_OAuth_API', 'Token refresh failed', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Token refresh failed',
      },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/crm/hubspot/oauth - Revoke access token
 */
export async function DELETE(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('HubSpot_OAuth_API', `Token revocation request from IP: ${ip}`)

    const url = new URL(request.url)
    const accessToken = url.searchParams.get('token')
    const providerId = url.searchParams.get('providerId')

    if (!accessToken) {
      return NextResponse.json(
        {
          success: false,
          error: 'Access token is required',
        },
        { status: 400 }
      )
    }

    // Get OAuth configuration
    const oauthConfig = await getOAuthConfig()
    const hubspotOAuth = new HubSpotOAuth(oauthConfig)

    // Revoke the token
    await hubspotOAuth.revokeToken(accessToken)

    // Remove provider if providerId is provided
    if (providerId) {
      await crmServiceRegistry.unregisterProvider(providerId)
    }

    logger.info('HubSpot_OAuth_API', 'Token revoked successfully')

    return NextResponse.json({
      success: true,
      message: 'Token revoked successfully',
    })
  } catch (error) {
    logger.error('HubSpot_OAuth_API', 'Token revocation failed', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Token revocation failed',
      },
      { status: 500 }
    )
  }
}

/**
 * Initiate OAuth flow
 */
async function initiateOAuthFlow(request: NextRequest): Promise<NextResponse> {
  try {
    // Get OAuth configuration
    const oauthConfig = await getOAuthConfig()
    const hubspotOAuth = new HubSpotOAuth(oauthConfig)

    // Generate secure state parameter
    const state = HubSpotOAuth.generateState()

    // Store state securely
    await HubSpotOAuth.storeState(state)

    // Generate authorization URL
    const authUrl = hubspotOAuth.getAuthorizationUrl(state)

    logger.info('HubSpot_OAuth_API', 'OAuth flow initiated', { state })

    // Redirect to HubSpot authorization page
    return NextResponse.redirect(authUrl)
  } catch (error) {
    logger.error('HubSpot_OAuth_API', 'Failed to initiate OAuth flow', error)
    throw error
  }
}

/**
 * Handle OAuth callback
 */
async function handleOAuthCallback(
  request: NextRequest,
  code: string,
  state?: string | null
): Promise<NextResponse> {
  try {
    // Validate state parameter
    if (state) {
      const isValidState = await HubSpotOAuth.validateState(state)
      if (!isValidState) {
        throw new Error('Invalid state parameter')
      }
    }

    // Get OAuth configuration
    const oauthConfig = await getOAuthConfig()
    const hubspotOAuth = new HubSpotOAuth(oauthConfig)

    // Exchange code for tokens
    const tokenResponse = await hubspotOAuth.exchangeCodeForToken(code)

    // Get token information
    const tokenInfo = await hubspotOAuth.getTokenInfo(tokenResponse.access_token)

    // Create or update CRM provider
    const provider = await createHubSpotProvider(tokenResponse, tokenInfo)

    // Register provider with CRM service registry
    await crmServiceRegistry.registerProvider(provider)

    logger.info('HubSpot_OAuth_API', 'OAuth callback handled successfully', {
      hubId: tokenInfo.hub_id,
      providerId: provider.id,
    })

    // Redirect to success page with provider information
    const successUrl = new URL('/crm/hubspot/oauth/success', request.url)
    successUrl.searchParams.set('providerId', provider.id)
    successUrl.searchParams.set('hubId', tokenInfo.hub_id.toString())

    return NextResponse.redirect(successUrl)
  } catch (error) {
    logger.error('HubSpot_OAuth_API', 'OAuth callback failed', error)

    // Redirect to error page
    const errorUrl = new URL('/crm/hubspot/oauth/error', request.url)
    errorUrl.searchParams.set('error', 'callback_failed')
    errorUrl.searchParams.set('description', error instanceof Error ? error.message : 'Unknown error')

    return NextResponse.redirect(errorUrl)
  }
}

/**
 * Get OAuth configuration from environment variables
 */
async function getOAuthConfig(): Promise<HubSpotOAuthConfig> {
  const clientId = process.env.HUBSPOT_CLIENT_ID
  const clientSecret = process.env.HUBSPOT_CLIENT_SECRET
  const redirectUri = process.env.HUBSPOT_REDIRECT_URI

  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error('HubSpot OAuth configuration is incomplete')
  }

  return HubSpotOAuth.createConfig(clientId, clientSecret, redirectUri)
}

/**
 * Create HubSpot CRM provider from OAuth response
 */
async function createHubSpotProvider(tokenResponse: any, tokenInfo: any): Promise<any> {
  const providerId = `hubspot-${tokenInfo.hub_id}`

  return {
    id: providerId,
    name: `HubSpot (${tokenInfo.hub_domain})`,
    type: 'hubspot',
    version: '1.0.0',
    isActive: true,
    configuration: {
      apiEndpoint: 'https://api.hubapi.com',
      portalId: tokenInfo.hub_id.toString(),
      appId: tokenInfo.app_id.toString(),
      authentication: {
        type: 'oauth2',
        credentials: {
          clientId: process.env.HUBSPOT_CLIENT_ID,
          clientSecret: process.env.HUBSPOT_CLIENT_SECRET,
        },
        tokenExpiry: new Date(Date.now() + tokenResponse.expires_in * 1000),
        refreshToken: tokenResponse.refresh_token,
        scopes: tokenInfo.scopes,
      },
      syncSettings: {
        direction: 'bidirectional',
        frequency: 'realtime',
        batchSize: 100,
        conflictResolution: 'source_wins',
        enableDeduplication: true,
        enableValidation: true,
      },
      fieldMappings: [
        { sourceField: 'businessName', targetField: 'name', required: true, dataType: 'string' },
        { sourceField: 'email.0', targetField: 'email', required: true, dataType: 'string' },
        { sourceField: 'phone', targetField: 'phone', required: false, dataType: 'string' },
        { sourceField: 'websiteUrl', targetField: 'website', required: false, dataType: 'string' },
        { sourceField: 'address.city', targetField: 'city', required: false, dataType: 'string' },
        { sourceField: 'address.state', targetField: 'state', required: false, dataType: 'string' },
        { sourceField: 'address.zipCode', targetField: 'zip', required: false, dataType: 'string' },
        { sourceField: 'industry', targetField: 'industry', required: false, dataType: 'string' },
      ],
      webhookUrl: `${process.env.NEXT_PUBLIC_APP_URL}/api/crm/webhook?providerId=${providerId}`,
      rateLimits: {
        requestsPerMinute: 100,
        requestsPerHour: 40000,
        requestsPerDay: 1000000,
        burstLimit: 10,
      },
    },
    capabilities: {
      bidirectionalSync: true,
      realTimeUpdates: true,
      bulkOperations: true,
      customFields: true,
      webhookSupport: true,
      deduplication: true,
      validation: true,
    },
  }
}

/**
 * Update provider tokens after refresh
 */
async function updateProviderTokens(providerId: string, tokenResponse: any): Promise<void> {
  try {
    const provider = crmServiceRegistry.getProvider(providerId)
    if (!provider) {
      throw new Error(`Provider not found: ${providerId}`)
    }

    await crmServiceRegistry.updateProvider(providerId, {
      configuration: {
        ...provider.configuration,
        authentication: {
          ...provider.configuration.authentication,
          tokenExpiry: new Date(Date.now() + tokenResponse.expires_in * 1000),
          refreshToken: tokenResponse.refresh_token,
        },
      },
    })

    logger.info('HubSpot_OAuth_API', `Updated tokens for provider: ${providerId}`)
  } catch (error) {
    logger.error('HubSpot_OAuth_API', `Failed to update provider tokens: ${providerId}`, error)
    throw error
  }
}
