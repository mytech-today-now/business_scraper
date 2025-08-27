/**
 * HubSpot OAuth2 Authentication Handler
 * Manages OAuth2 flow for HubSpot marketplace connector
 */

import { logger } from '@/utils/logger'

export interface HubSpotOAuthConfig {
  clientId: string
  clientSecret: string
  redirectUri: string
  scopes: string[]
}

export interface HubSpotTokenResponse {
  access_token: string
  refresh_token: string
  expires_in: number
  token_type: string
  scope: string
}

export interface HubSpotTokenInfo {
  token: string
  user: string
  hub_domain: string
  scopes: string[]
  scope_to_scope_group_pks: number[]
  trial_scopes: string[]
  trial_scope_to_scope_group_pks: number[]
  hub_id: number
  app_id: number
  expires_in: number
  user_id: number
  token_type: string
}

export class HubSpotOAuth {
  private config: HubSpotOAuthConfig
  private baseUrl = 'https://app.hubspot.com'
  private apiBaseUrl = 'https://api.hubapi.com'

  constructor(config: HubSpotOAuthConfig) {
    this.config = config
  }

  /**
   * Generate OAuth2 authorization URL
   */
  getAuthorizationUrl(state?: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      response_type: 'code',
    })

    if (state) {
      params.append('state', state)
    }

    return `${this.baseUrl}/oauth/authorize?${params.toString()}`
  }

  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForToken(code: string): Promise<HubSpotTokenResponse> {
    try {
      logger.info('HubSpotOAuth', 'Exchanging authorization code for token')

      const response = await fetch(`${this.apiBaseUrl}/oauth/v1/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
          redirect_uri: this.config.redirectUri,
          code: code,
        }),
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Token exchange failed: ${response.status} ${errorText}`)
      }

      const tokenData = (await response.json()) as HubSpotTokenResponse

      logger.info('HubSpotOAuth', 'Successfully exchanged code for token', {
        tokenType: tokenData.token_type,
        expiresIn: tokenData.expires_in,
        scopes: tokenData.scope,
      })

      return tokenData
    } catch (error) {
      logger.error('HubSpotOAuth', 'Failed to exchange code for token', error)
      throw error
    }
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken(refreshToken: string): Promise<HubSpotTokenResponse> {
    try {
      logger.info('HubSpotOAuth', 'Refreshing access token')

      const response = await fetch(`${this.apiBaseUrl}/oauth/v1/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
          refresh_token: refreshToken,
        }),
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Token refresh failed: ${response.status} ${errorText}`)
      }

      const tokenData = (await response.json()) as HubSpotTokenResponse

      logger.info('HubSpotOAuth', 'Successfully refreshed access token', {
        tokenType: tokenData.token_type,
        expiresIn: tokenData.expires_in,
      })

      return tokenData
    } catch (error) {
      logger.error('HubSpotOAuth', 'Failed to refresh access token', error)
      throw error
    }
  }

  /**
   * Get token information
   */
  async getTokenInfo(accessToken: string): Promise<HubSpotTokenInfo> {
    try {
      logger.info('HubSpotOAuth', 'Getting token information')

      const response = await fetch(`${this.apiBaseUrl}/oauth/v1/access-tokens/${accessToken}`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Get token info failed: ${response.status} ${errorText}`)
      }

      const tokenInfo = (await response.json()) as HubSpotTokenInfo

      logger.info('HubSpotOAuth', 'Successfully retrieved token information', {
        hubId: tokenInfo.hub_id,
        userId: tokenInfo.user_id,
        scopes: tokenInfo.scopes,
      })

      return tokenInfo
    } catch (error) {
      logger.error('HubSpotOAuth', 'Failed to get token information', error)
      throw error
    }
  }

  /**
   * Revoke access token
   */
  async revokeToken(accessToken: string): Promise<void> {
    try {
      logger.info('HubSpotOAuth', 'Revoking access token')

      const response = await fetch(`${this.apiBaseUrl}/oauth/v1/refresh-tokens/${accessToken}`, {
        method: 'DELETE',
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Token revocation failed: ${response.status} ${errorText}`)
      }

      logger.info('HubSpotOAuth', 'Successfully revoked access token')
    } catch (error) {
      logger.error('HubSpotOAuth', 'Failed to revoke access token', error)
      throw error
    }
  }

  /**
   * Validate access token
   */
  async validateToken(accessToken: string): Promise<boolean> {
    try {
      const tokenInfo = await this.getTokenInfo(accessToken)

      // Check if token is expired
      const now = Date.now() / 1000
      const expiresAt = tokenInfo.expires_in

      if (expiresAt && now >= expiresAt) {
        logger.warn('HubSpotOAuth', 'Access token has expired')
        return false
      }

      return true
    } catch (error) {
      logger.error('HubSpotOAuth', 'Token validation failed', error)
      return false
    }
  }

  /**
   * Get required scopes for Business Scraper integration
   */
  static getRequiredScopes(): string[] {
    return [
      'contacts',
      'content',
      'reports',
      'social',
      'automation',
      'timeline',
      'business-intelligence',
      'crm.objects.contacts.read',
      'crm.objects.contacts.write',
      'crm.objects.companies.read',
      'crm.objects.companies.write',
      'crm.objects.deals.read',
      'crm.objects.deals.write',
      'crm.schemas.contacts.read',
      'crm.schemas.companies.read',
      'crm.schemas.deals.read',
      'settings.users.read',
      'oauth',
    ]
  }

  /**
   * Create OAuth configuration for Business Scraper
   */
  static createConfig(
    clientId: string,
    clientSecret: string,
    redirectUri: string,
    customScopes?: string[]
  ): HubSpotOAuthConfig {
    return {
      clientId,
      clientSecret,
      redirectUri,
      scopes: customScopes || HubSpotOAuth.getRequiredScopes(),
    }
  }

  /**
   * Parse OAuth callback parameters
   */
  static parseCallbackParams(url: string): {
    code?: string
    state?: string
    error?: string
    error_description?: string
  } {
    const urlObj = new URL(url)
    const params = urlObj.searchParams

    return {
      code: params.get('code') || undefined,
      state: params.get('state') || undefined,
      error: params.get('error') || undefined,
      error_description: params.get('error_description') || undefined,
    }
  }

  /**
   * Generate secure state parameter for OAuth flow
   */
  static generateState(): string {
    const array = new Uint8Array(32)
    crypto.getRandomValues(array)
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
  }

  /**
   * Store OAuth state securely (implement based on your storage strategy)
   */
  static async storeState(state: string, userId?: string): Promise<void> {
    try {
      // Store state in secure storage (database, Redis, etc.)
      // Implementation depends on your storage strategy
      logger.debug('HubSpotOAuth', `Storing OAuth state: ${state}`)
    } catch (error) {
      logger.error('HubSpotOAuth', 'Failed to store OAuth state', error)
      throw error
    }
  }

  /**
   * Validate OAuth state parameter
   */
  static async validateState(state: string, userId?: string): Promise<boolean> {
    try {
      // Validate state from secure storage
      // Implementation depends on your storage strategy
      logger.debug('HubSpotOAuth', `Validating OAuth state: ${state}`)
      return true // Placeholder - implement actual validation
    } catch (error) {
      logger.error('HubSpotOAuth', 'Failed to validate OAuth state', error)
      return false
    }
  }

  /**
   * Clean up expired OAuth states
   */
  static async cleanupExpiredStates(): Promise<void> {
    try {
      // Clean up expired states from storage
      // Implementation depends on your storage strategy
      logger.debug('HubSpotOAuth', 'Cleaning up expired OAuth states')
    } catch (error) {
      logger.error('HubSpotOAuth', 'Failed to cleanup expired states', error)
    }
  }
}
