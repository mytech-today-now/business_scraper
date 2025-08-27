/**
 * OAuth 2.0 Service
 * Comprehensive OAuth 2.0 implementation for secure third-party access
 */

import { OAuth2Config, OAuth2Token, OAuth2Client, ApiPermission } from '@/types/integrations'
import { logger } from '@/utils/logger'
import crypto from 'crypto'

/**
 * OAuth 2.0 Service implementation
 */
export class OAuth2Service {
  private clients: Map<string, OAuth2Client> = new Map()
  private tokens: Map<string, OAuth2Token> = new Map()
  private authorizationCodes: Map<
    string,
    {
      clientId: string
      redirectUri: string
      scope: string[]
      codeChallenge?: string
      codeChallengeMethod?: string
      expiresAt: number
    }
  > = new Map()

  constructor() {
    this.initializeDefaultClients()
  }

  /**
   * Initialize default OAuth clients
   */
  private initializeDefaultClients(): void {
    // Example client for demonstration
    const defaultClient: OAuth2Client = {
      id: 'business-scraper-api',
      name: 'Business Scraper API Client',
      description: 'Default client for Business Scraper API access',
      config: {
        clientId: 'business-scraper-api',
        clientSecret: this.generateClientSecret(),
        authorizationUrl: '/api/v1/oauth/authorize',
        tokenUrl: '/api/v1/oauth/token',
        redirectUri: 'http://localhost:3000/oauth/callback',
        scopes: ['read:businesses', 'write:businesses', 'read:exports', 'write:exports'],
        responseType: 'code',
        grantType: 'authorization_code',
        pkce: true,
      },
      tokens: [],
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      usageCount: 0,
    }

    this.clients.set(defaultClient.id, defaultClient)
    logger.info('OAuth2Service', 'Initialized default OAuth client')
  }

  /**
   * Create OAuth 2.0 client
   */
  async createClient(
    clientData: Omit<
      OAuth2Client,
      'id' | 'tokens' | 'status' | 'createdAt' | 'updatedAt' | 'usageCount'
    >
  ): Promise<OAuth2Client> {
    const clientId = this.generateClientId()
    const clientSecret = this.generateClientSecret()

    const client: OAuth2Client = {
      id: clientId,
      name: clientData.name,
      description: clientData.description,
      config: {
        ...clientData.config,
        clientId,
        clientSecret,
      },
      tokens: [],
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      usageCount: 0,
    }

    this.clients.set(clientId, client)

    logger.info('OAuth2Service', `Created OAuth client: ${clientId}`, {
      clientId,
      name: client.name,
      scopes: client.config.scopes,
    })

    return client
  }

  /**
   * Get OAuth 2.0 client
   */
  async getClient(clientId: string): Promise<OAuth2Client | null> {
    return this.clients.get(clientId) || null
  }

  /**
   * Generate authorization URL
   */
  async generateAuthorizationUrl(
    clientId: string,
    redirectUri: string,
    scope: string[],
    state?: string,
    codeChallenge?: string,
    codeChallengeMethod?: string
  ): Promise<{
    authorizationUrl: string
    state: string
  }> {
    const client = await this.getClient(clientId)
    if (!client) {
      throw new Error('Client not found')
    }

    if (client.status !== 'active') {
      throw new Error('Client is not active')
    }

    // Validate redirect URI
    if (redirectUri !== client.config.redirectUri) {
      throw new Error('Invalid redirect URI')
    }

    // Validate scopes
    const invalidScopes = scope.filter(s => !client.config.scopes.includes(s))
    if (invalidScopes.length > 0) {
      throw new Error(`Invalid scopes: ${invalidScopes.join(', ')}`)
    }

    const generatedState = state || this.generateState()
    const authCode = this.generateAuthorizationCode()

    // Store authorization code
    this.authorizationCodes.set(authCode, {
      clientId,
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod,
      expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
    })

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scope.join(' '),
      state: generatedState,
      code: authCode,
    })

    if (codeChallenge) {
      params.append('code_challenge', codeChallenge)
      params.append('code_challenge_method', codeChallengeMethod || 'S256')
    }

    const authorizationUrl = `${client.config.authorizationUrl}?${params.toString()}`

    logger.info('OAuth2Service', `Generated authorization URL for client: ${clientId}`, {
      clientId,
      scope,
      state: generatedState,
    })

    return {
      authorizationUrl,
      state: generatedState,
    }
  }

  /**
   * Exchange authorization code for access token
   */
  async exchangeCodeForToken(
    clientId: string,
    clientSecret: string,
    code: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<OAuth2Token> {
    const client = await this.getClient(clientId)
    if (!client) {
      throw new Error('Client not found')
    }

    if (client.config.clientSecret !== clientSecret) {
      throw new Error('Invalid client secret')
    }

    const authData = this.authorizationCodes.get(code)
    if (!authData) {
      throw new Error('Invalid authorization code')
    }

    if (authData.expiresAt < Date.now()) {
      this.authorizationCodes.delete(code)
      throw new Error('Authorization code expired')
    }

    if (authData.clientId !== clientId) {
      throw new Error('Authorization code was issued to different client')
    }

    if (authData.redirectUri !== redirectUri) {
      throw new Error('Invalid redirect URI')
    }

    // Verify PKCE if used
    if (authData.codeChallenge) {
      if (!codeVerifier) {
        throw new Error('Code verifier required for PKCE')
      }

      const challenge =
        authData.codeChallengeMethod === 'S256'
          ? crypto.createHash('sha256').update(codeVerifier).digest('base64url')
          : codeVerifier

      if (challenge !== authData.codeChallenge) {
        throw new Error('Invalid code verifier')
      }
    }

    // Generate tokens
    const accessToken = this.generateAccessToken()
    const refreshToken = this.generateRefreshToken()
    const expiresIn = 3600 // 1 hour
    const issuedAt = Date.now()

    const token: OAuth2Token = {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn,
      expiresAt: issuedAt + expiresIn * 1000,
      scope: authData.scope,
      issuedAt,
    }

    // Store token
    this.tokens.set(accessToken, token)

    // Add token to client
    client.tokens.push(token)
    client.usageCount++
    client.lastUsed = new Date().toISOString()

    // Clean up authorization code
    this.authorizationCodes.delete(code)

    logger.info('OAuth2Service', `Issued access token for client: ${clientId}`, {
      clientId,
      scope: authData.scope,
      expiresIn,
    })

    return token
  }

  /**
   * Refresh access token
   */
  async refreshToken(
    clientId: string,
    clientSecret: string,
    refreshToken: string
  ): Promise<OAuth2Token> {
    const client = await this.getClient(clientId)
    if (!client) {
      throw new Error('Client not found')
    }

    if (client.config.clientSecret !== clientSecret) {
      throw new Error('Invalid client secret')
    }

    // Find existing token
    const existingToken = client.tokens.find(t => t.refreshToken === refreshToken)
    if (!existingToken) {
      throw new Error('Invalid refresh token')
    }

    // Generate new tokens
    const accessToken = this.generateAccessToken()
    const newRefreshToken = this.generateRefreshToken()
    const expiresIn = 3600 // 1 hour
    const issuedAt = Date.now()

    const newToken: OAuth2Token = {
      accessToken,
      refreshToken: newRefreshToken,
      tokenType: 'Bearer',
      expiresIn,
      expiresAt: issuedAt + expiresIn * 1000,
      scope: existingToken.scope,
      issuedAt,
    }

    // Remove old token
    this.tokens.delete(existingToken.accessToken)
    const tokenIndex = client.tokens.findIndex(t => t.refreshToken === refreshToken)
    if (tokenIndex !== -1) {
      client.tokens.splice(tokenIndex, 1)
    }

    // Store new token
    this.tokens.set(accessToken, newToken)
    client.tokens.push(newToken)
    client.lastUsed = new Date().toISOString()

    logger.info('OAuth2Service', `Refreshed access token for client: ${clientId}`, {
      clientId,
      scope: newToken.scope,
    })

    return newToken
  }

  /**
   * Validate access token
   */
  async validateToken(accessToken: string): Promise<{
    valid: boolean
    token?: OAuth2Token
    client?: OAuth2Client
    permissions?: ApiPermission[]
  }> {
    const token = this.tokens.get(accessToken)
    if (!token) {
      return { valid: false }
    }

    if (token.expiresAt < Date.now()) {
      this.tokens.delete(accessToken)
      return { valid: false }
    }

    // Find client
    const client = Array.from(this.clients.values()).find(c =>
      c.tokens.some(t => t.accessToken === accessToken)
    )

    if (!client || client.status !== 'active') {
      return { valid: false }
    }

    return {
      valid: true,
      token,
      client,
      permissions: token.scope as ApiPermission[],
    }
  }

  /**
   * Revoke token
   */
  async revokeToken(accessToken: string): Promise<void> {
    const token = this.tokens.get(accessToken)
    if (!token) {
      return
    }

    // Remove from tokens store
    this.tokens.delete(accessToken)

    // Remove from client
    const client = Array.from(this.clients.values()).find(c =>
      c.tokens.some(t => t.accessToken === accessToken)
    )

    if (client) {
      const tokenIndex = client.tokens.findIndex(t => t.accessToken === accessToken)
      if (tokenIndex !== -1) {
        client.tokens.splice(tokenIndex, 1)
      }
    }

    logger.info('OAuth2Service', `Revoked access token`, {
      tokenPrefix: accessToken.substring(0, 8) + '...',
    })
  }

  /**
   * Revoke all tokens for client
   */
  async revokeClientTokens(clientId: string): Promise<void> {
    const client = await this.getClient(clientId)
    if (!client) {
      return
    }

    // Remove all tokens
    for (const token of client.tokens) {
      this.tokens.delete(token.accessToken)
    }

    client.tokens = []

    logger.info('OAuth2Service', `Revoked all tokens for client: ${clientId}`)
  }

  /**
   * Generate client ID
   */
  private generateClientId(): string {
    return `client_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`
  }

  /**
   * Generate client secret
   */
  private generateClientSecret(): string {
    return crypto.randomBytes(32).toString('hex')
  }

  /**
   * Generate authorization code
   */
  private generateAuthorizationCode(): string {
    return crypto.randomBytes(32).toString('base64url')
  }

  /**
   * Generate access token
   */
  private generateAccessToken(): string {
    return `at_${crypto.randomBytes(32).toString('base64url')}`
  }

  /**
   * Generate refresh token
   */
  private generateRefreshToken(): string {
    return `rt_${crypto.randomBytes(32).toString('base64url')}`
  }

  /**
   * Generate state parameter
   */
  private generateState(): string {
    return crypto.randomBytes(16).toString('base64url')
  }

  /**
   * Get client statistics
   */
  getClientStatistics(): {
    totalClients: number
    activeClients: number
    totalTokens: number
    activeTokens: number
  } {
    const totalClients = this.clients.size
    const activeClients = Array.from(this.clients.values()).filter(
      c => c.status === 'active'
    ).length
    const totalTokens = Array.from(this.clients.values()).reduce(
      (sum, c) => sum + c.tokens.length,
      0
    )
    const activeTokens = Array.from(this.tokens.values()).filter(
      t => t.expiresAt > Date.now()
    ).length

    return {
      totalClients,
      activeClients,
      totalTokens,
      activeTokens,
    }
  }

  /**
   * Cleanup expired tokens
   */
  cleanupExpiredTokens(): void {
    const now = Date.now()
    let cleanedCount = 0

    // Clean tokens store
    for (const [accessToken, token] of this.tokens.entries()) {
      if (token.expiresAt < now) {
        this.tokens.delete(accessToken)
        cleanedCount++
      }
    }

    // Clean client tokens
    for (const client of this.clients.values()) {
      const originalLength = client.tokens.length
      client.tokens = client.tokens.filter(t => t.expiresAt >= now)
      cleanedCount += originalLength - client.tokens.length
    }

    // Clean authorization codes
    for (const [code, authData] of this.authorizationCodes.entries()) {
      if (authData.expiresAt < now) {
        this.authorizationCodes.delete(code)
      }
    }

    if (cleanedCount > 0) {
      logger.info('OAuth2Service', `Cleaned up ${cleanedCount} expired tokens`)
    }
  }
}

// Export singleton instance
export const oauth2Service = new OAuth2Service()

// Start cleanup interval
setInterval(
  () => {
    oauth2Service.cleanupExpiredTokens()
  },
  5 * 60 * 1000
) // Every 5 minutes
