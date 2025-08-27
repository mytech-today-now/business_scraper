/**
 * OAuth 2.0 Client Management Service
 * Handles client registration, validation, and management
 */

import crypto from 'crypto'
import { v4 as uuidv4 } from 'uuid'
import {
  OAuthClient,
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  GrantType,
} from '@/types/oauth'
import { clientRegistrationConfig, oauthConfig } from './config'
import { logger } from '@/utils/logger'

export class ClientService {
  private static instance: ClientService
  private clients = new Map<string, OAuthClient>()

  static getInstance(): ClientService {
    if (!ClientService.instance) {
      ClientService.instance = new ClientService()
      ClientService.instance.initializeDefaultClients()
    }
    return ClientService.instance
  }

  /**
   * Initialize default clients for the application
   */
  private initializeDefaultClients(): void {
    // Default web application client
    const webClient: OAuthClient = {
      id: 'business-scraper-web',
      secret: this.generateClientSecret(),
      name: 'Business Scraper Web Application',
      type: 'confidential',
      redirectUris: ['http://localhost:3000/auth/callback', 'https://localhost:3000/auth/callback'],
      allowedGrantTypes: ['authorization_code', 'refresh_token'],
      allowedScopes: ['openid', 'profile', 'email', 'read', 'write'],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      metadata: {
        description: 'Default web application client',
        isDefault: true,
      },
    }

    // Default mobile/SPA client (public)
    const mobileClient: OAuthClient = {
      id: 'business-scraper-mobile',
      name: 'Business Scraper Mobile/SPA',
      type: 'public',
      redirectUris: [
        'com.businessscraper://auth/callback',
        'http://localhost:3000/auth/callback',
        'https://localhost:3000/auth/callback',
      ],
      allowedGrantTypes: ['authorization_code', 'refresh_token'],
      allowedScopes: ['openid', 'profile', 'email', 'read'],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      metadata: {
        description: 'Default mobile and SPA client',
        isDefault: true,
        requiresPkce: true,
      },
    }

    // Default API client for server-to-server communication
    const apiClient: OAuthClient = {
      id: 'business-scraper-api',
      secret: this.generateClientSecret(),
      name: 'Business Scraper API Client',
      type: 'confidential',
      redirectUris: [],
      allowedGrantTypes: ['client_credentials'],
      allowedScopes: ['read', 'write', 'admin'],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      metadata: {
        description: 'Default API client for server-to-server communication',
        isDefault: true,
      },
    }

    this.clients.set(webClient.id, webClient)
    this.clients.set(mobileClient.id, mobileClient)
    this.clients.set(apiClient.id, apiClient)

    logger.info('ClientService', 'Initialized default OAuth clients')
  }

  /**
   * Register a new OAuth client
   */
  registerClient(request: ClientRegistrationRequest): ClientRegistrationResponse {
    const clientId = this.generateClientId()
    const clientSecret =
      request.clientType === 'confidential' ? this.generateClientSecret() : undefined
    const now = Math.floor(Date.now() / 1000)

    // Validate redirect URIs
    this.validateRedirectUris(request.redirectUris)

    // Validate grant types
    const grantTypes = request.grantTypes || clientRegistrationConfig.defaultGrantTypes
    this.validateGrantTypes(grantTypes)

    // Validate scopes
    const scopes = this.parseScopes(request.scope || clientRegistrationConfig.defaultScope)
    this.validateScopes(scopes)

    const client: OAuthClient = {
      id: clientId,
      secret: clientSecret,
      name: request.clientName,
      type: request.clientType,
      redirectUris: request.redirectUris,
      allowedGrantTypes: grantTypes,
      allowedScopes: scopes,
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      metadata: {
        contacts: request.contacts,
        logoUri: request.logoUri,
        clientUri: request.clientUri,
        policyUri: request.policyUri,
        tosUri: request.tosUri,
      },
    }

    this.clients.set(clientId, client)
    logger.info('ClientService', `Registered new client: ${clientId}`)

    const response: ClientRegistrationResponse = {
      clientId,
      clientSecret,
      clientIdIssuedAt: now,
      clientSecretExpiresAt: clientSecret ? 0 : undefined, // 0 means never expires
      clientName: request.clientName,
      clientType: request.clientType,
      redirectUris: request.redirectUris,
      grantTypes,
      responseTypes: request.responseTypes || clientRegistrationConfig.defaultResponseTypes,
      scope: scopes.join(' '),
      tokenEndpointAuthMethod:
        request.tokenEndpointAuthMethod || clientRegistrationConfig.defaultTokenEndpointAuthMethod,
    }

    return response
  }

  /**
   * Get client by ID
   */
  getClient(clientId: string): OAuthClient | null {
    return this.clients.get(clientId) || null
  }

  /**
   * Validate client credentials
   */
  validateClient(
    clientId: string,
    clientSecret?: string
  ): { valid: boolean; client?: OAuthClient; error?: string } {
    const client = this.getClient(clientId)

    if (!client) {
      return { valid: false, error: 'Client not found' }
    }

    if (!client.isActive) {
      return { valid: false, error: 'Client is inactive' }
    }

    // For confidential clients, validate secret
    if (client.type === 'confidential') {
      if (!clientSecret) {
        return { valid: false, error: 'Client secret required for confidential clients' }
      }

      if (client.secret !== clientSecret) {
        return { valid: false, error: 'Invalid client secret' }
      }
    }

    return { valid: true, client }
  }

  /**
   * Validate redirect URI for client
   */
  validateRedirectUri(clientId: string, redirectUri: string): boolean {
    const client = this.getClient(clientId)
    if (!client) {
      return false
    }

    return client.redirectUris.includes(redirectUri)
  }

  /**
   * Check if client supports grant type
   */
  supportsGrantType(clientId: string, grantType: GrantType): boolean {
    const client = this.getClient(clientId)
    if (!client) {
      return false
    }

    return client.allowedGrantTypes.includes(grantType)
  }

  /**
   * Check if client has access to scopes
   */
  hasScope(clientId: string, requestedScopes: string[]): boolean {
    const client = this.getClient(clientId)
    if (!client) {
      return false
    }

    return requestedScopes.every(scope => client.allowedScopes.includes(scope))
  }

  /**
   * Update client
   */
  updateClient(clientId: string, updates: Partial<OAuthClient>): boolean {
    const client = this.getClient(clientId)
    if (!client) {
      return false
    }

    // Validate updates
    if (updates.redirectUris) {
      this.validateRedirectUris(updates.redirectUris)
    }

    if (updates.allowedGrantTypes) {
      this.validateGrantTypes(updates.allowedGrantTypes)
    }

    if (updates.allowedScopes) {
      this.validateScopes(updates.allowedScopes)
    }

    // Apply updates
    const updatedClient = {
      ...client,
      ...updates,
      updatedAt: new Date(),
    }

    this.clients.set(clientId, updatedClient)
    logger.info('ClientService', `Updated client: ${clientId}`)

    return true
  }

  /**
   * Deactivate client
   */
  deactivateClient(clientId: string): boolean {
    const client = this.getClient(clientId)
    if (!client) {
      return false
    }

    client.isActive = false
    client.updatedAt = new Date()
    this.clients.set(clientId, client)

    logger.info('ClientService', `Deactivated client: ${clientId}`)
    return true
  }

  /**
   * List all clients
   */
  listClients(): OAuthClient[] {
    return Array.from(this.clients.values())
  }

  /**
   * Generate client ID
   */
  private generateClientId(): string {
    return crypto.randomBytes(clientRegistrationConfig.clientIdLength / 2).toString('hex')
  }

  /**
   * Generate client secret
   */
  private generateClientSecret(): string {
    return crypto.randomBytes(clientRegistrationConfig.clientSecretLength / 2).toString('hex')
  }

  /**
   * Validate redirect URIs
   */
  private validateRedirectUris(redirectUris: string[]): void {
    if (redirectUris.length === 0) {
      throw new Error('At least one redirect URI is required')
    }

    for (const uri of redirectUris) {
      try {
        const url = new URL(uri)

        // Validate protocol
        if (!['http:', 'https:', 'com.businessscraper:'].includes(url.protocol)) {
          throw new Error(`Invalid redirect URI protocol: ${url.protocol}`)
        }

        // In production, require HTTPS
        if (
          process.env.NODE_ENV === 'production' &&
          url.protocol === 'http:' &&
          url.hostname !== 'localhost'
        ) {
          throw new Error('HTTPS required for redirect URIs in production')
        }
      } catch (error) {
        throw new Error(`Invalid redirect URI: ${uri}`)
      }
    }
  }

  /**
   * Validate grant types
   */
  private validateGrantTypes(grantTypes: GrantType[]): void {
    for (const grantType of grantTypes) {
      if (!oauthConfig.supportedGrantTypes.includes(grantType)) {
        throw new Error(`Unsupported grant type: ${grantType}`)
      }
    }
  }

  /**
   * Validate scopes
   */
  private validateScopes(scopes: string[]): void {
    for (const scope of scopes) {
      if (!oauthConfig.supportedScopes.includes(scope)) {
        throw new Error(`Unsupported scope: ${scope}`)
      }
    }
  }

  /**
   * Parse scope string into array
   */
  private parseScopes(scopeString: string): string[] {
    return scopeString.split(' ').filter(scope => scope.length > 0)
  }

  /**
   * Get client statistics
   */
  getClientStats(): {
    totalClients: number
    activeClients: number
    publicClients: number
    confidentialClients: number
  } {
    const clients = Array.from(this.clients.values())

    return {
      totalClients: clients.length,
      activeClients: clients.filter(c => c.isActive).length,
      publicClients: clients.filter(c => c.type === 'public').length,
      confidentialClients: clients.filter(c => c.type === 'confidential').length,
    }
  }
}

export const clientService = ClientService.getInstance()
