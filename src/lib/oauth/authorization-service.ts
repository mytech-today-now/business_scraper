/**
 * OAuth 2.0 Authorization Service
 * Handles authorization codes and authorization flow
 */

import crypto from 'crypto'
import { AuthorizationCode, AuthorizationRequest, OAuthClient, OAuthUser } from '@/types/oauth'
import { oauthConfig } from './config'
import { logger } from '@/utils/logger'

export class AuthorizationService {
  private static instance: AuthorizationService
  private authorizationCodes = new Map<string, AuthorizationCode>()

  static getInstance(): AuthorizationService {
    if (!AuthorizationService.instance) {
      AuthorizationService.instance = new AuthorizationService()
    }
    return AuthorizationService.instance
  }

  /**
   * Generate authorization code
   */
  generateAuthorizationCode(
    client: OAuthClient,
    user: OAuthUser,
    redirectUri: string,
    scopes: string[],
    codeChallenge?: string,
    codeChallengeMethod?: 'S256' | 'plain'
  ): { code: string; expiresAt: Date } {
    const code = this.generateSecureCode()
    const expiresAt = new Date(Date.now() + oauthConfig.authorizationCodeLifetime * 1000)

    const authCode: AuthorizationCode = {
      code,
      clientId: client.id,
      userId: user.id,
      redirectUri,
      scopes,
      codeChallenge,
      codeChallengeMethod,
      expiresAt,
      createdAt: new Date(),
      isUsed: false,
    }

    this.authorizationCodes.set(code, authCode)
    logger.info(
      'AuthorizationService',
      `Generated authorization code for user ${user.id}, client ${client.id}`
    )

    return { code, expiresAt }
  }

  /**
   * Validate and consume authorization code
   */
  validateAndConsumeCode(
    code: string,
    clientId: string,
    redirectUri: string,
    codeVerifier?: string
  ): { valid: boolean; authCode?: AuthorizationCode; error?: string } {
    const authCode = this.authorizationCodes.get(code)

    if (!authCode) {
      return { valid: false, error: 'Invalid authorization code' }
    }

    // Check if code is already used
    if (authCode.isUsed) {
      return { valid: false, error: 'Authorization code already used' }
    }

    // Check expiration
    if (authCode.expiresAt < new Date()) {
      this.authorizationCodes.delete(code)
      return { valid: false, error: 'Authorization code expired' }
    }

    // Validate client
    if (authCode.clientId !== clientId) {
      return { valid: false, error: 'Invalid client for authorization code' }
    }

    // Validate redirect URI
    if (authCode.redirectUri !== redirectUri) {
      return { valid: false, error: 'Invalid redirect URI for authorization code' }
    }

    // Validate PKCE if present
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        return { valid: false, error: 'Code verifier required for PKCE flow' }
      }

      const isValidPkce = this.validatePKCE(
        codeVerifier,
        authCode.codeChallenge,
        authCode.codeChallengeMethod || 'S256'
      )

      if (!isValidPkce) {
        return { valid: false, error: 'Invalid PKCE verification' }
      }
    }

    // Mark as used
    authCode.isUsed = true
    this.authorizationCodes.set(code, authCode)

    logger.info(
      'AuthorizationService',
      `Validated and consumed authorization code for client ${clientId}`
    )
    return { valid: true, authCode }
  }

  /**
   * Validate authorization request
   */
  validateAuthorizationRequest(
    request: AuthorizationRequest,
    client: OAuthClient
  ): { valid: boolean; error?: string; scopes?: string[] } {
    // Validate response type
    if (request.responseType !== 'code') {
      return { valid: false, error: 'unsupported_response_type' }
    }

    // Validate client
    if (request.clientId !== client.id) {
      return { valid: false, error: 'invalid_client' }
    }

    // Validate redirect URI
    if (!client.redirectUris.includes(request.redirectUri)) {
      return { valid: false, error: 'invalid_request' }
    }

    // Validate and parse scopes
    const requestedScopes = this.parseScopes(request.scope || 'openid')
    const validationResult = this.validateScopes(requestedScopes, client.allowedScopes)

    if (!validationResult.valid) {
      return { valid: false, error: 'invalid_scope' }
    }

    // Validate PKCE for public clients
    if (client.type === 'public' && oauthConfig.requirePkce) {
      if (!request.codeChallenge) {
        return { valid: false, error: 'invalid_request' }
      }

      if (request.codeChallengeMethod && !['S256', 'plain'].includes(request.codeChallengeMethod)) {
        return { valid: false, error: 'invalid_request' }
      }
    }

    return { valid: true, scopes: requestedScopes }
  }

  /**
   * Generate authorization URL
   */
  generateAuthorizationUrl(
    baseUrl: string,
    clientId: string,
    redirectUri: string,
    scopes: string[],
    state?: string,
    codeChallenge?: string,
    codeChallengeMethod?: 'S256' | 'plain'
  ): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
    })

    if (state) {
      params.set('state', state)
    }

    if (codeChallenge) {
      params.set('code_challenge', codeChallenge)
      params.set('code_challenge_method', codeChallengeMethod || 'S256')
    }

    return `${baseUrl}${oauthConfig.authorizationEndpoint}?${params.toString()}`
  }

  /**
   * Clean up expired authorization codes
   */
  cleanupExpiredCodes(): number {
    const now = new Date()
    let cleanedCount = 0

    for (const [code, authCode] of this.authorizationCodes.entries()) {
      if (authCode.expiresAt < now || authCode.isUsed) {
        this.authorizationCodes.delete(code)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      logger.info(
        'AuthorizationService',
        `Cleaned up ${cleanedCount} expired/used authorization codes`
      )
    }

    return cleanedCount
  }

  /**
   * Revoke all authorization codes for a user
   */
  revokeUserCodes(userId: string): number {
    let revokedCount = 0

    for (const [code, authCode] of this.authorizationCodes.entries()) {
      if (authCode.userId === userId && !authCode.isUsed) {
        authCode.isUsed = true
        this.authorizationCodes.set(code, authCode)
        revokedCount++
      }
    }

    logger.info(
      'AuthorizationService',
      `Revoked ${revokedCount} authorization codes for user ${userId}`
    )
    return revokedCount
  }

  /**
   * Revoke all authorization codes for a client
   */
  revokeClientCodes(clientId: string): number {
    let revokedCount = 0

    for (const [code, authCode] of this.authorizationCodes.entries()) {
      if (authCode.clientId === clientId && !authCode.isUsed) {
        authCode.isUsed = true
        this.authorizationCodes.set(code, authCode)
        revokedCount++
      }
    }

    logger.info(
      'AuthorizationService',
      `Revoked ${revokedCount} authorization codes for client ${clientId}`
    )
    return revokedCount
  }

  /**
   * Generate secure authorization code
   */
  private generateSecureCode(): string {
    return crypto.randomBytes(32).toString('hex')
  }

  /**
   * Parse scope string into array
   */
  private parseScopes(scopeString: string): string[] {
    return scopeString.split(' ').filter(scope => scope.length > 0)
  }

  /**
   * Validate requested scopes against allowed scopes
   */
  private validateScopes(
    requestedScopes: string[],
    allowedScopes: string[]
  ): { valid: boolean; error?: string } {
    for (const scope of requestedScopes) {
      if (!allowedScopes.includes(scope)) {
        return { valid: false, error: `Scope '${scope}' not allowed for this client` }
      }
    }

    return { valid: true }
  }

  /**
   * Validate PKCE code verifier
   */
  private validatePKCE(
    codeVerifier: string,
    codeChallenge: string,
    method: 'S256' | 'plain'
  ): boolean {
    try {
      let expectedChallenge: string

      if (method === 'plain') {
        expectedChallenge = codeVerifier
      } else if (method === 'S256') {
        expectedChallenge = crypto
          .createHash('sha256')
          .update(codeVerifier)
          .digest('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '')
      } else {
        return false
      }

      return expectedChallenge === codeChallenge
    } catch (error) {
      logger.error('AuthorizationService', 'PKCE validation error', error)
      return false
    }
  }

  /**
   * Get authorization service statistics
   */
  getStats(): {
    totalCodes: number
    activeCodes: number
    usedCodes: number
    expiredCodes: number
  } {
    const now = new Date()
    let activeCodes = 0
    let usedCodes = 0
    let expiredCodes = 0

    for (const authCode of this.authorizationCodes.values()) {
      if (authCode.isUsed) {
        usedCodes++
      } else if (authCode.expiresAt < now) {
        expiredCodes++
      } else {
        activeCodes++
      }
    }

    return {
      totalCodes: this.authorizationCodes.size,
      activeCodes,
      usedCodes,
      expiredCodes,
    }
  }
}

export const authorizationService = AuthorizationService.getInstance()
