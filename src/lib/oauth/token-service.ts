/**
 * OAuth 2.0 Token Service
 * Handles JWT token creation, validation, and management
 */

import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'
import { AccessToken, RefreshToken, JWTPayload, OAuthClient, OAuthUser } from '@/types/oauth'
import { jwtConfig, oauthConfig } from './config'
import { logger } from '@/utils/logger'

export class TokenService {
  private static instance: TokenService
  private accessTokens = new Map<string, AccessToken>()
  private refreshTokens = new Map<string, RefreshToken>()
  private blacklistedTokens = new Set<string>()

  static getInstance(): TokenService {
    if (!TokenService.instance) {
      TokenService.instance = new TokenService()
    }
    return TokenService.instance
  }

  /**
   * Generate JWT access token
   */
  generateAccessToken(
    client: OAuthClient,
    user: OAuthUser,
    scopes: string[]
  ): { token: string; expiresAt: Date } {
    const now = Math.floor(Date.now() / 1000)
    const expiresAt = new Date((now + oauthConfig.accessTokenLifetime) * 1000)
    const jti = uuidv4()

    const payload: JWTPayload = {
      iss: jwtConfig.issuer,
      sub: user.id,
      aud: client.id,
      exp: now + oauthConfig.accessTokenLifetime,
      iat: now,
      jti,
      scope: scopes.join(' '),
      client_id: client.id,
      token_type: 'access_token',
    }

    const token = jwt.sign(payload, jwtConfig.secret, {
      algorithm: jwtConfig.algorithm,
    })

    // Store token metadata
    const accessToken: AccessToken = {
      token,
      tokenType: 'Bearer',
      clientId: client.id,
      userId: user.id,
      scopes,
      expiresAt,
      createdAt: new Date(),
      isRevoked: false,
    }

    this.accessTokens.set(jti, accessToken)
    logger.info('TokenService', `Generated access token for user ${user.id}, client ${client.id}`)

    return { token, expiresAt }
  }

  /**
   * Generate refresh token
   */
  generateRefreshToken(
    client: OAuthClient,
    user: OAuthUser,
    scopes: string[],
    accessTokenId: string
  ): { token: string; expiresAt: Date } {
    const now = Math.floor(Date.now() / 1000)
    const expiresAt = new Date((now + oauthConfig.refreshTokenLifetime) * 1000)
    const jti = uuidv4()

    const payload: JWTPayload = {
      iss: jwtConfig.issuer,
      sub: user.id,
      aud: client.id,
      exp: now + oauthConfig.refreshTokenLifetime,
      iat: now,
      jti,
      scope: scopes.join(' '),
      client_id: client.id,
      token_type: 'refresh_token',
    }

    const token = jwt.sign(payload, jwtConfig.secret, {
      algorithm: jwtConfig.algorithm,
    })

    // Store token metadata
    const refreshToken: RefreshToken = {
      token,
      clientId: client.id,
      userId: user.id,
      scopes,
      expiresAt,
      createdAt: new Date(),
      isRevoked: false,
      accessTokenId,
    }

    this.refreshTokens.set(jti, refreshToken)
    logger.info('TokenService', `Generated refresh token for user ${user.id}, client ${client.id}`)

    return { token, expiresAt }
  }

  /**
   * Validate and decode JWT token
   */
  validateToken(token: string): { valid: boolean; payload?: JWTPayload; error?: string } {
    try {
      // Check if token is blacklisted
      const decoded = jwt.decode(token) as JWTPayload
      if (!decoded || this.blacklistedTokens.has(decoded.jti)) {
        return { valid: false, error: 'Token is revoked' }
      }

      // Verify token signature and expiration
      const payload = jwt.verify(token, jwtConfig.secret, {
        algorithm: jwtConfig.algorithm,
        issuer: jwtConfig.issuer,
      }) as JWTPayload

      // Additional validation
      if (payload.token_type === 'access_token') {
        const accessToken = this.accessTokens.get(payload.jti)
        if (!accessToken || accessToken.isRevoked) {
          return { valid: false, error: 'Access token is revoked' }
        }
      } else if (payload.token_type === 'refresh_token') {
        const refreshToken = this.refreshTokens.get(payload.jti)
        if (!refreshToken || refreshToken.isRevoked) {
          return { valid: false, error: 'Refresh token is revoked' }
        }
      }

      return { valid: true, payload }
    } catch (error) {
      logger.warn('TokenService', 'Token validation failed', error)
      return { valid: false, error: 'Invalid token' }
    }
  }

  /**
   * Revoke token
   */
  revokeToken(token: string): boolean {
    try {
      const decoded = jwt.decode(token) as JWTPayload
      if (!decoded) {
        return false
      }

      // Add to blacklist
      this.blacklistedTokens.add(decoded.jti)

      // Mark as revoked in storage
      if (decoded.token_type === 'access_token') {
        const accessToken = this.accessTokens.get(decoded.jti)
        if (accessToken) {
          accessToken.isRevoked = true
          this.accessTokens.set(decoded.jti, accessToken)
        }
      } else if (decoded.token_type === 'refresh_token') {
        const refreshToken = this.refreshTokens.get(decoded.jti)
        if (refreshToken) {
          refreshToken.isRevoked = true
          this.refreshTokens.set(decoded.jti, refreshToken)
        }
      }

      logger.info('TokenService', `Revoked token ${decoded.jti}`)
      return true
    } catch (error) {
      logger.error('TokenService', 'Failed to revoke token', error)
      return false
    }
  }

  /**
   * Revoke all tokens for a user
   */
  revokeAllUserTokens(userId: string): number {
    let revokedCount = 0

    // Revoke access tokens
    for (const [jti, token] of this.accessTokens.entries()) {
      if (token.userId === userId && !token.isRevoked) {
        token.isRevoked = true
        this.blacklistedTokens.add(jti)
        this.accessTokens.set(jti, token)
        revokedCount++
      }
    }

    // Revoke refresh tokens
    for (const [jti, token] of this.refreshTokens.entries()) {
      if (token.userId === userId && !token.isRevoked) {
        token.isRevoked = true
        this.blacklistedTokens.add(jti)
        this.refreshTokens.set(jti, token)
        revokedCount++
      }
    }

    logger.info('TokenService', `Revoked ${revokedCount} tokens for user ${userId}`)
    return revokedCount
  }

  /**
   * Revoke all tokens for a client
   */
  revokeAllClientTokens(clientId: string): number {
    let revokedCount = 0

    // Revoke access tokens
    for (const [jti, token] of this.accessTokens.entries()) {
      if (token.clientId === clientId && !token.isRevoked) {
        token.isRevoked = true
        this.blacklistedTokens.add(jti)
        this.accessTokens.set(jti, token)
        revokedCount++
      }
    }

    // Revoke refresh tokens
    for (const [jti, token] of this.refreshTokens.entries()) {
      if (token.clientId === clientId && !token.isRevoked) {
        token.isRevoked = true
        this.blacklistedTokens.add(jti)
        this.refreshTokens.set(jti, token)
        revokedCount++
      }
    }

    logger.info('TokenService', `Revoked ${revokedCount} tokens for client ${clientId}`)
    return revokedCount
  }

  /**
   * Get token information for introspection
   */
  introspectToken(token: string): {
    active: boolean
    scope?: string
    clientId?: string
    username?: string
    tokenType?: string
    exp?: number
    iat?: number
    sub?: string
    aud?: string
    iss?: string
    jti?: string
  } {
    const validation = this.validateToken(token)

    if (!validation.valid || !validation.payload) {
      return { active: false }
    }

    const payload = validation.payload
    return {
      active: true,
      scope: payload.scope,
      clientId: payload.client_id,
      tokenType: 'Bearer',
      exp: payload.exp,
      iat: payload.iat,
      sub: payload.sub,
      aud: payload.aud,
      iss: payload.iss,
      jti: payload.jti,
    }
  }

  /**
   * Clean up expired tokens
   */
  cleanupExpiredTokens(): { accessTokens: number; refreshTokens: number } {
    const now = new Date()
    let expiredAccessTokens = 0
    let expiredRefreshTokens = 0

    // Clean up access tokens
    for (const [jti, token] of this.accessTokens.entries()) {
      if (token.expiresAt < now) {
        this.accessTokens.delete(jti)
        this.blacklistedTokens.add(jti)
        expiredAccessTokens++
      }
    }

    // Clean up refresh tokens
    for (const [jti, token] of this.refreshTokens.entries()) {
      if (token.expiresAt < now) {
        this.refreshTokens.delete(jti)
        this.blacklistedTokens.add(jti)
        expiredRefreshTokens++
      }
    }

    if (expiredAccessTokens > 0 || expiredRefreshTokens > 0) {
      logger.info(
        'TokenService',
        `Cleaned up ${expiredAccessTokens} access tokens and ${expiredRefreshTokens} refresh tokens`
      )
    }

    return { accessTokens: expiredAccessTokens, refreshTokens: expiredRefreshTokens }
  }

  /**
   * Get token statistics
   */
  getTokenStats(): {
    totalAccessTokens: number
    activeAccessTokens: number
    totalRefreshTokens: number
    activeRefreshTokens: number
    blacklistedTokens: number
  } {
    const now = new Date()

    let activeAccessTokens = 0
    for (const token of this.accessTokens.values()) {
      if (!token.isRevoked && token.expiresAt > now) {
        activeAccessTokens++
      }
    }

    let activeRefreshTokens = 0
    for (const token of this.refreshTokens.values()) {
      if (!token.isRevoked && token.expiresAt > now) {
        activeRefreshTokens++
      }
    }

    return {
      totalAccessTokens: this.accessTokens.size,
      activeAccessTokens,
      totalRefreshTokens: this.refreshTokens.size,
      activeRefreshTokens,
      blacklistedTokens: this.blacklistedTokens.size,
    }
  }
}

export const tokenService = TokenService.getInstance()
