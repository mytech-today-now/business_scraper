/**
 * PKCE (Proof Key for Code Exchange) Service
 * Implements RFC 7636 for enhanced security in OAuth 2.0 flows
 */

import crypto from 'crypto'
import { PKCEChallenge } from '@/types/oauth'
import { pkceConfig } from './config'
import { logger } from '@/utils/logger'

export class PKCEService {
  private static instance: PKCEService
  private challenges = new Map<string, { challenge: PKCEChallenge; expiresAt: Date }>()

  static getInstance(): PKCEService {
    if (!PKCEService.instance) {
      PKCEService.instance = new PKCEService()
    }
    return PKCEService.instance
  }

  /**
   * Generate a cryptographically secure code verifier
   */
  generateCodeVerifier(): string {
    const buffer = crypto.randomBytes(Math.ceil(pkceConfig.codeVerifierLength * 3 / 4))
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')
      .substring(0, pkceConfig.codeVerifierLength)
  }

  /**
   * Generate code challenge from verifier
   */
  generateCodeChallenge(codeVerifier: string, method: 'S256' | 'plain' = 'S256'): string {
    if (method === 'plain') {
      return codeVerifier
    }

    if (method === 'S256') {
      return crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
    }

    throw new Error(`Unsupported code challenge method: ${method}`)
  }

  /**
   * Generate complete PKCE challenge
   */
  generatePKCEChallenge(method: 'S256' | 'plain' = pkceConfig.defaultMethod): PKCEChallenge {
    const codeVerifier = this.generateCodeVerifier()
    const codeChallenge = this.generateCodeChallenge(codeVerifier, method)

    const challenge: PKCEChallenge = {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: method,
    }

    logger.debug('PKCEService', `Generated PKCE challenge with method ${method}`)
    return challenge
  }

  /**
   * Verify code verifier against stored challenge
   */
  verifyCodeVerifier(
    codeVerifier: string,
    codeChallenge: string,
    method: 'S256' | 'plain' = 'S256'
  ): boolean {
    try {
      const expectedChallenge = this.generateCodeChallenge(codeVerifier, method)
      const isValid = expectedChallenge === codeChallenge

      if (isValid) {
        logger.debug('PKCEService', 'PKCE verification successful')
      } else {
        logger.warn('PKCEService', 'PKCE verification failed')
      }

      return isValid
    } catch (error) {
      logger.error('PKCEService', 'PKCE verification error', error)
      return false
    }
  }

  /**
   * Store PKCE challenge temporarily (for authorization flow)
   */
  storePKCEChallenge(
    authorizationCode: string,
    challenge: PKCEChallenge,
    expirationMinutes: number = 10
  ): void {
    const expiresAt = new Date(Date.now() + expirationMinutes * 60 * 1000)
    
    this.challenges.set(authorizationCode, {
      challenge,
      expiresAt,
    })

    logger.debug('PKCEService', `Stored PKCE challenge for authorization code`)
  }

  /**
   * Retrieve and remove PKCE challenge
   */
  retrievePKCEChallenge(authorizationCode: string): PKCEChallenge | null {
    const stored = this.challenges.get(authorizationCode)
    
    if (!stored) {
      logger.warn('PKCEService', 'PKCE challenge not found for authorization code')
      return null
    }

    // Check expiration
    if (stored.expiresAt < new Date()) {
      this.challenges.delete(authorizationCode)
      logger.warn('PKCEService', 'PKCE challenge expired for authorization code')
      return null
    }

    // Remove challenge (one-time use)
    this.challenges.delete(authorizationCode)
    
    logger.debug('PKCEService', 'Retrieved PKCE challenge for authorization code')
    return stored.challenge
  }

  /**
   * Validate PKCE parameters from authorization request
   */
  validatePKCERequest(
    codeChallenge?: string,
    codeChallengeMethod?: string,
    isPublicClient: boolean = false
  ): { valid: boolean; error?: string } {
    // PKCE is required for public clients
    if (isPublicClient && !codeChallenge) {
      return {
        valid: false,
        error: 'PKCE code_challenge is required for public clients',
      }
    }

    // If PKCE is provided, validate parameters
    if (codeChallenge) {
      // Validate code challenge method
      if (codeChallengeMethod && !pkceConfig.supportedMethods.includes(codeChallengeMethod as any)) {
        return {
          valid: false,
          error: `Unsupported code_challenge_method: ${codeChallengeMethod}`,
        }
      }

      // Validate code challenge format
      if (!this.isValidCodeChallenge(codeChallenge)) {
        return {
          valid: false,
          error: 'Invalid code_challenge format',
        }
      }
    }

    return { valid: true }
  }

  /**
   * Validate code challenge format
   */
  private isValidCodeChallenge(codeChallenge: string): boolean {
    // Code challenge should be 43-128 characters long
    if (codeChallenge.length < 43 || codeChallenge.length > 128) {
      return false
    }

    // Should only contain URL-safe base64 characters
    const urlSafeBase64Regex = /^[A-Za-z0-9_-]+$/
    return urlSafeBase64Regex.test(codeChallenge)
  }

  /**
   * Validate code verifier format
   */
  isValidCodeVerifier(codeVerifier: string): boolean {
    // Code verifier should be 43-128 characters long
    if (codeVerifier.length < 43 || codeVerifier.length > 128) {
      return false
    }

    // Should only contain unreserved characters
    const unreservedCharsRegex = /^[A-Za-z0-9._~-]+$/
    return unreservedCharsRegex.test(codeVerifier)
  }

  /**
   * Clean up expired PKCE challenges
   */
  cleanupExpiredChallenges(): number {
    const now = new Date()
    let cleanedCount = 0

    for (const [code, stored] of this.challenges.entries()) {
      if (stored.expiresAt < now) {
        this.challenges.delete(code)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      logger.info('PKCEService', `Cleaned up ${cleanedCount} expired PKCE challenges`)
    }

    return cleanedCount
  }

  /**
   * Get PKCE service statistics
   */
  getStats(): {
    activeChallenges: number
    expiredChallenges: number
  } {
    const now = new Date()
    let activeChallenges = 0
    let expiredChallenges = 0

    for (const stored of this.challenges.values()) {
      if (stored.expiresAt > now) {
        activeChallenges++
      } else {
        expiredChallenges++
      }
    }

    return {
      activeChallenges,
      expiredChallenges,
    }
  }

  /**
   * Generate PKCE parameters for client-side use
   */
  generateClientPKCE(): {
    codeVerifier: string
    codeChallenge: string
    codeChallengeMethod: 'S256'
  } {
    const codeVerifier = this.generateCodeVerifier()
    const codeChallenge = this.generateCodeChallenge(codeVerifier, 'S256')

    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256',
    }
  }

  /**
   * Validate complete PKCE flow
   */
  validatePKCEFlow(
    authorizationCode: string,
    codeVerifier: string
  ): { valid: boolean; error?: string } {
    // Retrieve stored challenge
    const storedChallenge = this.retrievePKCEChallenge(authorizationCode)
    
    if (!storedChallenge) {
      return {
        valid: false,
        error: 'PKCE challenge not found or expired',
      }
    }

    // Validate code verifier format
    if (!this.isValidCodeVerifier(codeVerifier)) {
      return {
        valid: false,
        error: 'Invalid code_verifier format',
      }
    }

    // Verify code verifier against challenge
    const isValid = this.verifyCodeVerifier(
      codeVerifier,
      storedChallenge.codeChallenge,
      storedChallenge.codeChallengeMethod
    )

    if (!isValid) {
      return {
        valid: false,
        error: 'PKCE verification failed',
      }
    }

    return { valid: true }
  }
}

export const pkceService = PKCEService.getInstance()
