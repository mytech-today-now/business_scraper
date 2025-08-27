/**
 * OAuth 2.0 System Integration Tests
 * Tests the complete OAuth 2.0 implementation
 */

import { describe, it, expect, beforeEach } from '@jest/globals'
import { clientService } from '@/lib/oauth/client-service'
import { tokenService } from '@/lib/oauth/token-service'
import { authorizationService } from '@/lib/oauth/authorization-service'
import { pkceService } from '@/lib/oauth/pkce-service'

describe('OAuth 2.0 System', () => {
  beforeEach(() => {
    // Reset services for each test
    jest.clearAllMocks()
  })

  describe('Client Service', () => {
    it('should validate default clients', () => {
      // Test web client
      const webClient = clientService.getClient('business-scraper-web')
      expect(webClient).toBeTruthy()
      expect(webClient?.type).toBe('confidential')
      expect(webClient?.allowedScopes).toContain('read')

      // Test mobile client
      const mobileClient = clientService.getClient('business-scraper-mobile')
      expect(mobileClient).toBeTruthy()
      expect(mobileClient?.type).toBe('public')

      // Test API client
      const apiClient = clientService.getClient('business-scraper-api')
      expect(apiClient).toBeTruthy()
      expect(apiClient?.allowedGrantTypes).toContain('client_credentials')
    })

    it('should register new client', () => {
      const registrationRequest = {
        clientName: 'Test Client',
        clientType: 'public' as const,
        redirectUris: ['https://test.com/callback'],
        scope: 'openid profile',
      }

      const response = clientService.registerClient(registrationRequest)

      expect(response.clientId).toBeTruthy()
      expect(response.clientName).toBe('Test Client')
      expect(response.clientType).toBe('public')
      expect(response.clientSecret).toBeUndefined() // Public client has no secret
    })

    it('should validate client credentials', () => {
      const webClient = clientService.getClient('business-scraper-web')
      expect(webClient).toBeTruthy()

      const validation = clientService.validateClient('business-scraper-web', webClient!.secret)

      expect(validation.valid).toBe(true)
      expect(validation.client).toBeTruthy()
    })

    it('should reject invalid client credentials', () => {
      const validation = clientService.validateClient('business-scraper-web', 'wrong-secret')

      expect(validation.valid).toBe(false)
      expect(validation.error).toBeTruthy()
    })
  })

  describe('PKCE Service', () => {
    it('should generate valid PKCE challenge', () => {
      const challenge = pkceService.generatePKCEChallenge('S256')

      expect(challenge.codeVerifier).toBeTruthy()
      expect(challenge.codeChallenge).toBeTruthy()
      expect(challenge.codeChallengeMethod).toBe('S256')
      expect(challenge.codeVerifier.length).toBeGreaterThanOrEqual(43)
      expect(challenge.codeVerifier.length).toBeLessThanOrEqual(128)
    })

    it('should verify PKCE code verifier', () => {
      const challenge = pkceService.generatePKCEChallenge('S256')

      const isValid = pkceService.verifyCodeVerifier(
        challenge.codeVerifier,
        challenge.codeChallenge,
        'S256'
      )

      expect(isValid).toBe(true)
    })

    it('should reject invalid PKCE code verifier', () => {
      const challenge = pkceService.generatePKCEChallenge('S256')

      const isValid = pkceService.verifyCodeVerifier(
        'wrong-verifier',
        challenge.codeChallenge,
        'S256'
      )

      expect(isValid).toBe(false)
    })

    it('should validate PKCE request parameters', () => {
      // Generate a valid challenge first
      const challenge = pkceService.generatePKCEChallenge('S256')

      const validation = pkceService.validatePKCERequest(
        challenge.codeChallenge,
        'S256',
        true // is public client
      )

      expect(validation.valid).toBe(true)
    })

    it('should require PKCE for public clients', () => {
      const validation = pkceService.validatePKCERequest(
        undefined, // no challenge
        undefined,
        true // is public client
      )

      expect(validation.valid).toBe(false)
      expect(validation.error).toContain('required for public clients')
    })
  })

  describe('Authorization Service', () => {
    it('should generate authorization code', () => {
      const client = clientService.getClient('business-scraper-web')!
      const user = {
        id: 'test-user',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      const { code, expiresAt } = authorizationService.generateAuthorizationCode(
        client,
        user,
        'https://test.com/callback',
        ['openid', 'profile']
      )

      expect(code).toBeTruthy()
      expect(expiresAt).toBeInstanceOf(Date)
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now())
    })

    it('should validate authorization request', () => {
      const client = clientService.getClient('business-scraper-web')!
      const request = {
        responseType: 'code' as const,
        clientId: client.id,
        redirectUri: client.redirectUris[0],
        scope: 'openid profile',
      }

      const validation = authorizationService.validateAuthorizationRequest(request, client)

      expect(validation.valid).toBe(true)
      expect(validation.scopes).toContain('openid')
      expect(validation.scopes).toContain('profile')
    })

    it('should reject invalid redirect URI', () => {
      const client = clientService.getClient('business-scraper-web')!
      const request = {
        responseType: 'code' as const,
        clientId: client.id,
        redirectUri: 'https://malicious.com/callback',
        scope: 'openid profile',
      }

      const validation = authorizationService.validateAuthorizationRequest(request, client)

      expect(validation.valid).toBe(false)
      expect(validation.error).toBe('invalid_request')
    })
  })

  describe('Token Service', () => {
    it('should generate access token', () => {
      const client = clientService.getClient('business-scraper-web')!
      const user = {
        id: 'test-user',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      const { token, expiresAt } = tokenService.generateAccessToken(client, user, [
        'openid',
        'profile',
        'read',
      ])

      expect(token).toBeTruthy()
      expect(expiresAt).toBeInstanceOf(Date)
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now())
    })

    it('should validate access token', () => {
      const client = clientService.getClient('business-scraper-web')!
      const user = {
        id: 'test-user',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      const { token } = tokenService.generateAccessToken(client, user, [
        'openid',
        'profile',
        'read',
      ])

      const validation = tokenService.validateToken(token)

      expect(validation.valid).toBe(true)
      expect(validation.payload).toBeTruthy()
      expect(validation.payload?.sub).toBe('test-user')
      expect(validation.payload?.client_id).toBe(client.id)
    })

    it('should revoke token', () => {
      const client = clientService.getClient('business-scraper-web')!
      const user = {
        id: 'test-user',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      const { token } = tokenService.generateAccessToken(client, user, [
        'openid',
        'profile',
        'read',
      ])

      // Token should be valid initially
      let validation = tokenService.validateToken(token)
      expect(validation.valid).toBe(true)

      // Revoke token
      const revoked = tokenService.revokeToken(token)
      expect(revoked).toBe(true)

      // Token should be invalid after revocation
      validation = tokenService.validateToken(token)
      expect(validation.valid).toBe(false)
    })

    it('should introspect token', () => {
      const client = clientService.getClient('business-scraper-web')!
      const user = {
        id: 'test-user',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      const { token } = tokenService.generateAccessToken(client, user, [
        'openid',
        'profile',
        'read',
      ])

      const introspection = tokenService.introspectToken(token)

      expect(introspection.active).toBe(true)
      expect(introspection.scope).toBe('openid profile read')
      expect(introspection.clientId).toBe(client.id)
      expect(introspection.tokenType).toBe('Bearer')
    })
  })

  describe('Complete OAuth Flow', () => {
    it('should complete authorization code flow', () => {
      // 1. Get client
      const client = clientService.getClient('business-scraper-web')!

      // 2. Validate authorization request
      const authRequest = {
        responseType: 'code' as const,
        clientId: client.id,
        redirectUri: client.redirectUris[0],
        scope: 'openid profile read',
      }

      const requestValidation = authorizationService.validateAuthorizationRequest(
        authRequest,
        client
      )
      expect(requestValidation.valid).toBe(true)

      // 3. Generate authorization code
      const user = {
        id: 'test-user',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      const { code } = authorizationService.generateAuthorizationCode(
        client,
        user,
        authRequest.redirectUri,
        requestValidation.scopes!
      )

      // 4. Exchange code for tokens
      const codeValidation = authorizationService.validateAndConsumeCode(
        code,
        client.id,
        authRequest.redirectUri
      )

      expect(codeValidation.valid).toBe(true)
      expect(codeValidation.authCode).toBeTruthy()

      // 5. Generate access token
      const { token: accessToken } = tokenService.generateAccessToken(
        client,
        user,
        codeValidation.authCode!.scopes
      )

      // 6. Validate access token
      const tokenValidation = tokenService.validateToken(accessToken)
      expect(tokenValidation.valid).toBe(true)
      expect(tokenValidation.payload?.scope).toBe('openid profile read')
    })

    it('should complete PKCE flow', () => {
      // 1. Generate PKCE challenge
      const pkceChallenge = pkceService.generatePKCEChallenge('S256')

      // 2. Get public client
      const client = clientService.getClient('business-scraper-mobile')!

      // 3. Validate PKCE request
      const pkceValidation = pkceService.validatePKCERequest(
        pkceChallenge.codeChallenge,
        'S256',
        true
      )
      expect(pkceValidation.valid).toBe(true)

      // 4. Generate authorization code with PKCE
      const user = {
        id: 'test-user',
        username: 'testuser',
        email: 'test@example.com',
        roles: ['user'],
        permissions: ['read'],
        isActive: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      const { code } = authorizationService.generateAuthorizationCode(
        client,
        user,
        client.redirectUris[0],
        ['openid', 'profile'],
        pkceChallenge.codeChallenge,
        'S256'
      )

      // 5. Store PKCE challenge
      pkceService.storePKCEChallenge(code, pkceChallenge)

      // 6. Validate PKCE flow
      const pkceFlowValidation = pkceService.validatePKCEFlow(code, pkceChallenge.codeVerifier)
      expect(pkceFlowValidation.valid).toBe(true)
    })
  })
})
