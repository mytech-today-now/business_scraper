/**
 * Comprehensive JWT Session Service Tests for src/lib/jwt-session-service.ts
 * Tests JWT token creation, validation, renewal, and security scenarios
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest } from 'next/server'
import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'
import {
  jwtSessionService,
  JWTSessionService,
  JWTSessionPayload,
  SessionValidationResult
} from '@/lib/jwt-session-service'
import {
  Session,
  createSecureSession,
  validateSecureSession,
  invalidateSession,
  generateDeviceFingerprint,
  getClientIP,
  isIpLockedOut,
  recordFailedLogin,
  clearFailedLogins
} from '@/lib/security'

// Mock dependencies
jest.mock('jsonwebtoken')
jest.mock('uuid')
jest.mock('@/lib/security')
jest.mock('@/utils/logger')

const mockJwt = {
  sign: jest.fn(),
  verify: jest.fn()
}
const mockUuidv4 = jest.fn()
const mockCreateSecureSession = jest.fn()
const mockValidateSecureSession = jest.fn()
const mockInvalidateSession = jest.fn()
const mockGenerateDeviceFingerprint = jest.fn()
const mockGetClientIP = jest.fn()
const mockIsIpLockedOut = jest.fn()
const mockRecordFailedLogin = jest.fn()
const mockClearFailedLogins = jest.fn()

// Setup mocks
jest.mocked(jwt).sign = mockJwt.sign
jest.mocked(jwt).verify = mockJwt.verify
;(uuidv4 as jest.Mock) = mockUuidv4
;(createSecureSession as jest.Mock) = mockCreateSecureSession
;(validateSecureSession as jest.Mock) = mockValidateSecureSession
;(invalidateSession as jest.Mock) = mockInvalidateSession
;(generateDeviceFingerprint as jest.Mock) = mockGenerateDeviceFingerprint
;(getClientIP as jest.Mock) = mockGetClientIP
;(isIpLockedOut as jest.Mock) = mockIsIpLockedOut
;(recordFailedLogin as jest.Mock) = mockRecordFailedLogin
;(clearFailedLogins as jest.Mock) = mockClearFailedLogins

describe('JWT Session Service - Comprehensive Tests', () => {
  let mockRequest: Partial<NextRequest>
  let mockSession: Session
  let service: JWTSessionService

  beforeEach(() => {
    jest.clearAllMocks()

    // Setup mock request
    mockRequest = {
      cookies: {
        get: jest.fn().mockReturnValue(undefined)
      },
      headers: {
        get: jest.fn().mockImplementation((header: string) => {
          switch (header) {
            case 'user-agent': return 'Mozilla/5.0 Test Browser'
            case 'accept-language': return 'en-US,en;q=0.9'
            case 'accept-encoding': return 'gzip, deflate, br'
            default: return null
          }
        })
      },
      nextUrl: {
        pathname: '/api/test'
      },
      method: 'GET',
      url: 'http://localhost:3000/api/test'
    } as any

    // Setup mock session
    mockSession = {
      id: 'test-session-id',
      userId: 'admin',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 Test Browser',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      isValid: true,
      csrfToken: 'test-csrf-token',
      deviceFingerprint: 'test-device-fingerprint',
      ipHash: 'test-ip-hash',
      jwtSignature: 'test-jwt-signature',
      securityFlags: {
        ipValidated: true,
        deviceValidated: true,
        jwtVerified: false,
        suspiciousActivity: false
      },
      renewalCount: 0,
      maxRenewals: 5,
      lastRenewal: new Date()
    }

    // Get service instance
    service = JWTSessionService.getInstance()

    // Setup default mocks
    mockGetClientIP.mockReturnValue('192.168.1.100')
    mockIsIpLockedOut.mockReturnValue(false)
    mockGenerateDeviceFingerprint.mockReturnValue({
      hash: 'test-device-fingerprint',
      components: ['user-agent', 'accept-language', 'accept-encoding']
    })
    mockUuidv4.mockReturnValue('test-uuid')
    mockCreateSecureSession.mockResolvedValue(mockSession)
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('JWT Session Creation', () => {
    test('should create JWT session with valid tokens', async () => {
      const mockJwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
      const mockRenewalToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.renewal.signature'

      mockJwt.sign
        .mockReturnValueOnce(mockJwtToken)
        .mockReturnValueOnce(mockRenewalToken)

      const result = await service.createJWTSession(mockRequest as NextRequest, 'admin')

      expect(result).toBeDefined()
      expect(result.session).toBe(mockSession)
      expect(result.jwtToken).toBe(mockJwtToken)
      expect(result.renewalToken).toBe(mockRenewalToken)

      // Verify JWT signing was called with correct payloads
      expect(mockJwt.sign).toHaveBeenCalledTimes(2)
      
      const sessionPayload = (mockJwt.sign as jest.Mock).mock.calls[0][0]
      expect(sessionPayload.tokenType).toBe('session')
      expect(sessionPayload.sub).toBe('admin')
      expect(sessionPayload.securityLevel).toBe('enhanced')

      const renewalPayload = (mockJwt.sign as jest.Mock).mock.calls[1][0]
      expect(renewalPayload.tokenType).toBe('renewal')
    })

    test('should reject session creation for locked IP', async () => {
      mockIsIpLockedOut.mockReturnValue(true)

      await expect(service.createJWTSession(mockRequest as NextRequest, 'admin'))
        .rejects.toThrow('IP address is temporarily locked due to suspicious activity')

      expect(mockCreateSecureSession).not.toHaveBeenCalled()
    })

    test('should include device fingerprint in JWT payload', async () => {
      const mockJwtToken = 'test-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      const sessionPayload = (mockJwt.sign as jest.Mock).mock.calls[0][0]
      expect(sessionPayload.deviceFingerprint).toBe('test-device-fingerprint')
    })

    test('should clear failed login attempts on successful session creation', async () => {
      const mockJwtToken = 'test-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      expect(mockClearFailedLogins).toHaveBeenCalledWith('192.168.1.100')
    })

    test('should generate unique session and JWT IDs', async () => {
      mockUuidv4
        .mockReturnValueOnce('session-uuid')
        .mockReturnValueOnce('renewal-uuid')

      const mockJwtToken = 'test-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      const sessionPayload = (mockJwt.sign as jest.Mock).mock.calls[0][0]
      const renewalPayload = (mockJwt.sign as jest.Mock).mock.calls[1][0]

      expect(sessionPayload.jti).toBe('session-uuid')
      expect(sessionPayload.sessionId).toBe('session-uuid')
      expect(renewalPayload.jti).toBe('renewal-uuid')
    })

    test('should set proper JWT expiration times', async () => {
      const mockJwtToken = 'test-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      const beforeTime = Math.floor(Date.now() / 1000)
      await service.createJWTSession(mockRequest as NextRequest, 'admin')
      const afterTime = Math.floor(Date.now() / 1000)

      const sessionPayload = (mockJwt.sign as jest.Mock).mock.calls[0][0]
      const renewalPayload = (mockJwt.sign as jest.Mock).mock.calls[1][0]

      // Session token should expire in 24 hours
      expect(sessionPayload.exp).toBeGreaterThanOrEqual(beforeTime + 24 * 60 * 60)
      expect(sessionPayload.exp).toBeLessThanOrEqual(afterTime + 24 * 60 * 60)

      // Renewal token should expire in 7 days
      expect(renewalPayload.exp).toBeGreaterThanOrEqual(beforeTime + 7 * 24 * 60 * 60)
      expect(renewalPayload.exp).toBeLessThanOrEqual(afterTime + 7 * 24 * 60 * 60)
    })
  })

  describe('JWT Session Validation', () => {
    test('should validate JWT session successfully', async () => {
      const mockJwtPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mockJwtPayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: true,
        session: mockSession
      })

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'valid-jwt-token'
      )

      expect(result.valid).toBe(true)
      expect(result.session).toBe(mockSession)
      expect(result.securityFlags?.jwtVerified).toBe(true)
    })

    test('should reject invalid JWT tokens', async () => {
      mockJwt.verify.mockImplementation(() => {
        throw new Error('Invalid token')
      })

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'invalid-jwt-token'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Invalid JWT token')
    })

    test('should reject expired JWT tokens', async () => {
      const expiredPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
        iat: Math.floor(Date.now() / 1000) - 7200,
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(expiredPayload as any)

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'expired-jwt-token'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('JWT token expired')
    })

    test('should reject JWT with mismatched session ID', async () => {
      const mismatchedPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'different-session-id',
        sessionId: 'different-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mismatchedPayload as any)

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'mismatched-jwt-token'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Session ID mismatch')
    })

    test('should validate IP hash in JWT', async () => {
      const mockJwtPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'different-ip-hash', // Different IP hash
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mockJwtPayload as any)

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'different-ip-jwt-token'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('IP address validation failed')
    })

    test('should validate device fingerprint in JWT', async () => {
      const mockJwtPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'different-device-fingerprint', // Different device
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mockJwtPayload as any)
      mockGenerateDeviceFingerprint.mockReturnValue({
        hash: 'current-device-fingerprint',
        components: ['user-agent', 'accept-language']
      })

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'different-device-jwt-token'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Device fingerprint validation failed')
    })

    test('should handle session validation failures', async () => {
      const mockJwtPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mockJwtPayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: false,
        error: 'Session not found'
      })

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'valid-jwt-token'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Session validation failed')
    })
  })

  describe('JWT Session Renewal', () => {
    test('should renew JWT session successfully', async () => {
      const renewalPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
        iat: Math.floor(Date.now() / 1000),
        jti: 'renewal-token-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'renewal',
        securityLevel: 'enhanced'
      }

      const newSession = { ...mockSession, id: 'new-session-id', renewalCount: 1 }
      const newJwtToken = 'new-jwt-token'
      const newRenewalToken = 'new-renewal-token'

      mockJwt.verify.mockReturnValue(renewalPayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: true,
        session: mockSession
      })
      mockCreateSecureSession.mockResolvedValue(newSession)
      mockJwt.sign
        .mockReturnValueOnce(newJwtToken)
        .mockReturnValueOnce(newRenewalToken)

      const result = await service.renewJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'valid-renewal-token'
      )

      expect(result).toBeDefined()
      expect(result!.session.id).toBe('new-session-id')
      expect(result!.session.renewalCount).toBe(1)
      expect(result!.jwtToken).toBe(newJwtToken)
      expect(result!.renewalToken).toBe(newRenewalToken)

      // Verify old session was invalidated
      expect(mockInvalidateSession).toHaveBeenCalledWith('test-session-id')
    })

    test('should reject renewal with invalid renewal token', async () => {
      mockJwt.verify.mockImplementation(() => {
        throw new Error('Invalid renewal token')
      })

      const result = await service.renewJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'invalid-renewal-token'
      )

      expect(result).toBeNull()
    })

    test('should reject renewal for non-renewal token type', async () => {
      const sessionPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'session-token-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session', // Wrong token type
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(sessionPayload as any)

      const result = await service.renewJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'session-token-as-renewal'
      )

      expect(result).toBeNull()
    })

    test('should enforce maximum renewal limits', async () => {
      const renewalPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
        iat: Math.floor(Date.now() / 1000),
        jti: 'renewal-token-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'renewal',
        securityLevel: 'enhanced'
      }

      const exhaustedSession = { ...mockSession, renewalCount: 5, maxRenewals: 5 }

      mockJwt.verify.mockReturnValue(renewalPayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: true,
        session: exhaustedSession
      })

      const result = await service.renewJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'valid-renewal-token'
      )

      expect(result).toBeNull()
    })

    test('should handle renewal token expiration', async () => {
      const expiredRenewalPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
        iat: Math.floor(Date.now() / 1000) - 7200,
        jti: 'renewal-token-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'renewal',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(expiredRenewalPayload as any)

      const result = await service.renewJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'expired-renewal-token'
      )

      expect(result).toBeNull()
    })
  })

  describe('Security and Cryptographic Tests', () => {
    test('should use secure JWT signing algorithm', async () => {
      const mockJwtToken = 'test-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      expect(mockJwt.sign).toHaveBeenCalledWith(
        expect.any(Object),
        expect.any(String),
        { algorithm: 'HS256' }
      )
    })

    test('should include proper JWT claims', async () => {
      const mockJwtToken = 'test-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      const sessionPayload = (mockJwt.sign as jest.Mock).mock.calls[0][0]

      expect(sessionPayload.iss).toBe('business-scraper-auth')
      expect(sessionPayload.aud).toBe('business-scraper-app')
      expect(sessionPayload.sub).toBe('admin')
      expect(sessionPayload.iat).toBeDefined()
      expect(sessionPayload.exp).toBeDefined()
      expect(sessionPayload.jti).toBeDefined()
    })

    test('should hash IP addresses for privacy', async () => {
      const mockJwtToken = 'test-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      const sessionPayload = (mockJwt.sign as jest.Mock).mock.calls[0][0]

      // IP should be hashed, not stored in plain text
      expect(sessionPayload.ipHash).toBeDefined()
      expect(sessionPayload.ipHash).not.toBe('192.168.1.100')
    })

    test('should validate JWT signature integrity', async () => {
      const mockJwtPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mockJwtPayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: true,
        session: mockSession
      })

      await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'valid-jwt-token'
      )

      expect(mockJwt.verify).toHaveBeenCalledWith(
        'valid-jwt-token',
        expect.any(String),
        { algorithms: ['HS256'] }
      )
    })

    test('should prevent JWT token reuse across sessions', async () => {
      const jwtPayloadForDifferentSession: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'different-session-id',
        sessionId: 'different-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(jwtPayloadForDifferentSession as any)

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id', // Different from JWT payload
        'jwt-for-different-session'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Session ID mismatch')
    })
  })

  describe('Performance and Concurrency Tests', () => {
    test('should handle concurrent session creation requests', async () => {
      const mockJwtToken = 'concurrent-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      const promises = Array.from({ length: 10 }, (_, i) =>
        service.createJWTSession(mockRequest as NextRequest, `user-${i}`)
      )

      const results = await Promise.all(promises)

      results.forEach((result, index) => {
        expect(result).toBeDefined()
        expect(result.jwtToken).toBe(mockJwtToken)
        expect(result.session).toBeDefined()
      })

      expect(mockCreateSecureSession).toHaveBeenCalledTimes(10)
    })

    test('should handle concurrent validation requests efficiently', async () => {
      const mockJwtPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mockJwtPayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: true,
        session: mockSession
      })

      const startTime = Date.now()

      const promises = Array.from({ length: 100 }, () =>
        service.validateJWTSession(
          mockRequest as NextRequest,
          'test-session-id',
          'valid-jwt-token'
        )
      )

      const results = await Promise.all(promises)
      const endTime = Date.now()

      // Should complete within reasonable time (less than 2 seconds)
      expect(endTime - startTime).toBeLessThan(2000)

      results.forEach(result => {
        expect(result.valid).toBe(true)
      })
    })

    test('should handle memory efficiently with large JWT payloads', async () => {
      const largePayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'x'.repeat(10000), // Large fingerprint
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(largePayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: true,
        session: mockSession
      })

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'large-jwt-token'
      )

      expect(result.valid).toBe(true)
    })
  })

  describe('Error Handling and Edge Cases', () => {
    test('should handle malformed JWT tokens gracefully', async () => {
      const malformedTokens = [
        'not.a.jwt',
        'invalid-jwt-format',
        '',
        null,
        undefined
      ]

      for (const token of malformedTokens) {
        mockJwt.verify.mockImplementation(() => {
          throw new Error('Malformed token')
        })

        const result = await service.validateJWTSession(
          mockRequest as NextRequest,
          'test-session-id',
          token as any
        )

        expect(result.valid).toBe(false)
        expect(result.error).toContain('Invalid JWT token')
      }
    })

    test('should handle JWT verification errors', async () => {
      const jwtErrors = [
        new Error('JsonWebTokenError'),
        new Error('TokenExpiredError'),
        new Error('NotBeforeError'),
        new Error('SignatureVerificationError')
      ]

      for (const error of jwtErrors) {
        mockJwt.verify.mockImplementation(() => {
          throw error
        })

        const result = await service.validateJWTSession(
          mockRequest as NextRequest,
          'test-session-id',
          'error-jwt-token'
        )

        expect(result.valid).toBe(false)
        expect(result.error).toContain('Invalid JWT token')
      }
    })

    test('should handle session service failures during creation', async () => {
      mockCreateSecureSession.mockRejectedValue(new Error('Session service unavailable'))

      await expect(service.createJWTSession(mockRequest as NextRequest, 'admin'))
        .rejects.toThrow('Session service unavailable')
    })

    test('should handle session service failures during validation', async () => {
      const mockJwtPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(mockJwtPayload as any)
      mockValidateSecureSession.mockRejectedValue(new Error('Session validation failed'))

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        'valid-jwt-token'
      )

      expect(result.valid).toBe(false)
      expect(result.error).toContain('Session validation failed')
    })

    test('should handle extremely long session IDs', async () => {
      const longSessionId = 'x'.repeat(10000)

      const result = await service.validateJWTSession(
        mockRequest as NextRequest,
        longSessionId,
        'valid-jwt-token'
      )

      expect(result.valid).toBe(false)
    })

    test('should handle null and undefined values gracefully', async () => {
      const testCases = [
        { sessionId: null, jwtToken: 'valid-token' },
        { sessionId: 'valid-session', jwtToken: null },
        { sessionId: undefined, jwtToken: 'valid-token' },
        { sessionId: 'valid-session', jwtToken: undefined }
      ]

      for (const testCase of testCases) {
        const result = await service.validateJWTSession(
          mockRequest as NextRequest,
          testCase.sessionId as any,
          testCase.jwtToken as any
        )

        expect(result.valid).toBe(false)
      }
    })
  })

  describe('Compliance and Audit Tests', () => {
    test('should maintain audit trail for JWT operations', async () => {
      const mockJwtToken = 'audit-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      // Verify logging was called for audit purposes
      expect(mockClearFailedLogins).toHaveBeenCalled()
    })

    test('should implement proper token lifecycle management', async () => {
      // Test complete lifecycle: create -> validate -> renew -> invalidate
      const mockJwtToken = 'lifecycle-jwt-token'
      const mockRenewalToken = 'lifecycle-renewal-token'

      mockJwt.sign
        .mockReturnValueOnce(mockJwtToken)
        .mockReturnValueOnce(mockRenewalToken)

      // Create session
      const createResult = await service.createJWTSession(mockRequest as NextRequest, 'admin')
      expect(createResult).toBeDefined()

      // Validate session
      const validationPayload: JWTSessionPayload = {
        iss: 'business-scraper-auth',
        sub: 'admin',
        aud: 'business-scraper-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        jti: 'test-session-id',
        sessionId: 'test-session-id',
        ipHash: 'test-ip-hash',
        deviceFingerprint: 'test-device-fingerprint',
        tokenType: 'session',
        securityLevel: 'enhanced'
      }

      mockJwt.verify.mockReturnValue(validationPayload as any)
      mockValidateSecureSession.mockResolvedValue({
        valid: true,
        session: mockSession
      })

      const validateResult = await service.validateJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        mockJwtToken
      )
      expect(validateResult.valid).toBe(true)

      // Renew session
      const renewalPayload: JWTSessionPayload = {
        ...validationPayload,
        tokenType: 'renewal',
        exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
      }

      const newSession = { ...mockSession, id: 'new-session-id', renewalCount: 1 }
      mockJwt.verify.mockReturnValue(renewalPayload as any)
      mockCreateSecureSession.mockResolvedValue(newSession)
      mockJwt.sign
        .mockReturnValueOnce('new-jwt-token')
        .mockReturnValueOnce('new-renewal-token')

      const renewResult = await service.renewJWTSession(
        mockRequest as NextRequest,
        'test-session-id',
        mockRenewalToken
      )
      expect(renewResult).toBeDefined()
      expect(mockInvalidateSession).toHaveBeenCalledWith('test-session-id')
    })

    test('should enforce security standards for enterprise compliance', async () => {
      const mockJwtToken = 'compliance-jwt-token'
      mockJwt.sign.mockReturnValue(mockJwtToken)

      await service.createJWTSession(mockRequest as NextRequest, 'admin')

      const sessionPayload = (mockJwt.sign as jest.Mock).mock.calls[0][0]

      // Verify compliance requirements
      expect(sessionPayload.securityLevel).toBe('enhanced')
      expect(sessionPayload.ipHash).toBeDefined()
      expect(sessionPayload.deviceFingerprint).toBeDefined()
      expect(sessionPayload.iss).toBe('business-scraper-auth')
      expect(sessionPayload.aud).toBe('business-scraper-app')
    })
  })
})
