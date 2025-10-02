/**
 * Basic CSRF Protection Test
 * Simple test to verify CSRF functionality works
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals'
import { NextRequest } from 'next/server'

// Setup Web Crypto API mock for test environment
const mockCrypto = {
  getRandomValues: jest.fn().mockImplementation((array: Uint8Array) => {
    // Fill with predictable values for testing
    for (let i = 0; i < array.length; i++) {
      array[i] = (i % 256)
    }
    return array
  }),
  subtle: {
    importKey: jest.fn(),
    deriveBits: jest.fn(),
    digest: jest.fn()
  }
}

// Mock globalThis.crypto
Object.defineProperty(globalThis, 'crypto', {
  value: mockCrypto,
  writable: true
})

// Mock the dependencies before importing
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

// Now import the CSRF service
import { csrfProtectionService } from '@/lib/csrfProtection'

describe('Basic CSRF Protection Test', () => {
  const validSessionId = 'test-session-123'

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should generate a CSRF token', () => {
    // First test that the crypto mock is working
    const testArray = new Uint8Array(4)
    console.log('Before calling getRandomValues:', testArray)
    console.log('mockCrypto.getRandomValues:', mockCrypto.getRandomValues)

    const result = mockCrypto.getRandomValues(testArray)
    console.log('After calling getRandomValues:', testArray)
    console.log('Result:', result)

    // Check if globalThis.crypto is using our mock
    console.log('globalThis.crypto:', globalThis.crypto)
    console.log('globalThis.crypto === mockCrypto:', globalThis.crypto === mockCrypto)

    // Test the actual crypto API
    const testArray2 = new Uint8Array(4)
    globalThis.crypto.getRandomValues(testArray2)
    console.log('globalThis.crypto result:', testArray2)

    expect(testArray[0]).toBe(0)
    expect(testArray[1]).toBe(1)

    // Now test token generation
    let tokenInfo
    try {
      tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
    } catch (error) {
      console.error('Error generating CSRF token:', error)
      throw error
    }

    expect(tokenInfo).toBeDefined()
    expect(tokenInfo.token).toBeDefined()
    expect(typeof tokenInfo.token).toBe('string')
    expect(tokenInfo.expiresAt).toBeGreaterThan(Date.now())
    expect(tokenInfo.issuedAt).toBeLessThanOrEqual(Date.now())
  })

  it('should validate a correct CSRF token', () => {
    const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
    
    const request = new NextRequest('http://localhost:3000/api/test', {
      method: 'POST',
      headers: {
        'origin': 'http://localhost:3000',
        'content-type': 'application/json'
      }
    })

    const result = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, request)
    
    expect(result.isValid).toBe(true)
    expect(result.originValidated).toBe(true)
  })

  it('should reject invalid CSRF tokens', () => {
    csrfProtectionService.generateCSRFToken(validSessionId)
    
    const request = new NextRequest('http://localhost:3000/api/test', {
      method: 'POST',
      headers: {
        'origin': 'http://localhost:3000',
        'content-type': 'application/json'
      }
    })

    const result = csrfProtectionService.validateCSRFToken(validSessionId, 'invalid-token', request)
    
    expect(result.isValid).toBe(false)
    expect(result.securityViolation).toBe(true)
  })

  it('should reject requests from invalid origins', () => {
    const tokenInfo = csrfProtectionService.generateCSRFToken(validSessionId)
    
    const request = new NextRequest('http://localhost:3000/api/test', {
      method: 'POST',
      headers: {
        'origin': 'http://malicious-site.com',
        'content-type': 'application/json'
      }
    })

    const result = csrfProtectionService.validateCSRFToken(validSessionId, tokenInfo.token, request)
    
    expect(result.isValid).toBe(false)
    expect(result.securityViolation).toBe(true)
    expect(result.originValidated).toBe(false)
  })

  it('should handle token rotation', () => {
    const originalToken = csrfProtectionService.generateCSRFToken(validSessionId)
    const newToken = csrfProtectionService.rotateTokenOnAuthentication(validSessionId)
    
    expect(newToken.token).not.toBe(originalToken.token)
    expect(newToken.issuedAt).toBeGreaterThan(originalToken.issuedAt)
  })

  it('should clean up expired tokens', () => {
    // Add some tokens
    csrfProtectionService.generateCSRFToken('session-1')
    csrfProtectionService.generateCSRFToken('session-2')
    
    const initialCount = csrfProtectionService.getTokenCount()
    expect(initialCount).toBeGreaterThan(0)
    
    // Cleanup should not remove valid tokens
    csrfProtectionService.cleanupExpiredTokens()
    
    const afterCleanupCount = csrfProtectionService.getTokenCount()
    expect(afterCleanupCount).toBe(initialCount)
  })
})
