/**
 * Build Verification Tests (BVT) for Edge Runtime Middleware
 * Critical tests that must pass for Edge Runtime deployment
 */

import { NextRequest } from 'next/server'

describe('BVT: Edge Runtime Middleware', () => {
  describe('Critical Functionality', () => {
    it('should import middleware without Node.js dependencies', async () => {
      // This test ensures the middleware can be imported in Edge Runtime
      const middlewareModule = await import('@/middleware')
      expect(middlewareModule.middleware).toBeDefined()
      expect(typeof middlewareModule.middleware).toBe('function')
    })

    it('should process requests without crashing', async () => {
      const { middleware } = await import('@/middleware')
      
      const request = new NextRequest('https://example.com/api/health', {
        method: 'GET',
        headers: {
          'user-agent': 'bvt-test',
          'x-forwarded-for': '127.0.0.1'
        }
      })

      // Should not throw any errors
      await expect(middleware(request)).resolves.toBeDefined()
    })

    it('should apply security headers', async () => {
      const { middleware } = await import('@/middleware')
      
      const request = new NextRequest('https://example.com/test', {
        method: 'GET',
        headers: {
          'user-agent': 'bvt-test',
          'x-forwarded-for': '127.0.0.1'
        }
      })

      const response = await middleware(request)
      
      // Critical security headers must be present
      expect(response.headers.get('X-Frame-Options')).toBe('DENY')
      expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
      expect(response.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin')
    })

    it('should handle rate limiting', async () => {
      const { middleware } = await import('@/middleware')
      
      const request = new NextRequest('https://example.com/api/scrape', {
        method: 'GET',
        headers: {
          'user-agent': 'bvt-test',
          'x-forwarded-for': '127.0.0.1'
        }
      })

      const response = await middleware(request)
      expect(response).toBeDefined()
      expect(response.status).not.toBe(500) // Should not crash
    })
  })

  describe('Security Functions BVT', () => {
    it('should generate secure tokens', async () => {
      const { generateSecureToken } = await import('@/lib/security')
      
      const token = generateSecureToken(32)
      expect(token).toBeDefined()
      expect(typeof token).toBe('string')
      expect(token.length).toBe(64) // 32 bytes = 64 hex chars
    })

    it('should hash and verify passwords', async () => {
      const { hashPassword, verifyPassword } = await import('@/lib/security')
      
      const password = 'bvt-test-password'
      const { hash, salt } = await hashPassword(password)
      
      expect(hash).toBeDefined()
      expect(salt).toBeDefined()
      
      const isValid = await verifyPassword(password, hash, salt)
      expect(isValid).toBe(true)
    })

    it('should encrypt and decrypt data', async () => {
      const { encryptData, decryptData } = await import('@/lib/security')
      
      const data = 'bvt-test-data'
      const key = 'bvt-test-key'
      
      const encrypted = await encryptData(data, key)
      expect(encrypted.encrypted).toBeDefined()
      expect(encrypted.iv).toBeDefined()
      
      const decrypted = await decryptData(encrypted.encrypted, key, encrypted.iv)
      expect(decrypted).toBe(data)
    })
  })

  describe('CSRF Protection BVT', () => {
    it('should generate and validate CSRF tokens', async () => {
      const { csrfProtectionService } = await import('@/lib/csrfProtection')
      
      const sessionId = 'bvt-session'
      const tokenInfo = csrfProtectionService.generateCSRFToken(sessionId)
      
      expect(tokenInfo.token).toBeDefined()
      expect(tokenInfo.expiresAt).toBeGreaterThan(Date.now())
      
      const request = new NextRequest('https://example.com/test')
      const validation = csrfProtectionService.validateCSRFToken(sessionId, tokenInfo.token, request)
      
      expect(validation.isValid).toBe(true)
    })
  })

  describe('Rate Limiting BVT', () => {
    it('should perform rate limiting checks', async () => {
      const { advancedRateLimitService } = await import('@/lib/advancedRateLimit')
      
      const result = advancedRateLimitService.checkRateLimit('bvt-test', {
        windowMs: 60000,
        maxRequests: 100
      })
      
      expect(result.allowed).toBe(true)
      expect(typeof result.remaining).toBe('number')
      expect(typeof result.resetTime).toBe('number')
    })
  })

  describe('Cleanup Operations BVT', () => {
    it('should handle cleanup operations', async () => {
      const { edgeRuntimeCleanupManager } = await import('@/lib/edgeRuntimeCleanup')
      
      expect(edgeRuntimeCleanupManager).toBeDefined()
      
      const status = edgeRuntimeCleanupManager.getCleanupStatus()
      expect(Array.isArray(status)).toBe(true)
      
      // Should not throw errors
      await expect(edgeRuntimeCleanupManager.performScheduledCleanup()).resolves.not.toThrow()
    })
  })

  describe('Web Crypto API BVT', () => {
    it('should have access to Web Crypto API', () => {
      expect(globalThis.crypto).toBeDefined()
      expect(globalThis.crypto.getRandomValues).toBeDefined()
      expect(globalThis.crypto.subtle).toBeDefined()
    })

    it('should generate random values', () => {
      const array = new Uint8Array(32)
      globalThis.crypto.getRandomValues(array)
      
      // Verify randomness (sum should not be zero)
      const sum = array.reduce((acc, val) => acc + val, 0)
      expect(sum).toBeGreaterThan(0)
    })

    it('should support PBKDF2 key derivation', async () => {
      const encoder = new TextEncoder()
      const password = encoder.encode('test-password')
      const salt = encoder.encode('test-salt')
      
      const keyMaterial = await globalThis.crypto.subtle.importKey(
        'raw',
        password,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
      )
      
      const derivedKey = await globalThis.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 1000,
          hash: 'SHA-256'
        },
        keyMaterial,
        256
      )
      
      expect(derivedKey).toBeDefined()
      expect(derivedKey.byteLength).toBe(32) // 256 bits = 32 bytes
    })

    it('should support AES-GCM encryption', async () => {
      const encoder = new TextEncoder()
      const decoder = new TextDecoder()
      const data = encoder.encode('test-data')
      
      // Generate key
      const key = await globalThis.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      )
      
      // Generate IV
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
      
      // Encrypt
      const encrypted = await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        data
      )
      
      // Decrypt
      const decrypted = await globalThis.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encrypted
      )
      
      expect(decoder.decode(decrypted)).toBe('test-data')
    })
  })
})
