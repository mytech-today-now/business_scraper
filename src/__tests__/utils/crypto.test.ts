/**
 * Tests for the crypto utility module
 */

import { randomUUID, getRandomValues, generateSecureNonce, generateSecureToken } from '@/utils/crypto'

describe('Crypto Utility', () => {
  describe('randomUUID', () => {
    it('should generate a valid UUID', () => {
      const uuid = randomUUID()
      expect(uuid).toBeDefined()
      expect(typeof uuid).toBe('string')
      expect(uuid.length).toBeGreaterThan(0)
    })

    it('should generate unique UUIDs', () => {
      const uuid1 = randomUUID()
      const uuid2 = randomUUID()
      expect(uuid1).not.toBe(uuid2)
    })
  })

  describe('getRandomValues', () => {
    it('should fill array with random values', () => {
      const array = new Uint8Array(16)
      const result = getRandomValues(array)
      
      expect(result).toBe(array) // Should return the same array
      expect(array.some(val => val !== 0)).toBe(true) // Should have non-zero values
    })

    it('should work with different array sizes', () => {
      const small = new Uint8Array(4)
      const large = new Uint8Array(32)
      
      getRandomValues(small)
      getRandomValues(large)
      
      expect(small.length).toBe(4)
      expect(large.length).toBe(32)
    })
  })

  describe('generateSecureNonce', () => {
    it('should generate a secure nonce', () => {
      const nonce = generateSecureNonce()
      expect(nonce).toBeDefined()
      expect(typeof nonce).toBe('string')
      expect(nonce.length).toBeGreaterThan(0)
    })

    it('should generate unique nonces', () => {
      const nonce1 = generateSecureNonce()
      const nonce2 = generateSecureNonce()
      expect(nonce1).not.toBe(nonce2)
    })
  })

  describe('generateSecureToken', () => {
    it('should generate a secure token with default length', () => {
      const token = generateSecureToken()
      expect(token).toBeDefined()
      expect(typeof token).toBe('string')
      expect(token.length).toBeGreaterThan(0)
    })

    it('should generate a secure token with custom length', () => {
      const token = generateSecureToken(16)
      expect(token).toBeDefined()
      expect(typeof token).toBe('string')
      expect(token.length).toBeGreaterThan(0)
    })

    it('should generate unique tokens', () => {
      const token1 = generateSecureToken()
      const token2 = generateSecureToken()
      expect(token1).not.toBe(token2)
    })
  })
})
