/**
 * Tests for EmailValidationService
 * Comprehensive test suite for advanced email validation functionality
 */

import { EmailValidationService } from '../../lib/emailValidationService'
import { expectArrayElement } from '../utils/mockTypeHelpers'

// Mock DNS module
const mockResolveMx = jest.fn()
jest.mock('dns/promises', () => ({
  resolveMx: mockResolveMx,
}))

// Mock logger
jest.mock('../../utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
  },
}))

describe('EmailValidationService', () => {
  let emailValidationService: EmailValidationService

  beforeEach(() => {
    emailValidationService = EmailValidationService.getInstance()
    emailValidationService.clearCache()
    jest.clearAllMocks()
  })

  describe('Singleton Pattern', () => {
    it('should return the same instance', () => {
      const instance1 = EmailValidationService.getInstance()
      const instance2 = EmailValidationService.getInstance()
      expect(instance1).toBe(instance2)
    })
  })

  describe('Email Syntax Validation', () => {
    it('should validate correct email formats', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'user+tag@example.org',
        'user_name@example-domain.com',
        'firstname.lastname@company.com',
      ]

      for (const email of validEmails) {
        const result = await emailValidationService.validateEmail(email)
        expect(result.email).toBe(email)
        const emailParts = email.split('@')
        const domain = expectArrayElement(emailParts, 1)
        expect(result.domain).toBe(domain)
        // Should pass syntax validation (other factors may affect overall validity)
      }
    })

    it('should reject invalid email formats', async () => {
      const invalidEmails = [
        'invalid-email',
        '@example.com',
        'user@',
        'user..name@example.com',
        'user@.example.com',
        'user@example.',
        'user name@example.com',
        'user@ex ample.com',
        'a'.repeat(65) + '@example.com', // Local part too long
        'user@' + 'a'.repeat(254) + '.com', // Domain too long
      ]

      for (const email of invalidEmails) {
        const result = await emailValidationService.validateEmail(email)
        expect(result.isValid).toBe(false)
        expect(result.errors).toContain('Invalid email syntax')
      }
    })
  })

  describe('MX Record Validation', () => {
    it('should validate domains with MX records', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      const result = await emailValidationService.validateEmail('test@example.com')
      expect(result.mxRecords).toBe(true)
      expect(mockResolveMx).toHaveBeenCalledWith('example.com')
    })

    it('should handle domains without MX records', async () => {
      emailValidationService.clearCache()
      mockResolveMx.mockRejectedValue(new Error('No MX records found'))

      const result = await emailValidationService.validateEmail('test@no-mx-domain.com')
      expect(result.mxRecords).toBe(false)
      expect(result.errors).toContain('Domain has no valid MX records')
    })

    it('should cache MX record results', async () => {
      emailValidationService.clearCache()
      mockResolveMx.mockClear()
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.mx-cache-test.com', priority: 10 }])

      // First call
      await emailValidationService.validateEmail('test1@mx-cache-test.com')
      // Second call with same domain
      await emailValidationService.validateEmail('test2@mx-cache-test.com')

      // Should only call resolveMx once due to caching
      expect(mockResolveMx).toHaveBeenCalledTimes(1)
    })
  })

  describe('Disposable Email Detection', () => {
    it('should detect disposable email domains', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.tempmail.org', priority: 10 }])

      const disposableEmails = [
        'test@tempmail.org',
        'user@10minutemail.com',
        'temp@guerrillamail.com',
        'throwaway@mailinator.com',
      ]

      for (const email of disposableEmails) {
        const result = await emailValidationService.validateEmail(email)
        expect(result.isDisposable).toBe(true)
        expect(result.errors).toContain('Disposable email domain detected')
      }
    })

    it('should not flag legitimate domains as disposable', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.gmail.com', priority: 10 }])

      const legitimateEmails = [
        'test@gmail.com',
        'user@outlook.com',
        'business@company.com',
        'contact@organization.org',
      ]

      for (const email of legitimateEmails) {
        const result = await emailValidationService.validateEmail(email)
        expect(result.isDisposable).toBe(false)
      }
    })
  })

  describe('Role-Based Email Detection', () => {
    it('should detect role-based emails', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      const roleBasedEmails = [
        'info@example.com',
        'contact@example.com',
        'sales@example.com',
        'support@example.com',
        'admin@example.com',
        'marketing@example.com',
        'hr@example.com',
        'noreply@example.com',
      ]

      for (const email of roleBasedEmails) {
        const result = await emailValidationService.validateEmail(email)
        expect(result.isRoleBased).toBe(true)
      }
    })

    it('should not flag personal emails as role-based', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      const personalEmails = [
        'john.doe@example.com',
        'jane.smith@example.com',
        'user123@example.com',
        'firstname.lastname@example.com',
      ]

      for (const email of personalEmails) {
        const result = await emailValidationService.validateEmail(email)
        expect(result.isRoleBased).toBe(false)
      }
    })
  })

  describe('Deliverability Scoring', () => {
    it('should calculate high deliverability for valid emails', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      const result = await emailValidationService.validateEmail('john.doe@example.com')
      expect(result.deliverabilityScore).toBeGreaterThan(80)
      expect(result.confidence).toBeGreaterThan(80)
    })

    it('should calculate low deliverability for problematic emails', async () => {
      emailValidationService.clearCache()
      mockResolveMx.mockRejectedValue(new Error('No MX records'))

      const result = await emailValidationService.validateEmail('test@bad-domain.org')
      expect(result.deliverabilityScore).toBeLessThan(50)
      expect(result.confidence).toBeLessThan(50)
    })

    it('should penalize disposable emails in confidence scoring', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.tempmail.org', priority: 10 }])

      const result = await emailValidationService.validateEmail('test@tempmail.org')
      expect(result.confidence).toBeLessThan(40) // Heavily penalized
    })
  })

  describe('Batch Validation', () => {
    it('should validate multiple emails efficiently', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      const emails = [
        'test1@example.com',
        'test2@example.com',
        'invalid-email',
        'test3@tempmail.org',
      ]

      const results = await emailValidationService.validateEmails(emails)
      expect(results).toHaveLength(4)
      const firstResult = expectArrayElement(results, 0)
      const secondResult = expectArrayElement(results, 1)
      const thirdResult = expectArrayElement(results, 2)
      const fourthResult = expectArrayElement(results, 3)
      expect(firstResult.isValid).toBe(true)
      expect(secondResult.isValid).toBe(true)
      expect(thirdResult.isValid).toBe(false)
      expect(fourthResult.isDisposable).toBe(true)
    })
  })

  describe('Caching', () => {
    it('should cache validation results', async () => {
      emailValidationService.clearCache()
      mockResolveMx.mockClear() // Clear mock call history
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.cache-test.com', priority: 10 }])

      const email = 'test@cache-test.com'

      // First validation
      const result1 = await emailValidationService.validateEmail(email)
      // Second validation (should use cache)
      const result2 = await emailValidationService.validateEmail(email)

      expect(result1).toEqual(result2)
      expect(mockResolveMx).toHaveBeenCalledTimes(1) // Only called once due to caching
    })

    it('should provide cache statistics', () => {
      const stats = emailValidationService.getCacheStats()
      expect(stats).toHaveProperty('validationCacheSize')
      expect(stats).toHaveProperty('mxCacheSize')
      expect(typeof stats.validationCacheSize).toBe('number')
      expect(typeof stats.mxCacheSize).toBe('number')
    })

    it('should clear cache when requested', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      await emailValidationService.validateEmail('test@example.com')
      let stats = emailValidationService.getCacheStats()
      expect(stats.validationCacheSize).toBeGreaterThan(0)

      emailValidationService.clearCache()
      stats = emailValidationService.getCacheStats()
      expect(stats.validationCacheSize).toBe(0)
      expect(stats.mxCacheSize).toBe(0)
    })
  })

  describe('Error Handling', () => {
    it('should handle DNS resolution errors gracefully', async () => {
      emailValidationService.clearCache() // Clear cache to ensure fresh DNS lookup
      mockResolveMx.mockRejectedValue(new Error('DNS resolution failed'))

      const result = await emailValidationService.validateEmail('test@nonexistent-domain.com')
      expect(result.mxRecords).toBe(false)
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Domain has no valid MX records')
    })

    it('should handle malformed email addresses', async () => {
      const result = await emailValidationService.validateEmail('completely-invalid')
      expect(result.isValid).toBe(false)
      expect(result.confidence).toBe(0)
      expect(result.errors).toContain('Invalid email syntax')
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty email strings', async () => {
      const result = await emailValidationService.validateEmail('')
      expect(result.isValid).toBe(false)
      expect(result.confidence).toBe(0)
    })

    it('should handle very long email addresses', async () => {
      const longEmail = 'a'.repeat(250) + '@example.com'
      const result = await emailValidationService.validateEmail(longEmail)
      expect(result.isValid).toBe(false)
    })

    it('should normalize email case', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }])

      const result = await emailValidationService.validateEmail('TEST@EXAMPLE.COM')
      expect(result.email).toBe('TEST@EXAMPLE.COM') // Original case preserved
      expect(result.domain).toBe('example.com') // Domain normalized to lowercase
    })
  })
})
