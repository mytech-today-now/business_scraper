/**
 * Unit Tests for Utility Functions
 * Basic utility function tests that can run immediately
 */

import { describe, it, expect } from '@jest/globals'

// Simple utility functions to test
const formatPhoneNumber = (phone: string): string | null => {
  if (!phone || typeof phone !== 'string') return null
  const cleaned = phone.replace(/\D/g, '')
  if (cleaned.length === 10) {
    return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`
  } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
    return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`
  }
  return null
}

const isValidEmail = (email: string): boolean => {
  if (!email || typeof email !== 'string') return false
  // More strict email validation
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
  return emailRegex.test(email) && email.length <= 254 && !email.includes('..')
}

const sanitizeBusinessName = (name: string): string => {
  if (!name || typeof name !== 'string') return ''
  return name
    .trim()
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
    .replace(/<[^>]*>/g, '') // Remove other HTML tags
    .replace(/\s+/g, ' ')
    .substring(0, 100)
}

const calculateConfidence = (factors: { [key: string]: number }): number => {
  const weights = {
    hasName: 0.3,
    hasEmail: 0.2,
    hasPhone: 0.2,
    hasAddress: 0.2,
    hasWebsite: 0.1
  }

  let score = 0
  let totalWeight = 0

  for (const [factor, value] of Object.entries(factors)) {
    if (weights[factor] !== undefined) {
      score += weights[factor] * value
      totalWeight += weights[factor]
    }
  }

  return totalWeight > 0 ? score / totalWeight : 0
}

describe('Utility Functions', () => {
  describe('formatPhoneNumber', () => {
    it('should format 10-digit phone numbers correctly', () => {
      expect(formatPhoneNumber('5551234567')).toBe('(555) 123-4567')
      expect(formatPhoneNumber('555.123.4567')).toBe('(555) 123-4567')
      expect(formatPhoneNumber('555-123-4567')).toBe('(555) 123-4567')
      expect(formatPhoneNumber('(555) 123-4567')).toBe('(555) 123-4567')
    })

    it('should format 11-digit phone numbers with country code', () => {
      expect(formatPhoneNumber('15551234567')).toBe('+1 (555) 123-4567')
      expect(formatPhoneNumber('1-555-123-4567')).toBe('+1 (555) 123-4567')
    })

    it('should return null for invalid phone numbers', () => {
      expect(formatPhoneNumber('123')).toBeNull()
      expect(formatPhoneNumber('12345')).toBeNull()
      expect(formatPhoneNumber('abc-def-ghij')).toBeNull()
      expect(formatPhoneNumber('')).toBeNull()
    })
  })

  describe('isValidEmail', () => {
    it('should validate correct email formats', () => {
      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'user+tag@example.org',
        'firstname.lastname@company.com',
        'user@domain-name.com'
      ]
      
      validEmails.forEach(email => {
        expect(isValidEmail(email)).toBe(true)
      })
    })

    it('should reject invalid email formats', () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        'user@domain',
        'user space@domain.com',
        'user@domain..com',
        'user@@domain.com',
        ''
      ]
      
      invalidEmails.forEach(email => {
        expect(isValidEmail(email)).toBe(false)
      })
    })

    it('should reject emails that are too long', () => {
      const longEmail = 'a'.repeat(250) + '@example.com'
      expect(isValidEmail(longEmail)).toBe(false)
    })
  })

  describe('sanitizeBusinessName', () => {
    it('should remove dangerous characters', () => {
      expect(sanitizeBusinessName('Joe\'s <script>alert("xss")</script> Pizza')).toBe('Joe\'s Pizza')
      expect(sanitizeBusinessName('Business <> Name')).toBe('Business Name')
    })

    it('should normalize whitespace', () => {
      expect(sanitizeBusinessName('  Multiple   Spaces   Business  ')).toBe('Multiple Spaces Business')
      expect(sanitizeBusinessName('\t\nBusiness\t\nName\t\n')).toBe('Business Name')
    })

    it('should limit length to 100 characters', () => {
      const longName = 'A'.repeat(150)
      const result = sanitizeBusinessName(longName)
      expect(result.length).toBe(100)
      expect(result).toBe('A'.repeat(100))
    })

    it('should handle empty strings', () => {
      expect(sanitizeBusinessName('')).toBe('')
      expect(sanitizeBusinessName('   ')).toBe('')
    })
  })

  describe('calculateConfidence', () => {
    it('should calculate confidence based on available data', () => {
      const completeData = {
        hasName: 1,
        hasEmail: 1,
        hasPhone: 1,
        hasAddress: 1,
        hasWebsite: 1
      }
      
      expect(calculateConfidence(completeData)).toBe(1)
    })

    it('should handle partial data', () => {
      const partialData = {
        hasName: 1,
        hasEmail: 1,
        hasPhone: 0,
        hasAddress: 0,
        hasWebsite: 0
      }
      
      const confidence = calculateConfidence(partialData)
      expect(confidence).toBeGreaterThan(0)
      expect(confidence).toBeLessThan(1)
    })

    it('should handle missing data', () => {
      const noData = {
        hasName: 0,
        hasEmail: 0,
        hasPhone: 0,
        hasAddress: 0,
        hasWebsite: 0
      }
      
      expect(calculateConfidence(noData)).toBe(0)
    })

    it('should handle empty factors', () => {
      expect(calculateConfidence({})).toBe(0)
    })

    it('should ignore unknown factors', () => {
      const dataWithUnknown = {
        hasName: 0.8, // Partial name data
        hasEmail: 0.6, // Partial email data
        unknownFactor: 1 // This should be ignored
      }

      const confidence = calculateConfidence(dataWithUnknown)
      expect(confidence).toBeGreaterThan(0)
      expect(confidence).toBeLessThan(1)
      // Should be (0.3 * 0.8 + 0.2 * 0.6) / (0.3 + 0.2) = 0.36 / 0.5 = 0.72
      expect(confidence).toBeCloseTo(0.72, 2)
    })
  })

  describe('Edge Cases', () => {
    it('should handle null and undefined inputs gracefully', () => {
      expect(formatPhoneNumber(null as any)).toBeNull()
      expect(formatPhoneNumber(undefined as any)).toBeNull()
      
      expect(isValidEmail(null as any)).toBe(false)
      expect(isValidEmail(undefined as any)).toBe(false)
      
      expect(sanitizeBusinessName(null as any)).toBe('')
      expect(sanitizeBusinessName(undefined as any)).toBe('')
    })

    it('should handle special characters in business names', () => {
      const specialNames = [
        'José\'s Café',
        'Smith & Jones LLC',
        'Company (2024)',
        'Business-Name_123',
        'Müller\'s Bakery'
      ]
      
      specialNames.forEach(name => {
        const sanitized = sanitizeBusinessName(name)
        expect(sanitized.length).toBeGreaterThan(0)
        expect(sanitized).not.toContain('<')
        expect(sanitized).not.toContain('>')
      })
    })

    it('should handle international phone numbers', () => {
      // These should return null as they don't match our US format
      const internationalNumbers = [
        '+44 20 7946 0958', // UK
        '+33 1 42 86 83 26', // France
        '+49 30 12345678'    // Germany
      ]
      
      internationalNumbers.forEach(number => {
        expect(formatPhoneNumber(number)).toBeNull()
      })
    })
  })

  describe('Performance Tests', () => {
    it('should handle large inputs efficiently', () => {
      const start = Date.now()
      
      // Test with many iterations
      for (let i = 0; i < 1000; i++) {
        formatPhoneNumber('5551234567')
        isValidEmail('test@example.com')
        sanitizeBusinessName('Test Business Name')
        calculateConfidence({ hasName: 1, hasEmail: 1 })
      }
      
      const end = Date.now()
      const duration = end - start
      
      // Should complete 1000 iterations in under 100ms
      expect(duration).toBeLessThan(100)
    })

    it('should handle very long strings without crashing', () => {
      const veryLongString = 'A'.repeat(10000)
      
      expect(() => {
        sanitizeBusinessName(veryLongString)
        isValidEmail(veryLongString + '@example.com')
        formatPhoneNumber(veryLongString)
      }).not.toThrow()
    })
  })
})
