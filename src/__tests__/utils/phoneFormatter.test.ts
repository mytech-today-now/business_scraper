/**
 * Phone Formatter Tests
 *
 * Tests for enhanced phone number formatting functionality
 */

import { describe, it, expect, beforeEach } from '@jest/globals'
import { PhoneFormatter, formatPhoneNumber, isValidPhoneNumber } from '@/utils/phoneFormatter'

describe('PhoneFormatter', () => {
  let formatter: PhoneFormatter

  beforeEach(() => {
    formatter = new PhoneFormatter()
  })

  describe('formatPhone', () => {
    it('should format standard 10-digit phone number', () => {
      const result = formatter.formatPhone('5551234567')

      expect(result.formatted).toBe('5551234567')
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
      expect(result.isValid).toBe(true)
    })

    it('should remove +1 country code', () => {
      const result = formatter.formatPhone('+15551234567')

      expect(result.formatted).toBe('5551234567')
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
      expect(result.isValid).toBe(true)
    })

    it('should handle phone with parentheses', () => {
      const result = formatter.formatPhone('(555) 123-4567')

      expect(result.formatted).toBe('5551234567')
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
      expect(result.isValid).toBe(true)
    })

    it('should handle phone with dashes', () => {
      const result = formatter.formatPhone('555-123-4567')

      expect(result.formatted).toBe('5551234567')
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
      expect(result.isValid).toBe(true)
    })

    it('should handle phone with spaces', () => {
      const result = formatter.formatPhone('555 123 4567')

      expect(result.formatted).toBe('5551234567')
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
      expect(result.isValid).toBe(true)
    })

    it('should handle phone with dots', () => {
      const result = formatter.formatPhone('555.123.4567')

      expect(result.formatted).toBe('5551234567')
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
      expect(result.isValid).toBe(true)
    })

    it('should format to standard display format', () => {
      const result = formatter.formatPhone('5551234567', { format: 'standard' })

      expect(result.formatted).toBe('(555) 123-4567')
    })

    it('should format to display format', () => {
      const result = formatter.formatPhone('5551234567', { format: 'display' })

      expect(result.formatted).toBe('555-123-4567')
    })

    it('should reject invalid phone numbers', () => {
      const testCases = [
        '123456789', // Too short
        '10123456789', // Too long with invalid area code after country code removal
        '0551234567', // Invalid area code (starts with 0)
        '1551234567', // Invalid area code (starts with 1)
        '5550234567', // Invalid exchange (starts with 0)
        '5551034567', // Invalid number (starts with 0)
        '5555555555', // All same digits
        '1234567890', // Sequential digits
      ]

      testCases.forEach(phone => {
        const result = formatter.formatPhone(phone, { strictValidation: true })
        expect(result.isValid).toBe(false)
      })
    })

    it('should handle mixed format phone numbers', () => {
      const testCases = [
        '+1 (555) 123-4567',
        '1-555-123-4567',
        '1.555.123.4567',
        '1 555 123 4567',
        '15551234567',
      ]

      testCases.forEach(phone => {
        const result = formatter.formatPhone(phone)
        expect(result.formatted).toBe('5551234567')
        expect(result.isValid).toBe(true)
      })
    })

    it('should return empty result for invalid input', () => {
      const result = formatter.formatPhone('')

      expect(result.formatted).toBe('')
      expect(result.isValid).toBe(false)
      expect(result.confidence).toBe(0)
    })

    it('should handle phone numbers with extensions', () => {
      const result = formatter.formatPhone('555-123-4567 ext 123')

      expect(result.formatted).toBe('5551234567')
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
      expect(result.isValid).toBe(true)
    })

    it('should preserve country code when requested', () => {
      const result = formatter.formatPhone('+15551234567', { removeCountryCode: false })

      expect(result.digits).toBe('15551234567')
      expect(result.isValid).toBe(true) // 11 digits with country code should be valid
      expect(result.areaCode).toBe('555')
      expect(result.exchange).toBe('123')
      expect(result.number).toBe('4567')
    })
  })

  describe('formatMultiplePhones', () => {
    it('should format multiple phone numbers', () => {
      const phones = ['5551234567', '(555) 987-6543', '+1-555-555-5555']
      const results = formatter.formatMultiplePhones(phones)

      expect(results).toHaveLength(3)
      expect(results[0].formatted).toBe('5551234567')
      expect(results[1].formatted).toBe('5559876543')
      expect(results[2].formatted).toBe('5555555555')
    })
  })

  describe('getBestPhone', () => {
    it('should return the best phone from a list', () => {
      const phones = ['invalid', '5551234567', '(555) 987-6543']
      const result = formatter.getBestPhone(phones)

      // Should return a valid phone (either one is fine)
      expect(result.isValid).toBe(true)
      expect(['5551234567', '5559876543']).toContain(result.formatted)
    })

    it('should return empty result when no valid phones', () => {
      const phones = ['invalid', 'also invalid', '123']
      const result = formatter.getBestPhone(phones)

      expect(result.formatted).toBe('')
      expect(result.isValid).toBe(false)
    })
  })

  describe('isValidPhone', () => {
    it('should validate phone numbers correctly', () => {
      expect(formatter.isValidPhone('5551234567')).toBe(true)
      expect(formatter.isValidPhone('(555) 123-4567')).toBe(true)
      expect(formatter.isValidPhone('+1-555-123-4567')).toBe(true)
      expect(formatter.isValidPhone('123456789')).toBe(false)
      expect(formatter.isValidPhone('invalid')).toBe(false)
    })
  })

  describe('edge cases', () => {
    it('should handle null input', () => {
      const result = formatter.formatPhone(null as any)
      expect(result.isValid).toBe(false)
    })

    it('should handle undefined input', () => {
      const result = formatter.formatPhone(undefined as any)
      expect(result.isValid).toBe(false)
    })

    it('should handle non-string input', () => {
      const result = formatter.formatPhone(123 as any)
      expect(result.isValid).toBe(false)
    })
  })
})

describe('Utility Functions', () => {
  describe('formatPhoneNumber', () => {
    it('should format phone number with default programmatic format', () => {
      expect(formatPhoneNumber('(555) 123-4567')).toBe('5551234567')
    })

    it('should format phone number with standard format', () => {
      expect(formatPhoneNumber('5551234567', 'standard')).toBe('(555) 123-4567')
    })

    it('should format phone number with display format', () => {
      expect(formatPhoneNumber('5551234567', 'display')).toBe('555-123-4567')
    })
  })

  describe('isValidPhoneNumber', () => {
    it('should validate phone numbers', () => {
      expect(isValidPhoneNumber('5551234567')).toBe(true)
      expect(isValidPhoneNumber('(555) 123-4567')).toBe(true)
      expect(isValidPhoneNumber('invalid')).toBe(false)
    })
  })
})
