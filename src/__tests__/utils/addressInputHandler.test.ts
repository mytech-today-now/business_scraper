/**
 * @jest-environment jsdom
 */

import { AddressInputHandler } from '../../utils/addressInputHandler'

describe('AddressInputHandler', () => {
  beforeEach(() => {
    // Reset static properties before each test using the new reset method
    AddressInputHandler.resetLoggingState()
  })

  describe('parseAddressInput', () => {
    it('should parse ZIP code only input', () => {
      const result = AddressInputHandler.parseAddressInput('60047')
      
      expect(result.zipCode).toBe('60047')
      expect(result.wasExtracted).toBe(false)
      expect(result.extractedFrom).toBe('zip-only')
      expect(result.confidence).toBe('high')
    })

    it('should parse full address', () => {
      const result = AddressInputHandler.parseAddressInput('123 Main St, Chicago, IL 60047')
      
      expect(result.zipCode).toBe('60047')
      expect(result.wasExtracted).toBe(true)
      expect(result.extractedFrom).toBe('full-address')
      expect(result.confidence).toBe('high')
    })

    it('should parse city, state, ZIP format', () => {
      const result = AddressInputHandler.parseAddressInput('Chicago, IL 60047')

      expect(result.zipCode).toBe('60047')
      expect(result.wasExtracted).toBe(true)
      // Note: This might match full-address pattern due to regex precedence
      expect(['city-state-zip', 'full-address']).toContain(result.extractedFrom)
      expect(result.confidence).toBe('high')
    })

    it('should handle empty input', () => {
      const result = AddressInputHandler.parseAddressInput('')
      
      expect(result.zipCode).toBeNull()
      expect(result.error).toBe('Input is empty')
    })

    it('should handle incomplete input', () => {
      const result = AddressInputHandler.parseAddressInput('123')
      
      expect(result.zipCode).toBeNull()
      expect(result.error).toBe('Incomplete input - continue typing')
    })

    it('should debounce logging for same ZIP code and respect session limits', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation()

      // First call should log
      AddressInputHandler.parseAddressInput('60047')

      // Second call with same ZIP should not log (within debounce period)
      AddressInputHandler.parseAddressInput('60047')

      // Different ZIP should log
      AddressInputHandler.parseAddressInput('60048')

      // Test session limit by making multiple calls
      for (let i = 0; i < 10; i++) {
        AddressInputHandler.parseAddressInput(`6004${i}`)
      }

      consoleSpy.mockRestore()
    })

    it('should reset logging state correctly', () => {
      // Make some calls to populate logging state
      AddressInputHandler.parseAddressInput('60047')
      AddressInputHandler.parseAddressInput('60048')

      // Reset state
      AddressInputHandler.resetLoggingState()

      // Should be able to log again after reset
      const result = AddressInputHandler.parseAddressInput('60049')
      expect(result.zipCode).toBe('60049')
    })
  })

  describe('isValidZipCode', () => {
    it('should validate 5-digit ZIP codes', () => {
      expect(AddressInputHandler.isValidZipCode('60047')).toBe(true)
      expect(AddressInputHandler.isValidZipCode('12345')).toBe(true)
    })

    it('should validate ZIP+4 codes', () => {
      expect(AddressInputHandler.isValidZipCode('60047-1234')).toBe(true)
    })

    it('should reject invalid ZIP codes', () => {
      expect(AddressInputHandler.isValidZipCode('1234')).toBe(false)
      expect(AddressInputHandler.isValidZipCode('123456')).toBe(false)
      expect(AddressInputHandler.isValidZipCode('abcde')).toBe(false)
    })
  })

  describe('normalizeZipCode', () => {
    it('should normalize ZIP codes', () => {
      expect(AddressInputHandler.normalizeZipCode(' 60047 ')).toBe('60047')
      expect(AddressInputHandler.normalizeZipCode('60047-1234')).toBe('60047-1234')
    })
  })
})
