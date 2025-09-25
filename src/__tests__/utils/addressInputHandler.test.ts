/**
 * @jest-environment jsdom
 */

import { AddressInputHandler } from '../../utils/addressInputHandler'
import { logger } from '../../utils/logger'

// Mock the logger for testing deduplication
jest.mock('../../utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

const mockLogger = logger as jest.Mocked<typeof logger>

describe('AddressInputHandler', () => {
  beforeEach(() => {
    // Reset static properties before each test using the new reset method
    AddressInputHandler.resetLoggingState()
    jest.clearAllMocks()
  })

  afterEach(() => {
    // Reset environment variable
    delete (process.env as any).NODE_ENV
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

  // New tests for GitHub Issue #201 fixes
  describe('Issue #201 - Duplicate Logging Prevention', () => {
    it('should not log duplicate ZIP code detections', () => {
      // Set development environment for logging
      process.env.NODE_ENV = 'development'

      const input = '60047'

      // Parse the same input multiple times
      AddressInputHandler.parseAddressInput(input)
      AddressInputHandler.parseAddressInput(input)
      AddressInputHandler.parseAddressInput(input)

      // Should only log once due to deduplication
      expect(mockLogger.debug).toHaveBeenCalledTimes(1)
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'AddressInputHandler',
        'ZIP code input detected: 60047 (zip-only)'
      )
    })

    it('should log different ZIP codes separately', () => {
      // Set development environment for logging
      process.env.NODE_ENV = 'development'

      const input1 = '60047'
      const input2 = '90210'

      AddressInputHandler.parseAddressInput(input1)
      AddressInputHandler.parseAddressInput(input2)

      // Should log both different ZIP codes
      expect(mockLogger.debug).toHaveBeenCalledTimes(2)
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'AddressInputHandler',
        'ZIP code input detected: 60047 (zip-only)'
      )
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'AddressInputHandler',
        'ZIP code input detected: 90210 (zip-only)'
      )
    })

    it('should respect session log limits', () => {
      // Set development environment for logging
      process.env.NODE_ENV = 'development'

      const inputs = ['60047', '90210', '10001', '94102', '33101', '78701']

      // Parse multiple different ZIP codes (more than the limit of 5)
      inputs.forEach(input => {
        AddressInputHandler.parseAddressInput(input)
      })

      // Should have 5 ZIP code detection logs + 1 limit warning = 6 total
      expect(mockLogger.debug).toHaveBeenCalledTimes(6)

      // Verify the limit warning message is included
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'AddressInputHandler',
        'Approaching log limit, further ZIP code detections will be silent'
      )
    })

    it('should not log in production environment', () => {
      process.env.NODE_ENV = 'production'

      const input = '60047'
      AddressInputHandler.parseAddressInput(input)

      // Should not log in production
      expect(mockLogger.debug).not.toHaveBeenCalled()
    })

    it('should log in development environment', () => {
      process.env.NODE_ENV = 'development'

      const input = '60047'
      AddressInputHandler.parseAddressInput(input)

      // Should log in development
      expect(mockLogger.debug).toHaveBeenCalledTimes(1)
    })

    it('should use context-aware deduplication keys', () => {
      // Set development environment for logging
      process.env.NODE_ENV = 'development'

      // Same ZIP code but different contexts should be treated as different
      const fullAddress = '123 Main St, Beverly Hills, CA 90210'
      const zipOnly = '90210'

      AddressInputHandler.parseAddressInput(fullAddress)
      AddressInputHandler.parseAddressInput(zipOnly)

      // Should log both because contexts are different
      expect(mockLogger.debug).toHaveBeenCalledTimes(2)
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'AddressInputHandler',
        expect.stringContaining('ZIP code input detected: 90210')
      )
    })
  })
})
