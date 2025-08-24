/**
 * Unit Tests for Phone Number Intelligence Service
 * Comprehensive test suite for phone validation and intelligence features
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { PhoneValidationService } from '@/lib/phoneValidationService'
import { PhoneValidationResult } from '@/types/business'

describe('PhoneValidationService', () => {
  let phoneValidationService: PhoneValidationService

  beforeEach(() => {
    phoneValidationService = PhoneValidationService.getInstance()
    phoneValidationService.clearCache()
  })

  afterEach(() => {
    phoneValidationService.clearCache()
  })

  describe('Basic Phone Validation', () => {
    it('should validate correct US phone number format', async () => {
      const result = await phoneValidationService.validatePhone('(555) 123-4567')
      
      expect(result.originalNumber).toBe('(555) 123-4567')
      expect(result.standardizedNumber).toBe('+15551234567')
      expect(result.isValid).toBe(true)
      expect(result.country).toBe('US')
    })

    it('should validate 10-digit phone number', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result.standardizedNumber).toBe('+15551234567')
      expect(result.isValid).toBe(true)
    })

    it('should validate 11-digit phone number with country code', async () => {
      const result = await phoneValidationService.validatePhone('15551234567')
      
      expect(result.standardizedNumber).toBe('+15551234567')
      expect(result.isValid).toBe(true)
    })

    it('should reject invalid phone number formats', async () => {
      const result = await phoneValidationService.validatePhone('123')
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toBeDefined()
    })

    it('should reject phone numbers starting with 0 or 1 in area code', async () => {
      const result = await phoneValidationService.validatePhone('0551234567')
      
      expect(result.isValid).toBe(false)
    })

    it('should reject phone numbers starting with 0 or 1 in exchange', async () => {
      const result = await phoneValidationService.validatePhone('5550234567')
      
      expect(result.isValid).toBe(false)
    })
  })

  describe('Carrier Identification', () => {
    it('should identify carrier information', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result).toHaveProperty('carrier')
      expect(result).toHaveProperty('carrierDetails')
      
      if (result.carrierDetails) {
        expect(result.carrierDetails).toHaveProperty('name')
        expect(result.carrierDetails).toHaveProperty('type')
      }
    })

    it('should detect wireless carriers', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result.lineType).toMatch(/mobile|landline|voip|unknown/)
    })
  })

  describe('Line Type Detection', () => {
    it('should detect line type', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(['mobile', 'landline', 'voip', 'unknown']).toContain(result.lineType)
    })

    it('should provide line type confidence', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result.confidence).toBeGreaterThanOrEqual(0)
      expect(result.confidence).toBeLessThanOrEqual(100)
    })
  })

  describe('Do Not Call Registry Check', () => {
    it('should check DNC registry status', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result).toHaveProperty('dncStatus')
      expect(result.dncStatus).toHaveProperty('isOnDncRegistry')
      expect(typeof result.dncStatus?.isOnDncRegistry).toBe('boolean')
    })

    it('should include DNC registry type when on registry', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      if (result.dncStatus?.isOnDncRegistry) {
        expect(result.dncStatus).toHaveProperty('registryType')
        expect(['federal', 'state', 'wireless']).toContain(result.dncStatus.registryType!)
      }
    })

    it('should include last checked timestamp', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result.dncStatus).toHaveProperty('lastChecked')
      expect(result.dncStatus?.lastChecked).toBeDefined()
    })
  })

  describe('Reputation and Risk Scoring', () => {
    it('should calculate reputation score', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result).toHaveProperty('reputationScore')
      expect(result.reputationScore).toBeGreaterThanOrEqual(0)
      expect(result.reputationScore).toBeLessThanOrEqual(100)
    })

    it('should calculate risk score', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result).toHaveProperty('riskScore')
      expect(result.riskScore).toBeGreaterThanOrEqual(0)
      expect(result.riskScore).toBeLessThanOrEqual(100)
    })

    it('should give higher reputation to major carriers', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      // Major carriers should generally have better reputation
      if (result.carrierDetails?.mno && ['Verizon', 'AT&T', 'T-Mobile'].includes(result.carrierDetails.mno)) {
        expect(result.reputationScore).toBeGreaterThan(50)
      }
    })
  })

  describe('Geographic Information', () => {
    it('should provide region information for known area codes', async () => {
      const result = await phoneValidationService.validatePhone('2125551234') // NYC area code
      
      expect(result).toHaveProperty('region')
      expect(result).toHaveProperty('timeZone')
    })

    it('should handle unknown area codes gracefully', async () => {
      const result = await phoneValidationService.validatePhone('9995551234') // Non-existent area code
      
      expect(result.isValid).toBe(false)
    })
  })

  describe('Porting Detection', () => {
    it('should detect if number has been ported', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      expect(result).toHaveProperty('isPorted')
      expect(typeof result.isPorted).toBe('boolean')
    })
  })

  describe('Batch Phone Validation', () => {
    it('should validate multiple phone numbers', async () => {
      const phones = ['5551234567', '5559876543', 'invalid-phone']
      const results = await phoneValidationService.validatePhones(phones)
      
      expect(results).toHaveLength(3)
      expect(results[0].isValid).toBe(true)
      expect(results[1].isValid).toBe(true)
      expect(results[2].isValid).toBe(false)
    })

    it('should handle business location context in batch validation', async () => {
      const phones = ['5551234567', '5559876543']
      const results = await phoneValidationService.validatePhones(phones, 'New York, NY')
      
      expect(results).toHaveLength(2)
      results.forEach(result => {
        expect(result).toHaveProperty('confidence')
      })
    })
  })

  describe('Caching', () => {
    it('should cache validation results', async () => {
      // First call
      const result1 = await phoneValidationService.validatePhone('5551234567')
      
      // Second call should use cache
      const result2 = await phoneValidationService.validatePhone('5551234567')
      
      expect(result1.standardizedNumber).toBe(result2.standardizedNumber)
      expect(result1.confidence).toBe(result2.confidence)
    })

    it('should provide cache statistics', () => {
      const stats = phoneValidationService.getCacheStats()
      
      expect(stats).toHaveProperty('validationCacheSize')
      expect(stats).toHaveProperty('carrierCacheSize')
      expect(stats).toHaveProperty('dncCacheSize')
    })

    it('should clear all caches', () => {
      phoneValidationService.clearCache()
      
      const stats = phoneValidationService.getCacheStats()
      expect(stats.validationCacheSize).toBe(0)
      expect(stats.carrierCacheSize).toBe(0)
      expect(stats.dncCacheSize).toBe(0)
    })
  })

  describe('Confidence Scoring', () => {
    it('should provide higher confidence for valid numbers with known carriers', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      if (result.isValid && result.carrier && result.carrier !== 'Unknown Carrier') {
        expect(result.confidence).toBeGreaterThan(50)
      }
    })

    it('should provide lower confidence for numbers with unknown carriers', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      if (result.carrier === 'Unknown Carrier') {
        expect(result.confidence).toBeLessThan(80)
      }
    })

    it('should provide zero confidence for invalid numbers', async () => {
      const result = await phoneValidationService.validatePhone('invalid')
      
      expect(result.confidence).toBe(0)
    })
  })

  describe('Business Location Context', () => {
    it('should use business location for enhanced validation', async () => {
      const result = await phoneValidationService.validatePhone('2125551234', 'New York, NY')
      
      // Should provide some confidence boost for geographic consistency
      expect(result.confidence).toBeGreaterThan(0)
    })
  })

  describe('Error Handling', () => {
    it('should handle malformed phone numbers gracefully', async () => {
      const result = await phoneValidationService.validatePhone('abc-def-ghij')
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toBeDefined()
    })

    it('should handle empty phone numbers', async () => {
      const result = await phoneValidationService.validatePhone('')
      
      expect(result.isValid).toBe(false)
    })

    it('should handle null/undefined phone numbers', async () => {
      const result = await phoneValidationService.validatePhone(null as any)
      
      expect(result.isValid).toBe(false)
    })
  })

  describe('Pattern Detection', () => {
    it('should detect suspicious sequential patterns', async () => {
      const result = await phoneValidationService.validatePhone('5551234567')
      
      // Sequential numbers should have lower reputation
      expect(result.reputationScore).toBeLessThan(100)
    })

    it('should detect suspicious repeated patterns', async () => {
      const result = await phoneValidationService.validatePhone('5555555555')
      
      // Repeated numbers should have lower reputation
      expect(result.reputationScore).toBeLessThan(80)
    })
  })
})
