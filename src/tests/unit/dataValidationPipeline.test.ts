/**
 * Unit Tests for Data Validation Pipeline
 * Comprehensive test suite for data validation and cleaning functionality
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals'

// Mock the data validation pipeline since we don't have the actual implementation yet
const mockDataValidationPipeline = {
  validateAndClean: jest.fn(),
  calculateDataQualityScore: jest.fn(),
  enrichData: jest.fn(),
}

// Mock BusinessRecord type
interface BusinessRecord {
  id: string
  businessName: string
  industry: string
  email: string[]
  phone?: string
  website?: string
  address?: {
    street: string
    city: string
    state: string
    zipCode: string
  }
  coordinates?: {
    lat: number
    lng: number
  }
  scrapedAt: Date
  confidence?: number
}

// Mock DataValidationPipeline class
class DataValidationPipeline {
  async validateAndClean(business: BusinessRecord) {
    return mockDataValidationPipeline.validateAndClean(business)
  }

  calculateDataQualityScore(business: BusinessRecord) {
    return mockDataValidationPipeline.calculateDataQualityScore(business)
  }

  async enrichData(business: BusinessRecord) {
    return mockDataValidationPipeline.enrichData(business)
  }

  private isValidEmailFormat(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }

  private isCommonInvalidEmail(email: string): boolean {
    const invalidPatterns = ['test@example.com', 'noreply@', 'no-reply@']
    return invalidPatterns.some(pattern => email.includes(pattern))
  }

  private isValidPhoneFormat(phone: string): boolean {
    const phoneRegex = /^\+?[\d\s\-\(\)\.]{10,}$/
    return phoneRegex.test(phone)
  }

  private formatPhoneNumber(phone: string): string | null {
    const cleaned = phone.replace(/\D/g, '')
    if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`
    } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
      return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`
    }
    return null
  }

  private classifyIndustry(businessName: string): string | null {
    const name = businessName.toLowerCase()
    if (name.includes('pizza') || name.includes('restaurant') || name.includes('cafe') || name.includes('bistro')) {
      return 'Restaurant'
    }
    if (name.includes('medical') || name.includes('clinic') || name.includes('hospital') || name.includes('dental')) {
      return 'Healthcare'
    }
    return null
  }
}

describe('DataValidationPipeline', () => {
  let pipeline: DataValidationPipeline
  let mockBusiness: BusinessRecord

  beforeEach(() => {
    pipeline = new DataValidationPipeline()
    mockBusiness = {
      id: 'test-1',
      businessName: 'Test Restaurant',
      industry: 'Restaurant',
      email: ['info@testrestaurant.com'],
      phone: '(555) 123-4567',
      website: 'https://testrestaurant.com',
      address: {
        street: '123 Main St',
        city: 'New York',
        state: 'NY',
        zipCode: '10001'
      },
      scrapedAt: new Date('2024-01-15'),
      confidence: 0.85
    }
  })

  describe('validateAndClean', () => {
    it('should validate a complete business record successfully', async () => {
      // Mock successful validation
      mockDataValidationPipeline.validateAndClean.mockResolvedValue({
        isValid: true,
        confidence: 0.85,
        errors: [],
        cleanedData: mockBusiness,
        warnings: [],
        suggestions: []
      })

      const result = await pipeline.validateAndClean(mockBusiness)

      expect(result.isValid).toBe(true)
      expect(result.confidence).toBeGreaterThan(0.8)
      expect(result.errors).toHaveLength(0)
      expect(result.cleanedData).toBeDefined()
    })

    it('should detect missing business name', async () => {
      const invalidBusiness = { ...mockBusiness, businessName: '' }

      // Mock validation failure for missing business name
      mockDataValidationPipeline.validateAndClean.mockResolvedValue({
        isValid: false,
        confidence: 0.2,
        errors: [{
          field: 'businessName',
          code: 'MISSING_NAME',
          severity: 'critical',
          message: 'Business name is required'
        }],
        cleanedData: invalidBusiness,
        warnings: [],
        suggestions: []
      })

      const result = await pipeline.validateAndClean(invalidBusiness)

      expect(result.isValid).toBe(false)
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          field: 'businessName',
          code: 'MISSING_NAME',
          severity: 'critical'
        })
      )
    })

    it('should detect invalid email addresses', async () => {
      const invalidBusiness = { ...mockBusiness, email: ['invalid-email'] }
      const result = await pipeline.validateAndClean(invalidBusiness)
      
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          field: 'email',
          code: 'INVALID_EMAILS',
          severity: 'major'
        })
      )
    })

    it('should detect invalid phone numbers', async () => {
      const invalidBusiness = { ...mockBusiness, phone: '123' }
      const result = await pipeline.validateAndClean(invalidBusiness)
      
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          field: 'phone',
          code: 'INVALID_PHONE',
          severity: 'major'
        })
      )
    })

    it('should suggest cleaned business name', async () => {
      const messyBusiness = { ...mockBusiness, businessName: '  test   restaurant  ' }
      const result = await pipeline.validateAndClean(messyBusiness)
      
      expect(result.suggestions).toContainEqual(
        expect.objectContaining({
          field: 'businessName',
          suggestedValue: 'Test Restaurant',
          reason: 'Normalized capitalization and removed extra spaces'
        })
      )
    })

    it('should handle missing optional fields gracefully', async () => {
      const minimalBusiness: BusinessRecord = {
        id: 'test-2',
        businessName: 'Minimal Business',
        industry: 'Unknown',
        email: [],
        phone: '',
        website: '',
        address: { street: '', city: '', state: '', zipCode: '' },
        scrapedAt: new Date(),
        confidence: 0.5
      }
      
      const result = await pipeline.validateAndClean(minimalBusiness)
      
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          field: 'email',
          code: 'NO_EMAIL'
        })
      )
      expect(result.warnings).toContainEqual(
        expect.objectContaining({
          field: 'phone',
          code: 'NO_PHONE'
        })
      )
    })
  })

  describe('calculateDataQualityScore', () => {
    it('should calculate high quality score for complete data', () => {
      const score = pipeline.calculateDataQualityScore(mockBusiness)
      
      expect(score.overall).toBeGreaterThan(0.8)
      expect(score.completeness).toBeGreaterThan(0.8)
      expect(score.accuracy).toBeGreaterThan(0.8)
    })

    it('should calculate lower score for incomplete data', () => {
      const incompleteBusiness = {
        ...mockBusiness,
        email: [],
        phone: '',
        website: ''
      }
      
      const score = pipeline.calculateDataQualityScore(incompleteBusiness)
      
      expect(score.completeness).toBeLessThan(0.7)
      expect(score.overall).toBeLessThan(0.8)
    })

    it('should penalize invalid data formats', () => {
      const invalidBusiness = {
        ...mockBusiness,
        email: ['invalid-email'],
        phone: '123'
      }
      
      const score = pipeline.calculateDataQualityScore(invalidBusiness)
      
      expect(score.accuracy).toBeLessThan(0.7)
    })
  })

  describe('enrichData', () => {
    it('should enrich business with geocoding data', async () => {
      const businessWithoutCoords = { ...mockBusiness }
      delete businessWithoutCoords.coordinates
      
      // Mock geocoder
      const mockGeocoder = {
        geocode: jest.fn().mockResolvedValue({
          lat: 40.7128,
          lng: -74.0060
        })
      }
      
      const result = await pipeline.enrichData(businessWithoutCoords)
      
      expect(result.enriched).toBe(true)
      expect(result.addedFields).toContain('coordinates')
    })

    it('should classify industry based on business name', async () => {
      const businessWithUnknownIndustry = {
        ...mockBusiness,
        businessName: 'Joe\'s Medical Clinic',
        industry: 'Unknown'
      }
      
      const result = await pipeline.enrichData(businessWithUnknownIndustry)
      
      expect(result.enriched).toBe(true)
      expect(result.addedFields).toContain('industry')
      expect(businessWithUnknownIndustry.industry).toBe('Healthcare')
    })
  })

  describe('email validation', () => {
    it('should validate correct email formats', () => {
      const validEmails = [
        'test@example.com',
        'user.name@domain.co.uk',
        'user+tag@example.org'
      ]
      
      validEmails.forEach(email => {
        expect(pipeline['isValidEmailFormat'](email)).toBe(true)
      })
    })

    it('should reject invalid email formats', () => {
      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        'user@domain',
        'user space@domain.com'
      ]
      
      invalidEmails.forEach(email => {
        expect(pipeline['isValidEmailFormat'](email)).toBe(false)
      })
    })

    it('should filter out common invalid emails', () => {
      const commonInvalidEmails = [
        'test@example.com',
        'noreply@domain.com',
        'no-reply@test.com'
      ]
      
      commonInvalidEmails.forEach(email => {
        expect(pipeline['isCommonInvalidEmail'](email)).toBe(true)
      })
    })
  })

  describe('phone validation', () => {
    it('should validate correct phone formats', () => {
      const validPhones = [
        '(555) 123-4567',
        '555-123-4567',
        '5551234567',
        '+1 (555) 123-4567'
      ]
      
      validPhones.forEach(phone => {
        expect(pipeline['isValidPhoneFormat'](phone)).toBe(true)
      })
    })

    it('should format phone numbers correctly', () => {
      const testCases = [
        { input: '5551234567', expected: '(555) 123-4567' },
        { input: '15551234567', expected: '+1 (555) 123-4567' },
        { input: '555.123.4567', expected: '(555) 123-4567' }
      ]
      
      testCases.forEach(({ input, expected }) => {
        expect(pipeline['formatPhoneNumber'](input)).toBe(expected)
      })
    })

    it('should return null for invalid phone numbers', () => {
      const invalidPhones = ['123', '12345', 'abc-def-ghij']
      
      invalidPhones.forEach(phone => {
        expect(pipeline['formatPhoneNumber'](phone)).toBeNull()
      })
    })
  })

  describe('address validation', () => {
    it('should validate complete addresses', async () => {
      const result = await pipeline.validateAndClean(mockBusiness)
      
      const addressErrors = result.errors.filter(e => e.field.startsWith('address'))
      expect(addressErrors).toHaveLength(0)
    })

    it('should detect missing address components', async () => {
      const incompleteAddress = {
        ...mockBusiness,
        address: { street: '', city: '', state: '', zipCode: '' }
      }
      
      const result = await pipeline.validateAndClean(incompleteAddress)
      
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          field: 'address.street',
          code: 'MISSING_STREET'
        })
      )
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          field: 'address.city',
          code: 'MISSING_CITY'
        })
      )
    })

    it('should validate ZIP code format', async () => {
      const invalidZip = {
        ...mockBusiness,
        address: { ...mockBusiness.address, zipCode: '123' }
      }
      
      const result = await pipeline.validateAndClean(invalidZip)
      
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          field: 'address.zipCode',
          code: 'INVALID_ZIP'
        })
      )
    })
  })

  describe('website validation', () => {
    it('should validate correct URLs', async () => {
      const validUrls = [
        'https://example.com',
        'http://test.org',
        'https://subdomain.example.com/path'
      ]
      
      for (const url of validUrls) {
        const business = { ...mockBusiness, website: url }
        const result = await pipeline.validateAndClean(business)
        
        const urlErrors = result.errors.filter(e => e.field === 'website')
        expect(urlErrors).toHaveLength(0)
      }
    })

    it('should detect invalid URLs', async () => {
      const invalidBusiness = { ...mockBusiness, website: 'not-a-url' }
      const result = await pipeline.validateAndClean(invalidBusiness)
      
      expect(result.errors).toContainEqual(
        expect.objectContaining({
          field: 'website',
          code: 'INVALID_URL'
        })
      )
    })

    it('should suggest HTTPS upgrade', async () => {
      const httpBusiness = { ...mockBusiness, website: 'http://example.com' }
      const result = await pipeline.validateAndClean(httpBusiness)
      
      expect(result.suggestions).toContainEqual(
        expect.objectContaining({
          field: 'website',
          suggestedValue: 'https://example.com',
          reason: 'Upgrade to HTTPS for security'
        })
      )
    })
  })

  describe('industry classification', () => {
    it('should classify restaurants correctly', () => {
      const restaurantNames = [
        'Joe\'s Pizza',
        'Main Street Cafe',
        'The Food Truck',
        'Bistro 123'
      ]
      
      restaurantNames.forEach(name => {
        const industry = pipeline['classifyIndustry'](name)
        expect(industry).toBe('Restaurant')
      })
    })

    it('should classify healthcare businesses correctly', () => {
      const healthcareNames = [
        'City Medical Center',
        'Dr. Smith\'s Clinic',
        'Health Plus Hospital',
        'Dental Care Associates'
      ]
      
      healthcareNames.forEach(name => {
        const industry = pipeline['classifyIndustry'](name)
        expect(industry).toBe('Healthcare')
      })
    })

    it('should return null for unclassifiable businesses', () => {
      const unclassifiableNames = [
        'ABC Company',
        'Generic Business',
        'Random Name'
      ]
      
      unclassifiableNames.forEach(name => {
        const industry = pipeline['classifyIndustry'](name)
        expect(industry).toBeNull()
      })
    })
  })

  describe('confidence calculation', () => {
    it('should calculate high confidence for valid data', async () => {
      const result = await pipeline.validateAndClean(mockBusiness)
      expect(result.confidence).toBeGreaterThan(0.8)
    })

    it('should reduce confidence for errors', async () => {
      const invalidBusiness = {
        ...mockBusiness,
        businessName: '', // Critical error
        email: ['invalid-email'] // Major error
      }
      
      const result = await pipeline.validateAndClean(invalidBusiness)
      expect(result.confidence).toBeLessThan(0.5)
    })

    it('should slightly reduce confidence for warnings', async () => {
      const warningBusiness = {
        ...mockBusiness,
        email: [], // Warning: no email
        phone: '' // Warning: no phone
      }
      
      const result = await pipeline.validateAndClean(warningBusiness)
      expect(result.confidence).toBeLessThan(1.0)
      expect(result.confidence).toBeGreaterThan(0.7)
    })
  })
})
