/**
 * Data Validation Pipeline - Comprehensive Test Suite
 * Tests business record validation, cleaning, and enrichment
 */

import { dataValidationPipeline, ValidationResult } from '@/lib/dataValidationPipeline'
import { BusinessRecord } from '@/types/business'
import { EmailValidationService } from '@/lib/emailValidationService'
import { PhoneValidationService } from '@/lib/phoneValidationService'
import { BusinessIntelligenceService } from '@/lib/businessIntelligenceService'
import { geocoder } from '@/model/geocoder'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/lib/emailValidationService')
jest.mock('@/lib/phoneValidationService')
jest.mock('@/lib/businessIntelligenceService')
jest.mock('@/model/geocoder')
jest.mock('@/utils/logger')

const mockEmailValidationService = EmailValidationService as jest.MockedClass<typeof EmailValidationService>
const mockPhoneValidationService = PhoneValidationService as jest.MockedClass<typeof PhoneValidationService>
const mockBusinessIntelligenceService = BusinessIntelligenceService as jest.MockedClass<typeof BusinessIntelligenceService>
const mockGeocoder = geocoder as jest.Mocked<typeof geocoder>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('Data Validation Pipeline - Comprehensive Tests', () => {
  const createMockBusinessRecord = (overrides: Partial<BusinessRecord> = {}): BusinessRecord => ({
    id: 'test-business-1',
    businessName: 'Test Business Inc.',
    email: ['contact@testbusiness.com'],
    phone: '(555) 123-4567',
    websiteUrl: 'https://www.testbusiness.com',
    address: {
      street: '123 Main Street',
      city: 'Los Angeles',
      state: 'CA',
      zipCode: '90210',
      country: 'US',
    },
    industry: 'Technology',
    scrapedAt: new Date(),
    ...overrides,
  })

  beforeEach(() => {
    jest.clearAllMocks()

    // Setup email validation mock
    const mockEmailInstance = {
      validateEmail: jest.fn().mockResolvedValue({
        isValid: true,
        confidence: 0.9,
        metadata: {
          provider: 'gmail',
          disposable: false,
          role: false,
          deliverable: true,
        },
      }),
    }
    mockEmailValidationService.mockImplementation(() => mockEmailInstance as any)

    // Setup phone validation mock
    const mockPhoneInstance = {
      validatePhone: jest.fn().mockResolvedValue({
        isValid: true,
        formatted: '+15551234567',
        type: 'mobile',
        carrier: 'Verizon',
        location: 'Los Angeles, CA',
      }),
    }
    mockPhoneValidationService.mockImplementation(() => mockPhoneInstance as any)

    // Setup business intelligence mock
    const mockBIInstance = {
      analyzeBusinessIntelligence: jest.fn().mockResolvedValue({
        industryMatch: 0.95,
        businessSize: 'medium',
        marketPresence: 'strong',
        digitalFootprint: 'excellent',
        trustScore: 0.85,
        riskFactors: [],
        opportunities: ['digital_marketing', 'expansion'],
      }),
    }
    mockBusinessIntelligenceService.mockImplementation(() => mockBIInstance as any)

    // Setup geocoder mock
    mockGeocoder.geocodeAddress.mockResolvedValue({
      latitude: 34.0522,
      longitude: -118.2437,
      formattedAddress: '123 Main Street, Los Angeles, CA 90210',
      confidence: 0.95,
    })
  })

  describe('Basic Validation', () => {
    it('should validate a complete business record successfully', async () => {
      const business = createMockBusinessRecord()

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(true)
      expect(result.confidence).toBeGreaterThan(0.8)
      expect(result.errors).toHaveLength(0)
      expect(result.warnings).toHaveLength(0)
      expect(result.cleanedData).toBeDefined()
    })

    it('should identify missing required fields', async () => {
      const business = createMockBusinessRecord({
        businessName: '',
        email: [],
        phone: undefined,
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(false)
      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'businessName',
            code: 'REQUIRED_FIELD_MISSING',
            severity: 'critical',
          }),
          expect.objectContaining({
            field: 'contact',
            code: 'NO_CONTACT_INFO',
            severity: 'critical',
          }),
        ])
      )
    })

    it('should validate business name format and content', async () => {
      const business = createMockBusinessRecord({
        businessName: 'a', // Too short
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'businessName',
            code: 'INVALID_LENGTH',
            severity: 'major',
          }),
        ])
      )
    })

    it('should detect suspicious business names', async () => {
      const business = createMockBusinessRecord({
        businessName: 'Test123!@#$%^&*()',
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'businessName',
            code: 'SUSPICIOUS_CHARACTERS',
          }),
        ])
      )
    })
  })

  describe('Email Validation', () => {
    it('should validate email addresses correctly', async () => {
      const business = createMockBusinessRecord({
        email: ['valid@business.com', 'contact@company.org'],
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(true)
      expect(result.cleanedData?.email).toEqual(['valid@business.com', 'contact@company.org'])
    })

    it('should reject invalid email formats', async () => {
      const mockEmailInstance = new mockEmailValidationService()
      mockEmailInstance.validateEmail = jest.fn().mockResolvedValue({
        isValid: false,
        confidence: 0.1,
        metadata: {
          provider: 'unknown',
          disposable: false,
          role: false,
          deliverable: false,
        },
      })

      const business = createMockBusinessRecord({
        email: ['invalid-email', 'another@invalid'],
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'email',
            code: 'INVALID_EMAIL_FORMAT',
            severity: 'major',
          }),
        ])
      )
    })

    it('should warn about disposable email addresses', async () => {
      const mockEmailInstance = new mockEmailValidationService()
      mockEmailInstance.validateEmail = jest.fn().mockResolvedValue({
        isValid: true,
        confidence: 0.7,
        metadata: {
          provider: '10minutemail',
          disposable: true,
          role: false,
          deliverable: true,
        },
      })

      const business = createMockBusinessRecord({
        email: ['temp@10minutemail.com'],
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'email',
            code: 'DISPOSABLE_EMAIL',
          }),
        ])
      )
    })

    it('should handle email validation service errors gracefully', async () => {
      const mockEmailInstance = new mockEmailValidationService()
      mockEmailInstance.validateEmail = jest.fn().mockRejectedValue(new Error('Service unavailable'))

      const business = createMockBusinessRecord()
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'email',
            code: 'VALIDATION_SERVICE_ERROR',
          }),
        ])
      )
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'DataValidationPipeline',
        'Email validation service error',
        expect.any(Error)
      )
    })
  })

  describe('Phone Validation', () => {
    it('should validate and format phone numbers correctly', async () => {
      const business = createMockBusinessRecord({
        phone: '555-123-4567',
      })

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(true)
      expect(result.cleanedData?.phone).toBe('+15551234567')
    })

    it('should reject invalid phone numbers', async () => {
      const mockPhoneInstance = new mockPhoneValidationService()
      mockPhoneInstance.validatePhone = jest.fn().mockResolvedValue({
        isValid: false,
        formatted: null,
        type: 'unknown',
        carrier: null,
        location: null,
      })

      const business = createMockBusinessRecord({
        phone: '123',
      })

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'phone',
            code: 'INVALID_PHONE_FORMAT',
            severity: 'major',
          }),
        ])
      )
    })

    it('should handle international phone numbers', async () => {
      const mockPhoneInstance = new mockPhoneValidationService()
      mockPhoneInstance.validatePhone = jest.fn().mockResolvedValue({
        isValid: true,
        formatted: '+441234567890',
        type: 'mobile',
        carrier: 'Vodafone',
        location: 'London, UK',
      })

      const business = createMockBusinessRecord({
        phone: '+44 123 456 7890',
      })

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(true)
      expect(result.cleanedData?.phone).toBe('+441234567890')
    })
  })

  describe('Website Validation', () => {
    it('should validate website URLs correctly', async () => {
      const business = createMockBusinessRecord({
        websiteUrl: 'https://www.validwebsite.com',
      })

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(true)
      expect(result.cleanedData?.websiteUrl).toBe('https://www.validwebsite.com')
    })

    it('should normalize website URLs', async () => {
      const business = createMockBusinessRecord({
        websiteUrl: 'validwebsite.com',
      })

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.cleanedData?.websiteUrl).toBe('https://validwebsite.com')
    })

    it('should reject invalid website URLs', async () => {
      const business = createMockBusinessRecord({
        websiteUrl: 'not-a-valid-url',
      })

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'websiteUrl',
            code: 'INVALID_URL_FORMAT',
            severity: 'minor',
          }),
        ])
      )
    })
  })

  describe('Address Validation and Geocoding', () => {
    it('should validate and geocode complete addresses', async () => {
      const business = createMockBusinessRecord()
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(true)
      expect(result.cleanedData?.latitude).toBe(34.0522)
      expect(result.cleanedData?.longitude).toBe(-118.2437)
      expect(mockGeocoder.geocodeAddress).toHaveBeenCalledWith(
        '123 Main Street, Los Angeles, CA 90210, US'
      )
    })

    it('should handle geocoding failures gracefully', async () => {
      mockGeocoder.geocodeAddress.mockRejectedValue(new Error('Geocoding failed'))

      const business = createMockBusinessRecord()
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'address',
            code: 'GEOCODING_FAILED',
          }),
        ])
      )
    })

    it('should validate ZIP code format', async () => {
      const business = createMockBusinessRecord({
        address: {
          street: '123 Main Street',
          city: 'Los Angeles',
          state: 'CA',
          zipCode: 'INVALID',
          country: 'US',
        },
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.errors).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'zipCode',
            code: 'INVALID_ZIP_FORMAT',
            severity: 'major',
          }),
        ])
      )
    })
  })

  describe('Business Intelligence Integration', () => {
    it('should analyze business intelligence and provide insights', async () => {
      const business = createMockBusinessRecord()
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.isValid).toBe(true)
      expect(result.cleanedData?.businessIntelligence).toEqual({
        industryMatch: 0.95,
        businessSize: 'medium',
        marketPresence: 'strong',
        digitalFootprint: 'excellent',
        trustScore: 0.85,
        riskFactors: [],
        opportunities: ['digital_marketing', 'expansion'],
      })
    })

    it('should handle business intelligence service errors', async () => {
      const mockBIInstance = new mockBusinessIntelligenceService()
      mockBIInstance.analyzeBusinessIntelligence = jest.fn().mockRejectedValue(
        new Error('BI service unavailable')
      )

      const business = createMockBusinessRecord()
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.warnings).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'businessIntelligence',
            code: 'BI_SERVICE_ERROR',
          }),
        ])
      )
    })
  })

  describe('Data Cleaning and Normalization', () => {
    it('should clean and normalize business data', async () => {
      const business = createMockBusinessRecord({
        businessName: '  Test Business Inc.  ',
        email: ['  CONTACT@TESTBUSINESS.COM  '],
        phone: '555.123.4567',
        websiteUrl: 'HTTP://WWW.TESTBUSINESS.COM/',
      })

      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.cleanedData?.businessName).toBe('Test Business Inc.')
      expect(result.cleanedData?.email).toEqual(['contact@testbusiness.com'])
      expect(result.cleanedData?.websiteUrl).toBe('http://www.testbusiness.com')
    })

    it('should provide suggestions for data improvement', async () => {
      const business = createMockBusinessRecord({
        description: 'short',
      })
      
      const result = await dataValidationPipeline.validateAndClean(business)

      expect(result.suggestions).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            field: 'description',
            suggestion: 'Consider adding more detailed business description',
            impact: 'medium',
          }),
        ])
      )
    })
  })

  describe('Performance and Batch Processing', () => {
    it('should handle batch validation efficiently', async () => {
      const businesses = Array.from({ length: 10 }, (_, i) =>
        createMockBusinessRecord({ id: `business-${i}`, businessName: `Business ${i}` })
      )

      const results = await Promise.all(
        businesses.map(business => dataValidationPipeline.validateAndClean(business))
      )

      expect(results).toHaveLength(10)
      results.forEach(result => {
        expect(result.isValid).toBe(true)
        expect(result.confidence).toBeGreaterThan(0.8)
      })
    })

    it('should maintain performance with large datasets', async () => {
      const business = createMockBusinessRecord()
      const startTime = Date.now()
      
      await dataValidationPipeline.validateAndClean(business)
      
      const endTime = Date.now()
      const processingTime = endTime - startTime
      
      expect(processingTime).toBeLessThan(1000) // Should complete within 1 second
    })
  })
})
