/**
 * Integration Tests for Enhanced Data Validation Pipeline
 * Tests the complete data validation and enrichment workflow
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { DataValidationPipeline } from '@/lib/dataValidationPipeline'
import { BusinessRecord } from '@/types/business'

// Mock external dependencies
jest.mock('dns/promises', () => ({
  resolveMx: jest.fn()
}))

jest.mock('@/model/geocoder', () => ({
  geocoder: {
    geocodeAddress: jest.fn()
  }
}))

describe('Enhanced Data Validation Pipeline - Integration Tests', () => {
  let pipeline: DataValidationPipeline
  const mockResolveMx = require('dns/promises').resolveMx as jest.MockedFunction<any>
  const mockGeocoder = require('@/model/geocoder').geocoder

  beforeEach(() => {
    pipeline = new DataValidationPipeline()
    jest.clearAllMocks()
    
    // Setup default mocks
    mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
    mockGeocoder.geocodeAddress.mockResolvedValue({
      lat: 40.7128,
      lng: -74.0060
    })
  })

  describe('Complete Business Record Validation and Enrichment', () => {
    it('should validate and enrich a complete business record', async () => {
      const businessRecord: BusinessRecord = {
        id: 'test-business-1',
        businessName: 'Tech Solutions Inc.',
        email: ['contact@techsolutions.com', 'info@techsolutions.com'],
        phone: '(555) 123-4567',
        websiteUrl: 'https://techsolutions.com',
        address: {
          street: '123 Main St',
          city: 'New York',
          state: 'NY',
          zipCode: '10001'
        },
        industry: 'Technology',
        scrapedAt: new Date()
      }

      // Mock page for business intelligence
      const mockPage = {
        content: jest.fn().mockResolvedValue('<html><body>We have 25 employees and use WordPress</body></html>'),
        evaluate: jest.fn()
          .mockResolvedValueOnce('We have 25 employees and use WordPress') // text content
          .mockResolvedValueOnce(['/wp-content/script.js']) // scripts
          .mockResolvedValueOnce(['/wp-content/style.css']) // stylesheets
          .mockResolvedValueOnce([]) // headers
          .mockResolvedValueOnce([]) // social links
          .mockResolvedValueOnce([]) // widgets
      }

      // Perform validation and enrichment
      const validationResult = await pipeline.validateAndClean(businessRecord)
      const enrichmentResult = await pipeline.enrichData(businessRecord, mockPage)

      // Validate results
      expect(validationResult.isValid).toBe(true)
      expect(validationResult.confidence).toBeGreaterThan(0.7)
      expect(enrichmentResult.enriched).toBe(true)
      expect(enrichmentResult.addedFields.length).toBeGreaterThan(0)

      // Check email validation enrichment
      expect(businessRecord.emailValidation).toBeDefined()
      expect(businessRecord.emailValidation?.validationResults.length).toBe(2)
      expect(businessRecord.emailValidation?.overallConfidence).toBeGreaterThan(0)

      // Check phone validation enrichment
      expect(businessRecord.phoneValidation).toBeDefined()
      expect(businessRecord.phoneValidation?.isValid).toBe(true)
      expect(businessRecord.phoneValidation?.standardizedNumber).toBe('+15551234567')

      // Check business intelligence enrichment
      expect(businessRecord.businessIntelligence).toBeDefined()
      expect(businessRecord.businessIntelligence?.companySize?.employeeCount).toBe(25)
      expect(businessRecord.businessIntelligence?.technologyStack?.platforms?.length).toBeGreaterThan(0)

      // Check geocoding
      expect(businessRecord.coordinates).toBeDefined()
      expect(businessRecord.coordinates?.lat).toBe(40.7128)
      expect(businessRecord.coordinates?.lng).toBe(-74.0060)

      // Check overall data quality
      expect(businessRecord.dataQualityScore).toBeGreaterThan(70)
      expect(businessRecord.enrichmentSources).toContain('advanced_email_validation')
      expect(businessRecord.enrichmentSources).toContain('phone_intelligence')
      expect(businessRecord.enrichmentSources).toContain('business_intelligence')
    })

    it('should handle partial business records gracefully', async () => {
      const partialRecord: BusinessRecord = {
        id: 'partial-business',
        businessName: 'Small Shop',
        email: ['shop@example.com'],
        websiteUrl: 'https://smallshop.com',
        address: {
          street: '456 Oak St',
          city: 'Boston',
          state: 'MA',
          zipCode: '02101'
        },
        industry: 'Retail',
        scrapedAt: new Date()
        // No phone number
      }

      const validationResult = await pipeline.validateAndClean(partialRecord)
      const enrichmentResult = await pipeline.enrichData(partialRecord)

      expect(validationResult.isValid).toBe(true)
      expect(enrichmentResult.enriched).toBe(true)

      // Should have email validation but no phone validation
      expect(partialRecord.emailValidation).toBeDefined()
      expect(partialRecord.phoneValidation).toBeUndefined()

      // Should still have some data quality score
      expect(partialRecord.dataQualityScore).toBeGreaterThan(0)
    })

    it('should handle invalid data appropriately', async () => {
      const invalidRecord: BusinessRecord = {
        id: 'invalid-business',
        businessName: '',
        email: ['invalid-email', 'another-invalid'],
        phone: '123', // Invalid phone
        websiteUrl: 'not-a-url',
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: 'invalid'
        },
        industry: '',
        scrapedAt: new Date()
      }

      mockResolveMx.mockRejectedValue(new Error('No MX records'))

      const validationResult = await pipeline.validateAndClean(invalidRecord)
      const enrichmentResult = await pipeline.enrichData(invalidRecord)

      expect(validationResult.isValid).toBe(false)
      expect(validationResult.errors.length).toBeGreaterThan(0)

      // Should still attempt enrichment
      expect(enrichmentResult.enriched).toBe(true)
      expect(invalidRecord.dataQualityScore).toBeLessThan(50)
    })
  })

  describe('Email Validation Integration', () => {
    it('should perform comprehensive email validation', async () => {
      const businessRecord: BusinessRecord = {
        id: 'email-test',
        businessName: 'Email Test Co',
        email: ['test@gmail.com', 'info@company.com', 'spam@10minutemail.com'],
        websiteUrl: 'https://emailtest.com',
        address: {
          street: '123 Test St',
          city: 'Test City',
          state: 'TC',
          zipCode: '12345'
        },
        industry: 'Testing',
        scrapedAt: new Date()
      }

      await pipeline.validateAndClean(businessRecord)
      await pipeline.enrichData(businessRecord)

      expect(businessRecord.emailValidation).toBeDefined()
      expect(businessRecord.emailValidation?.validationResults.length).toBe(3)

      // Check that disposable email is detected
      const disposableEmail = businessRecord.emailValidation?.validationResults.find(
        r => r.email === 'spam@10minutemail.com'
      )
      expect(disposableEmail?.isDisposable).toBe(true)

      // Check that Gmail gets good reputation
      const gmailEmail = businessRecord.emailValidation?.validationResults.find(
        r => r.email === 'test@gmail.com'
      )
      expect(gmailEmail?.reputationScore).toBeGreaterThan(50)
    })
  })

  describe('Phone Validation Integration', () => {
    it('should perform comprehensive phone validation', async () => {
      const businessRecord: BusinessRecord = {
        id: 'phone-test',
        businessName: 'Phone Test Co',
        email: ['test@phonetest.com'],
        phone: '(212) 555-1234', // NYC number
        websiteUrl: 'https://phonetest.com',
        address: {
          street: '123 Broadway',
          city: 'New York',
          state: 'NY',
          zipCode: '10001'
        },
        industry: 'Testing',
        scrapedAt: new Date()
      }

      await pipeline.validateAndClean(businessRecord)
      await pipeline.enrichData(businessRecord)

      expect(businessRecord.phoneValidation).toBeDefined()
      expect(businessRecord.phoneValidation?.isValid).toBe(true)
      expect(businessRecord.phoneValidation?.standardizedNumber).toBe('+12125551234')
      expect(businessRecord.phoneValidation?.region).toContain('New York')
      expect(businessRecord.phoneValidation?.dncStatus).toBeDefined()
    })
  })

  describe('Business Intelligence Integration', () => {
    it('should perform comprehensive business intelligence enrichment', async () => {
      const businessRecord: BusinessRecord = {
        id: 'bi-test',
        businessName: 'Business Intelligence Corp',
        email: ['contact@bicorp.com'],
        websiteUrl: 'https://bicorp.com',
        address: {
          street: '123 Corporate Blvd',
          city: 'San Francisco',
          state: 'CA',
          zipCode: '94105'
        },
        industry: 'Technology',
        scrapedAt: new Date()
      }

      const mockPage = {
        content: jest.fn().mockResolvedValue(`
          <html>
            <head>
              <script src="https://www.google-analytics.com/analytics.js"></script>
              <link rel="stylesheet" href="/wp-content/themes/style.css">
            </head>
            <body>
              <p>Founded in 2010, we are an established company with 150 employees.</p>
              <p>Annual revenue of $25 million.</p>
              <a href="https://linkedin.com/company/bicorp">LinkedIn</a>
              <a href="https://twitter.com/bicorp">Twitter</a>
            </body>
          </html>
        `),
        evaluate: jest.fn()
          .mockResolvedValueOnce('Founded in 2010, we are an established company with 150 employees. Annual revenue of $25 million.')
          .mockResolvedValueOnce(['https://www.google-analytics.com/analytics.js', '/wp-content/script.js'])
          .mockResolvedValueOnce(['/wp-content/themes/style.css'])
          .mockResolvedValueOnce([])
          .mockResolvedValueOnce([
            { href: 'https://linkedin.com/company/bicorp', text: 'LinkedIn', title: '' },
            { href: 'https://twitter.com/bicorp', text: 'Twitter', title: '' }
          ])
          .mockResolvedValueOnce([])
      }

      await pipeline.enrichData(businessRecord, mockPage)

      expect(businessRecord.businessIntelligence).toBeDefined()

      // Company size
      expect(businessRecord.businessIntelligence?.companySize?.employeeCount).toBe(150)
      expect(businessRecord.businessIntelligence?.companySize?.employeeRange).toBe('51-200')

      // Revenue
      expect(businessRecord.businessIntelligence?.revenue?.estimatedRevenue).toBe(25000000)
      expect(businessRecord.businessIntelligence?.revenue?.revenueRange).toBe('$10M-$50M')

      // Maturity
      expect(businessRecord.businessIntelligence?.businessMaturity?.yearsInBusiness).toBeGreaterThan(10)
      expect(businessRecord.businessIntelligence?.businessMaturity?.maturityStage).toBe('mature')

      // Technology
      const techPlatforms = businessRecord.businessIntelligence?.technologyStack?.platforms
      expect(techPlatforms?.some(p => p.name === 'WordPress')).toBe(true)
      expect(techPlatforms?.some(p => p.name === 'Google Analytics')).toBe(true)

      // Social media
      const socialProfiles = businessRecord.businessIntelligence?.socialMediaPresence?.profiles
      expect(socialProfiles?.some(p => p.platform === 'LinkedIn')).toBe(true)
      expect(socialProfiles?.some(p => p.platform === 'Twitter')).toBe(true)
    })
  })

  describe('Data Quality Scoring', () => {
    it('should calculate accurate data quality scores', async () => {
      const highQualityRecord: BusinessRecord = {
        id: 'high-quality',
        businessName: 'High Quality Corp',
        email: ['ceo@highquality.com'],
        phone: '(555) 123-4567',
        websiteUrl: 'https://highquality.com',
        address: {
          street: '123 Quality St',
          city: 'Excellence',
          state: 'EX',
          zipCode: '12345'
        },
        industry: 'Quality Assurance',
        scrapedAt: new Date()
      }

      await pipeline.validateAndClean(highQualityRecord)
      await pipeline.enrichData(highQualityRecord)

      expect(highQualityRecord.dataQualityScore).toBeGreaterThan(70)

      const lowQualityRecord: BusinessRecord = {
        id: 'low-quality',
        businessName: '',
        email: ['invalid-email'],
        websiteUrl: 'not-a-url',
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: ''
        },
        industry: '',
        scrapedAt: new Date()
      }

      mockResolveMx.mockRejectedValue(new Error('No MX records'))

      await pipeline.validateAndClean(lowQualityRecord)
      await pipeline.enrichData(lowQualityRecord)

      expect(lowQualityRecord.dataQualityScore).toBeLessThan(30)
    })
  })

  describe('Performance and Caching', () => {
    it('should cache validation results for performance', async () => {
      const businessRecord1: BusinessRecord = {
        id: 'cache-test-1',
        businessName: 'Cache Test 1',
        email: ['test@cache.com'],
        websiteUrl: 'https://cache1.com',
        address: {
          street: '123 Cache St',
          city: 'Cache City',
          state: 'CC',
          zipCode: '12345'
        },
        industry: 'Testing',
        scrapedAt: new Date()
      }

      const businessRecord2: BusinessRecord = {
        id: 'cache-test-2',
        businessName: 'Cache Test 2',
        email: ['test@cache.com'], // Same email
        websiteUrl: 'https://cache2.com',
        address: {
          street: '456 Cache Ave',
          city: 'Cache City',
          state: 'CC',
          zipCode: '12345'
        },
        industry: 'Testing',
        scrapedAt: new Date()
      }

      // First validation
      await pipeline.validateAndClean(businessRecord1)
      await pipeline.enrichData(businessRecord1)

      // Second validation should use cached email results
      await pipeline.validateAndClean(businessRecord2)
      await pipeline.enrichData(businessRecord2)

      // Both should have email validation results
      expect(businessRecord1.emailValidation).toBeDefined()
      expect(businessRecord2.emailValidation).toBeDefined()

      // Email validation results should be similar due to caching
      expect(businessRecord1.emailValidation?.validationResults[0].confidence)
        .toBe(businessRecord2.emailValidation?.validationResults[0].confidence)
    })
  })

  describe('Error Recovery', () => {
    it('should continue enrichment even when some services fail', async () => {
      const businessRecord: BusinessRecord = {
        id: 'error-recovery',
        businessName: 'Error Recovery Co',
        email: ['test@errorrecovery.com'],
        phone: '(555) 123-4567',
        websiteUrl: 'https://errorrecovery.com',
        address: {
          street: '123 Error St',
          city: 'Recovery',
          state: 'RC',
          zipCode: '12345'
        },
        industry: 'Testing',
        scrapedAt: new Date()
      }

      // Simulate email validation failure
      mockResolveMx.mockRejectedValue(new Error('DNS failure'))

      // Simulate geocoding failure
      mockGeocoder.geocodeAddress.mockRejectedValue(new Error('Geocoding failure'))

      const validationResult = await pipeline.validateAndClean(businessRecord)
      const enrichmentResult = await pipeline.enrichData(businessRecord)

      // Should still complete with some results
      expect(validationResult).toBeDefined()
      expect(enrichmentResult).toBeDefined()

      // Phone validation should still work
      expect(businessRecord.phoneValidation).toBeDefined()

      // Should have some data quality score
      expect(businessRecord.dataQualityScore).toBeGreaterThan(0)
    })
  })
})
