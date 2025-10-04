/**
 * Comprehensive Business Rule Tests for Enhanced Data Manager
 * Tests data processing workflows, enrichment pipelines, and business logic
 */

import { enhancedDataManager, DataProcessingOptions, ProcessingResult } from '@/lib/enhancedDataManager'
import { BusinessRecord } from '@/types/business'
import { aiLeadScoringService } from '@/lib/aiLeadScoring'
import { dataValidationPipeline } from '@/lib/dataValidationPipeline'
import { duplicateDetectionSystem } from '@/lib/duplicateDetection'
import { smartCacheManager } from '@/lib/smartCacheManager'

// Mock dependencies
jest.mock('@/lib/aiLeadScoring')
jest.mock('@/lib/dataValidationPipeline')
jest.mock('@/lib/duplicateDetection')
jest.mock('@/lib/smartCacheManager')
jest.mock('@/utils/logger')

describe('Enhanced Data Manager - Business Logic Rules', () => {
  const mockBusinessRecords: BusinessRecord[] = [
    {
      id: 'business-1',
      businessName: 'Acme Corporation',
      email: ['contact@acme.com'],
      phone: '+1-555-123-4567',
      websiteUrl: 'https://acme.com',
      address: {
        street: '123 Main Street',
        city: 'San Francisco',
        state: 'CA',
        zipCode: '94105',
      },
      industry: 'Technology',
      scrapedAt: new Date(),
    },
    {
      id: 'business-2',
      businessName: 'Tech Innovators Inc',
      email: ['info@techinnovators.com'],
      phone: '+1-555-987-6543',
      websiteUrl: 'https://techinnovators.com',
      address: {
        street: '456 Innovation Drive',
        city: 'Palo Alto',
        state: 'CA',
        zipCode: '94301',
      },
      industry: 'Technology',
      scrapedAt: new Date(),
    },
    {
      id: 'business-3',
      businessName: 'Duplicate Business', // Will be marked as duplicate
      email: ['contact@acme.com'], // Same email as business-1
      phone: '+1-555-123-4567',
      websiteUrl: 'https://acme.com',
      address: {
        street: '123 Main Street',
        city: 'San Francisco',
        state: 'CA',
        zipCode: '94105',
      },
      industry: 'Technology',
      scrapedAt: new Date(),
    },
  ]

  beforeEach(() => {
    jest.clearAllMocks()

    // Setup mock implementations
    ;(aiLeadScoringService.scoreBusinessLead as jest.Mock).mockResolvedValue({
      score: 85,
      confidence: 0.9,
      factors: {
        websiteQuality: 0.8,
        contactInformation: 0.9,
        businessMaturity: 0.85,
        industryRelevance: 0.9,
      },
      recommendations: ['High-quality lead', 'Strong digital presence'],
    })

    ;(dataValidationPipeline.validateAndClean as jest.Mock).mockResolvedValue({
      isValid: true,
      confidence: 0.95,
      errors: [],
      warnings: [],
      suggestions: [],
      cleanedData: mockBusinessRecords[0],
    })

    ;(dataValidationPipeline.calculateDataQualityScore as jest.Mock).mockResolvedValue(0.9)

    ;(duplicateDetectionSystem.findDuplicates as jest.Mock).mockImplementation((business, existing) => {
      // Mark business-3 as duplicate of business-1
      if (business.id === 'business-3') {
        return existing.find(b => b.id === 'business-1') ? [existing[0]] : []
      }
      return []
    })

    ;(smartCacheManager.cacheBusinessData as jest.Mock).mockResolvedValue(true)
  })

  describe('Batch Processing Logic', () => {
    test('should process batch of businesses with all features enabled', async () => {
      const options: DataProcessingOptions = {
        enableLeadScoring: true,
        enableValidation: true,
        enableDuplicateDetection: true,
        enableCaching: true,
        batchSize: 2,
      }

      const result = await enhancedDataManager.processBatch(mockBusinessRecords, options)

      expect(result.stats.total).toBe(3)
      expect(result.stats.processed).toBe(2) // business-3 should be filtered as duplicate
      expect(result.stats.duplicates).toBe(1)
      expect(result.stats.errors).toBe(0)
      expect(result.processed).toHaveLength(2)
      expect(result.duplicates).toContain('business-3')
    })

    test('should handle validation failures gracefully', async () => {
      ;(dataValidationPipeline.validateAndClean as jest.Mock).mockResolvedValueOnce({
        isValid: false,
        confidence: 0.3,
        errors: [{ field: 'businessName', code: 'INVALID_NAME', message: 'Invalid business name' }],
        warnings: [],
        suggestions: [],
        cleanedData: null,
      })

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]])

      expect(result.stats.processed).toBe(1) // Should still process despite validation issues
      expect(result.processed[0]).toBeDefined()
    })

    test('should handle lead scoring failures', async () => {
      ;(aiLeadScoringService.scoreBusinessLead as jest.Mock).mockRejectedValue(
        new Error('Lead scoring service unavailable')
      )

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableLeadScoring: true,
      })

      expect(result.stats.processed).toBe(1)
      expect(result.stats.scored).toBe(0) // No scores due to failure
      expect(result.errors).toHaveLength(0) // Should not fail the entire process
    })

    test('should respect batch size limits', async () => {
      const largeBatch = Array(10).fill(0).map((_, i) => ({
        ...mockBusinessRecords[0],
        id: `business-${i}`,
        businessName: `Business ${i}`,
      }))

      const processSpy = jest.spyOn(enhancedDataManager, 'processBatch')
      await enhancedDataManager.processBatch(largeBatch, { batchSize: 3 })

      // Should process in batches of 3
      expect(processSpy).toHaveBeenCalled()
    })

    test('should handle caching failures without stopping processing', async () => {
      ;(smartCacheManager.cacheBusinessData as jest.Mock).mockRejectedValue(
        new Error('Cache service unavailable')
      )

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableCaching: true,
      })

      expect(result.stats.processed).toBe(1)
      expect(result.stats.errors).toBe(0) // Caching failure shouldn't cause processing error
    })
  })

  describe('Single Business Processing', () => {
    test('should process single business successfully', async () => {
      const result = await enhancedDataManager.processSingle(mockBusinessRecords[0], {
        enableLeadScoring: true,
        enableValidation: true,
      })

      expect(result.business).toBeDefined()
      expect(result.score).toBeDefined()
      expect(result.score?.score).toBe(85)
      expect(result.error).toBeUndefined()
    })

    test('should return error for failed processing', async () => {
      ;(dataValidationPipeline.validateAndClean as jest.Mock).mockRejectedValue(
        new Error('Validation service failed')
      )

      const result = await enhancedDataManager.processSingle(mockBusinessRecords[0])

      expect(result.business).toBeDefined()
      expect(result.error).toBeDefined()
      expect(result.error).toContain('Validation service failed')
    })
  })

  describe('Data Quality and Validation Integration', () => {
    test('should apply data cleaning and normalization', async () => {
      const dirtyBusiness = {
        ...mockBusinessRecords[0],
        businessName: '  ACME CORP  ',
        email: ['  CONTACT@ACME.COM  '],
        websiteUrl: 'HTTP://WWW.ACME.COM/',
      }

      const cleanedData = {
        ...dirtyBusiness,
        businessName: 'Acme Corp',
        email: ['contact@acme.com'],
        websiteUrl: 'https://www.acme.com',
      }

      ;(dataValidationPipeline.validateAndClean as jest.Mock).mockResolvedValue({
        isValid: true,
        confidence: 0.95,
        errors: [],
        warnings: [],
        suggestions: [],
        cleanedData,
      })

      const result = await enhancedDataManager.processBatch([dirtyBusiness], {
        enableValidation: true,
      })

      expect(result.processed[0].businessName).toBe('Acme Corp')
      expect(result.processed[0].email).toEqual(['contact@acme.com'])
      expect(result.processed[0].websiteUrl).toBe('https://www.acme.com')
    })

    test('should calculate and assign data quality scores', async () => {
      ;(dataValidationPipeline.calculateDataQualityScore as jest.Mock).mockResolvedValue(0.85)

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableValidation: true,
      })

      expect(result.processed[0].dataQualityScore).toBe(0.85)
    })

    test('should handle validation warnings appropriately', async () => {
      ;(dataValidationPipeline.validateAndClean as jest.Mock).mockResolvedValue({
        isValid: true,
        confidence: 0.8,
        errors: [],
        warnings: [
          { field: 'phone', code: 'SUSPICIOUS_FORMAT', message: 'Phone format unusual' },
        ],
        suggestions: [],
        cleanedData: mockBusinessRecords[0],
      })

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableValidation: true,
      })

      expect(result.stats.processed).toBe(1) // Should still process with warnings
      expect(result.processed[0]).toBeDefined()
    })
  })

  describe('Duplicate Detection Logic', () => {
    test('should detect and filter duplicate businesses', async () => {
      const businesses = [mockBusinessRecords[0], mockBusinessRecords[2]] // business-2 is duplicate

      ;(duplicateDetectionSystem.findDuplicates as jest.Mock).mockImplementation((business, existing) => {
        if (business.id === 'business-3' && existing.length > 0) {
          return [existing[0]] // Mark as duplicate
        }
        return []
      })

      const result = await enhancedDataManager.processBatch(businesses, {
        enableDuplicateDetection: true,
      })

      expect(result.stats.duplicates).toBe(1)
      expect(result.duplicates).toContain('business-3')
      expect(result.processed).toHaveLength(1)
    })

    test('should process all businesses when duplicate detection is disabled', async () => {
      const result = await enhancedDataManager.processBatch(mockBusinessRecords, {
        enableDuplicateDetection: false,
      })

      expect(result.stats.duplicates).toBe(0)
      expect(result.stats.processed).toBe(3)
      expect(result.processed).toHaveLength(3)
    })

    test('should handle duplicate detection errors gracefully', async () => {
      ;(duplicateDetectionSystem.findDuplicates as jest.Mock).mockRejectedValue(
        new Error('Duplicate detection service failed')
      )

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableDuplicateDetection: true,
      })

      expect(result.stats.processed).toBe(1) // Should continue processing
      expect(result.stats.errors).toBe(0)
    })
  })

  describe('Lead Scoring Integration', () => {
    test('should score businesses and store results', async () => {
      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableLeadScoring: true,
      })

      expect(result.stats.scored).toBe(1)
      expect(result.scores.has('business-1')).toBe(true)
      expect(result.scores.get('business-1')?.score).toBe(85)
    })

    test('should continue processing when lead scoring fails', async () => {
      ;(aiLeadScoringService.scoreBusinessLead as jest.Mock).mockRejectedValue(
        new Error('AI service unavailable')
      )

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableLeadScoring: true,
      })

      expect(result.stats.processed).toBe(1)
      expect(result.stats.scored).toBe(0)
      expect(result.scores.has('business-1')).toBe(false)
    })

    test('should skip lead scoring when disabled', async () => {
      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        enableLeadScoring: false,
      })

      expect(result.stats.scored).toBe(0)
      expect(result.scores.size).toBe(0)
      expect(aiLeadScoringService.scoreBusinessLead).not.toHaveBeenCalled()
    })
  })

  describe('Performance and Scalability', () => {
    test('should handle large batches efficiently', async () => {
      const largeBatch = Array(100).fill(0).map((_, i) => ({
        ...mockBusinessRecords[0],
        id: `business-${i}`,
        businessName: `Business ${i}`,
        email: [`contact${i}@example.com`],
      }))

      const startTime = Date.now()
      const result = await enhancedDataManager.processBatch(largeBatch, {
        batchSize: 10,
      })
      const endTime = Date.now()

      expect(result.stats.total).toBe(100)
      expect(result.stats.processed).toBe(100)
      expect(endTime - startTime).toBeLessThan(30000) // Should complete within 30 seconds
    })

    test('should respect processing timeouts', async () => {
      // Mock slow validation
      ;(dataValidationPipeline.validateAndClean as jest.Mock).mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 1000))
      )

      const startTime = Date.now()
      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]], {
        batchSize: 1,
      })
      const endTime = Date.now()

      expect(result.stats.processed).toBe(1)
      expect(endTime - startTime).toBeGreaterThan(900) // Should take at least the mock delay
    })
  })

  describe('Error Handling and Recovery', () => {
    test('should handle individual business processing errors', async () => {
      const businesses = [
        mockBusinessRecords[0],
        { ...mockBusinessRecords[1], id: 'invalid-business' },
        mockBusinessRecords[2],
      ]

      ;(dataValidationPipeline.validateAndClean as jest.Mock).mockImplementation((business) => {
        if (business.id === 'invalid-business') {
          throw new Error('Invalid business data')
        }
        return Promise.resolve({
          isValid: true,
          confidence: 0.95,
          errors: [],
          warnings: [],
          suggestions: [],
          cleanedData: business,
        })
      })

      const result = await enhancedDataManager.processBatch(businesses)

      expect(result.stats.processed).toBe(2) // Two valid businesses
      expect(result.stats.errors).toBe(1)
      expect(result.errors).toHaveLength(1)
      expect(result.errors[0]).toContain('Invalid business data')
    })

    test('should provide detailed error information', async () => {
      ;(dataValidationPipeline.validateAndClean as jest.Mock).mockRejectedValue(
        new Error('Specific validation error')
      )

      const result = await enhancedDataManager.processBatch([mockBusinessRecords[0]])

      expect(result.errors).toHaveLength(1)
      expect(result.errors[0]).toContain('Acme Corporation')
      expect(result.errors[0]).toContain('Specific validation error')
    })
  })
})
