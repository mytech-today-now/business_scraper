/**
 * Enhanced Data Manager - Comprehensive Test Suite
 * Tests data processing, validation, transformation, and AI lead scoring
 */

import { enhancedDataManager, DataProcessingOptions } from '@/lib/enhancedDataManager'
import { BusinessRecord } from '@/types/business'
import { aiLeadScoringService } from '@/lib/aiLeadScoring'
import { dataValidationPipeline } from '@/lib/dataValidationPipeline'
import { duplicateDetectionSystem } from '@/lib/duplicateDetection'
import { smartCacheManager } from '@/lib/smartCacheManager'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/lib/aiLeadScoring')
jest.mock('@/lib/dataValidationPipeline')
jest.mock('@/lib/duplicateDetection')
jest.mock('@/lib/smartCacheManager')
jest.mock('@/utils/logger')

const mockAiLeadScoringService = aiLeadScoringService as jest.Mocked<typeof aiLeadScoringService>
const mockDataValidationPipeline = dataValidationPipeline as jest.Mocked<typeof dataValidationPipeline>
const mockDuplicateDetectionSystem = duplicateDetectionSystem as jest.Mocked<typeof duplicateDetectionSystem>
const mockSmartCacheManager = smartCacheManager as jest.Mocked<typeof smartCacheManager>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('Enhanced Data Manager - Comprehensive Tests', () => {
  const createMockBusinessRecord = (overrides: Partial<BusinessRecord> = {}): BusinessRecord => ({
    id: 'test-business-1',
    businessName: 'Test Business',
    email: ['test@business.com'],
    phone: ['555-0123'],
    website: 'https://testbusiness.com',
    streetName: 'Main St',
    streetNumber: '123',
    city: 'Test City',
    state: 'CA',
    zipCode: '90210',
    industry: 'Technology',
    description: 'A test business',
    scrapedAt: new Date(),
    source: 'test',
    ...overrides,
  })

  beforeEach(() => {
    jest.clearAllMocks()
    
    // Setup default mocks
    mockAiLeadScoringService.initialize.mockResolvedValue()
    mockAiLeadScoringService.getLeadScore.mockResolvedValue({
      score: 75,
      confidence: 0.8,
      factors: {
        contactability: { score: 80, weight: 0.3, details: 'Good contact info' },
        businessMaturity: { score: 70, weight: 0.25, details: 'Established business' },
        marketPotential: { score: 75, weight: 0.25, details: 'Good market potential' },
        engagementLikelihood: { score: 80, weight: 0.2, details: 'High engagement likelihood' },
      },
      recommendations: ['Contact via email', 'Follow up within 24 hours'],
    })

    mockDataValidationPipeline.validateBusiness.mockResolvedValue({
      isValid: true,
      confidence: 0.9,
      errors: [],
      warnings: [],
      suggestions: [],
      cleanedData: {},
    })

    mockDuplicateDetectionSystem.findDuplicates.mockResolvedValue([])
    mockSmartCacheManager.get.mockResolvedValue(null)
    mockSmartCacheManager.set.mockResolvedValue()
  })

  describe('Initialization', () => {
    it('should initialize all dependencies correctly', async () => {
      await enhancedDataManager.initialize()

      expect(mockAiLeadScoringService.initialize).toHaveBeenCalled()
      expect(mockLogger.info).toHaveBeenCalledWith(
        'EnhancedDataManager',
        'Initialized with AI lead scoring, validation, and caching'
      )
    })

    it('should handle initialization errors gracefully', async () => {
      mockAiLeadScoringService.initialize.mockRejectedValue(new Error('AI service unavailable'))

      await expect(enhancedDataManager.initialize()).rejects.toThrow('AI service unavailable')
      expect(mockLogger.error).toHaveBeenCalledWith(
        'EnhancedDataManager',
        'Failed to initialize',
        expect.any(Error)
      )
    })
  })

  describe('Single Business Processing', () => {
    it('should process a single business with all features enabled', async () => {
      const business = createMockBusinessRecord()
      
      const result = await enhancedDataManager.processSingle(business, {
        enableLeadScoring: true,
        enableValidation: true,
        enableDuplicateDetection: true,
        enableCaching: true,
      })

      expect(result.processed).toEqual(business)
      expect(result.score).toEqual({
        score: 75,
        confidence: 0.8,
        factors: expect.any(Object),
        recommendations: expect.any(Array),
      })
      expect(result.validation).toEqual({
        isValid: true,
        confidence: 0.9,
        errors: [],
        warnings: [],
        suggestions: [],
        cleanedData: {},
      })
      expect(result.duplicates).toEqual([])

      expect(mockAiLeadScoringService.getLeadScore).toHaveBeenCalledWith(business)
      expect(mockDataValidationPipeline.validateBusiness).toHaveBeenCalledWith(business)
      expect(mockDuplicateDetectionSystem.findDuplicates).toHaveBeenCalledWith([business])
    })

    it('should skip lead scoring when disabled', async () => {
      const business = createMockBusinessRecord()
      
      const result = await enhancedDataManager.processSingle(business, {
        enableLeadScoring: false,
      })

      expect(result.score).toBeUndefined()
      expect(mockAiLeadScoringService.getLeadScore).not.toHaveBeenCalled()
    })

    it('should skip validation when disabled', async () => {
      const business = createMockBusinessRecord()
      
      const result = await enhancedDataManager.processSingle(business, {
        enableValidation: false,
      })

      expect(result.validation).toBeUndefined()
      expect(mockDataValidationPipeline.validateBusiness).not.toHaveBeenCalled()
    })

    it('should handle lead scoring errors gracefully', async () => {
      const business = createMockBusinessRecord()
      mockAiLeadScoringService.getLeadScore.mockRejectedValue(new Error('Scoring failed'))
      
      const result = await enhancedDataManager.processSingle(business)

      expect(result.processed).toEqual(business)
      expect(result.score).toBeUndefined()
      expect(mockLogger.error).toHaveBeenCalledWith(
        'EnhancedDataManager',
        'Lead scoring failed for business: test-business-1',
        expect.any(Error)
      )
    })

    it('should handle validation errors gracefully', async () => {
      const business = createMockBusinessRecord()
      mockDataValidationPipeline.validateBusiness.mockRejectedValue(new Error('Validation failed'))
      
      const result = await enhancedDataManager.processSingle(business)

      expect(result.processed).toEqual(business)
      expect(result.validation).toBeUndefined()
      expect(mockLogger.error).toHaveBeenCalledWith(
        'EnhancedDataManager',
        'Validation failed for business: test-business-1',
        expect.any(Error)
      )
    })
  })

  describe('Batch Processing', () => {
    it('should process multiple businesses in batches', async () => {
      const businesses = [
        createMockBusinessRecord({ id: 'business-1', businessName: 'Business 1' }),
        createMockBusinessRecord({ id: 'business-2', businessName: 'Business 2' }),
        createMockBusinessRecord({ id: 'business-3', businessName: 'Business 3' }),
      ]

      const result = await enhancedDataManager.processBatch(businesses, {
        batchSize: 2,
      })

      expect(result.processed).toHaveLength(3)
      expect(result.stats.total).toBe(3)
      expect(result.stats.processed).toBe(3)
      expect(result.stats.scored).toBe(3)
      expect(result.stats.errors).toBe(0)

      expect(mockAiLeadScoringService.getLeadScore).toHaveBeenCalledTimes(3)
      expect(mockDataValidationPipeline.validateBusiness).toHaveBeenCalledTimes(3)
    })

    it('should handle empty batch gracefully', async () => {
      const result = await enhancedDataManager.processBatch([])

      expect(result.processed).toHaveLength(0)
      expect(result.stats.total).toBe(0)
      expect(result.stats.processed).toBe(0)
    })

    it('should continue processing when individual businesses fail', async () => {
      const businesses = [
        createMockBusinessRecord({ id: 'business-1' }),
        createMockBusinessRecord({ id: 'business-2' }),
        createMockBusinessRecord({ id: 'business-3' }),
      ]

      // Make the second business fail
      mockAiLeadScoringService.getLeadScore
        .mockResolvedValueOnce({
          score: 75,
          confidence: 0.8,
          factors: expect.any(Object),
          recommendations: [],
        })
        .mockRejectedValueOnce(new Error('Scoring failed'))
        .mockResolvedValueOnce({
          score: 80,
          confidence: 0.9,
          factors: expect.any(Object),
          recommendations: [],
        })

      const result = await enhancedDataManager.processBatch(businesses)

      expect(result.processed).toHaveLength(3)
      expect(result.stats.processed).toBe(3)
      expect(result.stats.scored).toBe(2) // Only 2 successful scores
      expect(result.stats.errors).toBe(1)
      expect(result.errors).toHaveLength(1)
      expect(result.errors[0]).toEqual({
        businessId: 'business-2',
        error: 'Scoring failed',
        step: 'lead_scoring',
      })
    })
  })

  describe('Duplicate Detection', () => {
    it('should detect and handle duplicates correctly', async () => {
      const businesses = [
        createMockBusinessRecord({ id: 'business-1' }),
        createMockBusinessRecord({ id: 'business-2' }),
      ]

      mockDuplicateDetectionSystem.findDuplicates.mockResolvedValue([
        {
          original: businesses[0],
          duplicates: [businesses[1]],
          confidence: 0.95,
          matchingFields: ['businessName', 'email'],
        },
      ])

      const result = await enhancedDataManager.processBatch(businesses)

      expect(result.duplicates).toHaveLength(1)
      expect(result.duplicates[0].confidence).toBe(0.95)
      expect(result.stats.duplicates).toBe(1)
    })
  })

  describe('Caching', () => {
    it('should use cached results when available', async () => {
      const business = createMockBusinessRecord()
      const cachedResult = {
        processed: business,
        score: { score: 85, confidence: 0.9, factors: {}, recommendations: [] },
        validation: { isValid: true, confidence: 1.0, errors: [], warnings: [], suggestions: [] },
        duplicates: [],
      }

      mockSmartCacheManager.get.mockResolvedValue(cachedResult)

      const result = await enhancedDataManager.processSingle(business, {
        enableCaching: true,
      })

      expect(result).toEqual(cachedResult)
      expect(mockAiLeadScoringService.getLeadScore).not.toHaveBeenCalled()
      expect(mockDataValidationPipeline.validateBusiness).not.toHaveBeenCalled()
    })

    it('should cache results after processing', async () => {
      const business = createMockBusinessRecord()
      
      await enhancedDataManager.processSingle(business, {
        enableCaching: true,
      })

      expect(mockSmartCacheManager.set).toHaveBeenCalledWith(
        expect.stringContaining('enhanced_data_'),
        expect.any(Object),
        expect.any(Number)
      )
    })
  })

  describe('Performance and Memory Management', () => {
    it('should handle large batches efficiently', async () => {
      const businesses = Array.from({ length: 100 }, (_, i) =>
        createMockBusinessRecord({ id: `business-${i}`, businessName: `Business ${i}` })
      )

      const result = await enhancedDataManager.processBatch(businesses, {
        batchSize: 10,
      })

      expect(result.processed).toHaveLength(100)
      expect(result.stats.total).toBe(100)
      expect(result.stats.processed).toBe(100)
    })

    it('should respect batch size limits', async () => {
      const businesses = Array.from({ length: 25 }, (_, i) =>
        createMockBusinessRecord({ id: `business-${i}` })
      )

      await enhancedDataManager.processBatch(businesses, {
        batchSize: 5,
      })

      // Should process in 5 batches of 5 each
      expect(mockLogger.info).toHaveBeenCalledWith(
        'EnhancedDataManager',
        'Processing 25 businesses'
      )
    })
  })

  describe('Error Recovery and Resilience', () => {
    it('should continue processing after dependency failures', async () => {
      const businesses = [
        createMockBusinessRecord({ id: 'business-1' }),
        createMockBusinessRecord({ id: 'business-2' }),
      ]

      // Simulate intermittent failures
      mockAiLeadScoringService.getLeadScore
        .mockRejectedValueOnce(new Error('Temporary failure'))
        .mockResolvedValueOnce({
          score: 80,
          confidence: 0.8,
          factors: expect.any(Object),
          recommendations: [],
        })

      const result = await enhancedDataManager.processBatch(businesses)

      expect(result.processed).toHaveLength(2)
      expect(result.stats.errors).toBe(1)
      expect(result.stats.scored).toBe(1)
    })

    it('should provide detailed error information', async () => {
      const business = createMockBusinessRecord()
      const error = new Error('Detailed error message')
      mockAiLeadScoringService.getLeadScore.mockRejectedValue(error)

      const result = await enhancedDataManager.processSingle(business)

      expect(result.processed).toEqual(business)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'EnhancedDataManager',
        'Lead scoring failed for business: test-business-1',
        error
      )
    })
  })
})
