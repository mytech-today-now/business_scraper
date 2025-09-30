'use strict'

/**
 * AI Service Unit Tests
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { AIService } from '@/lib/aiService'
import { BusinessRecord } from '@/types/business'
import { AIServiceConfig } from '@/types/ai'

// Mock dependencies
jest.mock('@tensorflow/tfjs', () => ({
  ready: jest.fn().mockResolvedValue(undefined),
  sequential: jest.fn().mockReturnValue({
    compile: jest.fn(),
    predict: jest.fn().mockReturnValue({
      data: jest.fn().mockResolvedValue([0.75]),
      dispose: jest.fn(),
    }),
  }),
  layers: {
    dense: jest.fn().mockReturnValue({}),
    dropout: jest.fn().mockReturnValue({}),
  },
  tensor2d: jest.fn().mockReturnValue({}),
}))

jest.mock('@huggingface/inference', () => ({
  HfInference: jest.fn().mockImplementation(() => ({})),
}))

describe('AIService', () => {
  let aiService: AIService
  let mockConfig: AIServiceConfig

  beforeEach(() => {
    mockConfig = {
      enabled: true,
      models: {
        leadScoring: {
          name: 'leadScoring',
          version: '1.0.0',
          type: 'classification',
          features: ['website', 'phone', 'email'],
          parameters: {},
          trainingInfo: {
            datasetSize: 1000,
            lastTrainedAt: new Date(),
            accuracy: 0.85,
            precision: 0.82,
            recall: 0.88,
          },
        },
        websiteQuality: {
          name: 'websiteQuality',
          version: '1.0.0',
          type: 'regression',
          features: ['loadTime', 'mobileOptimized'],
          parameters: {},
          trainingInfo: {
            datasetSize: 500,
            lastTrainedAt: new Date(),
            accuracy: 0.78,
            precision: 0.75,
            recall: 0.8,
          },
        },
        conversionPrediction: {
          name: 'conversionPrediction',
          version: '1.0.0',
          type: 'classification',
          features: ['leadScore', 'websiteQuality'],
          parameters: {},
          trainingInfo: {
            datasetSize: 800,
            lastTrainedAt: new Date(),
            accuracy: 0.72,
            precision: 0.7,
            recall: 0.75,
          },
        },
      },
      apis: {
        huggingFace: {
          apiKey: 'test-key',
          model: 'test-model',
        },
        lighthouse: {
          enabled: true,
          timeout: 30000,
        },
      },
      performance: {
        batchSize: 10,
        maxConcurrentAnalysis: 3,
        cacheResults: true,
        cacheTTL: 3600000,
      },
    }

    aiService = new AIService(mockConfig)
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Initialization', () => {
    it('should initialize successfully with valid config', async () => {
      await aiService.initialize()
      expect(aiService.isInitialized()).toBe(true)
    })

    it('should handle initialization with disabled config', async () => {
      const disabledConfig = { ...mockConfig, enabled: false }
      const disabledService = new AIService(disabledConfig)

      await disabledService.initialize()
      expect(disabledService.isInitialized()).toBe(false)
    })

    it('should return correct configuration', () => {
      const config = aiService.getConfig()
      expect(config).toEqual(mockConfig)
    })
  })

  describe('Business Analysis', () => {
    let mockBusiness: BusinessRecord

    beforeEach(() => {
      mockBusiness = {
        id: 'test-business-1',
        businessName: 'Test Business',
        contactPerson: 'John Doe',
        email: ['test@business.com'],
        phone: '+1-555-123-4567',
        websiteUrl: 'https://testbusiness.com',
        address: {
          street: '123 Main St',
          city: 'Test City',
          state: 'TS',
          zipCode: '12345',
        },
        industry: 'Technology',
        // Note: description is not part of BusinessRecord type
        scrapedAt: new Date(),
        // Note: website is not part of BusinessRecord type, use websiteUrl instead
      }
    })

    it('should analyze business record successfully', async () => {
      await aiService.initialize()

      const analytics = await aiService.analyzeBusinessRecord(mockBusiness)

      expect(analytics).toBeDefined()
      expect(analytics.leadScoring).toBeDefined()
      expect(analytics.websiteQuality).toBeDefined()
      expect(analytics.businessMaturity).toBeDefined()
      expect(analytics.conversionPrediction).toBeDefined()
      expect(analytics.recommendation).toBeDefined()
      expect(analytics.generatedAt).toBeInstanceOf(Date)
    })

    it('should generate lead score within valid range', async () => {
      await aiService.initialize()

      const analytics = await aiService.analyzeBusinessRecord(mockBusiness)

      expect(analytics.leadScoring.overallScore).toBeGreaterThanOrEqual(0)
      expect(analytics.leadScoring.overallScore).toBeLessThanOrEqual(100)
      expect(analytics.leadScoring.confidence).toBeGreaterThanOrEqual(0)
      expect(analytics.leadScoring.confidence).toBeLessThanOrEqual(1)
    })

    it('should include all required component scores', async () => {
      await aiService.initialize()

      const analytics = await aiService.analyzeBusinessRecord(mockBusiness)
      const components = analytics.leadScoring.components

      expect(components.websiteQuality).toBeDefined()
      expect(components.businessMaturity).toBeDefined()
      expect(components.conversionProbability).toBeDefined()
      expect(components.industryRelevance).toBeDefined()

      // All scores should be in valid range
      Object.values(components).forEach(score => {
        expect(score).toBeGreaterThanOrEqual(0)
        expect(score).toBeLessThanOrEqual(100)
      })
    })

    it('should generate website quality analysis', async () => {
      await aiService.initialize()

      const analytics = await aiService.analyzeBusinessRecord(mockBusiness)
      const websiteQuality = analytics.websiteQuality

      expect(websiteQuality.healthScore).toBeGreaterThanOrEqual(0)
      expect(websiteQuality.healthScore).toBeLessThanOrEqual(100)
      expect(websiteQuality.lighthouse).toBeDefined()
      expect(websiteQuality.content).toBeDefined()
      expect(websiteQuality.technical).toBeDefined()
      expect(websiteQuality.analyzedAt).toBeInstanceOf(Date)
    })

    it('should generate business maturity indicators', async () => {
      await aiService.initialize()

      const analytics = await aiService.analyzeBusinessRecord(mockBusiness)
      const maturity = analytics.businessMaturity

      expect(maturity.maturityScore).toBeGreaterThanOrEqual(0)
      expect(maturity.maturityScore).toBeLessThanOrEqual(100)
      expect(maturity.growthSignals).toBeDefined()
      expect(maturity.sizeIndicators).toBeDefined()
      expect(maturity.digitalPresence).toBeDefined()
      expect(maturity.analyzedAt).toBeInstanceOf(Date)
    })

    it('should generate conversion prediction', async () => {
      await aiService.initialize()

      const analytics = await aiService.analyzeBusinessRecord(mockBusiness)
      const prediction = analytics.conversionPrediction

      expect(prediction.probability).toBeGreaterThanOrEqual(0)
      expect(prediction.probability).toBeLessThanOrEqual(1)
      expect(prediction.confidenceInterval).toBeDefined()
      expect(prediction.factors).toBeDefined()
      expect(prediction.recommendedStrategy).toBeDefined()
      expect(prediction.bestContactTime).toBeDefined()
      expect(prediction.predictedAt).toBeInstanceOf(Date)
    })

    it('should generate appropriate recommendations', async () => {
      await aiService.initialize()

      const analytics = await aiService.analyzeBusinessRecord(mockBusiness)
      const recommendation = analytics.recommendation

      expect(recommendation.priority).toMatch(/^(high|medium|low)$/)
      expect(recommendation.reasoning).toBeDefined()
      expect(recommendation.nextSteps).toBeInstanceOf(Array)
      expect(recommendation.estimatedValue).toBeDefined()
    })
  })

  describe('Error Handling', () => {
    it('should handle business without website gracefully', async () => {
      await aiService.initialize()

      const businessWithoutWebsite: BusinessRecord = {
        id: 'test-business-2',
        businessName: 'Test Business No Website',
        contactPerson: 'Jane Doe',
        email: ['jane@business.com'],
        phone: '+1-555-987-6543',
        websiteUrl: '',
        address: {
          street: '456 Oak St',
          city: 'Test City',
          state: 'TS',
          zipCode: '12345',
        },
        industry: 'Retail',
        // Note: description is not part of BusinessRecord type
        scrapedAt: new Date(),
        // Note: website is not part of BusinessRecord type
      }

      const analytics = await aiService.analyzeBusinessRecord(businessWithoutWebsite)

      expect(analytics).toBeDefined()
      expect(analytics.leadScoring.overallScore).toBeGreaterThanOrEqual(0)
      expect(analytics.websiteQuality.healthScore).toBe(0) // No website = 0 score
    })

    it('should handle incomplete business data', async () => {
      await aiService.initialize()

      const incompleteBusiness: BusinessRecord = {
        id: 'test-business-3',
        businessName: 'Incomplete Business',
        contactPerson: '',
        email: [],
        phone: '',
        websiteUrl: '',
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: '',
        },
        industry: '',
        // Note: description is not part of BusinessRecord type
        scrapedAt: new Date(),
        // Note: website is not part of BusinessRecord type
      }

      const analytics = await aiService.analyzeBusinessRecord(incompleteBusiness)

      expect(analytics).toBeDefined()
      expect(analytics.leadScoring.overallScore).toBeGreaterThanOrEqual(0)
      expect(analytics.leadScoring.overallScore).toBeLessThanOrEqual(100)
    })

    it('should handle analysis errors gracefully', async () => {
      // Mock an error in the analysis process
      const errorService = new AIService(mockConfig)

      // Override the analyzeBusinessRecord method to throw an error
      jest
        .spyOn(errorService as any, 'calculateLeadScore')
        .mockRejectedValue(new Error('Test error'))

      await expect(errorService.initialize()).resolves.not.toThrow()

      const mockBusiness: BusinessRecord = {
        id: 'error-business',
        businessName: 'Error Business',
        contactPerson: '',
        email: [],
        phone: '',
        websiteUrl: '',
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: '',
        },
        industry: '',
        // Note: description is not part of BusinessRecord type
        scrapedAt: new Date(),
        // Note: website is not part of BusinessRecord type
      }

      await expect(errorService.analyzeBusinessRecord(mockBusiness)).rejects.toThrow('Test error')
    })
  })

  describe('Configuration Management', () => {
    it('should handle missing HuggingFace API key', () => {
      const configWithoutKey = {
        ...mockConfig,
        apis: {
          ...mockConfig.apis,
          huggingFace: {
            apiKey: null,
            model: 'test-model',
          },
        },
      }

      const serviceWithoutKey = new AIService(configWithoutKey)
      expect(() => serviceWithoutKey).not.toThrow()
    })

    it('should validate performance settings', () => {
      const config = aiService.getConfig()

      expect(config.performance.batchSize).toBeGreaterThan(0)
      expect(config.performance.maxConcurrentAnalysis).toBeGreaterThan(0)
      expect(config.performance.cacheTTL).toBeGreaterThan(0)
      expect(typeof config.performance.cacheResults).toBe('boolean')
    })
  })
})
