/**
 * Tests for AI Lead Scoring Service
 */

import { AILeadScoringService } from '@/lib/aiLeadScoring'
import { BusinessRecord } from '@/types/business'

// Mock TensorFlow.js
jest.mock('@tensorflow/tfjs', () => ({
  sequential: jest.fn(() => ({
    add: jest.fn(),
    compile: jest.fn(),
    fit: jest.fn(() => Promise.resolve()),
    predict: jest.fn(() => ({
      data: jest.fn(() => Promise.resolve([0.75])),
      dispose: jest.fn(),
    })),
    dispose: jest.fn(),
  })),
  layers: {
    dense: jest.fn(() => ({})),
    dropout: jest.fn(() => ({})),
  },
  train: {
    adam: jest.fn(() => ({})),
  },
  tensor2d: jest.fn(() => ({
    dispose: jest.fn(),
  })),
}))

describe('AILeadScoringService', () => {
  let service: AILeadScoringService
  let mockBusiness: BusinessRecord

  beforeEach(() => {
    service = new AILeadScoringService()
    mockBusiness = {
      id: 'test-business-1',
      businessName: 'Test Company Inc.',
      email: ['contact@testcompany.com', 'info@testcompany.com'],
      phone: '+1-555-123-4567',
      websiteUrl: 'https://www.testcompany.com',
      address: {
        street: '123 Business St',
        suite: 'Suite 100',
        city: 'Business City',
        state: 'CA',
        zipCode: '90210',
      },
      contactPerson: 'John Doe',
      coordinates: {
        lat: 34.0522,
        lng: -118.2437,
      },
      industry: 'Technology',
      scrapedAt: new Date('2024-01-15T10:00:00Z'),
    }
  })

  afterEach(() => {
    service.dispose()
  })

  describe('initialization', () => {
    it('should initialize successfully', async () => {
      await expect(service.initialize()).resolves.not.toThrow()
    })

    it('should handle initialization errors gracefully', async () => {
      // Mock TensorFlow error
      const mockError = new Error('TensorFlow initialization failed')
      jest.spyOn(service as any, 'trainModel').mockRejectedValueOnce(mockError)

      await expect(service.initialize()).rejects.toThrow('TensorFlow initialization failed')
    })
  })

  describe('lead scoring', () => {
    beforeEach(async () => {
      await service.initialize()
    })

    it('should calculate lead score for complete business record', async () => {
      const result = await service.getLeadScore(mockBusiness)

      expect(result).toHaveProperty('score')
      expect(result).toHaveProperty('confidence')
      expect(result).toHaveProperty('factors')
      expect(result).toHaveProperty('recommendations')

      expect(result.score).toBeGreaterThanOrEqual(0)
      expect(result.score).toBeLessThanOrEqual(100)
      expect(result.confidence).toBeGreaterThanOrEqual(0)
      expect(result.confidence).toBeLessThanOrEqual(1)
    })

    it('should handle incomplete business records', async () => {
      const incompleteBusiness: BusinessRecord = {
        ...mockBusiness,
        email: [],
        phone: undefined,
        contactPerson: undefined,
        coordinates: undefined,
      }

      const result = await service.getLeadScore(incompleteBusiness)

      expect(result.score).toBeLessThan(mockBusiness.email.length > 0 ? 80 : 100)
      expect(result.factors.contactQuality).toBeLessThan(50)
    })

    it('should calculate data completeness correctly', async () => {
      const result = await service.getLeadScore(mockBusiness)

      // Complete business should have high data completeness
      expect(result.factors.dataCompleteness).toBeGreaterThan(80)
    })

    it('should calculate contact quality correctly', async () => {
      const result = await service.getLeadScore(mockBusiness)

      // Business with multiple emails, phone, and contact person should have high contact quality
      expect(result.factors.contactQuality).toBeGreaterThan(70)
    })

    it('should calculate industry relevance based on configuration', async () => {
      const result = await service.getLeadScore(mockBusiness)

      // Technology industry should have high relevance in default config
      expect(result.factors.industryRelevance).toBeGreaterThan(80)
    })

    it('should calculate geographic desirability based on state', async () => {
      const result = await service.getLeadScore(mockBusiness)

      // California should have high geographic desirability in default config
      expect(result.factors.geographicDesirability).toBeGreaterThan(80)
    })

    it('should provide relevant recommendations', async () => {
      const result = await service.getLeadScore(mockBusiness)

      expect(result.recommendations).toBeInstanceOf(Array)
      expect(result.recommendations.length).toBeGreaterThan(0)

      if (result.score >= 80) {
        expect(
          result.recommendations.some(
            rec => rec.includes('High-quality lead') || rec.includes('prioritize')
          )
        ).toBe(true)
      }
    })
  })

  describe('batch scoring', () => {
    beforeEach(async () => {
      await service.initialize()
    })

    it('should score multiple businesses', async () => {
      const businesses = [
        mockBusiness,
        { ...mockBusiness, id: 'test-business-2', businessName: 'Another Company' },
        { ...mockBusiness, id: 'test-business-3', businessName: 'Third Company' },
      ]

      const scores = await service.scoreBusinesses(businesses)

      expect(scores.size).toBe(3)
      expect(scores.has('test-business-1')).toBe(true)
      expect(scores.has('test-business-2')).toBe(true)
      expect(scores.has('test-business-3')).toBe(true)
    })

    it('should handle errors in batch scoring gracefully', async () => {
      const businesses = [
        mockBusiness,
        { ...mockBusiness, id: 'invalid-business', businessName: null as any }, // Invalid data
      ]

      const scores = await service.scoreBusinesses(businesses)

      // Should still score the valid business
      expect(scores.has('test-business-1')).toBe(true)
      // Invalid business should not be scored
      expect(scores.has('invalid-business')).toBe(false)
    })
  })

  describe('configuration management', () => {
    it('should update configuration', () => {
      const newConfig = {
        weights: {
          dataCompleteness: 0.3,
          contactQuality: 0.3,
          businessSize: 0.1,
          industryRelevance: 0.1,
          geographicDesirability: 0.1,
          webPresence: 0.1,
        },
      }

      expect(() => service.updateConfig(newConfig)).not.toThrow()

      const currentConfig = service.getConfig()
      expect(currentConfig.weights.dataCompleteness).toBe(0.3)
      expect(currentConfig.weights.contactQuality).toBe(0.3)
    })

    it('should return current configuration', () => {
      const config = service.getConfig()

      expect(config).toHaveProperty('weights')
      expect(config).toHaveProperty('industryPriorities')
      expect(config).toHaveProperty('geographicPriorities')
      expect(config).toHaveProperty('minimumScore')
      expect(config).toHaveProperty('confidenceThreshold')
    })
  })

  describe('fallback behavior', () => {
    it('should use rule-based scoring when ML model fails', async () => {
      await service.initialize()

      // Mock ML model failure
      jest
        .spyOn(service as any, 'calculateMLScore')
        .mockRejectedValueOnce(new Error('ML model error'))

      const result = await service.getLeadScore(mockBusiness)

      // Should still return a valid score using rule-based fallback
      expect(result.score).toBeGreaterThanOrEqual(0)
      expect(result.score).toBeLessThanOrEqual(100)
      expect(result.confidence).toBe(0.5) // Fallback confidence
    })
  })

  describe('edge cases', () => {
    beforeEach(async () => {
      await service.initialize()
    })

    it('should handle business with no email', async () => {
      const businessNoEmail = { ...mockBusiness, email: [] }
      const result = await service.getLeadScore(businessNoEmail)

      expect(result.factors.contactQuality).toBeLessThan(50)
    })

    it('should handle business with unknown industry', async () => {
      const businessUnknownIndustry = { ...mockBusiness, industry: 'Unknown Industry' }
      const result = await service.getLeadScore(businessUnknownIndustry)

      expect(result.factors.industryRelevance).toBe(50) // Default relevance
    })

    it('should handle business with unknown state', async () => {
      const businessUnknownState = {
        ...mockBusiness,
        address: { ...mockBusiness.address, state: 'XX' },
      }
      const result = await service.getLeadScore(businessUnknownState)

      expect(result.factors.geographicDesirability).toBe(50) // Default desirability
    })

    it('should handle business with no website', async () => {
      const businessNoWebsite = { ...mockBusiness, websiteUrl: '' }
      const result = await service.getLeadScore(businessNoWebsite)

      expect(result.factors.webPresence).toBe(0)
    })

    it('should enforce minimum score', async () => {
      const veryPoorBusiness: BusinessRecord = {
        id: 'poor-business',
        businessName: 'Poor Company',
        email: [],
        websiteUrl: '',
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: '',
        },
        industry: '',
        scrapedAt: new Date(),
      }

      const result = await service.getLeadScore(veryPoorBusiness)

      expect(result.score).toBeGreaterThanOrEqual(service.getConfig().minimumScore)
    })
  })

  describe('memory management', () => {
    it('should dispose of resources properly', async () => {
      await service.initialize()

      expect(() => service.dispose()).not.toThrow()
    })

    it('should handle multiple dispose calls', async () => {
      await service.initialize()

      service.dispose()
      expect(() => service.dispose()).not.toThrow()
    })
  })
})
