/**
 * Integration Tests for AI/ML Workflow
 * Tests the complete AI lead scoring and business intelligence pipeline
 */

import { enhancedDataManager } from '@/lib/enhancedDataManager'
import { aiLeadScoringService } from '@/lib/aiLeadScoring'
import { BusinessRecord } from '@/types/business'

// Mock external dependencies
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

jest.mock('@/lib/dataValidationPipeline', () => ({
  dataValidationPipeline: {
    validateAndClean: jest.fn(business => ({
      isValid: true,
      cleanedData: business,
      errors: [],
    })),
    calculateDataQualityScore: jest.fn(() => Promise.resolve(85)),
  },
}))

jest.mock('@/lib/duplicateDetection', () => ({
  duplicateDetectionSystem: {
    compareRecords: jest.fn(() => Promise.resolve({ isDuplicate: false, similarity: 0.1 })),
  },
}))

jest.mock('@/lib/smartCacheManager', () => ({
  smartCacheManager: {
    cacheBusinessData: jest.fn(() => Promise.resolve()),
  },
}))

describe('AI/ML Workflow Integration', () => {
  let testBusinesses: BusinessRecord[]

  beforeEach(() => {
    testBusinesses = [
      {
        id: 'test-1',
        businessName: 'TechCorp Solutions',
        email: ['contact@techcorp.com', 'sales@techcorp.com'],
        phone: '+1-555-123-4567',
        websiteUrl: 'https://www.techcorp.com',
        address: {
          street: '123 Innovation Drive',
          suite: 'Suite 200',
          city: 'San Francisco',
          state: 'CA',
          zipCode: '94105',
        },
        contactPerson: 'Jane Smith',
        coordinates: {
          lat: 37.7749,
          lng: -122.4194,
        },
        industry: 'Technology',
        scrapedAt: new Date('2024-01-15T10:00:00Z'),
      },
      {
        id: 'test-2',
        businessName: 'HealthPlus Medical',
        email: ['info@healthplus.com'],
        websiteUrl: 'https://healthplus.com',
        address: {
          street: '456 Medical Center Blvd',
          city: 'Los Angeles',
          state: 'CA',
          zipCode: '90210',
        },
        industry: 'Healthcare',
        scrapedAt: new Date('2024-01-16T11:00:00Z'),
      },
      {
        id: 'test-3',
        businessName: 'Local Bakery',
        email: ['orders@localbakery.com'],
        websiteUrl: 'http://localbakery.com',
        address: {
          street: '789 Main Street',
          city: 'Small Town',
          state: 'TX',
          zipCode: '75001',
        },
        industry: 'Food Service',
        scrapedAt: new Date('2024-01-17T12:00:00Z'),
      },
    ]
  })

  afterEach(async () => {
    enhancedDataManager.dispose()
  })

  describe('Complete AI Pipeline', () => {
    it('should process businesses through the complete AI pipeline', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses, {
        enableLeadScoring: true,
        enableValidation: true,
        enableDuplicateDetection: true,
        enableCaching: true,
      })

      // Verify processing results
      expect(result.processed).toHaveLength(3)
      expect(result.scores.size).toBe(3)
      expect(result.stats.processed).toBe(3)
      expect(result.stats.scored).toBe(3)
      expect(result.errors).toHaveLength(0)

      // Verify each business has lead score data
      result.processed.forEach(business => {
        expect(business.leadScore).toBeDefined()
        expect(business.leadScore?.score).toBeGreaterThanOrEqual(0)
        expect(business.leadScore?.score).toBeLessThanOrEqual(100)
        expect(business.leadScore?.confidence).toBeGreaterThanOrEqual(0)
        expect(business.leadScore?.confidence).toBeLessThanOrEqual(1)
        expect(business.leadScore?.factors).toBeDefined()
        expect(business.leadScore?.recommendations).toBeDefined()
      })
    })

    it('should handle mixed quality data appropriately', async () => {
      // Add a low-quality business record
      const lowQualityBusiness: BusinessRecord = {
        id: 'test-low-quality',
        businessName: 'Incomplete Business',
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

      const mixedBusinesses = [...testBusinesses, lowQualityBusiness]
      const result = await enhancedDataManager.processBatch(mixedBusinesses)

      // High-quality businesses should have higher scores
      const techCorpScore = result.scores.get('test-1')
      const lowQualityScore = result.scores.get('test-low-quality')

      expect(techCorpScore?.score).toBeGreaterThan(lowQualityScore?.score || 0)
      expect(techCorpScore?.factors.dataCompleteness).toBeGreaterThan(
        lowQualityScore?.factors.dataCompleteness || 0
      )
    })

    it('should provide industry-specific scoring', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses)

      const techScore = result.scores.get('test-1') // Technology
      const healthScore = result.scores.get('test-2') // Healthcare
      const foodScore = result.scores.get('test-3') // Food Service

      // Technology should have highest industry relevance in default config
      expect(techScore?.factors.industryRelevance).toBeGreaterThanOrEqual(
        healthScore?.factors.industryRelevance || 0
      )
      expect(healthScore?.factors.industryRelevance).toBeGreaterThanOrEqual(
        foodScore?.factors.industryRelevance || 0
      )
    })

    it('should provide geographic scoring', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses)

      const caBusinesses = [
        result.scores.get('test-1'), // CA
        result.scores.get('test-2'), // CA
      ]
      const txBusiness = result.scores.get('test-3') // TX

      // California businesses should have higher geographic desirability
      caBusinesses.forEach(score => {
        expect(score?.factors.geographicDesirability).toBeGreaterThanOrEqual(
          txBusiness?.factors.geographicDesirability || 0
        )
      })
    })
  })

  describe('Batch Processing Performance', () => {
    it('should handle large batches efficiently', async () => {
      // Create a larger dataset
      const largeBatch = Array.from({ length: 50 }, (_, index) => ({
        ...testBusinesses[0],
        id: `batch-business-${index}`,
        businessName: `Business ${index}`,
      }))

      const startTime = Date.now()
      const result = await enhancedDataManager.processBatch(largeBatch, {
        batchSize: 10,
      })
      const endTime = Date.now()

      expect(result.processed).toHaveLength(50)
      expect(result.scores.size).toBe(50)
      expect(endTime - startTime).toBeLessThan(30000) // Should complete within 30 seconds
    })

    it('should handle errors gracefully in batch processing', async () => {
      // Add some invalid businesses
      const invalidBusinesses = [
        ...testBusinesses,
        { ...testBusinesses[0], id: 'invalid-1', businessName: null as any },
        { ...testBusinesses[0], id: 'invalid-2', email: null as any },
      ]

      const result = await enhancedDataManager.processBatch(invalidBusinesses)

      // Should process valid businesses and report errors for invalid ones
      expect(result.processed.length).toBeGreaterThan(0)
      expect(result.errors.length).toBeGreaterThan(0)
      expect(result.stats.errors).toBeGreaterThan(0)
    })
  })

  describe('Data Enhancement', () => {
    it('should enhance business records with AI insights', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses)

      result.processed.forEach(business => {
        // Should have data quality score
        expect(business.dataQualityScore).toBeDefined()
        expect(business.dataQualityScore).toBeGreaterThanOrEqual(0)
        expect(business.dataQualityScore).toBeLessThanOrEqual(100)

        // Should have lead score with all components
        expect(business.leadScore).toBeDefined()
        expect(business.leadScore?.factors).toHaveProperty('dataCompleteness')
        expect(business.leadScore?.factors).toHaveProperty('contactQuality')
        expect(business.leadScore?.factors).toHaveProperty('businessSize')
        expect(business.leadScore?.factors).toHaveProperty('industryRelevance')
        expect(business.leadScore?.factors).toHaveProperty('geographicDesirability')
        expect(business.leadScore?.factors).toHaveProperty('webPresence')
      })
    })

    it('should provide actionable recommendations', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses)

      result.processed.forEach(business => {
        expect(business.leadScore?.recommendations).toBeInstanceOf(Array)
        expect(business.leadScore?.recommendations?.length).toBeGreaterThan(0)

        // Recommendations should be relevant to score
        const score = business.leadScore?.score || 0
        const recommendations = business.leadScore?.recommendations || []

        if (score >= 80) {
          expect(
            recommendations.some(rec => rec.includes('High-quality') || rec.includes('prioritize'))
          ).toBe(true)
        } else if (score < 40) {
          expect(
            recommendations.some(rec => rec.includes('Low-priority') || rec.includes('nurturing'))
          ).toBe(true)
        }
      })
    })
  })

  describe('Export Integration', () => {
    it('should export enhanced data with AI insights', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses)
      const exportData = enhancedDataManager.exportEnhancedData(result.processed)

      expect(exportData).toHaveLength(3)

      exportData.forEach(record => {
        expect(record).toHaveProperty('leadScore')
        expect(record).toHaveProperty('leadConfidence')
        expect(record).toHaveProperty('dataQuality')
        expect(record).toHaveProperty('recommendations')
        expect(record).toHaveProperty('factors')

        // Verify factor scores are included
        if (record.factors) {
          expect(record.factors).toHaveProperty('dataCompleteness')
          expect(record.factors).toHaveProperty('contactQuality')
          expect(record.factors).toHaveProperty('businessSize')
          expect(record.factors).toHaveProperty('industryRelevance')
          expect(record.factors).toHaveProperty('geographicDesirability')
          expect(record.factors).toHaveProperty('webPresence')
        }
      })
    })
  })

  describe('Filtering and Sorting', () => {
    it('should filter businesses by lead score', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses)

      const highQualityLeads = enhancedDataManager.getHighQualityLeads(result.processed)
      const mediumQualityLeads = enhancedDataManager.filterByScore(result.processed, 50, 69)

      highQualityLeads.forEach(business => {
        expect(business.leadScore?.score).toBeGreaterThanOrEqual(70)
      })

      mediumQualityLeads.forEach(business => {
        expect(business.leadScore?.score).toBeGreaterThanOrEqual(50)
        expect(business.leadScore?.score).toBeLessThanOrEqual(69)
      })
    })

    it('should sort businesses by lead score', async () => {
      const result = await enhancedDataManager.processBatch(testBusinesses)

      const sortedDesc = enhancedDataManager.sortByScore(result.processed, true)
      const sortedAsc = enhancedDataManager.sortByScore(result.processed, false)

      // Verify descending order
      for (let i = 0; i < sortedDesc.length - 1; i++) {
        const currentScore = sortedDesc[i].leadScore?.score || 0
        const nextScore = sortedDesc[i + 1].leadScore?.score || 0
        expect(currentScore).toBeGreaterThanOrEqual(nextScore)
      }

      // Verify ascending order
      for (let i = 0; i < sortedAsc.length - 1; i++) {
        const currentScore = sortedAsc[i].leadScore?.score || 0
        const nextScore = sortedAsc[i + 1].leadScore?.score || 0
        expect(currentScore).toBeLessThanOrEqual(nextScore)
      }
    })

    it('should identify businesses needing attention', async () => {
      // Add a business with missing data
      const businessNeedingAttention: BusinessRecord = {
        ...testBusinesses[0],
        id: 'needs-attention',
        email: [], // Missing email
        phone: undefined, // Missing phone
      }

      const allBusinesses = [...testBusinesses, businessNeedingAttention]
      const result = await enhancedDataManager.processBatch(allBusinesses)

      const needsAttention = enhancedDataManager.getBusinessesNeedingAttention(result.processed)

      expect(needsAttention.length).toBeGreaterThan(0)
      expect(needsAttention.some(b => b.id === 'needs-attention')).toBe(true)
    })
  })
})
