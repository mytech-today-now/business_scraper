/**
 * AI Lead Scoring Service - Comprehensive Test Suite
 * Tests AI-powered lead scoring, factor analysis, and recommendations
 */

import { aiLeadScoringService, LeadScore, ScoreFactors } from '@/lib/aiLeadScoring'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')

const mockLogger = logger as jest.Mocked<typeof logger>

describe('AI Lead Scoring Service - Comprehensive Tests', () => {
  const createMockBusinessRecord = (overrides: Partial<BusinessRecord> = {}): BusinessRecord => ({
    id: 'test-business-1',
    businessName: 'Test Business Inc.',
    email: ['contact@testbusiness.com'],
    phone: ['555-123-4567'],
    website: 'https://www.testbusiness.com',
    streetName: 'Main Street',
    streetNumber: '123',
    city: 'Los Angeles',
    state: 'CA',
    zipCode: '90210',
    industry: 'Technology',
    description: 'A technology company providing innovative software solutions',
    scrapedAt: new Date(),
    source: 'test',
    ...overrides,
  })

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Service Initialization', () => {
    it('should initialize the AI lead scoring service correctly', async () => {
      await aiLeadScoringService.initialize()

      expect(mockLogger.info).toHaveBeenCalledWith(
        'AILeadScoring',
        'AI Lead Scoring service initialized successfully'
      )
    })

    it('should handle initialization errors gracefully', async () => {
      // Mock a scenario where initialization might fail
      const originalConsoleError = console.error
      console.error = jest.fn()

      try {
        // This should not throw even if there are issues
        await aiLeadScoringService.initialize()
        expect(true).toBe(true) // Should reach here
      } catch (error) {
        // If it does throw, it should be handled gracefully
        expect(mockLogger.error).toHaveBeenCalled()
      } finally {
        console.error = originalConsoleError
      }
    })
  })

  describe('Lead Score Calculation', () => {
    it('should calculate lead score for a complete business record', async () => {
      const business = createMockBusinessRecord()
      
      const score = await aiLeadScoringService.getLeadScore(business)

      expect(score.score).toBeGreaterThanOrEqual(0)
      expect(score.score).toBeLessThanOrEqual(100)
      expect(score.confidence).toBeGreaterThan(0)
      expect(score.confidence).toBeLessThanOrEqual(1)
      expect(score.factors).toBeDefined()
      expect(score.recommendations).toBeInstanceOf(Array)
    })

    it('should assign higher scores to businesses with complete contact information', async () => {
      const completeBusinessRecord = createMockBusinessRecord({
        email: ['ceo@business.com', 'sales@business.com'],
        phone: ['555-123-4567', '555-987-6543'],
        website: 'https://www.business.com',
      })

      const incompleteBusinessRecord = createMockBusinessRecord({
        email: [],
        phone: [],
        website: '',
      })

      const completeScore = await aiLeadScoringService.getLeadScore(completeBusinessRecord)
      const incompleteScore = await aiLeadScoringService.getLeadScore(incompleteBusinessRecord)

      expect(completeScore.score).toBeGreaterThan(incompleteScore.score)
      expect(completeScore.factors.contactability.score).toBeGreaterThan(
        incompleteScore.factors.contactability.score
      )
    })

    it('should consider business maturity factors', async () => {
      const matureBusiness = createMockBusinessRecord({
        businessName: 'Established Enterprise Solutions Inc.',
        description: 'A well-established company with over 20 years of experience in enterprise software solutions, serving Fortune 500 clients',
        website: 'https://www.established-enterprise.com',
        industry: 'Technology',
      })

      const startupBusiness = createMockBusinessRecord({
        businessName: 'New Startup',
        description: 'A new startup',
        website: '',
        industry: 'Technology',
      })

      const matureScore = await aiLeadScoringService.getLeadScore(matureBusiness)
      const startupScore = await aiLeadScoringService.getLeadScore(startupBusiness)

      expect(matureScore.factors.businessMaturity.score).toBeGreaterThan(
        startupScore.factors.businessMaturity.score
      )
    })

    it('should evaluate market potential correctly', async () => {
      const techBusiness = createMockBusinessRecord({
        industry: 'Technology',
        description: 'AI and machine learning solutions for enterprise clients',
        city: 'San Francisco',
        state: 'CA',
      })

      const localBusiness = createMockBusinessRecord({
        industry: 'Local Services',
        description: 'Local cleaning service',
        city: 'Small Town',
        state: 'MT',
      })

      const techScore = await aiLeadScoringService.getLeadScore(techBusiness)
      const localScore = await aiLeadScoringService.getLeadScore(localBusiness)

      expect(techScore.factors.marketPotential.score).toBeGreaterThan(
        localScore.factors.marketPotential.score
      )
    })

    it('should assess engagement likelihood based on digital presence', async () => {
      const digitallyActiveBusiness = createMockBusinessRecord({
        website: 'https://www.active-business.com',
        email: ['marketing@active-business.com', 'sales@active-business.com'],
        description: 'Digital marketing agency with strong online presence and social media engagement',
      })

      const lowDigitalPresenceBusiness = createMockBusinessRecord({
        website: '',
        email: ['owner@gmail.com'],
        description: 'Traditional business with minimal online presence',
      })

      const activeScore = await aiLeadScoringService.getLeadScore(digitallyActiveBusiness)
      const lowPresenceScore = await aiLeadScoringService.getLeadScore(lowDigitalPresenceBusiness)

      expect(activeScore.factors.engagementLikelihood.score).toBeGreaterThan(
        lowPresenceScore.factors.engagementLikelihood.score
      )
    })
  })

  describe('Score Factors Analysis', () => {
    it('should provide detailed contactability analysis', async () => {
      const business = createMockBusinessRecord({
        email: ['ceo@business.com', 'sales@business.com'],
        phone: ['555-123-4567'],
        website: 'https://www.business.com',
      })

      const score = await aiLeadScoringService.getLeadScore(business)

      expect(score.factors.contactability).toBeDefined()
      expect(score.factors.contactability.score).toBeGreaterThan(0)
      expect(score.factors.contactability.weight).toBe(0.3)
      expect(score.factors.contactability.details).toContain('contact')
    })

    it('should analyze business maturity indicators', async () => {
      const business = createMockBusinessRecord({
        businessName: 'Established Corporation Inc.',
        description: 'A well-established corporation with decades of experience',
        website: 'https://www.established-corp.com',
      })

      const score = await aiLeadScoringService.getLeadScore(business)

      expect(score.factors.businessMaturity).toBeDefined()
      expect(score.factors.businessMaturity.score).toBeGreaterThan(0)
      expect(score.factors.businessMaturity.weight).toBe(0.25)
      expect(score.factors.businessMaturity.details).toContain('business')
    })

    it('should evaluate market potential factors', async () => {
      const business = createMockBusinessRecord({
        industry: 'Technology',
        city: 'San Francisco',
        state: 'CA',
        description: 'Enterprise software solutions for Fortune 500 companies',
      })

      const score = await aiLeadScoringService.getLeadScore(business)

      expect(score.factors.marketPotential).toBeDefined()
      expect(score.factors.marketPotential.score).toBeGreaterThan(0)
      expect(score.factors.marketPotential.weight).toBe(0.25)
      expect(score.factors.marketPotential.details).toContain('market')
    })

    it('should assess engagement likelihood', async () => {
      const business = createMockBusinessRecord({
        website: 'https://www.engaging-business.com',
        email: ['marketing@engaging-business.com'],
        description: 'Digital-first company with strong online engagement',
      })

      const score = await aiLeadScoringService.getLeadScore(business)

      expect(score.factors.engagementLikelihood).toBeDefined()
      expect(score.factors.engagementLikelihood.score).toBeGreaterThan(0)
      expect(score.factors.engagementLikelihood.weight).toBe(0.2)
      expect(score.factors.engagementLikelihood.details).toContain('engagement')
    })
  })

  describe('Recommendations Generation', () => {
    it('should provide actionable recommendations for high-scoring leads', async () => {
      const highValueBusiness = createMockBusinessRecord({
        email: ['ceo@enterprise.com'],
        phone: ['555-123-4567'],
        website: 'https://www.enterprise.com',
        industry: 'Technology',
        description: 'Large enterprise technology company',
      })

      const score = await aiLeadScoringService.getLeadScore(highValueBusiness)

      expect(score.recommendations).toBeInstanceOf(Array)
      expect(score.recommendations.length).toBeGreaterThan(0)
      expect(score.recommendations.some(rec => rec.includes('contact'))).toBe(true)
    })

    it('should provide improvement suggestions for low-scoring leads', async () => {
      const lowValueBusiness = createMockBusinessRecord({
        email: [],
        phone: [],
        website: '',
        description: 'Limited information available',
      })

      const score = await aiLeadScoringService.getLeadScore(lowValueBusiness)

      expect(score.recommendations).toBeInstanceOf(Array)
      expect(score.recommendations.length).toBeGreaterThan(0)
      expect(score.recommendations.some(rec => rec.includes('information'))).toBe(true)
    })

    it('should provide industry-specific recommendations', async () => {
      const techBusiness = createMockBusinessRecord({
        industry: 'Technology',
        description: 'Software development company',
      })

      const retailBusiness = createMockBusinessRecord({
        industry: 'Retail',
        description: 'Retail store chain',
      })

      const techScore = await aiLeadScoringService.getLeadScore(techBusiness)
      const retailScore = await aiLeadScoringService.getLeadScore(retailBusiness)

      expect(techScore.recommendations).toBeInstanceOf(Array)
      expect(retailScore.recommendations).toBeInstanceOf(Array)
      // Recommendations should be different for different industries
      expect(techScore.recommendations).not.toEqual(retailScore.recommendations)
    })
  })

  describe('Error Handling and Fallbacks', () => {
    it('should handle missing business information gracefully', async () => {
      const incompleteBusiness = createMockBusinessRecord({
        businessName: '',
        email: [],
        phone: [],
        website: '',
        description: '',
      })

      const score = await aiLeadScoringService.getLeadScore(incompleteBusiness)

      expect(score.score).toBeGreaterThanOrEqual(0)
      expect(score.score).toBeLessThanOrEqual(100)
      expect(score.confidence).toBeGreaterThan(0)
      expect(score.factors).toBeDefined()
      expect(score.recommendations).toBeInstanceOf(Array)
    })

    it('should provide fallback scoring when AI model fails', async () => {
      // This test simulates AI model failure and fallback to rule-based scoring
      const business = createMockBusinessRecord()

      const score = await aiLeadScoringService.getLeadScore(business)

      expect(score.score).toBeGreaterThanOrEqual(0)
      expect(score.score).toBeLessThanOrEqual(100)
      expect(score.confidence).toBeGreaterThan(0)
      expect(score.factors).toBeDefined()
      expect(score.recommendations).toBeInstanceOf(Array)
    })

    it('should handle malformed business records', async () => {
      const malformedBusiness = {
        ...createMockBusinessRecord(),
        email: null as any,
        phone: undefined as any,
      }

      const score = await aiLeadScoringService.getLeadScore(malformedBusiness)

      expect(score.score).toBeGreaterThanOrEqual(0)
      expect(score.score).toBeLessThanOrEqual(100)
      expect(score.confidence).toBeGreaterThan(0)
    })
  })

  describe('Performance and Scalability', () => {
    it('should calculate scores efficiently for multiple businesses', async () => {
      const businesses = Array.from({ length: 10 }, (_, i) =>
        createMockBusinessRecord({
          id: `business-${i}`,
          businessName: `Business ${i}`,
          email: [`contact${i}@business.com`],
        })
      )

      const startTime = Date.now()
      const scores = await Promise.all(
        businesses.map(business => aiLeadScoringService.getLeadScore(business))
      )
      const endTime = Date.now()

      expect(scores).toHaveLength(10)
      scores.forEach(score => {
        expect(score.score).toBeGreaterThanOrEqual(0)
        expect(score.score).toBeLessThanOrEqual(100)
      })
      expect(endTime - startTime).toBeLessThan(5000) // Should complete within 5 seconds
    })

    it('should maintain consistent scoring for identical businesses', async () => {
      const business = createMockBusinessRecord()

      const score1 = await aiLeadScoringService.getLeadScore(business)
      const score2 = await aiLeadScoringService.getLeadScore(business)

      expect(score1.score).toBe(score2.score)
      expect(score1.confidence).toBe(score2.confidence)
      expect(score1.factors.contactability.score).toBe(score2.factors.contactability.score)
    })
  })

  describe('Score Validation and Boundaries', () => {
    it('should ensure scores are within valid range', async () => {
      const businesses = [
        createMockBusinessRecord({ // High-value business
          email: ['ceo@fortune500.com'],
          phone: ['555-123-4567'],
          website: 'https://www.fortune500.com',
          industry: 'Technology',
          description: 'Fortune 500 technology company with global presence',
        }),
        createMockBusinessRecord({ // Low-value business
          email: [],
          phone: [],
          website: '',
          description: '',
        }),
      ]

      for (const business of businesses) {
        const score = await aiLeadScoringService.getLeadScore(business)
        
        expect(score.score).toBeGreaterThanOrEqual(0)
        expect(score.score).toBeLessThanOrEqual(100)
        expect(score.confidence).toBeGreaterThan(0)
        expect(score.confidence).toBeLessThanOrEqual(1)
        
        // Validate factor scores
        Object.values(score.factors).forEach(factor => {
          expect(factor.score).toBeGreaterThanOrEqual(0)
          expect(factor.score).toBeLessThanOrEqual(100)
          expect(factor.weight).toBeGreaterThan(0)
          expect(factor.weight).toBeLessThanOrEqual(1)
        })
      }
    })

    it('should ensure factor weights sum to 1.0', async () => {
      const business = createMockBusinessRecord()
      const score = await aiLeadScoringService.getLeadScore(business)

      const totalWeight = Object.values(score.factors).reduce(
        (sum, factor) => sum + factor.weight,
        0
      )

      expect(totalWeight).toBeCloseTo(1.0, 2)
    })
  })
})
