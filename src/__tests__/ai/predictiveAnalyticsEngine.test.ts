'use strict'

/**
 * Predictive Analytics Engine Unit Tests
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { PredictiveAnalyticsEngine } from '@/lib/predictiveAnalyticsEngine'
import { BusinessRecord } from '@/types/business'

// Mock date-fns
jest.mock('date-fns', () => ({
  addDays: jest.fn((date, days) => new Date(date.getTime() + days * 24 * 60 * 60 * 1000)),
  addWeeks: jest.fn((date, weeks) => new Date(date.getTime() + weeks * 7 * 24 * 60 * 60 * 1000)),
  addMonths: jest.fn((date, months) => new Date(date.getTime() + months * 30 * 24 * 60 * 60 * 1000)),
  format: jest.fn((date, format) => date.toISOString()),
  parseISO: jest.fn((str) => new Date(str)),
  isWeekend: jest.fn((date) => date.getDay() === 0 || date.getDay() === 6)
}))

// Mock simple-statistics
jest.mock('simple-statistics', () => ({
  mean: jest.fn((arr) => arr.reduce((sum: number, val: number) => sum + val, 0) / arr.length),
  standardDeviation: jest.fn(() => 0.2),
  linearRegression: jest.fn(() => ({ m: 1, b: 0 }))
}))

describe('PredictiveAnalyticsEngine', () => {
  let engine: PredictiveAnalyticsEngine
  let mockBusiness: BusinessRecord

  beforeEach(() => {
    engine = new PredictiveAnalyticsEngine()
    
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
        zipCode: '12345'
      },
      industry: 'Technology',
      description: 'A test business for unit testing',
      scrapedAt: new Date(),
      website: 'https://testbusiness.com'
    }
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Initialization', () => {
    it('should initialize successfully', async () => {
      await engine.initialize()
      expect(engine.isInitialized()).toBe(true)
    })

    it('should handle initialization errors gracefully', async () => {
      // Mock an initialization error
      jest.spyOn(engine as any, 'loadHistoricalData').mockRejectedValue(new Error('Init error'))
      
      await expect(engine.initialize()).rejects.toThrow('Init error')
    })
  })

  describe('Contact Time Prediction', () => {
    it('should predict best contact time', async () => {
      await engine.initialize()
      
      const contactTiming = await engine.predictBestContactTime(mockBusiness)
      
      expect(contactTiming).toBeDefined()
      expect(contactTiming.bestDayOfWeek).toBeDefined()
      expect(contactTiming.bestHourRange).toBeDefined()
      expect(contactTiming.timezone).toBeDefined()
      expect(contactTiming.confidence).toBeGreaterThanOrEqual(0)
      expect(contactTiming.confidence).toBeLessThanOrEqual(1)
      expect(contactTiming.historicalData).toBeInstanceOf(Array)
    })

    it('should return valid day of week', async () => {
      await engine.initialize()
      
      const contactTiming = await engine.predictBestContactTime(mockBusiness)
      const validDays = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
      
      expect(validDays).toContain(contactTiming.bestDayOfWeek)
    })

    it('should return valid hour range format', async () => {
      await engine.initialize()
      
      const contactTiming = await engine.predictBestContactTime(mockBusiness)
      
      expect(contactTiming.bestHourRange).toMatch(/^\d{1,2}:\d{2}-\d{1,2}:\d{2}$/)
    })

    it('should handle business without industry', async () => {
      await engine.initialize()
      
      const businessWithoutIndustry = { ...mockBusiness, industry: '' }
      const contactTiming = await engine.predictBestContactTime(businessWithoutIndustry)
      
      expect(contactTiming).toBeDefined()
      expect(contactTiming.bestDayOfWeek).toBeDefined()
    })
  })

  describe('Response Rate Forecasting', () => {
    it('should forecast response rate', async () => {
      await engine.initialize()
      
      const forecast = await engine.forecastResponseRate(mockBusiness)
      
      expect(forecast).toBeDefined()
      expect(forecast.predictedRate).toBeGreaterThanOrEqual(0)
      expect(forecast.predictedRate).toBeLessThanOrEqual(1)
      expect(forecast.confidenceInterval).toBeDefined()
      expect(forecast.confidenceInterval.lower).toBeLessThanOrEqual(forecast.predictedRate)
      expect(forecast.confidenceInterval.upper).toBeGreaterThanOrEqual(forecast.predictedRate)
      expect(forecast.recommendedStrategy).toBeDefined()
      expect(forecast.factors).toBeDefined()
    })

    it('should return valid outreach strategy', async () => {
      await engine.initialize()
      
      const forecast = await engine.forecastResponseRate(mockBusiness)
      const validStrategies = ['email', 'phone', 'linkedin', 'form']
      
      expect(validStrategies).toContain(forecast.recommendedStrategy)
    })

    it('should calculate business factors correctly', async () => {
      await engine.initialize()
      
      const forecast = await engine.forecastResponseRate(mockBusiness)
      const factors = forecast.factors
      
      expect(factors.hasWebsite).toBe(1) // Business has website
      expect(factors.hasPhone).toBe(1) // Business has phone
      expect(factors.hasEmail).toBe(1) // Business has email
      expect(factors.hasAddress).toBe(1) // Business has address
      expect(factors.descriptionQuality).toBeGreaterThan(0) // Has description
      expect(factors.industryRelevance).toBeGreaterThan(0) // Has industry
      expect(factors.businessMaturity).toBeGreaterThan(0) // Should have some maturity
    })

    it('should handle business with minimal data', async () => {
      await engine.initialize()
      
      const minimalBusiness: BusinessRecord = {
        id: 'minimal-business',
        businessName: 'Minimal Business',
        contactPerson: '',
        email: [],
        phone: '',
        websiteUrl: '',
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: ''
        },
        industry: '',
        description: '',
        scrapedAt: new Date(),
        website: ''
      }
      
      const forecast = await engine.forecastResponseRate(minimalBusiness)
      
      expect(forecast).toBeDefined()
      expect(forecast.predictedRate).toBeGreaterThanOrEqual(0)
      expect(forecast.factors.hasWebsite).toBe(0)
      expect(forecast.factors.hasPhone).toBe(0)
      expect(forecast.factors.hasEmail).toBe(0)
    })
  })

  describe('Industry Trend Analysis', () => {
    it('should analyze industry trends', async () => {
      await engine.initialize()
      
      const trendAnalysis = await engine.analyzeIndustryTrends('Technology')
      
      expect(trendAnalysis).toBeDefined()
      expect(trendAnalysis.industry).toBe('Technology')
      expect(['growing', 'stable', 'declining']).toContain(trendAnalysis.trendDirection)
      expect(trendAnalysis.trendStrength).toBeGreaterThanOrEqual(0)
      expect(trendAnalysis.trendStrength).toBeLessThanOrEqual(1)
      expect(trendAnalysis.insights).toBeDefined()
      expect(trendAnalysis.analysisPeriod).toBeDefined()
      expect(trendAnalysis.analyzedAt).toBeInstanceOf(Date)
    })

    it('should include trend insights', async () => {
      await engine.initialize()
      
      const trendAnalysis = await engine.analyzeIndustryTrends('Healthcare')
      const insights = trendAnalysis.insights
      
      expect(insights.emergingKeywords).toBeInstanceOf(Array)
      expect(insights.decliningKeywords).toBeInstanceOf(Array)
      expect(insights.seasonalPatterns).toBeInstanceOf(Array)
      expect(typeof insights.competitorActivity).toBe('number')
      expect(typeof insights.marketSentiment).toBe('number')
      expect(insights.marketSentiment).toBeGreaterThanOrEqual(-1)
      expect(insights.marketSentiment).toBeLessThanOrEqual(1)
    })

    it('should handle unknown industries', async () => {
      await engine.initialize()
      
      const trendAnalysis = await engine.analyzeIndustryTrends('UnknownIndustry')
      
      expect(trendAnalysis).toBeDefined()
      expect(trendAnalysis.industry).toBe('UnknownIndustry')
    })
  })

  describe('Seasonal Pattern Detection', () => {
    it('should detect seasonal patterns', async () => {
      await engine.initialize()
      
      const patterns = await engine.detectSeasonalPatterns('Retail')
      
      expect(patterns).toBeInstanceOf(Array)
      
      patterns.forEach(pattern => {
        expect(pattern.name).toBeDefined()
        expect(pattern.peakMonths).toBeInstanceOf(Array)
        expect(pattern.lowMonths).toBeInstanceOf(Array)
        expect(pattern.strength).toBeGreaterThanOrEqual(0)
        expect(pattern.strength).toBeLessThanOrEqual(1)
        expect(pattern.historicalData).toBeInstanceOf(Array)
        
        // Validate month values
        pattern.peakMonths.forEach(month => {
          expect(month).toBeGreaterThanOrEqual(0)
          expect(month).toBeLessThanOrEqual(11)
        })
        
        pattern.lowMonths.forEach(month => {
          expect(month).toBeGreaterThanOrEqual(0)
          expect(month).toBeLessThanOrEqual(11)
        })
      })
    })

    it('should handle industries with no patterns', async () => {
      await engine.initialize()
      
      // Mock the pattern detection to return weak patterns
      jest.spyOn(engine as any, 'analyzeMonthlyPattern').mockReturnValue({
        name: 'Weak Pattern',
        peakMonths: [],
        lowMonths: [],
        strength: 0.1, // Below threshold
        historicalData: []
      })
      
      const patterns = await engine.detectSeasonalPatterns('StableIndustry')
      
      expect(patterns).toBeInstanceOf(Array)
      // Should filter out weak patterns
    })
  })

  describe('Error Handling', () => {
    it('should handle contact time prediction errors', async () => {
      await engine.initialize()
      
      // Mock an error in the prediction process
      jest.spyOn(engine as any, 'analyzeDayOfWeekPatterns').mockImplementation(() => {
        throw new Error('Analysis error')
      })
      
      const contactTiming = await engine.predictBestContactTime(mockBusiness)
      
      // Should return default timing on error
      expect(contactTiming.bestDayOfWeek).toBe('Tuesday')
      expect(contactTiming.bestHourRange).toBe('10:00-11:00')
      expect(contactTiming.confidence).toBe(0.5)
    })

    it('should handle response rate forecasting errors', async () => {
      await engine.initialize()
      
      // Mock an error in the forecasting process
      jest.spyOn(engine as any, 'calculatePredictedResponseRate').mockImplementation(() => {
        throw new Error('Forecasting error')
      })
      
      const forecast = await engine.forecastResponseRate(mockBusiness)
      
      // Should return default forecast on error
      expect(forecast.predictedRate).toBe(0.3)
      expect(forecast.recommendedStrategy).toBe('email')
    })

    it('should handle trend analysis errors', async () => {
      await engine.initialize()
      
      // Mock an error in trend analysis
      jest.spyOn(engine as any, 'generateIndustryTrendAnalysis').mockRejectedValue(new Error('Trend error'))
      
      const trendAnalysis = await engine.analyzeIndustryTrends('ErrorIndustry')
      
      // Should return default analysis on error
      expect(trendAnalysis.industry).toBe('ErrorIndustry')
      expect(trendAnalysis.trendDirection).toBe('stable')
      expect(trendAnalysis.trendStrength).toBe(0.5)
    })
  })
})
