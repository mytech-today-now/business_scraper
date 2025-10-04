/**
 * Comprehensive Business Rule Tests for Analytics Service
 * Tests analytics calculation logic, ROI calculations, and performance metrics
 */

import { AnalyticsService } from '@/lib/analytics-service'
import { ROIService } from '@/lib/roi-service'
import { PredictiveAnalyticsEngine } from '@/lib/predictiveAnalyticsEngine'
import { BusinessIntelligenceService } from '@/lib/businessIntelligenceService'
import { PerformanceMonitoringService } from '@/lib/performanceMonitoringService'
import { AILeadScoringService } from '@/lib/aiLeadScoringService'
import { BusinessRecord } from '@/types/business'
import { AnalyticsFilters, ROICalculationInput } from '@/types/analytics'

// Mock dependencies
jest.mock('@/lib/postgresql-database')
jest.mock('@/utils/logger')
jest.mock('puppeteer')

describe('Analytics Service - Business Logic Rules', () => {
  let analyticsService: AnalyticsService
  let roiService: ROIService
  let predictiveEngine: PredictiveAnalyticsEngine
  let biService: BusinessIntelligenceService
  let performanceService: PerformanceMonitoringService
  let leadScoringService: AILeadScoringService

  const mockAnalyticsFilters: AnalyticsFilters = {
    workspaceId: 'workspace-1',
    period: 'month',
    startDate: new Date('2024-01-01'),
    endDate: new Date('2024-01-31'),
    userId: 'user-1',
  }

  const mockROIInput: ROICalculationInput = {
    workspaceId: 'workspace-1',
    period: 'month',
    startDate: new Date('2024-01-01'),
    endDate: new Date('2024-01-31'),
    costPerHour: 50,
    estimatedLeadValue: 100,
    conversionData: {
      leadsContacted: 100,
      responseRate: 0.15,
      conversionRate: 0.08,
      avgDealValue: 5000,
    },
  }

  const mockBusinessRecord: BusinessRecord = {
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
    description: 'Leading technology solutions provider with 50+ employees',
    scrapedAt: new Date(),
  }

  beforeEach(() => {
    analyticsService = new AnalyticsService()
    roiService = new ROIService()
    predictiveEngine = new PredictiveAnalyticsEngine()
    biService = new BusinessIntelligenceService()
    performanceService = new PerformanceMonitoringService()
    leadScoringService = new AILeadScoringService()

    jest.clearAllMocks()
  })

  describe('ROI Calculation Logic', () => {
    test('should calculate ROI metrics correctly', async () => {
      // Mock database responses
      const mockCampaignData = {
        totalCampaigns: 5,
        totalTimeSpent: 40, // hours
        avgCampaignDuration: 8,
      }

      const mockScrapingData = {
        totalSessions: 20,
        avgSessionDuration: 2,
        totalBusinessesFound: 500,
      }

      const mockBusinessData = {
        totalBusinesses: 500,
        validatedBusinesses: 400,
        highQualityLeads: 150,
        enrichedBusinesses: 350,
        avgConfidenceScore: 0.85,
        dataAccuracyRate: 0.92,
        duplicateRate: 0.08,
      }

      jest.spyOn(ROIService as any, 'getCampaignData').mockResolvedValue(mockCampaignData)
      jest.spyOn(ROIService as any, 'getScrapingData').mockResolvedValue(mockScrapingData)
      jest.spyOn(ROIService as any, 'getBusinessData').mockResolvedValue(mockBusinessData)

      const result = await ROIService.calculateROI(mockROIInput)

      // Verify ROI calculation logic
      expect(result.totalCampaigns).toBe(5)
      expect(result.totalScrapingSessions).toBe(20)
      expect(result.totalTimeSpent).toBe(40)
      expect(result.totalCosts).toBe(2000) // 40 hours * $50/hour

      expect(result.totalBusinessesFound).toBe(500)
      expect(result.validatedBusinesses).toBe(400)
      expect(result.highQualityLeads).toBe(150)

      expect(result.avgConfidenceScore).toBe(85) // 0.85 * 100
      expect(result.dataAccuracyRate).toBe(92) // 0.92 * 100
      expect(result.duplicateRate).toBe(8) // 0.08 * 100

      expect(result.costPerLead).toBe(4) // $2000 / 500 leads
      expect(result.costPerValidatedLead).toBe(5) // $2000 / 400 validated

      // ROI calculation: (value - cost) / cost * 100
      const expectedValue = 150 * 100 // high quality leads * lead value
      const expectedROI = ((expectedValue - 2000) / 2000) * 100
      expect(result.roi).toBeCloseTo(expectedROI, 1)
    })

    test('should handle zero cost scenarios', async () => {
      const zeroTimeInput = {
        ...mockROIInput,
        costPerHour: 0,
      }

      jest.spyOn(ROIService as any, 'getCampaignData').mockResolvedValue({
        totalCampaigns: 1,
        totalTimeSpent: 0,
        avgCampaignDuration: 0,
      })

      jest.spyOn(ROIService as any, 'getScrapingData').mockResolvedValue({
        totalSessions: 1,
        avgSessionDuration: 0,
        totalBusinessesFound: 10,
      })

      jest.spyOn(ROIService as any, 'getBusinessData').mockResolvedValue({
        totalBusinesses: 10,
        validatedBusinesses: 8,
        highQualityLeads: 5,
        enrichedBusinesses: 7,
        avgConfidenceScore: 0.8,
        dataAccuracyRate: 0.9,
        duplicateRate: 0.1,
      })

      const result = await ROIService.calculateROI(zeroTimeInput)

      expect(result.totalCosts).toBe(0)
      expect(result.roi).toBe(0) // Should handle division by zero
    })

    test('should calculate conversion metrics correctly', async () => {
      const result = await ROIService.calculateROI(mockROIInput)

      expect(result.leadsContacted).toBe(100)
      expect(result.responseRate).toBe(15) // 0.15 * 100
      expect(result.conversionRate).toBe(8) // 0.08 * 100

      // Verify conversion calculations
      const expectedResponses = 100 * 0.15 // 15 responses
      const expectedConversions = expectedResponses * 0.08 // 1.2 conversions
      const expectedRevenue = expectedConversions * 5000 // $6000
    })
  })

  describe('Performance Metrics Calculation', () => {
    test('should calculate scraping performance metrics', async () => {
      const mockPerformanceData = {
        avg_scraping_time: 120, // 2 minutes
        success_rate: 85,
        error_rate: 15,
        total_sessions: 50,
        total_successful: 425,
        total_failed: 75,
      }

      jest.spyOn(AnalyticsService as any, 'database').mockReturnValue({
        query: jest.fn().mockResolvedValue({
          rows: [mockPerformanceData],
        }),
      })

      const result = await AnalyticsService.getPerformanceMetrics(mockAnalyticsFilters)

      expect(result.avgScrapingTime).toBe(120)
      expect(result.successRate).toBe(85)
      expect(result.errorRate).toBe(15)
      expect(result.totalActions).toBe(50)

      // Calculate request throughput
      const expectedThroughput = 425 / (120 * 50) // successful requests per second
      expect(result.requestThroughput).toBeCloseTo(expectedThroughput, 3)
    })

    test('should handle performance calculation edge cases', async () => {
      const edgeCaseData = {
        avg_scraping_time: null,
        success_rate: null,
        error_rate: null,
        total_sessions: 0,
        total_successful: 0,
        total_failed: 0,
      }

      jest.spyOn(AnalyticsService as any, 'database').mockReturnValue({
        query: jest.fn().mockResolvedValue({
          rows: [edgeCaseData],
        }),
      })

      const result = await AnalyticsService.getPerformanceMetrics(mockAnalyticsFilters)

      expect(result.avgScrapingTime).toBe(0)
      expect(result.successRate).toBe(0)
      expect(result.errorRate).toBe(0)
      expect(result.requestThroughput).toBe(0)
    })
  })

  describe('Predictive Analytics Logic', () => {
    test('should predict response rates based on business factors', async () => {
      const mockBusinessFactors = {
        businessMaturity: 0.8,
        descriptionQuality: 0.7,
        hasWebsite: 1,
        hasPhone: 1,
        hasEmail: 1,
      }

      const mockIndustryRates = {
        technology: 0.12,
        healthcare: 0.08,
        finance: 0.10,
      }

      jest.spyOn(predictiveEngine as any, 'analyzeBusinessFactors').mockReturnValue(mockBusinessFactors)
      jest.spyOn(predictiveEngine as any, 'getIndustryResponseRates').mockReturnValue(mockIndustryRates)

      const result = await predictiveEngine.predictResponseRate(mockBusinessRecord)

      expect(result.predictedRate).toBeGreaterThan(0)
      expect(result.predictedRate).toBeLessThanOrEqual(0.8)
      expect(result.confidenceInterval).toBeDefined()
      expect(result.recommendedStrategy).toBeDefined()
      expect(result.factors).toEqual(mockBusinessFactors)

      // Verify calculation logic
      const baseRate = 0.1 // average of industry rates
      let expectedRate = baseRate
      expectedRate *= 1 + mockBusinessFactors.businessMaturity * 0.3 // 1.24
      expectedRate *= 1 + mockBusinessFactors.descriptionQuality * 0.2 // 1.14
      expectedRate *= 1 + (mockBusinessFactors.hasWebsite + mockBusinessFactors.hasPhone + mockBusinessFactors.hasEmail) * 0.1 // 1.3

      const finalExpectedRate = Math.max(0.05, Math.min(0.8, expectedRate))
      expect(result.predictedRate).toBeCloseTo(finalExpectedRate, 2)
    })

    test('should generate ROI forecasts', async () => {
      const mockLeadData = [
        { score: 85, timeframe: 'week_1' },
        { score: 78, timeframe: 'week_2' },
        { score: 82, timeframe: 'week_3' },
        { score: 90, timeframe: 'week_4' },
      ]

      jest.spyOn(predictiveEngine as any, 'getLeadScoreData').mockResolvedValue(mockLeadData)

      const forecasts = await predictiveEngine.generateROIForecasts('workspace-1', 4)

      expect(forecasts).toHaveLength(4)

      forecasts.forEach((forecast, index) => {
        expect(forecast.timeframe).toBe(mockLeadData[index].timeframe)
        expect(forecast.expectedRevenue).toBeGreaterThan(0)
        expect(forecast.expectedCosts).toBeGreaterThan(0)
        expect(forecast.projectedROI).toBeDefined()
        expect(forecast.confidence).toBeGreaterThan(0.5)
        expect(forecast.confidence).toBeLessThanOrEqual(0.9)
        expect(forecast.assumptions).toBeInstanceOf(Array)
      })
    })
  })

  describe('Business Intelligence Calculations', () => {
    test('should estimate company size accurately', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <div>We have over 100 employees across 3 offices</div>
              <p>Our team of 150+ professionals serves clients worldwide</p>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const result = await biService.estimateCompanySize(
        'https://acme.com',
        'Acme Corporation',
        mockPage as any
      )

      expect(result.employeeRange).toBe('101-500')
      expect(result.confidence).toBeGreaterThan(70)
      expect(result.source).toBe('website_content')
    })

    test('should estimate revenue based on indicators', async () => {
      const mockPage = {
        goto: jest.fn(),
        content: jest.fn().mockResolvedValue(`
          <html>
            <body>
              <div>Fortune 500 company with global operations</div>
              <p>Multi-billion dollar revenue and market leader</p>
            </body>
          </html>
        `),
        close: jest.fn(),
      }

      const result = await biService.estimateRevenue(
        'https://acme.com',
        'Acme Corporation',
        { employeeRange: '1000+', confidence: 90, source: 'website', lastUpdated: new Date() },
        mockPage as any
      )

      expect(result.revenueRange).toBe('$100M+')
      expect(result.confidence).toBeGreaterThan(60)
      expect(result.source).toBe('content_analysis')
    })

    test('should handle missing business intelligence data', async () => {
      const mockPage = {
        goto: jest.fn().mockRejectedValue(new Error('Website unreachable')),
        content: jest.fn(),
        close: jest.fn(),
      }

      const sizeResult = await biService.estimateCompanySize(
        'https://invalid-url.com',
        'Unknown Business',
        mockPage as any
      )

      expect(sizeResult.employeeRange).toBe('1-10')
      expect(sizeResult.confidence).toBe(20)
      expect(sizeResult.source).toBe('default_estimate')

      const revenueResult = await biService.estimateRevenue(
        'https://invalid-url.com',
        'Unknown Business',
        sizeResult,
        mockPage as any
      )

      expect(revenueResult.revenueRange).toBe('$100K-$1M')
      expect(revenueResult.confidence).toBeLessThanOrEqual(40)
    })
  })

  describe('Lead Scoring Calculations', () => {
    test('should calculate comprehensive lead scores', async () => {
      const result = await leadScoringService.scoreBusinessRecord(mockBusinessRecord)

      expect(result.overallScore).toBeGreaterThanOrEqual(0)
      expect(result.overallScore).toBeLessThanOrEqual(100)

      expect(result.scores.contactability).toBeDefined()
      expect(result.scores.businessQuality).toBeDefined()
      expect(result.scores.marketPotential).toBeDefined()
      expect(result.scores.digitalPresence).toBeDefined()

      // Verify score components are within valid ranges
      Object.values(result.scores).forEach(scoreData => {
        expect(scoreData.score).toBeGreaterThanOrEqual(0)
        expect(scoreData.score).toBeLessThanOrEqual(100)
        expect(scoreData.details).toBeDefined()
      })
    })

    test('should handle businesses with minimal information', async () => {
      const minimalBusiness = {
        id: 'minimal-1',
        businessName: 'Small Shop',
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
        description: '',
        scrapedAt: new Date(),
      }

      const result = await leadScoringService.scoreBusinessRecord(minimalBusiness)

      expect(result.overallScore).toBeLessThan(50) // Should be low for minimal info
      expect(result.scores.contactability.score).toBeLessThan(30) // Low contactability
      expect(result.scores.digitalPresence.score).toBeLessThan(20) // Minimal digital presence
    })
  })

  describe('Performance Monitoring Logic', () => {
    test('should calculate performance scores correctly', () => {
      // Mock performance metrics
      performanceService.recordMetric('test-component', 'render', 150) // Good render time
      performanceService.recordMetric('test-component', 'render', 200) // Acceptable render time
      performanceService.recordMetric('test-component', 'render', 800) // Poor render time

      const score = performanceService.getPerformanceScore('test-component')

      expect(score).toBeGreaterThanOrEqual(0)
      expect(score).toBeLessThanOrEqual(100)

      // Should be penalized for the poor render time
      expect(score).toBeLessThan(100)
    })

    test('should track component-specific metrics', () => {
      performanceService.recordMetric('search-engine', 'query', 50)
      performanceService.recordMetric('data-processor', 'batch', 2000)
      performanceService.recordMetric('export-service', 'generation', 500)

      const searchStats = performanceService.getStatistics('search-engine')
      const processorStats = performanceService.getStatistics('data-processor')
      const exportStats = performanceService.getStatistics('export-service')

      expect(searchStats.metricsCount).toBe(1)
      expect(processorStats.metricsCount).toBe(1)
      expect(exportStats.metricsCount).toBe(1)

      expect(searchStats.avgRenderTime).toBe(50)
      expect(processorStats.avgRenderTime).toBe(2000)
      expect(exportStats.avgRenderTime).toBe(500)
    })
  })

  describe('Error Handling and Edge Cases', () => {
    test('should handle database connection failures', async () => {
      jest.spyOn(AnalyticsService as any, 'database').mockReturnValue({
        query: jest.fn().mockRejectedValue(new Error('Database connection failed')),
      })

      await expect(AnalyticsService.getPerformanceMetrics(mockAnalyticsFilters)).rejects.toThrow(
        'Database connection failed'
      )
    })

    test('should handle invalid date ranges', async () => {
      const invalidFilters = {
        ...mockAnalyticsFilters,
        startDate: new Date('2024-12-31'),
        endDate: new Date('2024-01-01'), // End before start
      }

      // Should handle gracefully or throw appropriate error
      const result = await AnalyticsService.getOverviewMetrics(invalidFilters)
      expect(result).toBeDefined()
    })

    test('should handle missing workspace data', async () => {
      const emptyFilters = {
        ...mockAnalyticsFilters,
        workspaceId: 'non-existent-workspace',
      }

      jest.spyOn(AnalyticsService as any, 'database').mockReturnValue({
        query: jest.fn().mockResolvedValue({ rows: [] }),
      })

      const result = await AnalyticsService.getOverviewMetrics(emptyFilters)

      expect(result.totalBusinesses).toBe(0)
      expect(result.totalCampaigns).toBe(0)
      expect(result.totalUsers).toBe(0)
    })
  })

  describe('Performance and Efficiency', () => {
    test('should complete analytics calculations within reasonable time', async () => {
      const startTime = Date.now()

      await Promise.all([
        AnalyticsService.getOverviewMetrics(mockAnalyticsFilters),
        AnalyticsService.getPerformanceMetrics(mockAnalyticsFilters),
        ROIService.calculateROI(mockROIInput),
      ])

      const endTime = Date.now()
      const processingTime = endTime - startTime

      expect(processingTime).toBeLessThan(3000) // Should complete within 3 seconds
    })

    test('should handle concurrent analytics requests', async () => {
      const requests = Array(10)
        .fill(0)
        .map(() => AnalyticsService.getOverviewMetrics(mockAnalyticsFilters))

      const startTime = Date.now()
      const results = await Promise.all(requests)
      const endTime = Date.now()

      expect(results).toHaveLength(10)
      expect(endTime - startTime).toBeLessThan(5000) // Should handle concurrency efficiently
    })
  })
})
