'use strict'

/**
 * Predictive Analytics Engine - Time-series forecasting and trend analysis
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { addDays, addWeeks, addMonths, format, parseISO, isWeekend } from 'date-fns'
import { mean, standardDeviation, linearRegression } from 'simple-statistics'
import { BusinessRecord } from '@/types/business'
import { ConversionPrediction, IndustryTrendAnalysis, SeasonalPattern } from '@/types/ai'
import { logger } from '@/utils/logger'

/**
 * Time series data point
 */
interface TimeSeriesDataPoint {
  date: Date
  value: number
  metadata?: Record<string, any>
}

/**
 * Contact timing analysis result
 */
interface ContactTimingAnalysis {
  bestDayOfWeek: string
  bestHourRange: string
  timezone: string
  confidence: number
  historicalData: TimeSeriesDataPoint[]
}

/**
 * Response rate forecast
 */
interface ResponseRateForecast {
  predictedRate: number
  confidenceInterval: { lower: number; upper: number }
  recommendedStrategy: 'email' | 'phone' | 'linkedin' | 'form'
  factors: Record<string, number>
}

/**
 * Predictive Analytics Engine class
 * Handles time-series forecasting and predictive insights
 */
export class PredictiveAnalyticsEngine {
  private historicalData: Map<string, TimeSeriesDataPoint[]> = new Map()
  private industryTrends: Map<string, IndustryTrendAnalysis> = new Map()
  private initialized = false

  constructor() {}

  /**
   * Initialize the analytics engine
   */
  async initialize(): Promise<void> {
    try {
      logger.info('PredictiveAnalyticsEngine', 'Initializing predictive analytics engine...')

      // Load historical data (in production, this would come from database)
      await this.loadHistoricalData()

      // Initialize industry trend tracking
      await this.initializeIndustryTrends()

      this.initialized = true
      logger.info('PredictiveAnalyticsEngine', 'Predictive analytics engine initialized')
    } catch (error) {
      logger.error('PredictiveAnalyticsEngine', 'Failed to initialize analytics engine', error)
      throw error
    }
  }

  /**
   * Predict best contact time for a business
   */
  async predictBestContactTime(business: BusinessRecord): Promise<ContactTimingAnalysis> {
    try {
      if (!this.initialized) {
        await this.initialize()
      }

      logger.info(
        'PredictiveAnalyticsEngine',
        `Predicting contact time for: ${business.businessName}`
      )

      // Get historical contact data for this industry
      const industryKey = business.industry || 'general'
      const historicalData = this.getHistoricalContactData(industryKey)

      // Analyze patterns
      const dayOfWeekAnalysis = this.analyzeDayOfWeekPatterns(historicalData)
      const hourAnalysis = this.analyzeHourPatterns(historicalData)

      // Determine best contact time
      const bestDayOfWeek = this.getBestDayOfWeek(dayOfWeekAnalysis)
      const bestHourRange = this.getBestHourRange(hourAnalysis)

      // Calculate confidence based on data quality
      const confidence = this.calculateTimingConfidence(historicalData)

      return {
        bestDayOfWeek,
        bestHourRange,
        timezone: 'EST', // Default timezone
        confidence,
        historicalData,
      }
    } catch (error) {
      logger.error('PredictiveAnalyticsEngine', 'Contact time prediction failed', error)
      return this.getDefaultContactTiming()
    }
  }

  /**
   * Forecast response rates for different outreach strategies
   */
  async forecastResponseRate(business: BusinessRecord): Promise<ResponseRateForecast> {
    try {
      if (!this.initialized) {
        await this.initialize()
      }

      logger.info(
        'PredictiveAnalyticsEngine',
        `Forecasting response rate for: ${business.businessName}`
      )

      // Analyze business characteristics
      const businessFactors = this.analyzeBusinessFactors(business)

      // Get industry-specific response rates
      const industryRates = this.getIndustryResponseRates(business.industry || 'general')

      // Calculate predicted rate
      const predictedRate = this.calculatePredictedResponseRate(businessFactors, industryRates)

      // Calculate confidence interval
      const confidenceInterval = this.calculateConfidenceInterval(predictedRate, 0.1)

      // Recommend best strategy
      const recommendedStrategy = this.recommendOutreachStrategy(businessFactors)

      return {
        predictedRate,
        confidenceInterval,
        recommendedStrategy,
        factors: businessFactors,
      }
    } catch (error) {
      logger.error('PredictiveAnalyticsEngine', 'Response rate forecasting failed', error)
      return this.getDefaultResponseForecast()
    }
  }

  /**
   * Analyze industry trends
   */
  async analyzeIndustryTrends(industry: string): Promise<IndustryTrendAnalysis> {
    try {
      if (!this.initialized) {
        await this.initialize()
      }

      logger.info('PredictiveAnalyticsEngine', `Analyzing trends for industry: ${industry}`)

      // Get existing trend data or create new
      let trendAnalysis = this.industryTrends.get(industry)

      if (!trendAnalysis) {
        trendAnalysis = await this.generateIndustryTrendAnalysis(industry)
        this.industryTrends.set(industry, trendAnalysis)
      }

      // Update with recent data
      trendAnalysis = await this.updateTrendAnalysis(trendAnalysis)

      return trendAnalysis
    } catch (error) {
      logger.error(
        'PredictiveAnalyticsEngine',
        `Industry trend analysis failed for: ${industry}`,
        error
      )
      return this.getDefaultTrendAnalysis(industry)
    }
  }

  /**
   * Detect seasonal business patterns
   */
  async detectSeasonalPatterns(industry: string): Promise<SeasonalPattern[]> {
    try {
      const historicalData = this.getIndustryHistoricalData(industry)
      const patterns: SeasonalPattern[] = []

      // Analyze monthly patterns
      const monthlyData = this.groupDataByMonth(historicalData)
      const monthlyPattern = this.analyzeMonthlyPattern(monthlyData)

      if (monthlyPattern.strength > 0.3) {
        patterns.push(monthlyPattern)
      }

      // Analyze quarterly patterns
      const quarterlyPattern = this.analyzeQuarterlyPattern(historicalData)
      if (quarterlyPattern.strength > 0.3) {
        patterns.push(quarterlyPattern)
      }

      // Analyze holiday patterns
      const holidayPattern = this.analyzeHolidayPattern(historicalData)
      if (holidayPattern.strength > 0.3) {
        patterns.push(holidayPattern)
      }

      logger.info(
        'PredictiveAnalyticsEngine',
        `Found ${patterns.length} seasonal patterns for ${industry}`
      )
      return patterns
    } catch (error) {
      logger.error(
        'PredictiveAnalyticsEngine',
        `Seasonal pattern detection failed for: ${industry}`,
        error
      )
      return []
    }
  }

  /**
   * Load historical data (placeholder - would come from database)
   */
  private async loadHistoricalData(): Promise<void> {
    // Generate sample historical data for demonstration
    const industries = ['construction', 'healthcare', 'technology', 'retail', 'finance']

    industries.forEach(industry => {
      const data: TimeSeriesDataPoint[] = []
      const startDate = addMonths(new Date(), -12)

      for (let i = 0; i < 365; i++) {
        const date = addDays(startDate, i)
        const baseValue = 0.3 + Math.random() * 0.4 // 30-70% base response rate

        // Add day-of-week patterns
        const dayOfWeek = date.getDay()
        let dayMultiplier = 1
        if (dayOfWeek === 1 || dayOfWeek === 2) dayMultiplier = 1.2 // Monday/Tuesday better
        if (dayOfWeek === 0 || dayOfWeek === 6) dayMultiplier = 0.6 // Weekend worse

        // Add seasonal patterns
        const month = date.getMonth()
        let seasonalMultiplier = 1
        if (month >= 2 && month <= 4) seasonalMultiplier = 1.1 // Spring boost
        if (month >= 10 && month <= 11) seasonalMultiplier = 0.8 // Holiday slowdown

        const value = baseValue * dayMultiplier * seasonalMultiplier

        data.push({
          date,
          value: Math.max(0, Math.min(1, value)),
          metadata: { dayOfWeek, month, industry },
        })
      }

      this.historicalData.set(industry, data)
    })
  }

  /**
   * Initialize industry trends
   */
  private async initializeIndustryTrends(): Promise<void> {
    const industries = ['construction', 'healthcare', 'technology', 'retail', 'finance']

    for (const industry of industries) {
      const trendAnalysis = await this.generateIndustryTrendAnalysis(industry)
      this.industryTrends.set(industry, trendAnalysis)
    }
  }

  /**
   * Get historical contact data for industry
   */
  private getHistoricalContactData(industry: string): TimeSeriesDataPoint[] {
    return this.historicalData.get(industry) || this.historicalData.get('general') || []
  }

  /**
   * Analyze day-of-week patterns
   */
  private analyzeDayOfWeekPatterns(data: TimeSeriesDataPoint[]): Record<string, number> {
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    const dayAverages: Record<string, number> = {}

    dayNames.forEach((day, index) => {
      const dayData = data.filter(point => point.date.getDay() === index)
      dayAverages[day] = dayData.length > 0 ? mean(dayData.map(p => p.value)) : 0
    })

    return dayAverages
  }

  /**
   * Analyze hour patterns
   */
  private analyzeHourPatterns(data: TimeSeriesDataPoint[]): Record<string, number> {
    // Simulate hour-based patterns
    const hourRanges = {
      '8:00-9:00': 0.4,
      '9:00-10:00': 0.6,
      '10:00-11:00': 0.8,
      '11:00-12:00': 0.7,
      '12:00-13:00': 0.3,
      '13:00-14:00': 0.5,
      '14:00-15:00': 0.7,
      '15:00-16:00': 0.6,
      '16:00-17:00': 0.4,
    }

    return hourRanges
  }

  /**
   * Get best day of week
   */
  private getBestDayOfWeek(dayAnalysis: Record<string, number>): string {
    return Object.entries(dayAnalysis).sort(([, a], [, b]) => b - a)[0][0]
  }

  /**
   * Get best hour range
   */
  private getBestHourRange(hourAnalysis: Record<string, number>): string {
    return Object.entries(hourAnalysis).sort(([, a], [, b]) => b - a)[0][0]
  }

  /**
   * Calculate timing confidence
   */
  private calculateTimingConfidence(data: TimeSeriesDataPoint[]): number {
    if (data.length < 30) return 0.3
    if (data.length < 100) return 0.6
    return 0.8
  }

  /**
   * Analyze business factors for response prediction
   */
  private analyzeBusinessFactors(business: BusinessRecord): Record<string, number> {
    return {
      hasWebsite: business.website ? 1 : 0,
      hasPhone: business.phone ? 1 : 0,
      hasEmail: business.email ? 1 : 0,
      hasAddress: business.address ? 1 : 0,
      descriptionQuality: business.description ? Math.min(1, business.description.length / 200) : 0,
      industryRelevance: business.industry ? 0.8 : 0.5,
      businessMaturity: this.estimateBusinessMaturity(business),
    }
  }

  /**
   * Estimate business maturity
   */
  private estimateBusinessMaturity(business: BusinessRecord): number {
    let score = 0.3 // Base score

    if (business.website) score += 0.2
    if (business.phone && business.email) score += 0.2
    if (business.description && business.description.length > 100) score += 0.2
    if (business.address) score += 0.1

    return Math.min(1, score)
  }

  /**
   * Get industry response rates
   */
  private getIndustryResponseRates(industry: string): Record<string, number> {
    const industryRates: Record<string, Record<string, number>> = {
      construction: { email: 0.25, phone: 0.45, linkedin: 0.15, form: 0.35 },
      healthcare: { email: 0.3, phone: 0.4, linkedin: 0.2, form: 0.25 },
      technology: { email: 0.35, phone: 0.25, linkedin: 0.4, form: 0.3 },
      retail: { email: 0.2, phone: 0.35, linkedin: 0.1, form: 0.4 },
      finance: { email: 0.4, phone: 0.3, linkedin: 0.35, form: 0.25 },
      general: { email: 0.28, phone: 0.35, linkedin: 0.22, form: 0.3 },
    }

    return industryRates[industry] || industryRates.general
  }

  /**
   * Calculate predicted response rate
   */
  private calculatePredictedResponseRate(
    businessFactors: Record<string, number>,
    industryRates: Record<string, number>
  ): number {
    const baseRate = mean(Object.values(industryRates))

    // Adjust based on business factors
    let adjustedRate = baseRate
    adjustedRate *= 1 + businessFactors.businessMaturity * 0.3
    adjustedRate *= 1 + businessFactors.descriptionQuality * 0.2
    adjustedRate *=
      1 + (businessFactors.hasWebsite + businessFactors.hasPhone + businessFactors.hasEmail) * 0.1

    return Math.max(0.05, Math.min(0.8, adjustedRate))
  }

  /**
   * Calculate confidence interval
   */
  private calculateConfidenceInterval(
    predicted: number,
    margin: number
  ): { lower: number; upper: number } {
    return {
      lower: Math.max(0, predicted - margin),
      upper: Math.min(1, predicted + margin),
    }
  }

  /**
   * Recommend outreach strategy
   */
  private recommendOutreachStrategy(
    factors: Record<string, number>
  ): 'email' | 'phone' | 'linkedin' | 'form' {
    if (factors.hasEmail && factors.businessMaturity > 0.6) return 'email'
    if (factors.hasPhone && factors.businessMaturity > 0.4) return 'phone'
    if (factors.hasWebsite) return 'form'
    return 'linkedin'
  }

  /**
   * Generate industry trend analysis
   */
  private async generateIndustryTrendAnalysis(industry: string): Promise<IndustryTrendAnalysis> {
    const trendDirection =
      Math.random() > 0.3 ? 'growing' : Math.random() > 0.5 ? 'stable' : 'declining'
    const trendStrength = Math.random() * 0.8 + 0.2

    return {
      industry,
      trendDirection,
      trendStrength,
      insights: {
        emergingKeywords: ['digital transformation', 'automation', 'sustainability'],
        decliningKeywords: ['traditional', 'manual', 'legacy'],
        seasonalPatterns: await this.detectSeasonalPatterns(industry),
        competitorActivity: Math.random() * 100,
        marketSentiment: Math.random() * 2 - 1, // -1 to 1
      },
      analysisPeriod: {
        startDate: addMonths(new Date(), -6),
        endDate: new Date(),
      },
      analyzedAt: new Date(),
    }
  }

  /**
   * Update trend analysis with recent data
   */
  private async updateTrendAnalysis(
    analysis: IndustryTrendAnalysis
  ): Promise<IndustryTrendAnalysis> {
    // Update with recent data (placeholder)
    return {
      ...analysis,
      analyzedAt: new Date(),
    }
  }

  /**
   * Get industry historical data
   */
  private getIndustryHistoricalData(industry: string): TimeSeriesDataPoint[] {
    return this.historicalData.get(industry) || []
  }

  /**
   * Group data by month
   */
  private groupDataByMonth(data: TimeSeriesDataPoint[]): Record<number, TimeSeriesDataPoint[]> {
    const grouped: Record<number, TimeSeriesDataPoint[]> = {}

    data.forEach(point => {
      const month = point.date.getMonth()
      if (!grouped[month]) grouped[month] = []
      grouped[month].push(point)
    })

    return grouped
  }

  /**
   * Analyze monthly pattern
   */
  private analyzeMonthlyPattern(
    monthlyData: Record<number, TimeSeriesDataPoint[]>
  ): SeasonalPattern {
    const monthlyAverages: Record<number, number> = {}

    Object.entries(monthlyData).forEach(([month, data]) => {
      monthlyAverages[parseInt(month)] = mean(data.map(p => p.value))
    })

    const values = Object.values(monthlyAverages)
    const avgValue = mean(values)
    const stdDev = standardDeviation(values)

    // Find peak and low months
    const peakMonths = Object.entries(monthlyAverages)
      .filter(([, value]) => value > avgValue + stdDev * 0.5)
      .map(([month]) => parseInt(month))

    const lowMonths = Object.entries(monthlyAverages)
      .filter(([, value]) => value < avgValue - stdDev * 0.5)
      .map(([month]) => parseInt(month))

    return {
      name: 'Monthly Pattern',
      peakMonths,
      lowMonths,
      strength: stdDev / avgValue, // Coefficient of variation
      historicalData: Object.entries(monthlyAverages).map(([month, value]) => ({
        month: parseInt(month),
        year: new Date().getFullYear(),
        activityLevel: value,
      })),
    }
  }

  /**
   * Analyze quarterly pattern
   */
  private analyzeQuarterlyPattern(data: TimeSeriesDataPoint[]): SeasonalPattern {
    // Simplified quarterly analysis
    return {
      name: 'Quarterly Pattern',
      peakMonths: [2, 3, 4], // Q2
      lowMonths: [11, 0, 1], // Q4/Q1
      strength: 0.4,
      historicalData: [],
    }
  }

  /**
   * Analyze holiday pattern
   */
  private analyzeHolidayPattern(data: TimeSeriesDataPoint[]): SeasonalPattern {
    return {
      name: 'Holiday Pattern',
      peakMonths: [9, 10], // October/November
      lowMonths: [11, 0], // December/January
      strength: 0.3,
      historicalData: [],
    }
  }

  /**
   * Default contact timing
   */
  private getDefaultContactTiming(): ContactTimingAnalysis {
    return {
      bestDayOfWeek: 'Tuesday',
      bestHourRange: '10:00-11:00',
      timezone: 'EST',
      confidence: 0.5,
      historicalData: [],
    }
  }

  /**
   * Default response forecast
   */
  private getDefaultResponseForecast(): ResponseRateForecast {
    return {
      predictedRate: 0.3,
      confidenceInterval: { lower: 0.2, upper: 0.4 },
      recommendedStrategy: 'email',
      factors: {},
    }
  }

  /**
   * Default trend analysis
   */
  private getDefaultTrendAnalysis(industry: string): IndustryTrendAnalysis {
    return {
      industry,
      trendDirection: 'stable',
      trendStrength: 0.5,
      insights: {
        emergingKeywords: [],
        decliningKeywords: [],
        seasonalPatterns: [],
        competitorActivity: 50,
        marketSentiment: 0,
      },
      analysisPeriod: {
        startDate: addMonths(new Date(), -3),
        endDate: new Date(),
      },
      analyzedAt: new Date(),
    }
  }

  /**
   * Check if engine is initialized
   */
  isInitialized(): boolean {
    return this.initialized
  }
}

// Export singleton instance
export const predictiveAnalyticsEngine = new PredictiveAnalyticsEngine()
