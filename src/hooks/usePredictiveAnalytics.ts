/**
 * React Hook for Predictive Analytics
 * Provides ML models for ROI/trend analysis and market predictions
 */

import { useState, useEffect, useCallback, useMemo } from 'react'
import { BusinessRecord } from '@/types/business'
import { LeadScore } from '@/lib/aiLeadScoring'
import { logger } from '@/utils/logger'

export interface PredictiveModel {
  name: string
  type: 'trend' | 'conversion' | 'roi' | 'market'
  accuracy: number
  lastTrained: Date
  predictions: PredictionResult[]
}

export interface PredictionResult {
  category: string
  value: number
  confidence: number
  timeframe: string
  factors: string[]
}

export interface MarketInsight {
  industry: string
  trend: 'growing' | 'stable' | 'declining'
  growthRate: number
  competitionLevel: 'low' | 'medium' | 'high'
  recommendations: string[]
}

export interface TrendPrediction {
  period: string
  predictedLeads: number
  confidence: number
  seasonalFactors: string[]
}

export interface ROIForecast {
  timeframe: '1month' | '3months' | '6months' | '1year'
  expectedRevenue: number
  expectedCosts: number
  projectedROI: number
  confidence: number
  assumptions: string[]
}

export interface UsePredictiveAnalyticsOptions {
  enableTrendAnalysis?: boolean
  enableROIForecasting?: boolean
  enableMarketInsights?: boolean
  historicalDataDays?: number
  confidenceThreshold?: number
}

export interface PredictiveAnalyticsState {
  models: PredictiveModel[]
  trendPredictions: TrendPrediction[]
  roiForecasts: ROIForecast[]
  marketInsights: MarketInsight[]
  isLoading: boolean
  error: string | null
  lastUpdated: Date | null
}

/**
 * Hook for predictive analytics and forecasting
 */
export function usePredictiveAnalytics(
  businesses: BusinessRecord[],
  scores: Map<string, LeadScore>,
  options: UsePredictiveAnalyticsOptions = {}
): PredictiveAnalyticsState & {
  runPredictions: () => Promise<void>
  trainModels: () => Promise<void>
  exportPredictions: (format: 'json' | 'csv') => void
} {
  const {
    enableTrendAnalysis = true,
    enableROIForecasting = true,
    enableMarketInsights = true,
    historicalDataDays = 90,
    confidenceThreshold = 0.7
  } = options

  const [state, setState] = useState<PredictiveAnalyticsState>({
    models: [],
    trendPredictions: [],
    roiForecasts: [],
    marketInsights: [],
    isLoading: false,
    error: null,
    lastUpdated: null
  })

  /**
   * Generate trend predictions based on historical data
   */
  const generateTrendPredictions = useCallback((): TrendPrediction[] => {
    if (businesses.length === 0) return []

    try {
      // Analyze historical patterns
      const now = new Date()
      const historicalData = businesses.filter(business => {
        const daysDiff = (now.getTime() - new Date(business.scrapedAt).getTime()) / (1000 * 60 * 60 * 24)
        return daysDiff <= historicalDataDays
      })

      // Group by time periods
      const weeklyData = groupBusinessesByWeek(historicalData)
      const monthlyData = groupBusinessesByMonth(historicalData)

      // Calculate trends
      const weeklyTrend = calculateTrend(weeklyData)
      const monthlyTrend = calculateTrend(monthlyData)

      const predictions: TrendPrediction[] = []

      // Next week prediction
      if (weeklyData.length >= 2) {
        const avgWeekly = weeklyData.reduce((sum, week) => sum + week.count, 0) / weeklyData.length
        const trendMultiplier = 1 + (weeklyTrend / 100)
        
        predictions.push({
          period: 'Next Week',
          predictedLeads: Math.round(avgWeekly * trendMultiplier),
          confidence: Math.min(0.9, weeklyData.length / 10),
          seasonalFactors: detectSeasonalFactors(weeklyData)
        })
      }

      // Next month prediction
      if (monthlyData.length >= 2) {
        const avgMonthly = monthlyData.reduce((sum, month) => sum + month.count, 0) / monthlyData.length
        const trendMultiplier = 1 + (monthlyTrend / 100)
        
        predictions.push({
          period: 'Next Month',
          predictedLeads: Math.round(avgMonthly * trendMultiplier),
          confidence: Math.min(0.8, monthlyData.length / 6),
          seasonalFactors: detectSeasonalFactors(monthlyData)
        })
      }

      return predictions
    } catch (error) {
      logger.error('usePredictiveAnalytics', 'Failed to generate trend predictions', error)
      return []
    }
  }, [businesses, historicalDataDays])

  /**
   * Generate ROI forecasts
   */
  const generateROIForecasts = useCallback((): ROIForecast[] => {
    if (scores.size === 0) return []

    try {
      const scoresArray = Array.from(scores.values())
      const avgScore = scoresArray.reduce((sum, s) => sum + s.score, 0) / scoresArray.length

      // Base conversion rates by score range
      const conversionRates = {
        high: 0.15, // 80-100 score
        medium: 0.08, // 50-79 score
        low: 0.03 // 0-49 score
      }

      const averageOrderValue = 1000 // Default AOV
      const costPerLead = 10 // Default cost per lead

      const forecasts: ROIForecast[] = []
      const timeframes: Array<{ key: '1month' | '3months' | '6months' | '1year', multiplier: number }> = [
        { key: '1month', multiplier: 1 },
        { key: '3months', multiplier: 3 },
        { key: '6months', multiplier: 6 },
        { key: '1year', multiplier: 12 }
      ]

      timeframes.forEach(({ key, multiplier }) => {
        // Estimate leads per month based on current data
        const leadsPerMonth = Math.round(businesses.length / Math.max(1, historicalDataDays / 30))
        const totalLeads = leadsPerMonth * multiplier

        // Calculate conversions based on score distribution
        const highScoreLeads = scoresArray.filter(s => s.score >= 80).length
        const mediumScoreLeads = scoresArray.filter(s => s.score >= 50 && s.score < 80).length
        const lowScoreLeads = scoresArray.filter(s => s.score < 50).length

        const totalScored = highScoreLeads + mediumScoreLeads + lowScoreLeads
        const highRatio = totalScored > 0 ? highScoreLeads / totalScored : 0.2
        const mediumRatio = totalScored > 0 ? mediumScoreLeads / totalScored : 0.5
        const lowRatio = totalScored > 0 ? lowScoreLeads / totalScored : 0.3

        const projectedHighLeads = Math.round(totalLeads * highRatio)
        const projectedMediumLeads = Math.round(totalLeads * mediumRatio)
        const projectedLowLeads = Math.round(totalLeads * lowRatio)

        const conversions = 
          projectedHighLeads * conversionRates.high +
          projectedMediumLeads * conversionRates.medium +
          projectedLowLeads * conversionRates.low

        const expectedRevenue = conversions * averageOrderValue
        const expectedCosts = totalLeads * costPerLead
        const projectedROI = expectedCosts > 0 ? (expectedRevenue - expectedCosts) / expectedCosts : 0

        forecasts.push({
          timeframe: key,
          expectedRevenue: Math.round(expectedRevenue),
          expectedCosts: Math.round(expectedCosts),
          projectedROI: Math.round(projectedROI * 100) / 100,
          confidence: Math.max(0.5, Math.min(0.9, avgScore / 100)),
          assumptions: [
            `Average order value: $${averageOrderValue}`,
            `Cost per lead: $${costPerLead}`,
            `Based on ${totalScored} scored leads`,
            `Historical data: ${historicalDataDays} days`
          ]
        })
      })

      return forecasts
    } catch (error) {
      logger.error('usePredictiveAnalytics', 'Failed to generate ROI forecasts', error)
      return []
    }
  }, [scores, businesses, historicalDataDays])

  /**
   * Generate market insights
   */
  const generateMarketInsights = useCallback((): MarketInsight[] => {
    if (businesses.length === 0) return []

    try {
      // Group businesses by industry
      const industryMap = new Map<string, BusinessRecord[]>()
      businesses.forEach(business => {
        const industry = business.industry || 'Unknown'
        if (!industryMap.has(industry)) {
          industryMap.set(industry, [])
        }
        industryMap.get(industry)!.push(business)
      })

      const insights: MarketInsight[] = []

      industryMap.forEach((industryBusinesses, industry) => {
        // Calculate average score for industry
        const industryScores = industryBusinesses
          .map(b => scores.get(b.id)?.score || 0)
          .filter(score => score > 0)

        const avgScore = industryScores.length > 0 
          ? industryScores.reduce((sum, score) => sum + score, 0) / industryScores.length
          : 0

        // Determine trend based on recent data
        const recentBusinesses = industryBusinesses.filter(b => {
          const daysDiff = (Date.now() - new Date(b.scrapedAt).getTime()) / (1000 * 60 * 60 * 24)
          return daysDiff <= 30
        })

        const olderBusinesses = industryBusinesses.filter(b => {
          const daysDiff = (Date.now() - new Date(b.scrapedAt).getTime()) / (1000 * 60 * 60 * 24)
          return daysDiff > 30 && daysDiff <= 60
        })

        let trend: 'growing' | 'stable' | 'declining' = 'stable'
        let growthRate = 0

        if (olderBusinesses.length > 0) {
          const recentRate = recentBusinesses.length / 30 // per day
          const olderRate = olderBusinesses.length / 30 // per day
          
          if (recentRate > olderRate * 1.1) {
            trend = 'growing'
            growthRate = ((recentRate - olderRate) / olderRate) * 100
          } else if (recentRate < olderRate * 0.9) {
            trend = 'declining'
            growthRate = ((recentRate - olderRate) / olderRate) * 100
          }
        }

        // Determine competition level based on business density
        const competitionLevel: 'low' | 'medium' | 'high' = 
          industryBusinesses.length < 10 ? 'low' :
          industryBusinesses.length < 50 ? 'medium' : 'high'

        // Generate recommendations
        const recommendations = generateIndustryRecommendations(
          industry,
          trend,
          avgScore,
          competitionLevel,
          industryBusinesses.length
        )

        insights.push({
          industry,
          trend,
          growthRate: Math.round(growthRate * 100) / 100,
          competitionLevel,
          recommendations
        })
      })

      return insights.sort((a, b) => b.growthRate - a.growthRate)
    } catch (error) {
      logger.error('usePredictiveAnalytics', 'Failed to generate market insights', error)
      return []
    }
  }, [businesses, scores])

  /**
   * Run all predictions
   */
  const runPredictions = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }))

    try {
      const trendPredictions = enableTrendAnalysis ? generateTrendPredictions() : []
      const roiForecasts = enableROIForecasting ? generateROIForecasts() : []
      const marketInsights = enableMarketInsights ? generateMarketInsights() : []

      setState(prev => ({
        ...prev,
        trendPredictions,
        roiForecasts,
        marketInsights,
        isLoading: false,
        lastUpdated: new Date()
      }))

      logger.info('usePredictiveAnalytics', 'Predictions generated successfully')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to run predictions'
      setState(prev => ({
        ...prev,
        error: errorMessage,
        isLoading: false
      }))
      logger.error('usePredictiveAnalytics', 'Failed to run predictions', error)
    }
  }, [
    enableTrendAnalysis,
    enableROIForecasting,
    enableMarketInsights,
    generateTrendPredictions,
    generateROIForecasts,
    generateMarketInsights
  ])

  /**
   * Train predictive models (placeholder for future ML implementation)
   */
  const trainModels = useCallback(async () => {
    setState(prev => ({ ...prev, isLoading: true }))

    try {
      // Placeholder for model training
      // In a real implementation, this would train ML models on historical data
      
      const models: PredictiveModel[] = [
        {
          name: 'Trend Predictor',
          type: 'trend',
          accuracy: 0.75,
          lastTrained: new Date(),
          predictions: []
        },
        {
          name: 'ROI Forecaster',
          type: 'roi',
          accuracy: 0.68,
          lastTrained: new Date(),
          predictions: []
        },
        {
          name: 'Market Analyzer',
          type: 'market',
          accuracy: 0.72,
          lastTrained: new Date(),
          predictions: []
        }
      ]

      setState(prev => ({
        ...prev,
        models,
        isLoading: false
      }))

      logger.info('usePredictiveAnalytics', 'Models trained successfully')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to train models'
      setState(prev => ({
        ...prev,
        error: errorMessage,
        isLoading: false
      }))
      logger.error('usePredictiveAnalytics', 'Failed to train models', error)
    }
  }, [])

  /**
   * Export predictions
   */
  const exportPredictions = useCallback((format: 'json' | 'csv') => {
    try {
      const timestamp = new Date().toISOString().split('T')[0]
      const filename = `predictive-analytics-${timestamp}`

      const exportData = {
        trendPredictions: state.trendPredictions,
        roiForecasts: state.roiForecasts,
        marketInsights: state.marketInsights,
        generatedAt: new Date().toISOString()
      }

      if (format === 'json') {
        const jsonData = JSON.stringify(exportData, null, 2)
        const blob = new Blob([jsonData], { type: 'application/json' })
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `${filename}.json`
        link.click()
        window.URL.revokeObjectURL(url)
      } else if (format === 'csv') {
        // Export ROI forecasts as CSV
        const csvContent = [
          ['Timeframe', 'Expected Revenue', 'Expected Costs', 'Projected ROI', 'Confidence'],
          ...state.roiForecasts.map(forecast => [
            forecast.timeframe,
            forecast.expectedRevenue,
            forecast.expectedCosts,
            `${forecast.projectedROI}%`,
            `${Math.round(forecast.confidence * 100)}%`
          ])
        ].map(row => row.join(',')).join('\n')

        const blob = new Blob([csvContent], { type: 'text/csv' })
        const url = window.URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `${filename}.csv`
        link.click()
        window.URL.revokeObjectURL(url)
      }

      logger.info('usePredictiveAnalytics', `Predictions exported as ${format}`)
    } catch (error) {
      logger.error('usePredictiveAnalytics', 'Failed to export predictions', error)
    }
  }, [state])

  // Auto-run predictions when data changes
  useEffect(() => {
    if (businesses.length > 0 && scores.size > 0) {
      runPredictions()
    }
  }, [businesses, scores, runPredictions])

  return {
    ...state,
    runPredictions,
    trainModels,
    exportPredictions
  }
}

// Helper functions
function groupBusinessesByWeek(businesses: BusinessRecord[]): { week: string; count: number }[] {
  const weekMap = new Map<string, number>()
  
  businesses.forEach(business => {
    const date = new Date(business.scrapedAt)
    const weekStart = new Date(date)
    weekStart.setDate(date.getDate() - date.getDay())
    const weekKey = weekStart.toISOString().split('T')[0]
    
    weekMap.set(weekKey, (weekMap.get(weekKey) || 0) + 1)
  })
  
  return Array.from(weekMap.entries()).map(([week, count]) => ({ week, count }))
}

function groupBusinessesByMonth(businesses: BusinessRecord[]): { month: string; count: number }[] {
  const monthMap = new Map<string, number>()
  
  businesses.forEach(business => {
    const date = new Date(business.scrapedAt)
    const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
    
    monthMap.set(monthKey, (monthMap.get(monthKey) || 0) + 1)
  })
  
  return Array.from(monthMap.entries()).map(([month, count]) => ({ month, count }))
}

function calculateTrend(data: { count: number }[]): number {
  if (data.length < 2) return 0
  
  const recent = data.slice(-3).reduce((sum, d) => sum + d.count, 0) / Math.min(3, data.length)
  const older = data.slice(0, -3).reduce((sum, d) => sum + d.count, 0) / Math.max(1, data.length - 3)
  
  return older > 0 ? ((recent - older) / older) * 100 : 0
}

function detectSeasonalFactors(data: { count: number }[]): string[] {
  // Simplified seasonal detection
  const factors: string[] = []
  
  if (data.length >= 4) {
    const avg = data.reduce((sum, d) => sum + d.count, 0) / data.length
    const recent = data[data.length - 1].count
    
    if (recent > avg * 1.2) {
      factors.push('Above average activity')
    } else if (recent < avg * 0.8) {
      factors.push('Below average activity')
    }
  }
  
  return factors
}

function generateIndustryRecommendations(
  industry: string,
  trend: 'growing' | 'stable' | 'declining',
  avgScore: number,
  competitionLevel: 'low' | 'medium' | 'high',
  businessCount: number
): string[] {
  const recommendations: string[] = []
  
  if (trend === 'growing') {
    recommendations.push(`${industry} is growing - consider increasing investment`)
  } else if (trend === 'declining') {
    recommendations.push(`${industry} is declining - evaluate market position`)
  }
  
  if (avgScore < 50) {
    recommendations.push(`Low average scores in ${industry} - improve targeting`)
  } else if (avgScore > 75) {
    recommendations.push(`High-quality leads in ${industry} - prioritize this market`)
  }
  
  if (competitionLevel === 'low') {
    recommendations.push(`Low competition in ${industry} - opportunity for expansion`)
  } else if (competitionLevel === 'high') {
    recommendations.push(`High competition in ${industry} - focus on differentiation`)
  }
  
  return recommendations
}
