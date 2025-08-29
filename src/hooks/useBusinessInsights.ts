/**
 * React Hook for Business Intelligence Insights
 * Provides processed BI metrics, distribution analysis, and predictions
 */

import { useState, useEffect, useCallback, useMemo } from 'react'
import { BusinessRecord } from '@/types/business'
import { LeadScore } from '@/lib/aiLeadScoring'
import {
  generateIndustryDistribution,
  generateScoreDistribution,
  generateGeographicDistribution,
  generateTrendData,
  generateConversionPrediction,
  calculateROIPredictions,
  ChartData,
  GeographicData,
  TrendData,
} from '@/utils/chartHelpers'
import { logger } from '@/utils/logger'

export interface BusinessInsights {
  industryDistribution: ChartData[]
  scoreDistribution: ChartData[]
  geographicDistribution: GeographicData[]
  trendData: TrendData[]
  conversionPredictions: ChartData[]
  roiPredictions: { category: string; leads: number; predictedRevenue: number; roi: number }[]
  summary: InsightsSummary
}

export interface InsightsSummary {
  totalBusinesses: number
  averageScore: number
  topIndustry: string
  topState: string
  highQualityLeads: number
  predictedConversions: number
  estimatedRevenue: number
  recommendations: string[]
}

export interface UseBusinessInsightsOptions {
  autoRefresh?: boolean
  refreshInterval?: number
  includeROI?: boolean
  averageOrderValue?: number
  conversionRates?: Record<string, number>
}

export interface BusinessInsightsState {
  insights: BusinessInsights | null
  isLoading: boolean
  error: string | null
  lastUpdated: Date | null
}

/**
 * Hook for generating business intelligence insights
 */
export function useBusinessInsights(
  businesses: BusinessRecord[],
  scores: Map<string, LeadScore>,
  options: UseBusinessInsightsOptions = {}
): BusinessInsightsState & {
  refreshInsights: () => void
  exportInsights: (format: 'json' | 'csv') => void
} {
  const {
    autoRefresh = true,
    refreshInterval = 30000, // 30 seconds
    includeROI = true,
    averageOrderValue = 1000,
    conversionRates = {
      high: 0.15,
      medium: 0.08,
      low: 0.03,
    },
  } = options

  const [state, setState] = useState<BusinessInsightsState>({
    insights: null,
    isLoading: false,
    error: null,
    lastUpdated: null,
  })

  /**
   * Generate comprehensive business insights
   */
  const generateInsights = useCallback(async (): Promise<BusinessInsights> => {
    try {
      logger.info('useBusinessInsights', 'Generating business insights...')

      // Industry distribution
      const industryDistribution = generateIndustryDistribution(businesses, scores)

      // Score distribution
      const scoreDistribution = generateScoreDistribution(scores)

      // Geographic distribution
      const geographicDistribution = generateGeographicDistribution(businesses, scores)

      // Trend data (daily for last 30 days)
      const trendData = generateTrendData(businesses, 'daily')

      // Conversion predictions
      const conversionPredictions = generateConversionPrediction(scores)

      // ROI predictions
      const roiPredictions = includeROI
        ? calculateROIPredictions(scores, averageOrderValue, conversionRates)
        : []

      // Generate summary
      const summary = generateInsightsSummary(
        businesses,
        scores,
        industryDistribution,
        geographicDistribution,
        conversionPredictions,
        roiPredictions
      )

      return {
        industryDistribution,
        scoreDistribution,
        geographicDistribution,
        trendData,
        conversionPredictions,
        roiPredictions,
        summary,
      }
    } catch (error) {
      logger.error('useBusinessInsights', 'Failed to generate insights', error)
      throw error
    }
  }, [businesses, scores, includeROI, averageOrderValue, conversionRates])

  /**
   * Generate insights summary
   */
  const generateInsightsSummary = useCallback(
    (
      businesses: BusinessRecord[],
      scores: Map<string, LeadScore>,
      industryDist: ChartData[],
      geoDist: GeographicData[],
      conversionPred: ChartData[],
      roiPred: { category: string; leads: number; predictedRevenue: number; roi: number }[]
    ): InsightsSummary => {
      const totalBusinesses = businesses.length
      const scoresArray = Array.from(scores.values())
      const averageScore =
        scoresArray.length > 0
          ? Math.round(scoresArray.reduce((sum, s) => sum + s.score, 0) / scoresArray.length)
          : 0

      const topIndustry = industryDist.length > 0 ? industryDist[0].name : 'Unknown'
      const topState =
        geoDist.length > 0
          ? geoDist.reduce((max, current) => (current.count > max.count ? current : max)).state
          : 'Unknown'

      const highQualityLeads = scoresArray.filter(s => s.score >= 70).length
      const predictedConversions = conversionPred.reduce((sum, p) => sum + p.value, 0)
      const estimatedRevenue = roiPred.reduce((sum, r) => sum + r.predictedRevenue, 0)

      // Generate recommendations
      const recommendations = generateRecommendations(
        totalBusinesses,
        averageScore,
        highQualityLeads,
        industryDist,
        geoDist
      )

      return {
        totalBusinesses,
        averageScore,
        topIndustry,
        topState,
        highQualityLeads,
        predictedConversions,
        estimatedRevenue,
        recommendations,
      }
    },
    []
  )

  /**
   * Generate actionable recommendations
   */
  const generateRecommendations = useCallback(
    (
      totalBusinesses: number,
      averageScore: number,
      highQualityLeads: number,
      industryDist: ChartData[],
      geoDist: GeographicData[]
    ): string[] => {
      const recommendations: string[] = []

      // Score-based recommendations
      if (averageScore < 50) {
        recommendations.push(
          'Consider improving data collection quality to increase average lead scores'
        )
      } else if (averageScore > 75) {
        recommendations.push(
          'Excellent lead quality! Focus on rapid follow-up for high-scoring leads'
        )
      }

      // Volume recommendations
      if (totalBusinesses < 100) {
        recommendations.push('Expand search criteria to capture more potential leads')
      } else if (totalBusinesses > 1000) {
        recommendations.push(
          'Consider implementing lead prioritization to focus on highest-quality prospects'
        )
      }

      // Quality recommendations
      const qualityRatio = totalBusinesses > 0 ? highQualityLeads / totalBusinesses : 0
      if (qualityRatio < 0.2) {
        recommendations.push('Low percentage of high-quality leads - review targeting criteria')
      } else if (qualityRatio > 0.4) {
        recommendations.push('High percentage of quality leads - excellent targeting!')
      }

      // Industry recommendations
      if (industryDist.length > 0) {
        const topIndustry = industryDist[0]
        if (topIndustry.value / totalBusinesses > 0.5) {
          recommendations.push(
            `Strong concentration in ${topIndustry.name} - consider diversifying or specializing further`
          )
        }
      }

      // Geographic recommendations
      if (geoDist.length > 0) {
        const topStates = geoDist.slice(0, 3)
        const topStatesCount = topStates.reduce((sum, state) => sum + state.count, 0)
        if (topStatesCount / totalBusinesses > 0.7) {
          recommendations.push(
            'Geographic concentration detected - consider expanding to new markets'
          )
        }
      }

      return recommendations
    },
    []
  )

  /**
   * Refresh insights
   */
  const refreshInsights = useCallback(async () => {
    if (businesses.length === 0) {
      setState(prev => ({
        ...prev,
        insights: null,
        error: 'No business data available',
      }))
      return
    }

    setState(prev => ({ ...prev, isLoading: true, error: null }))

    try {
      const insights = await generateInsights()
      setState(prev => ({
        ...prev,
        insights,
        isLoading: false,
        lastUpdated: new Date(),
      }))
      logger.info('useBusinessInsights', 'Insights refreshed successfully')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to generate insights'
      setState(prev => ({
        ...prev,
        error: errorMessage,
        isLoading: false,
      }))
      logger.error('useBusinessInsights', 'Failed to refresh insights', error)
    }
  }, [businesses, generateInsights])

  /**
   * Export insights to different formats
   */
  const exportInsights = useCallback(
    (format: 'json' | 'csv') => {
      if (!state.insights) {
        logger.warn('useBusinessInsights', 'No insights available to export')
        return
      }

      try {
        const timestamp = new Date().toISOString().split('T')[0]
        const filename = `business-insights-${timestamp}`

        if (format === 'json') {
          const jsonData = JSON.stringify(state.insights, null, 2)
          const blob = new Blob([jsonData], { type: 'application/json' })
          const url = window.URL.createObjectURL(blob)
          const link = document.createElement('a')
          link.href = url
          link.download = `${filename}.json`
          link.click()
          window.URL.revokeObjectURL(url)
        } else if (format === 'csv') {
          // Export summary as CSV
          const csvContent = [
            ['Metric', 'Value'],
            ['Total Businesses', state.insights.summary.totalBusinesses],
            ['Average Score', state.insights.summary.averageScore],
            ['Top Industry', state.insights.summary.topIndustry],
            ['Top State', state.insights.summary.topState],
            ['High Quality Leads', state.insights.summary.highQualityLeads],
            ['Predicted Conversions', state.insights.summary.predictedConversions],
            ['Estimated Revenue', `$${state.insights.summary.estimatedRevenue.toLocaleString()}`],
          ]
            .map(row => row.join(','))
            .join('\n')

          const blob = new Blob([csvContent], { type: 'text/csv' })
          const url = window.URL.createObjectURL(blob)
          const link = document.createElement('a')
          link.href = url
          link.download = `${filename}.csv`
          link.click()
          window.URL.revokeObjectURL(url)
        }

        logger.info('useBusinessInsights', `Insights exported as ${format}`)
      } catch (error) {
        logger.error('useBusinessInsights', 'Failed to export insights', error)
      }
    },
    [state.insights]
  )

  // Auto-refresh insights when data changes
  useEffect(() => {
    if (autoRefresh && businesses.length > 0) {
      refreshInsights()
    }
  }, [businesses, scores, autoRefresh, refreshInsights])

  // Set up auto-refresh interval
  useEffect(() => {
    if (!autoRefresh || refreshInterval <= 0) return

    const interval = setInterval(() => {
      if (!state.isLoading) {
        refreshInsights()
      }
    }, refreshInterval)

    return () => clearInterval(interval)
  }, [autoRefresh, refreshInterval, state.isLoading, refreshInsights])

  // Memoized computed values
  const memoizedState = useMemo(() => state, [state])

  return {
    ...memoizedState,
    refreshInsights,
    exportInsights,
  }
}
