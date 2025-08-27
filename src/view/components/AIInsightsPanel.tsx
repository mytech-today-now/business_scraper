'use strict'

/**
 * AI Insights Panel Component
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import React, { useState, useEffect } from 'react'
import {
  Brain,
  TrendingUp,
  Target,
  Lightbulb,
  RefreshCw,
  BarChart3,
  Users,
  Star,
  AlertCircle,
  CheckCircle,
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { AIInsightsSummary, PredictiveAnalytics } from '@/types/ai'
import { logger } from '@/utils/logger'

interface AIInsightsPanelProps {
  businessAnalytics?: (PredictiveAnalytics & { businessId: string })[]
  onRefresh?: () => void
}

/**
 * AI Insights Panel Component
 * Displays AI-powered insights, recommendations, and analytics
 */
export function AIInsightsPanel({ businessAnalytics = [], onRefresh }: AIInsightsPanelProps) {
  const [insights, setInsights] = useState<AIInsightsSummary | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  /**
   * Safely get array property with fallback to empty array
   */
  const safeArray = (arr: any[] | undefined | null): any[] => {
    return Array.isArray(arr) ? arr : []
  }

  /**
   * Safely get number property with fallback to 0
   */
  const safeNumber = (num: number | undefined | null): number => {
    return typeof num === 'number' && !isNaN(num) ? num : 0
  }

  /**
   * Load AI insights from API
   */
  const loadInsights = async (regenerate = false) => {
    try {
      setLoading(true)
      setError(null)

      const url = `/api/ai/insights${regenerate ? '?regenerate=true' : ''}`
      const response = await fetch(url)

      if (!response.ok) {
        throw new Error(`Failed to load insights: ${response.statusText}`)
      }

      const data = await response.json()
      if (data.success && data.data) {
        // Ensure all required arrays exist and are properly formatted
        const normalizedInsights: AIInsightsSummary = {
          totalAnalyzed: safeNumber(data.data.totalAnalyzed),
          averageLeadScore: safeNumber(data.data.averageLeadScore),
          highPriorityLeads: safeNumber(data.data.highPriorityLeads),
          topIndustries: safeArray(data.data.topIndustries),
          keyTrends: safeArray(data.data.keyTrends),
          recommendations: safeArray(data.data.recommendations),
          generatedAt: data.data.generatedAt ? new Date(data.data.generatedAt) : new Date(),
        }
        setInsights(normalizedInsights)
        logger.info('AIInsightsPanel', 'Insights loaded successfully')
      } else {
        throw new Error(data.error || 'Failed to load insights')
      }
    } catch (error) {
      logger.error('AIInsightsPanel', 'Failed to load insights', error)
      setError(error instanceof Error ? error.message : 'Failed to load insights')
    } finally {
      setLoading(false)
    }
  }

  /**
   * Generate new insights
   */
  const generateInsights = async () => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/ai/insights', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (!response.ok) {
        throw new Error(`Failed to generate insights: ${response.statusText}`)
      }

      const data = await response.json()
      if (data.success && data.data) {
        // Ensure all required arrays exist and are properly formatted
        const normalizedInsights: AIInsightsSummary = {
          totalAnalyzed: safeNumber(data.data.totalAnalyzed),
          averageLeadScore: safeNumber(data.data.averageLeadScore),
          highPriorityLeads: safeNumber(data.data.highPriorityLeads),
          topIndustries: safeArray(data.data.topIndustries),
          keyTrends: safeArray(data.data.keyTrends),
          recommendations: safeArray(data.data.recommendations),
          generatedAt: data.data.generatedAt ? new Date(data.data.generatedAt) : new Date(),
        }
        setInsights(normalizedInsights)
        logger.info('AIInsightsPanel', 'Insights generated successfully')
        if (onRefresh) onRefresh()
      } else {
        throw new Error(data.error || 'Failed to generate insights')
      }
    } catch (error) {
      logger.error('AIInsightsPanel', 'Failed to generate insights', error)
      setError(error instanceof Error ? error.message : 'Failed to generate insights')
    } finally {
      setLoading(false)
    }
  }

  // Load insights on component mount
  useEffect(() => {
    loadInsights()
  }, [])

  /**
   * Get priority color for lead score
   */
  const getPriorityColor = (score: number): string => {
    if (score >= 80) return 'text-green-600'
    if (score >= 60) return 'text-yellow-600'
    return 'text-red-600'
  }

  /**
   * Get priority icon for lead score
   */
  const getPriorityIcon = (score: number) => {
    if (score >= 80) return <CheckCircle className="h-4 w-4 text-green-600" />
    if (score >= 60) return <AlertCircle className="h-4 w-4 text-yellow-600" />
    return <AlertCircle className="h-4 w-4 text-red-600" />
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Brain className="h-6 w-6 text-blue-600" />
          <h2 className="text-2xl font-bold">AI Insights</h2>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => loadInsights(true)} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="default" size="sm" onClick={generateInsights} disabled={loading}>
            <Brain className="h-4 w-4 mr-2" />
            Generate New
          </Button>
        </div>
      </div>

      {/* Error State */}
      {error && (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-red-600">
              <AlertCircle className="h-5 w-5" />
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Loading State */}
      {loading && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="h-8 w-8 animate-spin text-blue-600" />
              <span className="ml-2 text-gray-600">Generating AI insights...</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* No Data State */}
      {!insights && !loading && !error && (
        <Card>
          <CardContent className="pt-6">
            <div className="text-center py-8">
              <Brain className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No AI Insights Available</h3>
              <p className="text-gray-500 mb-4">
                Generate AI-powered insights to analyze your business data and get actionable
                recommendations.
              </p>
              <Button variant="default" onClick={generateInsights} disabled={loading}>
                <Brain className="h-4 w-4 mr-2" />
                Generate Insights
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Insights Content */}
      {insights && !loading && (
        <>
          {/* Summary Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Total Analyzed</p>
                    <p className="text-2xl font-bold">{insights.totalAnalyzed}</p>
                  </div>
                  <Users className="h-8 w-8 text-blue-600" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Avg Lead Score</p>
                    <p
                      className={`text-2xl font-bold ${getPriorityColor(insights.averageLeadScore)}`}
                    >
                      {insights.averageLeadScore}
                    </p>
                  </div>
                  <BarChart3 className="h-8 w-8 text-green-600" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">High Priority</p>
                    <p className="text-2xl font-bold text-green-600">
                      {insights.highPriorityLeads}
                    </p>
                  </div>
                  <Star className="h-8 w-8 text-yellow-600" />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-600">Industries</p>
                    <p className="text-2xl font-bold">
                      {safeArray(insights?.topIndustries).length}
                    </p>
                  </div>
                  <Target className="h-8 w-8 text-purple-600" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Top Industries */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Top Performing Industries
              </CardTitle>
            </CardHeader>
            <CardContent>
              {(() => {
                const topIndustries = safeArray(insights?.topIndustries)
                return topIndustries.length > 0 ? (
                  <div className="space-y-2">
                    {topIndustries.map((industry, index) => (
                      <div
                        key={`industry-${index}-${industry}`}
                        className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                      >
                        <div className="flex items-center gap-3">
                          <span className="flex items-center justify-center w-6 h-6 bg-blue-600 text-white text-sm font-bold rounded-full">
                            {index + 1}
                          </span>
                          <span className="font-medium">{industry || 'Unknown Industry'}</span>
                        </div>
                        <TrendingUp className="h-4 w-4 text-green-600" />
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 text-center py-4">No industry data available</p>
                )
              })()}
            </CardContent>
          </Card>

          {/* Key Trends */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Key Trends
              </CardTitle>
            </CardHeader>
            <CardContent>
              {(() => {
                const keyTrends = safeArray(insights?.keyTrends)
                return keyTrends.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {keyTrends.map((trend, index) => (
                      <div
                        key={`trend-${index}`}
                        className="flex items-center gap-2 p-3 bg-blue-50 rounded-lg"
                      >
                        <TrendingUp className="h-4 w-4 text-blue-600 flex-shrink-0" />
                        <span className="text-sm">{trend || 'Unknown trend'}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 text-center py-4">No trends identified yet</p>
                )
              })()}
            </CardContent>
          </Card>

          {/* Recommendations */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lightbulb className="h-5 w-5" />
                AI Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent>
              {(() => {
                const recommendations = safeArray(insights?.recommendations)
                return recommendations.length > 0 ? (
                  <div className="space-y-3">
                    {recommendations.map((recommendation, index) => (
                      <div
                        key={`recommendation-${index}`}
                        className="flex items-start gap-3 p-4 bg-yellow-50 border border-yellow-200 rounded-lg"
                      >
                        <Lightbulb className="h-5 w-5 text-yellow-600 flex-shrink-0 mt-0.5" />
                        <span className="text-sm">
                          {recommendation || 'No recommendation text available'}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-gray-500 text-center py-4">No recommendations available</p>
                )
              })()}
            </CardContent>
          </Card>

          {/* Recent Analytics Preview */}
          {(() => {
            const analytics = safeArray(businessAnalytics)
            return (
              analytics.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <BarChart3 className="h-5 w-5" />
                      Recent Business Analytics
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {analytics.slice(0, 5).map((analyticsItem, index) => {
                        const leadScore = safeNumber(analyticsItem?.leadScoring?.overallScore)
                        const businessId = analyticsItem?.businessId || `business-${index}`
                        const generatedAt = analyticsItem?.generatedAt
                          ? new Date(analyticsItem.generatedAt)
                          : new Date()

                        return (
                          <div
                            key={`analytics-${businessId}-${index}`}
                            className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                          >
                            <div className="flex items-center gap-3">
                              {getPriorityIcon(leadScore)}
                              <div>
                                <p className="font-medium">Business ID: {businessId}</p>
                                <p className="text-sm text-gray-600">
                                  Generated: {generatedAt.toLocaleDateString()}
                                </p>
                              </div>
                            </div>
                            <div className="text-right">
                              <p className={`font-bold ${getPriorityColor(leadScore)}`}>
                                {leadScore}
                              </p>
                              <p className="text-sm text-gray-600">Lead Score</p>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </CardContent>
                </Card>
              )
            )
          })()}

          {/* Last Updated */}
          <div className="text-center text-sm text-gray-500">
            Last updated:{' '}
            {insights?.generatedAt ? new Date(insights.generatedAt).toLocaleString() : 'Unknown'}
          </div>
        </>
      )}
    </div>
  )
}
