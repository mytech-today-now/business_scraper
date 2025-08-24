'use strict'

/**
 * Lead Score Badge Component
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import React, { useState, useEffect } from 'react'
import { 
  Brain, 
  Star, 
  TrendingUp, 
  AlertCircle, 
  CheckCircle, 
  RefreshCw,
  Eye,
  Zap
} from 'lucide-react'
import { Button } from './ui/Button'
import { PredictiveAnalytics, LeadScore } from '@/types/ai'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

interface LeadScoreBadgeProps {
  business: BusinessRecord
  analytics?: PredictiveAnalytics
  onAnalyticsUpdate?: (analytics: PredictiveAnalytics) => void
  showDetails?: boolean
  size?: 'sm' | 'md' | 'lg'
}

/**
 * Lead Score Badge Component
 * Displays AI-powered lead score with interactive features
 */
export function LeadScoreBadge({ 
  business, 
  analytics, 
  onAnalyticsUpdate,
  showDetails = false,
  size = 'md'
}: LeadScoreBadgeProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showDetailedView, setShowDetailedView] = useState(false)

  /**
   * Calculate lead score if not available
   */
  const calculateLeadScore = async () => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('/api/ai/lead-scoring', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          businessId: business.id,
          business
        })
      })

      if (!response.ok) {
        throw new Error(`Failed to calculate lead score: ${response.statusText}`)
      }

      const data = await response.json()
      if (data.success && onAnalyticsUpdate) {
        onAnalyticsUpdate(data.data.analytics)
        logger.info('LeadScoreBadge', `Lead score calculated for: ${business.businessName}`)
      } else {
        throw new Error(data.error || 'Failed to calculate lead score')
      }

    } catch (error) {
      logger.error('LeadScoreBadge', 'Failed to calculate lead score', error)
      setError(error instanceof Error ? error.message : 'Failed to calculate lead score')
    } finally {
      setLoading(false)
    }
  }

  /**
   * Get score color based on value
   */
  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'bg-green-100 text-green-800 border-green-200'
    if (score >= 60) return 'bg-yellow-100 text-yellow-800 border-yellow-200'
    if (score >= 40) return 'bg-orange-100 text-orange-800 border-orange-200'
    return 'bg-red-100 text-red-800 border-red-200'
  }

  /**
   * Get score icon based on value
   */
  const getScoreIcon = (score: number) => {
    if (score >= 80) return <Star className="h-3 w-3" />
    if (score >= 60) return <TrendingUp className="h-3 w-3" />
    if (score >= 40) return <AlertCircle className="h-3 w-3" />
    return <AlertCircle className="h-3 w-3" />
  }

  /**
   * Get priority label
   */
  const getPriorityLabel = (score: number): string => {
    if (score >= 80) return 'High'
    if (score >= 60) return 'Medium'
    if (score >= 40) return 'Low'
    return 'Very Low'
  }

  /**
   * Get size classes
   */
  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return 'px-2 py-1 text-xs'
      case 'lg':
        return 'px-4 py-2 text-base'
      default:
        return 'px-3 py-1.5 text-sm'
    }
  }

  // If no analytics and not loading, show calculate button
  if (!analytics && !loading) {
    return (
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={calculateLeadScore}
          disabled={loading}
          className="h-8"
        >
          <Brain className="h-3 w-3 mr-1" />
          Score
        </Button>
        {error && (
          <div className="text-xs text-red-600" title={error}>
            <AlertCircle className="h-3 w-3" />
          </div>
        )}
      </div>
    )
  }

  // Loading state
  if (loading) {
    return (
      <div className={`inline-flex items-center gap-1 rounded-full border ${getSizeClasses()} bg-gray-100 text-gray-600`}>
        <RefreshCw className="h-3 w-3 animate-spin" />
        <span>Calculating...</span>
      </div>
    )
  }

  // No analytics available
  if (!analytics) {
    return (
      <div className={`inline-flex items-center gap-1 rounded-full border ${getSizeClasses()} bg-gray-100 text-gray-600`}>
        <Brain className="h-3 w-3" />
        <span>No Score</span>
      </div>
    )
  }

  const leadScore = analytics.leadScoring
  const scoreColor = getScoreColor(leadScore.overallScore)
  const scoreIcon = getScoreIcon(leadScore.overallScore)
  const priorityLabel = getPriorityLabel(leadScore.overallScore)

  return (
    <div className="flex items-center gap-2">
      {/* Main Score Badge */}
      <div 
        className={`inline-flex items-center gap-1 rounded-full border ${getSizeClasses()} ${scoreColor} cursor-pointer transition-all hover:shadow-sm`}
        onClick={() => showDetails && setShowDetailedView(!showDetailedView)}
        title={`Lead Score: ${leadScore.overallScore} (${priorityLabel} Priority)`}
      >
        {scoreIcon}
        <span className="font-medium">{leadScore.overallScore}</span>
        {showDetails && (
          <Eye className="h-3 w-3 ml-1" />
        )}
      </div>

      {/* Confidence Indicator */}
      {leadScore.confidence > 0.8 && (
        <div className="inline-flex items-center" title={`High Confidence (${Math.round(leadScore.confidence * 100)}%)`}>
          <CheckCircle className="h-3 w-3 text-green-600" />
        </div>
      )}

      {/* Quick Actions */}
      <Button
        variant="ghost"
        size="sm"
        onClick={calculateLeadScore}
        disabled={loading}
        className="h-6 w-6 p-0"
        title="Recalculate Score"
      >
        <RefreshCw className="h-3 w-3" />
      </Button>

      {/* Detailed View Modal/Popup */}
      {showDetailedView && showDetails && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowDetailedView(false)}>
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Brain className="h-5 w-5 text-blue-600" />
                Lead Score Details
              </h3>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowDetailedView(false)}
                className="h-8 w-8 p-0"
              >
                ×
              </Button>
            </div>

            {/* Overall Score */}
            <div className="mb-4 p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Overall Score</span>
                <div className={`px-3 py-1 rounded-full text-sm font-bold ${scoreColor}`}>
                  {leadScore.overallScore}
                </div>
              </div>
              <div className="mt-2 text-xs text-gray-600">
                Priority: {priorityLabel} | Confidence: {Math.round(leadScore.confidence * 100)}%
              </div>
            </div>

            {/* Component Scores */}
            <div className="space-y-3 mb-4">
              <h4 className="font-medium text-sm">Component Scores</h4>
              
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-sm">Website Quality</span>
                  <span className="font-medium">{leadScore.components.websiteQuality}</span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-sm">Business Maturity</span>
                  <span className="font-medium">{leadScore.components.businessMaturity}</span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-sm">Conversion Probability</span>
                  <span className="font-medium">{leadScore.components.conversionProbability}</span>
                </div>
                
                <div className="flex justify-between items-center">
                  <span className="text-sm">Industry Relevance</span>
                  <span className="font-medium">{leadScore.components.industryRelevance}</span>
                </div>
              </div>
            </div>

            {/* Recommendation */}
            {analytics.recommendation && (
              <div className="p-3 bg-blue-50 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Zap className="h-4 w-4 text-blue-600" />
                  <span className="font-medium text-sm">Recommendation</span>
                </div>
                <p className="text-sm text-gray-700">{analytics.recommendation.reasoning}</p>
                <div className="mt-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    analytics.recommendation.priority === 'high' ? 'bg-green-100 text-green-800' :
                    analytics.recommendation.priority === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-gray-100 text-gray-800'
                  }`}>
                    {analytics.recommendation.priority.toUpperCase()} PRIORITY
                  </span>
                </div>
              </div>
            )}

            {/* Last Updated */}
            <div className="mt-4 text-xs text-gray-500 text-center">
              Calculated: {new Date(leadScore.calculatedAt).toLocaleString()}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
