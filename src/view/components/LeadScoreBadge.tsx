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
  Zap,
} from 'lucide-react'
import { Button } from './ui/Button'
import { BusinessRecord } from '@/types/business'
import { LeadScore } from '@/lib/aiLeadScoring'
import { logger } from '@/utils/logger'

interface LeadScoreBadgeProps {
  business: BusinessRecord
  leadScore?: LeadScore
  onScoreUpdate?: (score: LeadScore) => void
  showDetails?: boolean
  size?: 'sm' | 'md' | 'lg'
}

/**
 * Lead Score Badge Component
 * Displays AI-powered lead score with interactive features
 */
export function LeadScoreBadge({
  business,
  leadScore,
  onScoreUpdate,
  showDetails = false,
  size = 'md',
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

      // Import the AI service dynamically to avoid SSR issues
      const { aiLeadScoringService } = await import('@/lib/aiLeadScoring')

      const score = await aiLeadScoringService.getLeadScore(business)

      if (onScoreUpdate) {
        onScoreUpdate(score)
        logger.info('LeadScoreBadge', `Lead score calculated for: ${business.businessName}`)
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

  // If no lead score and not loading, show calculate button
  if (!leadScore && !business.leadScore && !loading) {
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
      <div
        className={`inline-flex items-center gap-1 rounded-full border ${getSizeClasses()} bg-gray-100 text-gray-600`}
      >
        <RefreshCw className="h-3 w-3 animate-spin" />
        <span>Calculating...</span>
      </div>
    )
  }

  // Get the score from props or business record
  const currentScore = leadScore || (business.leadScore ? {
    score: business.leadScore.score,
    confidence: business.leadScore.confidence,
    factors: business.leadScore.factors,
    recommendations: business.leadScore.recommendations || []
  } : null)

  // No score available
  if (!currentScore) {
    return (
      <div
        className={`inline-flex items-center gap-1 rounded-full border ${getSizeClasses()} bg-gray-100 text-gray-600`}
      >
        <Brain className="h-3 w-3" />
        <span>No Score</span>
      </div>
    )
  }

  const scoreColor = getScoreColor(currentScore.score)
  const scoreIcon = getScoreIcon(currentScore.score)
  const priorityLabel = getPriorityLabel(currentScore.score)

  return (
    <div className="flex items-center gap-2">
      {/* Main Score Badge */}
      <div
        className={`inline-flex items-center gap-1 rounded-full border ${getSizeClasses()} ${scoreColor} cursor-pointer transition-all hover:shadow-sm`}
        onClick={() => showDetails && setShowDetailedView(!showDetailedView)}
        title={`Lead Score: ${currentScore.score} (${priorityLabel} Priority)`}
      >
        {scoreIcon}
        <span className="font-medium">{currentScore.score}</span>
        {showDetails && <Eye className="h-3 w-3 ml-1" />}
      </div>

      {/* Confidence Indicator */}
      {currentScore.confidence > 0.8 && (
        <div
          className="inline-flex items-center"
          title={`High Confidence (${Math.round(currentScore.confidence * 100)}%)`}
        >
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
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          onClick={() => setShowDetailedView(false)}
        >
          <div
            className="bg-white rounded-lg p-6 max-w-md w-full mx-4"
            onClick={e => e.stopPropagation()}
          >
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
                  {currentScore.score}
                </div>
              </div>
              <div className="mt-2 text-xs text-gray-600">
                Priority: {priorityLabel} | Confidence: {Math.round(currentScore.confidence * 100)}%
              </div>
            </div>

            {/* Component Scores */}
            {currentScore.factors && (
              <div className="space-y-3 mb-4">
                <h4 className="font-medium text-sm">Component Scores</h4>

                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm">Data Completeness</span>
                    <span className="font-medium">{Math.round(currentScore.factors.dataCompleteness)}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-sm">Contact Quality</span>
                    <span className="font-medium">{Math.round(currentScore.factors.contactQuality)}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-sm">Business Size</span>
                    <span className="font-medium">{Math.round(currentScore.factors.businessSize)}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-sm">Industry Relevance</span>
                    <span className="font-medium">{Math.round(currentScore.factors.industryRelevance)}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-sm">Geographic Desirability</span>
                    <span className="font-medium">{Math.round(currentScore.factors.geographicDesirability)}</span>
                  </div>

                  <div className="flex justify-between items-center">
                    <span className="text-sm">Web Presence</span>
                    <span className="font-medium">{Math.round(currentScore.factors.webPresence)}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Recommendations */}
            {currentScore.recommendations && currentScore.recommendations.length > 0 && (
              <div className="p-3 bg-blue-50 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Zap className="h-4 w-4 text-blue-600" />
                  <span className="font-medium text-sm">Recommendations</span>
                </div>
                <div className="space-y-1">
                  {currentScore.recommendations.map((rec, index) => (
                    <p key={index} className="text-sm text-gray-700">• {rec}</p>
                  ))}
                </div>
              </div>
            )}

            {/* Last Updated */}
            <div className="mt-4 text-xs text-gray-500 text-center">
              Calculated: {business.leadScore?.scoredAt ? new Date(business.leadScore.scoredAt).toLocaleString() : 'Just now'}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
