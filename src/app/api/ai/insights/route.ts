'use strict'

/**
 * AI Insights API Route
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { NextRequest, NextResponse } from 'next/server'
import { storage } from '@/model/storage'
import { predictiveAnalyticsEngine } from '@/lib/predictiveAnalyticsEngine'
import { logger } from '@/utils/logger'
import { AIInsightsSummary } from '@/types/ai'

/**
 * GET /api/ai/insights
 * Get AI insights summary
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const regenerate = searchParams.get('regenerate') === 'true'

    logger.info('AI API', 'Getting AI insights summary')

    let insights: AIInsightsSummary | null = null

    if (!regenerate) {
      // Try to get existing insights
      insights = await storage.getLatestAIInsights()
    }

    if (!insights || regenerate) {
      // Generate new insights
      insights = await generateInsightsSummary()
      await storage.saveAIInsights(insights)
    }

    return NextResponse.json({
      success: true,
      data: insights
    })

  } catch (error) {
    logger.error('AI API', 'Failed to get AI insights', error)
    return NextResponse.json(
      { 
        error: 'Failed to get AI insights',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * POST /api/ai/insights
 * Generate new AI insights summary
 */
export async function POST(request: NextRequest) {
  try {
    logger.info('AI API', 'Generating new AI insights summary')

    // Generate insights
    const insights = await generateInsightsSummary()

    // Save insights
    await storage.saveAIInsights(insights)

    return NextResponse.json({
      success: true,
      data: insights,
      message: 'AI insights generated successfully'
    })

  } catch (error) {
    logger.error('AI API', 'Failed to generate AI insights', error)
    return NextResponse.json(
      { 
        error: 'Failed to generate AI insights',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * Generate insights summary from all AI analytics
 */
async function generateInsightsSummary(): Promise<AIInsightsSummary> {
  try {
    // Get all AI analytics
    const allAnalytics = await storage.getAllAIAnalytics()
    
    if (allAnalytics.length === 0) {
      return createEmptyInsights()
    }

    // Calculate summary statistics
    const totalAnalyzed = allAnalytics.length
    const leadScores = allAnalytics.map(a => a.leadScoring.overallScore)
    const averageLeadScore = Math.round(leadScores.reduce((sum, score) => sum + score, 0) / leadScores.length)

    // Count high-priority leads (score >= 80)
    const highPriorityLeads = allAnalytics.filter(a => a.leadScoring.overallScore >= 80).length

    // Analyze industries
    const industryMap = new Map<string, number>()
    const industryScores = new Map<string, number[]>()

    allAnalytics.forEach(analytics => {
      // Get business to find industry
      const industry = 'General' // Would need to get from business record
      
      industryMap.set(industry, (industryMap.get(industry) || 0) + 1)
      
      if (!industryScores.has(industry)) {
        industryScores.set(industry, [])
      }
      industryScores.get(industry)!.push(analytics.leadScoring.overallScore)
    })

    // Get top performing industries
    const topIndustries = Array.from(industryScores.entries())
      .map(([industry, scores]) => ({
        industry,
        avgScore: scores.reduce((sum, score) => sum + score, 0) / scores.length,
        count: scores.length
      }))
      .sort((a, b) => b.avgScore - a.avgScore)
      .slice(0, 5)
      .map(item => item.industry)

    // Initialize predictive analytics engine
    if (!predictiveAnalyticsEngine.isInitialized()) {
      await predictiveAnalyticsEngine.initialize()
    }

    // Analyze trends for top industries
    const keyTrends: string[] = []
    for (const industry of topIndustries.slice(0, 3)) {
      try {
        const trendAnalysis = await predictiveAnalyticsEngine.analyzeIndustryTrends(industry)
        if (trendAnalysis.trendDirection === 'growing') {
          keyTrends.push(`${industry} industry showing growth trend`)
        }
        keyTrends.push(...trendAnalysis.insights.emergingKeywords.slice(0, 2))
      } catch (error) {
        logger.warn('AI API', `Failed to analyze trends for ${industry}`, error)
      }
    }

    // Generate recommendations
    const recommendations = generateRecommendations(allAnalytics, averageLeadScore, highPriorityLeads)

    const insights: AIInsightsSummary = {
      totalAnalyzed,
      averageLeadScore,
      highPriorityLeads,
      topIndustries,
      keyTrends: keyTrends.slice(0, 10), // Limit to 10 trends
      recommendations,
      generatedAt: new Date()
    }

    logger.info('AI API', `Generated insights for ${totalAnalyzed} businesses`)
    return insights

  } catch (error) {
    logger.error('AI API', 'Failed to generate insights summary', error)
    return createEmptyInsights()
  }
}

/**
 * Generate recommendations based on analytics
 */
function generateRecommendations(
  allAnalytics: any[], 
  averageLeadScore: number, 
  highPriorityLeads: number
): string[] {
  const recommendations: string[] = []

  // Lead score recommendations
  if (averageLeadScore < 60) {
    recommendations.push('Consider refining lead qualification criteria to improve average lead quality')
  } else if (averageLeadScore > 80) {
    recommendations.push('Excellent lead quality detected - consider expanding search criteria')
  }

  // High priority recommendations
  const highPriorityPercentage = (highPriorityLeads / allAnalytics.length) * 100
  if (highPriorityPercentage < 20) {
    recommendations.push('Low percentage of high-priority leads - review targeting strategy')
  } else if (highPriorityPercentage > 50) {
    recommendations.push('High percentage of quality leads - prioritize immediate outreach')
  }

  // Website quality recommendations
  const websiteQualityScores = allAnalytics.map(a => a.websiteQuality.healthScore)
  const avgWebsiteScore = websiteQualityScores.reduce((sum, score) => sum + score, 0) / websiteQualityScores.length
  
  if (avgWebsiteScore < 60) {
    recommendations.push('Many leads have poor website quality - consider this in outreach strategy')
  }

  // Conversion probability recommendations
  const conversionProbs = allAnalytics.map(a => a.conversionPrediction.probability)
  const avgConversionProb = conversionProbs.reduce((sum, prob) => sum + prob, 0) / conversionProbs.length
  
  if (avgConversionProb > 0.7) {
    recommendations.push('High conversion probability detected - accelerate outreach efforts')
  } else if (avgConversionProb < 0.3) {
    recommendations.push('Low conversion probability - consider lead nurturing strategies')
  }

  // Contact strategy recommendations
  const emailStrategy = allAnalytics.filter(a => a.conversionPrediction.recommendedStrategy === 'email').length
  const phoneStrategy = allAnalytics.filter(a => a.conversionPrediction.recommendedStrategy === 'phone').length
  
  if (emailStrategy > phoneStrategy) {
    recommendations.push('Email outreach recommended for majority of leads')
  } else {
    recommendations.push('Phone outreach recommended for majority of leads')
  }

  // Business maturity recommendations
  const maturityScores = allAnalytics.map(a => a.businessMaturity.maturityScore)
  const avgMaturityScore = maturityScores.reduce((sum, score) => sum + score, 0) / maturityScores.length
  
  if (avgMaturityScore > 70) {
    recommendations.push('High business maturity detected - focus on value proposition')
  } else if (avgMaturityScore < 50) {
    recommendations.push('Many early-stage businesses - tailor messaging for growth-focused companies')
  }

  return recommendations.slice(0, 8) // Limit to 8 recommendations
}

/**
 * Create empty insights for when no data is available
 */
function createEmptyInsights(): AIInsightsSummary {
  return {
    totalAnalyzed: 0,
    averageLeadScore: 0,
    highPriorityLeads: 0,
    topIndustries: [],
    keyTrends: [],
    recommendations: [
      'Start by analyzing some business records to generate insights',
      'Use the batch processing feature to analyze multiple businesses at once',
      'Review lead scoring criteria to ensure optimal results'
    ],
    generatedAt: new Date()
  }
}
