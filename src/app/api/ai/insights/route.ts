'use strict'

/**
 * AI Insights API Route
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'
import { AIInsightsSummary } from '@/types/ai'

/**
 * GET /api/ai/insights
 * Get AI insights summary
 */
/**
 * Initialize server-side database with AI tables
 */
async function initializeServerDatabase() {
  try {
    const { PostgreSQLDatabase } = await import('@/lib/postgresql-database')

    const config = {
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432'),
      database: process.env.DB_NAME || 'business_scraper',
      username: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || '',
      ssl: process.env.DB_SSL === 'true',
      poolMin: parseInt(process.env.DB_POOL_MIN || '2'),
      poolMax: parseInt(process.env.DB_POOL_MAX || '10'),
      idleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '30000'),
      connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '5000'),
    }

    const db = new PostgreSQLDatabase(config)

    // Test connection with a simple query first
    await db.executeQuery('SELECT 1 as test')

    // Check if AI tables exist, if not create them
    const checkQuery = `
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'ai_analytics'
      ) as ai_tables_exist
    `

    const result = await db.executeQuery(checkQuery)
    const aiTablesExist = result.rows[0]?.ai_tables_exist

    if (!aiTablesExist) {
      logger.info('AI API', 'AI tables not found, creating them...')

      // Create AI tables directly
      const createTablesSQL = `
        -- AI Analytics Table
        CREATE TABLE IF NOT EXISTS ai_analytics (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          campaign_id UUID,
          analysis_type VARCHAR(100) NOT NULL,
          data JSONB NOT NULL DEFAULT '{}',
          insights JSONB NOT NULL DEFAULT '{}',
          confidence_score DECIMAL(5,4) DEFAULT 0.0,
          processing_time_ms INTEGER DEFAULT 0,
          model_version VARCHAR(50) DEFAULT 'v1.0',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- AI Insights Table
        CREATE TABLE IF NOT EXISTS ai_insights (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          title VARCHAR(255) NOT NULL,
          summary TEXT NOT NULL,
          recommendations JSONB DEFAULT '[]',
          data_sources JSONB DEFAULT '[]',
          confidence_level VARCHAR(20) DEFAULT 'medium',
          impact_score DECIMAL(5,4) DEFAULT 0.0,
          category VARCHAR(100) DEFAULT 'general',
          tags JSONB DEFAULT '[]',
          expires_at TIMESTAMP WITH TIME ZONE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_ai_analytics_created_at ON ai_analytics(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ai_insights_created_at ON ai_insights(created_at DESC);
      `

      await db.executeQuery(createTablesSQL)
      logger.info('AI API', 'AI tables created successfully')
    }

    return db
  } catch (error) {
    logger.error('AI API', 'Failed to initialize server database', error)
    throw error
  }
}

/**
 * Generate mock AI insights for development/demo purposes
 */
function generateMockInsights(): AIInsightsSummary {
  const currentDate = new Date()

  return {
    totalAnalyzed: 25,
    averageLeadScore: 72,
    highPriorityLeads: 8,
    topIndustries: [
      'Retail & Shopping',
      'Food & Restaurants',
      'Professional Services',
      'Healthcare',
      'Technology',
    ],
    keyTrends: [
      'Increased demand for local services',
      'Growing emphasis on digital presence',
      'Rising customer service expectations',
      'Shift towards sustainable business practices',
      'Mobile-first customer interactions',
    ],
    recommendations: [
      'Focus on local retail stores and shopping centers for immediate opportunities',
      'Target food service establishments with strong community presence',
      'Expand into professional services sector for B2B partnerships',
      'Consider seasonal trends when planning outreach campaigns',
      'Leverage location-based marketing for better conversion rates',
    ],
    generatedAt: currentDate,
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const regenerate = searchParams.get('regenerate') === 'true'

    logger.info('AI API', 'Getting AI insights summary')

    let insights: AIInsightsSummary | null = null
    let usingMockData = false

    try {
      // Try to initialize server database
      const db = await initializeServerDatabase()

      if (!regenerate) {
        // Try to get existing insights from PostgreSQL
        try {
          const latestInsights = await db.getLatestAIInsights(1)
          if (latestInsights.length > 0) {
            const insight = latestInsights[0]
            // Convert database format to AIInsightsSummary format
            insights = {
              totalAnalyzed: insight.totalAnalyzed || 0,
              averageLeadScore: insight.averageLeadScore || 0,
              highPriorityLeads: insight.highPriorityLeads || 0,
              topIndustries: Array.isArray(insight.topIndustries) ? insight.topIndustries : [],
              keyTrends: Array.isArray(insight.keyTrends) ? insight.keyTrends : [],
              recommendations: Array.isArray(insight.recommendations)
                ? insight.recommendations
                : [],
              generatedAt: insight.createdAt || new Date(),
            }
          }
        } catch (dbQueryError) {
          logger.warn(
            'AI API',
            'Failed to query existing insights, will generate new ones',
            dbQueryError
          )
        }
      }

      if (!insights || regenerate) {
        // Generate new insights
        insights = await generateInsightsSummary()

        // Save to PostgreSQL (convert AIInsightsSummary to database format)
        try {
          await db.saveAIInsights({
            title: 'AI Insights Summary',
            summary: `Generated insights for ${insights.totalAnalyzed} businesses with average lead score of ${insights.averageLeadScore}`,
            recommendations: insights.recommendations,
            dataSources: ['Business analytics', 'Lead scoring', 'Industry trends'],
            confidenceLevel: 'high',
            impactScore: insights.averageLeadScore / 100,
            category: 'business_intelligence',
            tags: ['ai_insights', 'lead_scoring', 'business_analytics'],
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
            // Store additional AIInsightsSummary data in a custom field if supported
            totalAnalyzed: insights.totalAnalyzed,
            averageLeadScore: insights.averageLeadScore,
            highPriorityLeads: insights.highPriorityLeads,
            topIndustries: insights.topIndustries,
            keyTrends: insights.keyTrends,
          })
        } catch (dbSaveError) {
          logger.warn('AI API', 'Failed to save insights to database', dbSaveError)
        }
      }
    } catch (dbError) {
      // Database connection failed, use mock data for development
      logger.warn('AI API', 'Database connection failed, using mock insights', dbError)
      insights = generateMockInsights()
      usingMockData = true
    }

    return NextResponse.json({
      success: true,
      data: insights,
      meta: {
        usingMockData,
        message: usingMockData
          ? 'Using mock data - PostgreSQL not available'
          : 'Data from PostgreSQL database',
      },
    })
  } catch (error) {
    logger.error('AI API', 'Failed to get AI insights', error)
    return NextResponse.json(
      {
        error: 'Failed to get AI insights',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * POST /api/ai/insights
 * Generate new AI insights summary
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    logger.info('AI API', 'Generating new AI insights summary')

    let insights: AIInsightsSummary
    let usingMockData = false

    try {
      // Try to initialize server database
      const db = await initializeServerDatabase()

      // Generate insights
      insights = await generateInsightsSummary()

      // Save insights to PostgreSQL (convert AIInsightsSummary to database format)
      try {
        await db.saveAIInsights({
          title: 'AI Insights Summary',
          summary: `Generated insights for ${insights.totalAnalyzed} businesses with average lead score of ${insights.averageLeadScore}`,
          recommendations: insights.recommendations,
          dataSources: ['Business analytics', 'Lead scoring', 'Industry trends'],
          confidenceLevel: 'high',
          impactScore: insights.averageLeadScore / 100,
          category: 'business_intelligence',
          tags: ['ai_insights', 'lead_scoring', 'business_analytics'],
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
          // Store additional AIInsightsSummary data in a custom field if supported
          totalAnalyzed: insights.totalAnalyzed,
          averageLeadScore: insights.averageLeadScore,
          highPriorityLeads: insights.highPriorityLeads,
          topIndustries: insights.topIndustries,
          keyTrends: insights.keyTrends,
        })
      } catch (dbSaveError) {
        logger.warn('AI API', 'Failed to save insights to database', dbSaveError)
      }
    } catch (dbError) {
      // Database connection failed, use mock data for development
      logger.warn('AI API', 'Database connection failed, generating mock insights', dbError)
      insights = generateMockInsights()
      usingMockData = true
    }

    return NextResponse.json({
      success: true,
      data: insights,
      meta: {
        usingMockData,
        message: usingMockData
          ? 'Generated mock data - PostgreSQL not available'
          : 'Data saved to PostgreSQL database',
      },
    })
  } catch (error) {
    logger.error('AI API', 'Failed to generate AI insights', error)
    return NextResponse.json(
      {
        error: 'Failed to generate AI insights',
        details: error instanceof Error ? error.message : 'Unknown error',
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
    // Try to get analytics from database, fall back to mock data if not available
    let allAnalytics: any[] = []

    try {
      // Initialize server database
      const db = await initializeServerDatabase()

      // Get all AI analytics from PostgreSQL
      allAnalytics = await db.getAllAIAnalytics()
    } catch (dbError) {
      logger.warn('AI API', 'Database not available for analytics, using mock data', dbError)
      // Use empty analytics array, will generate insights based on current trends
      allAnalytics = []
    }

    if (allAnalytics.length === 0) {
      return createEmptyInsights()
    }

    // Calculate summary statistics
    const totalAnalyzed = allAnalytics.length
    const leadScores = allAnalytics.map(a => a.leadScoring.overallScore)
    const averageLeadScore = Math.round(
      leadScores.reduce((sum, score) => sum + score, 0) / leadScores.length
    )

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
        count: scores.length,
      }))
      .sort((a, b) => b.avgScore - a.avgScore)
      .slice(0, 5)
      .map(item => item.industry)

    // Generate key trends (simplified approach for now)
    const keyTrends: string[] = []

    try {
      // Try to use predictive analytics engine if available
      const { predictiveAnalyticsEngine } = await import('@/lib/aiLeadScoringService')

      if (predictiveAnalyticsEngine && !predictiveAnalyticsEngine.isInitialized()) {
        await predictiveAnalyticsEngine.initialize()
      }

      // Analyze trends for top industries
      for (const industry of topIndustries.slice(0, 3)) {
        try {
          if (predictiveAnalyticsEngine) {
            const trendAnalysis = await predictiveAnalyticsEngine.analyzeIndustryTrends(industry)
            if (trendAnalysis.trendDirection === 'growing') {
              keyTrends.push(`${industry} industry showing growth trend`)
            }
            keyTrends.push(...trendAnalysis.insights.emergingKeywords.slice(0, 2))
          }
        } catch (error) {
          logger.warn('AI API', `Failed to analyze trends for ${industry}`, error)
        }
      }
    } catch (importError) {
      logger.warn(
        'AI API',
        'Predictive analytics engine not available, using fallback trends',
        importError
      )

      // Fallback trends when analytics engine is not available
      keyTrends.push(
        'Digital transformation accelerating across industries',
        'Increased focus on customer experience',
        'Growing demand for sustainable business practices',
        'Remote work driving technology adoption',
        'Local businesses emphasizing community engagement'
      )
    }

    // Generate recommendations
    const recommendations = generateRecommendations(
      allAnalytics,
      averageLeadScore,
      highPriorityLeads
    )

    const insights: AIInsightsSummary = {
      totalAnalyzed,
      averageLeadScore,
      highPriorityLeads,
      topIndustries,
      keyTrends: keyTrends.slice(0, 10), // Limit to 10 trends
      recommendations,
      generatedAt: new Date(),
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
    recommendations.push(
      'Consider refining lead qualification criteria to improve average lead quality'
    )
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
  const avgWebsiteScore =
    websiteQualityScores.reduce((sum, score) => sum + score, 0) / websiteQualityScores.length

  if (avgWebsiteScore < 60) {
    recommendations.push(
      'Many leads have poor website quality - consider this in outreach strategy'
    )
  }

  // Conversion probability recommendations
  const conversionProbs = allAnalytics.map(a => a.conversionPrediction.probability)
  const avgConversionProb =
    conversionProbs.reduce((sum, prob) => sum + prob, 0) / conversionProbs.length

  if (avgConversionProb > 0.7) {
    recommendations.push('High conversion probability detected - accelerate outreach efforts')
  } else if (avgConversionProb < 0.3) {
    recommendations.push('Low conversion probability - consider lead nurturing strategies')
  }

  // Contact strategy recommendations
  const emailStrategy = allAnalytics.filter(
    a => a.conversionPrediction.recommendedStrategy === 'email'
  ).length
  const phoneStrategy = allAnalytics.filter(
    a => a.conversionPrediction.recommendedStrategy === 'phone'
  ).length

  if (emailStrategy > phoneStrategy) {
    recommendations.push('Email outreach recommended for majority of leads')
  } else {
    recommendations.push('Phone outreach recommended for majority of leads')
  }

  // Business maturity recommendations
  const maturityScores = allAnalytics.map(a => a.businessMaturity.maturityScore)
  const avgMaturityScore =
    maturityScores.reduce((sum, score) => sum + score, 0) / maturityScores.length

  if (avgMaturityScore > 70) {
    recommendations.push('High business maturity detected - focus on value proposition')
  } else if (avgMaturityScore < 50) {
    recommendations.push(
      'Many early-stage businesses - tailor messaging for growth-focused companies'
    )
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
      'Review lead scoring criteria to ensure optimal results',
    ],
    generatedAt: new Date(),
  }
}
