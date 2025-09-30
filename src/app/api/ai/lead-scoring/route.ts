'use strict'

/**
 * AI Lead Scoring API Route
 * Phase 2: AI & Automation Enhancement (v1.10.0)
 */

import { NextRequest, NextResponse } from 'next/server'
import { aiLeadScoringService } from '@/lib/aiLeadScoring'
import { enhancedDataManager } from '@/lib/enhancedDataManager'
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { BusinessRecord } from '@/types/business'
import { withApiSecurity } from '@/lib/api-security'

/**
 * POST /api/ai/lead-scoring
 * Calculate lead score for a business record or batch of businesses
 */
export const POST = withApiSecurity(
  async (request: NextRequest) => {
    try {
      const body = await request.json()
      const { businessId, business, businesses, action = 'score' } = body

      switch (action) {
        case 'score':
          if (!businessId && !business) {
            return NextResponse.json(
              { error: 'Business ID or business record is required' },
              { status: 400 }
            )
          }

          logger.info(
            'AI API',
            `Lead scoring request for business: ${businessId || business?.businessName}`
          )

          // Get business record if only ID provided
          let businessRecord: BusinessRecord
          if (businessId && !business) {
            const storedBusiness = await storage.getBusiness(businessId)
            if (!storedBusiness) {
              return NextResponse.json({ error: 'Business not found' }, { status: 404 })
            }
            businessRecord = storedBusiness
          } else {
            businessRecord = business
          }

          // Calculate lead score using new AI service
          const leadScore = await aiLeadScoringService.getLeadScore(businessRecord)

          logger.info('AI API', `Lead scoring completed for: ${businessRecord.businessName}`)

          return NextResponse.json({
            success: true,
            data: {
              businessId: businessId || businessRecord.id,
              businessName: businessRecord.businessName,
              leadScore,
            },
          })

        case 'batch':
          if (!businesses || !Array.isArray(businesses)) {
            return NextResponse.json(
              { error: 'businesses array is required for batch scoring' },
              { status: 400 }
            )
          }

          // Process batch with enhanced data manager
          const result = await enhancedDataManager.processBatch(businesses, {
            enableLeadScoring: true,
            enableValidation: true,
            enableDuplicateDetection: true,
            enableCaching: true,
          })

          return NextResponse.json({
            success: true,
            data: {
              processed: result.processed,
              scores: Object.fromEntries(result.scores),
              stats: result.stats,
              duplicates: result.duplicates,
              errors: result.errors,
            },
          })

        default:
          return NextResponse.json({ error: `Unknown action: ${action}` }, { status: 400 })
      }
    } catch (error) {
      logger.error('AI API', 'Lead scoring failed', error)
      return NextResponse.json(
        {
          error: 'Failed to calculate lead score',
          details: error instanceof Error ? error.message : 'Unknown error',
        },
        { status: 500 }
      )
    }
  },
  {
    requireAuth: false,
    requireCSRF: false,
    rateLimit: 'general',
    validateInput: true,
    logRequests: true,
  }
)

/**
 * GET /api/ai/lead-scoring?businessId=xxx
 * Get existing lead score for a business
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const businessId = searchParams.get('businessId')

    if (!businessId) {
      return NextResponse.json({ error: 'Business ID is required' }, { status: 400 })
    }

    logger.info('AI API', `Getting lead score for business: ${businessId}`)

    // Get existing analytics
    const analytics = await storage.getAIAnalytics(businessId)

    if (!analytics) {
      return NextResponse.json(
        { error: 'No AI analytics found for this business' },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      data: {
        businessId,
        analytics,
      },
    })
  } catch (error) {
    logger.error('AI API', 'Failed to get lead score', error)
    return NextResponse.json(
      {
        error: 'Failed to get lead score',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * PUT /api/ai/lead-scoring
 * Update lead score for a business
 */
export async function PUT(request: NextRequest) {
  try {
    const body = await request.json()
    const { businessId } = body

    if (!businessId) {
      return NextResponse.json({ error: 'Business ID is required' }, { status: 400 })
    }

    logger.info('AI API', `Updating lead score for business: ${businessId}`)

    // Get business record
    const business = await storage.getBusiness(businessId)
    if (!business) {
      return NextResponse.json({ error: 'Business not found' }, { status: 404 })
    }

    // Use AI lead scoring service to regenerate analytics
    const leadScore = await aiLeadScoringService.getLeadScore(business)

    // Convert lead score to analytics format
    const analytics = {
      leadScoring: {
        overallScore: leadScore.score,
        confidence: leadScore.confidence,
        components: {
          websiteQuality: leadScore.factors.webPresence,
          businessMaturity: leadScore.factors.businessSize,
          conversionProbability: leadScore.confidence * 100,
          industryRelevance: leadScore.factors.industryRelevance
        },
        breakdown: {
          domainAuthority: leadScore.factors.webPresence,
          contentQuality: leadScore.factors.dataCompleteness,
          technicalPerformance: leadScore.factors.webPresence,
          businessSignals: leadScore.factors.businessSize,
          contactAvailability: leadScore.factors.contactQuality
        },
        calculatedAt: new Date(),
        modelVersion: '1.0.0'
      },
      websiteQuality: {
        healthScore: 75,
        lighthouse: {
          performance: 75,
          accessibility: 75,
          bestPractices: 75,
          seo: 75,
          pwa: 75
        },
        content: {
          professionalismScore: 75,
          readabilityScore: 75,
          keywordRelevance: 75,
          callToActionPresence: true,
          contactInfoAvailability: true
        },
        technical: {
          loadTime: 2.5,
          mobileOptimized: true,
          httpsEnabled: true,
          socialMediaPresence: true,
          structuredDataPresent: true
        },
        recommendations: ['Improve website performance'],
        analyzedAt: new Date()
      },
      businessMaturity: {
        maturityScore: 70,
        growthSignals: {
          careersPageExists: false,
          jobPostingsFound: 0,
          fundingMentions: [],
          pressReleases: [],
          investorRelationsPage: false,
          teamPageExists: false,
          aboutPageQuality: 70
        },
        sizeIndicators: {
          estimatedEmployeeCount: null,
          officeLocations: [],
          serviceAreas: [],
          clientTestimonials: 0,
          caseStudies: 0
        },
        digitalPresence: {
          socialMediaAccounts: [],
          blogActivity: false,
          lastBlogPost: null,
          emailMarketingSignup: false,
          liveChatAvailable: false
        },
        analyzedAt: new Date()
      },
      conversionPrediction: {
        probability: leadScore.confidence,
        confidenceInterval: {
          lower: Math.max(0, leadScore.confidence - 0.1),
          upper: Math.min(1, leadScore.confidence + 0.1)
        },
        factors: {
          industryMatch: 75,
          businessSize: 70,
          websiteQuality: 75,
          contactAvailability: 80,
          geographicRelevance: 70
        },
        recommendedStrategy: 'email' as const,
        bestContactTime: {
          dayOfWeek: 'Tuesday',
          hourRange: '10:00-12:00',
          timezone: 'EST'
        },
        predictedAt: new Date()
      },
      industryTrends: [],
      recommendation: {
        priority: leadScore.score > 70 ? 'high' as const : leadScore.score > 40 ? 'medium' as const : 'low' as const,
        reasoning: `Lead score of ${leadScore.score} indicates ${leadScore.score > 70 ? 'high' : leadScore.score > 40 ? 'medium' : 'low'} potential`,
        nextSteps: leadScore.recommendations,
        estimatedValue: null
      },
      generatedAt: new Date()
    }

    // Save updated analytics
    await storage.saveAIAnalytics(businessId, analytics)

    logger.info('AI API', `Lead score updated for: ${business.businessName}`)

    return NextResponse.json({
      success: true,
      data: {
        businessId,
        businessName: business.businessName,
        analytics,
      },
    })
  } catch (error) {
    logger.error('AI API', 'Failed to update lead score', error)
    return NextResponse.json(
      {
        error: 'Failed to update lead score',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/ai/lead-scoring?businessId=xxx
 * Delete lead score for a business
 */
export async function DELETE(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const businessId = searchParams.get('businessId')

    if (!businessId) {
      return NextResponse.json({ error: 'Business ID is required' }, { status: 400 })
    }

    logger.info('AI API', `Deleting lead score for business: ${businessId}`)

    // Delete analytics
    await storage.deleteAIAnalytics(businessId)

    return NextResponse.json({
      success: true,
      message: 'Lead score deleted successfully',
    })
  } catch (error) {
    logger.error('AI API', 'Failed to delete lead score', error)
    return NextResponse.json(
      {
        error: 'Failed to delete lead score',
        details: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}
