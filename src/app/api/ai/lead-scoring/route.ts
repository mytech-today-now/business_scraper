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
            enableCaching: true
          })

          return NextResponse.json({
            success: true,
            data: {
              processed: result.processed,
              scores: Object.fromEntries(result.scores),
              stats: result.stats,
              duplicates: result.duplicates,
              errors: result.errors
            }
          })

        default:
          return NextResponse.json(
            { error: `Unknown action: ${action}` },
            { status: 400 }
          )
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
    logRequests: true
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

    // Initialize AI service if needed
    if (!aiService.isInitialized()) {
      await aiService.initialize()
    }

    // Regenerate analytics
    const analytics = await aiService.analyzeBusinessRecord(business)

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
