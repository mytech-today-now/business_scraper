import { NextRequest, NextResponse } from 'next/server'
import { searchOrchestrator } from '@/lib/searchProviderAbstraction'
import { logger } from '@/utils/logger'

/**
 * GET /api/provider-management - Get provider metrics and cost tracking data
 */
export async function GET(request: NextRequest) {
  try {
    const metrics = searchOrchestrator.getProviderMetrics()
    const costTrackers = searchOrchestrator.getCostTrackers()
    const quotaLimits = searchOrchestrator.getQuotaLimits()

    logger.info('ProviderManagementAPI', `Returning ${metrics.length} provider metrics and ${costTrackers.length} cost trackers`)

    return NextResponse.json({
      success: true,
      data: {
        metrics,
        costTrackers,
        quotaLimits
      },
      timestamp: new Date().toISOString()
    })

  } catch (error) {
    logger.error('ProviderManagementAPI', 'Failed to get provider data', error)
    
    return NextResponse.json({
      success: false,
      error: 'Failed to get provider data',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

/**
 * POST /api/provider-management - Update quota limits
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { quotaLimits } = body

    if (!quotaLimits) {
      return NextResponse.json({
        success: false,
        error: 'Quota limits are required'
      }, { status: 400 })
    }

    // Update quota limits in the search orchestrator
    searchOrchestrator.setQuotaLimits(quotaLimits)

    logger.info('ProviderManagementAPI', 'Updated quota limits', quotaLimits)

    return NextResponse.json({
      success: true,
      message: 'Quota limits updated successfully',
      quotaLimits: searchOrchestrator.getQuotaLimits()
    })

  } catch (error) {
    logger.error('ProviderManagementAPI', 'Failed to update quota limits', error)
    
    return NextResponse.json({
      success: false,
      error: 'Failed to update quota limits',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
