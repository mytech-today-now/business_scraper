/**
 * CRM Sync API Endpoint
 * Handles business record synchronization with CRM systems
 */

import { NextRequest, NextResponse } from 'next/server'
import { crmServiceRegistry } from '@/lib/crm/crmServiceRegistry'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'
import { withApiSecurity } from '@/lib/api-security'
import { getClientIP } from '@/lib/security'
import { database } from '@/lib/postgresql-database'

/**
 * POST /api/crm/sync - Sync business records to CRM systems
 */
async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_SYNC_API', `Sync request from IP: ${ip}`)

    const body = await request.json()

    // Validate request body
    if (!body.records || !Array.isArray(body.records)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Records array is required',
        },
        { status: 400 }
      )
    }

    const { records, providerIds, syncMode = 'push' } = body
    const businessRecords: BusinessRecord[] = records

    // Get target CRM services
    let targetServices = crmServiceRegistry.getActiveServices()

    if (providerIds && Array.isArray(providerIds)) {
      targetServices = targetServices.filter(service =>
        providerIds.includes(service.getProvider().id)
      )
    }

    if (targetServices.length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: 'No active CRM services found',
        },
        { status: 400 }
      )
    }

    logger.info(
      'CRM_SYNC_API',
      `Starting sync of ${businessRecords.length} records to ${targetServices.length} CRM systems`
    )

    const syncResults = []

    // Sync to each CRM service
    for (const service of targetServices) {
      try {
        const provider = service.getProvider()
        logger.info('CRM_SYNC_API', `Syncing to ${provider.name}`)

        let syncResult
        if (businessRecords.length === 1 && businessRecords[0]) {
          // Single record sync
          syncResult = await service.syncBusinessRecord(businessRecords[0])
          syncResults.push({
            providerId: provider.id,
            providerName: provider.name,
            type: 'single',
            result: syncResult,
          })
        } else {
          // Batch sync
          const batchResult = await service.syncBusinessRecords(businessRecords)
          syncResults.push({
            providerId: provider.id,
            providerName: provider.name,
            type: 'batch',
            result: batchResult,
          })
        }

        logger.info('CRM_SYNC_API', `Sync completed for ${provider.name}`)
      } catch (error) {
        logger.error('CRM_SYNC_API', `Sync failed for ${service.getProvider().name}`, error)
        syncResults.push({
          providerId: service.getProvider().id,
          providerName: service.getProvider().name,
          type: 'error',
          error: error instanceof Error ? error.message : 'Unknown error',
        })
      }
    }

    // Calculate overall statistics
    const totalSynced = syncResults.reduce((total, result) => {
      if (result.type === 'single' && (result.result as any)?.syncStatus === 'synced') {
        return total + 1
      } else if (result.type === 'batch' && (result.result as any)?.successfulRecords) {
        return total + (result.result as any).successfulRecords
      }
      return total
    }, 0)

    const totalFailed = syncResults.reduce((total, result) => {
      if (result.type === 'single' && (result.result as any)?.syncStatus === 'failed') {
        return total + 1
      } else if (result.type === 'batch' && (result.result as any)?.failedRecords) {
        return total + (result.result as any).failedRecords
      } else if (result.type === 'error') {
        return total + businessRecords.length
      }
      return total
    }, 0)

    logger.info('CRM_SYNC_API', `Sync completed: ${totalSynced} successful, ${totalFailed} failed`)

    return NextResponse.json({
      success: true,
      data: {
        syncResults,
        summary: {
          totalRecords: businessRecords.length,
          totalProviders: targetServices.length,
          totalSynced,
          totalFailed,
          syncMode,
        },
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('CRM_SYNC_API', 'Sync operation failed', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Sync operation failed',
      },
      { status: 500 }
    )
  }
}

/**
 * GET /api/crm/sync - Get sync status and history
 */
async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_SYNC_API', `Get sync status request from IP: ${ip}`)

    const url = new URL(request.url)
    const providerId = url.searchParams.get('providerId')
    const limit = parseInt(url.searchParams.get('limit') || '50')
    const offset = parseInt(url.searchParams.get('offset') || '0')

    // Get sync history from database
    // This would typically query a sync_records table
    const syncHistory = await getSyncHistory(providerId, limit, offset)

    // Get current sync statistics
    const statistics = crmServiceRegistry.getStatistics()

    return NextResponse.json({
      success: true,
      data: {
        syncHistory,
        statistics,
        pagination: {
          limit,
          offset,
          total: syncHistory.length,
        },
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('CRM_SYNC_API', 'Failed to get sync status', error)
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to retrieve sync status',
      },
      { status: 500 }
    )
  }
}

/**
 * PUT /api/crm/sync - Retry failed sync operations
 */
async function PUT(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    logger.info('CRM_SYNC_API', `Retry sync request from IP: ${ip}`)

    const body = await request.json()
    const { syncRecordIds, providerId } = body

    if (!syncRecordIds || !Array.isArray(syncRecordIds)) {
      return NextResponse.json(
        {
          success: false,
          error: 'Sync record IDs array is required',
        },
        { status: 400 }
      )
    }

    // Get the CRM service
    const service = providerId ? crmServiceRegistry.getService(providerId) : null
    if (!service) {
      return NextResponse.json(
        {
          success: false,
          error: 'CRM service not found',
        },
        { status: 404 }
      )
    }

    // Get failed sync records from database
    const failedRecords = await getFailedSyncRecords(syncRecordIds)

    if (failedRecords.length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: 'No failed sync records found',
        },
        { status: 404 }
      )
    }

    logger.info('CRM_SYNC_API', `Retrying ${failedRecords.length} failed sync records`)

    // Retry sync for each record
    const retryResults = []
    for (const syncRecord of failedRecords) {
      try {
        const result = await service.syncBusinessRecord((syncRecord as any).businessRecord)
        retryResults.push({
          originalSyncId: (syncRecord as any).id,
          newResult: result,
        })
      } catch (error) {
        logger.error('CRM_SYNC_API', `Retry failed for sync record: ${(syncRecord as any).id}`, error)
        retryResults.push({
          originalSyncId: (syncRecord as any).id,
          error: error instanceof Error ? error.message : 'Unknown error',
        })
      }
    }

    const successfulRetries = retryResults.filter(r => r.newResult?.syncStatus === 'synced').length
    const failedRetries = retryResults.length - successfulRetries

    logger.info(
      'CRM_SYNC_API',
      `Retry completed: ${successfulRetries} successful, ${failedRetries} failed`
    )

    return NextResponse.json({
      success: true,
      data: {
        retryResults,
        summary: {
          totalRetried: retryResults.length,
          successfulRetries,
          failedRetries,
        },
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('CRM_SYNC_API', 'Retry operation failed', error)
    return NextResponse.json(
      {
        success: false,
        error: error instanceof Error ? error.message : 'Retry operation failed',
      },
      { status: 500 }
    )
  }
}

// Helper functions
async function getSyncHistory(providerId?: string | null, limit: number = 50, offset: number = 0) {
  try {
    // This would typically query a database table
    // For now, return mock data
    return []
  } catch (error) {
    logger.error('CRM_SYNC_API', 'Failed to get sync history', error)
    return []
  }
}

async function getFailedSyncRecords(syncRecordIds: string[]) {
  try {
    // This would typically query a database table
    // For now, return mock data
    return []
  } catch (error) {
    logger.error('CRM_SYNC_API', 'Failed to get failed sync records', error)
    return []
  }
}

// Apply security middleware
const securedPOST = withApiSecurity(POST, {
  requireAuth: false,
  rateLimit: 'general',
  validateInput: true,
  logRequests: true,
})

const securedGET = withApiSecurity(GET, {
  requireAuth: false,
  rateLimit: 'general',
  validateInput: true,
  logRequests: true,
})

const securedPUT = withApiSecurity(PUT, {
  requireAuth: false,
  rateLimit: 'general',
  validateInput: true,
  logRequests: true,
})

export { securedPOST as POST, securedGET as GET, securedPUT as PUT }
