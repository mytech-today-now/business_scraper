/**
 * Data Retention Execution API
 * Handles manual execution of retention policies
 */

import { NextRequest, NextResponse } from 'next/server'
import { dataRetentionService } from '@/lib/compliance/retention'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'
import { logger } from '@/utils/logger'
import { withAuth } from '@/lib/auth-middleware'

/**
 * POST /api/compliance/retention/execute
 * Manually execute retention policy
 */
async function executeRetention(request: NextRequest) {
  try {
    const body = await request.json()
    const { policyId, dryRun = false } = body

    // Validate required fields
    if (!policyId) {
      return NextResponse.json({ error: 'Missing required field: policyId' }, { status: 400 })
    }

    if (dryRun) {
      // For dry run, just check what would be affected
      const status = await dataRetentionService.checkRetentionStatus()

      return NextResponse.json({
        success: true,
        dryRun: true,
        policyId,
        message: 'Dry run completed - no data was actually deleted',
        status,
      })
    }

    // Execute the retention policy
    const purgeRecord = await dataRetentionService.executeRetentionPolicy(policyId)

    // Log audit event
    await auditService.logEvent({
      eventType: AuditEventType.DATA_RETENTION_APPLIED,
      severity: AuditSeverity.HIGH,
      resource: 'retention_execution',
      action: 'manual_execute',
      details: {
        policyId,
        recordsAffected: purgeRecord.recordsAffected,
        purgeRecord,
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true,
      },
    })

    logger.info('Retention Execution API', `Retention policy executed: ${policyId}`, {
      recordsAffected: purgeRecord.recordsAffected,
      status: purgeRecord.status,
    })

    return NextResponse.json({
      success: true,
      policyId,
      purgeRecord,
      message: `Retention policy executed successfully. ${purgeRecord.recordsAffected} records affected.`,
    })
  } catch (error) {
    logger.error('Retention Execution API', 'Failed to execute retention policy', error)
    return NextResponse.json({ error: 'Failed to execute retention policy' }, { status: 500 })
  }
}

/**
 * GET /api/compliance/retention/status
 * Get retention status for all data types
 */
async function getRetentionStatus(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const dataType = searchParams.get('dataType')

    await dataRetentionService.checkRetentionStatus(dataType || undefined)

    // Get current statuses
    const statuses = await dataRetentionService.statuses

    return NextResponse.json({
      success: true,
      statuses,
      dataType: dataType || 'all',
    })
  } catch (error) {
    logger.error('Retention Status API', 'Failed to get retention status', error)
    return NextResponse.json({ error: 'Failed to get retention status' }, { status: 500 })
  }
}

/**
 * GET /api/compliance/retention/upcoming
 * Get upcoming purges within specified days
 */
async function getUpcomingPurges(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const days = parseInt(searchParams.get('days') || '30')

    const upcomingPurges = await dataRetentionService.getUpcomingPurges(days)

    return NextResponse.json({
      success: true,
      upcomingPurges,
      days,
      count: upcomingPurges.length,
    })
  } catch (error) {
    logger.error('Upcoming Purges API', 'Failed to get upcoming purges', error)
    return NextResponse.json({ error: 'Failed to get upcoming purges' }, { status: 500 })
  }
}

// Apply authentication middleware
export const POST = withAuth(executeRetention, {
  required: true,
  roles: ['admin', 'compliance_officer'],
})
export const GET = withAuth(getRetentionStatus, {
  required: true,
  roles: ['admin', 'compliance_officer', 'operator'],
})
