/**
 * Individual Retention Policy API
 * Manages specific retention policy operations
 */

import { NextRequest, NextResponse } from 'next/server'
import { dataRetentionService } from '@/lib/compliance/retention'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'
import { logger } from '@/utils/logger'
import { withAuth } from '@/lib/auth-middleware'

/**
 * PUT /api/compliance/retention/policies/[id]
 * Update retention policy
 */
async function updatePolicy(request: NextRequest, context?: any) {
  try {
    const url = new URL(request.url)
    const pathSegments = url.pathname.split('/')
    const policyId = pathSegments[pathSegments.length - 1]
    const body = await request.json()

    // Validate policy ID
    if (!policyId) {
      return NextResponse.json({ error: 'Policy ID is required' }, { status: 400 })
    }

    const success = await (dataRetentionService as any).updatePolicy(policyId, body)

    if (!success) {
      return NextResponse.json({ error: 'Failed to update retention policy' }, { status: 404 })
    }

    // Log audit event
    await auditService.logEvent({
      eventType: AuditEventType.SYSTEM_CONFIG_CHANGED,
      severity: AuditSeverity.MEDIUM,
      resource: 'retention_policy',
      action: 'update',
      details: {
        policyId,
        updates: body,
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true,
      },
    })

    logger.info('Retention Policy API', `Retention policy updated: ${policyId}`)

    return NextResponse.json({
      success: true,
      policyId,
      message: 'Retention policy updated successfully',
    })
  } catch (error) {
    logger.error('Retention Policy API', 'Failed to update retention policy', error)
    return NextResponse.json({ error: 'Failed to update retention policy' }, { status: 500 })
  }
}

/**
 * DELETE /api/compliance/retention/policies/[id]
 * Delete retention policy
 */
async function deletePolicy(request: NextRequest, context?: any) {
  try {
    const url = new URL(request.url)
    const pathSegments = url.pathname.split('/')
    const policyId = pathSegments[pathSegments.length - 1]

    // Validate policy ID
    if (!policyId) {
      return NextResponse.json({ error: 'Policy ID is required' }, { status: 400 })
    }

    const success = await (dataRetentionService as any).deletePolicy(policyId)

    if (!success) {
      return NextResponse.json({ error: 'Failed to delete retention policy' }, { status: 404 })
    }

    // Log audit event
    await auditService.logEvent({
      eventType: AuditEventType.SYSTEM_CONFIG_CHANGED,
      severity: AuditSeverity.HIGH,
      resource: 'retention_policy',
      action: 'delete',
      details: {
        policyId,
        deletedAt: new Date().toISOString(),
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true,
      },
    })

    logger.info('Retention Policy API', `Retention policy deleted: ${policyId}`)

    return NextResponse.json({
      success: true,
      policyId,
      message: 'Retention policy deleted successfully',
    })
  } catch (error) {
    logger.error('Retention Policy API', 'Failed to delete retention policy', error)
    return NextResponse.json({ error: 'Failed to delete retention policy' }, { status: 500 })
  }
}

// Apply authentication middleware
export const PUT = withAuth(updatePolicy, {
  required: true,
  roles: ['admin', 'compliance_officer'],
})
export const DELETE = withAuth(deletePolicy, { required: true, roles: ['admin'] })
