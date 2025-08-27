/**
 * Data Retention Policies API
 * Manages retention policy CRUD operations
 */

import { NextRequest, NextResponse } from 'next/server'
import { dataRetentionService } from '@/lib/compliance/retention'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'
import { logger } from '@/utils/logger'
import { withAuth } from '@/lib/auth-middleware'

/**
 * GET /api/compliance/retention/policies
 * Get all retention policies
 */
async function getPolicies(request: NextRequest) {
  try {
    const policies = await dataRetentionService.getRetentionPolicies()

    return NextResponse.json({
      success: true,
      policies,
      count: policies.length
    })

  } catch (error) {
    logger.error('Retention Policies API', 'Failed to get retention policies', error)
    return NextResponse.json(
      { error: 'Failed to retrieve retention policies' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/compliance/retention/policies
 * Create new retention policy
 */
async function createPolicy(request: NextRequest) {
  try {
    const body = await request.json()
    const {
      name,
      description,
      dataType,
      retentionPeriodDays,
      legalBasis,
      autoDelete,
      archiveBeforeDelete,
      notificationDays,
      isActive
    } = body

    // Validate required fields
    if (!name || !dataType || !retentionPeriodDays || !legalBasis) {
      return NextResponse.json(
        { error: 'Missing required fields: name, dataType, retentionPeriodDays, legalBasis' },
        { status: 400 }
      )
    }

    // Validate retention period
    if (retentionPeriodDays < 1) {
      return NextResponse.json(
        { error: 'Retention period must be at least 1 day' },
        { status: 400 }
      )
    }

    const policy = {
      name,
      description: description || '',
      dataType,
      retentionPeriodDays,
      legalBasis,
      autoDelete: autoDelete || false,
      archiveBeforeDelete: archiveBeforeDelete || true,
      notificationDays: notificationDays || [30, 7, 1],
      isActive: isActive !== false
    }

    const policyId = await dataRetentionService.createOrUpdatePolicy(policy)

    // Log audit event
    await auditService.logEvent({
      eventType: AuditEventType.SYSTEM_CONFIG_CHANGED,
      severity: AuditSeverity.MEDIUM,
      resource: 'retention_policy',
      action: 'create',
      details: {
        policyId,
        policy
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true
      }
    })

    logger.info('Retention Policies API', `Retention policy created: ${name}`, {
      policyId,
      dataType,
      retentionPeriodDays
    })

    return NextResponse.json({
      success: true,
      policyId,
      policy,
      message: 'Retention policy created successfully'
    })

  } catch (error) {
    logger.error('Retention Policies API', 'Failed to create retention policy', error)
    return NextResponse.json(
      { error: 'Failed to create retention policy' },
      { status: 500 }
    )
  }
}

// Apply authentication middleware
export const GET = withAuth(getPolicies, { required: true, roles: ['admin', 'compliance_officer'] })
export const POST = withAuth(createPolicy, { required: true, roles: ['admin', 'compliance_officer'] })
