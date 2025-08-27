/**
 * Consent Withdrawal API
 * Handles specific consent type withdrawals
 */

import { NextRequest, NextResponse } from 'next/server'
import { consentService, ConsentType } from '@/lib/compliance/consent'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'
import { logger } from '@/utils/logger'

/**
 * POST /api/compliance/consent/withdraw
 * Withdraw specific consent type
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { consentType, reason, userId, sessionId } = body

    // Validate required fields
    if (!consentType) {
      return NextResponse.json({ error: 'Missing required field: consentType' }, { status: 400 })
    }

    // Validate consent type
    if (!Object.values(ConsentType).includes(consentType)) {
      return NextResponse.json({ error: 'Invalid consent type' }, { status: 400 })
    }

    const clientIP =
      request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const userAgent = request.headers.get('user-agent') || 'unknown'

    // Withdraw consent
    await consentService.withdrawConsent(
      userId,
      sessionId,
      consentType,
      reason || 'User requested withdrawal'
    )

    // Log audit event
    await auditService.logEvent({
      eventType: AuditEventType.CONSENT_WITHDRAWN,
      severity: AuditSeverity.MEDIUM,
      userId,
      sessionId,
      ipAddress: clientIP,
      userAgent,
      details: {
        consentType,
        reason: reason || 'User requested withdrawal',
        withdrawnAt: new Date().toISOString(),
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true,
      },
    })

    logger.info('Consent Withdrawal API', `Consent withdrawn: ${consentType}`, {
      userId,
      sessionId,
      reason,
    })

    return NextResponse.json({
      success: true,
      consentType,
      message: 'Consent withdrawn successfully',
    })
  } catch (error) {
    logger.error('Consent Withdrawal API', 'Failed to withdraw consent', error)
    return NextResponse.json({ error: 'Failed to withdraw consent' }, { status: 500 })
  }
}
