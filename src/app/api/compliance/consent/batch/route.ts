/**
 * Batch Consent Management API
 * Handles multiple consent updates in a single request
 */

import { NextRequest, NextResponse } from 'next/server'
import { consentService, ConsentType, ConsentStatus } from '@/lib/compliance/consent'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'
import { logger } from '@/utils/logger'

/**
 * POST /api/compliance/consent/batch
 * Update multiple consent preferences at once
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { preferences, userId, sessionId } = body

    // Validate required fields
    if (!preferences || typeof preferences !== 'object') {
      return NextResponse.json({ error: 'Missing or invalid preferences object' }, { status: 400 })
    }

    // Validate preference entries
    const validConsentTypes = Object.values(ConsentType)
    const validConsentStatuses = Object.values(ConsentStatus)

    for (const [consentType, status] of Object.entries(preferences)) {
      if (!validConsentTypes.includes(consentType as ConsentType)) {
        return NextResponse.json({ error: `Invalid consent type: ${consentType}` }, { status: 400 })
      }

      if (!validConsentStatuses.includes(status as ConsentStatus)) {
        return NextResponse.json({ error: `Invalid consent status: ${status}` }, { status: 400 })
      }
    }

    const clientIP =
      request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
    const userAgent = request.headers.get('user-agent') || 'unknown'

    // Update consent preferences
    await consentService.updateConsentPreferences(
      userId,
      sessionId,
      preferences as Record<ConsentType, ConsentStatus>,
      clientIP,
      userAgent
    )

    // Log audit event
    await auditService.logEvent({
      eventType: AuditEventType.CONSENT_GIVEN,
      severity: AuditSeverity.MEDIUM,
      userId,
      sessionId,
      ipAddress: clientIP,
      userAgent,
      details: {
        preferences,
        preferencesCount: Object.keys(preferences).length,
        updatedAt: new Date().toISOString(),
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true,
      },
    })

    logger.info('Batch Consent API', 'Consent preferences updated', {
      userId,
      sessionId,
      preferencesCount: Object.keys(preferences).length,
    })

    return NextResponse.json({
      success: true,
      updatedPreferences: preferences,
      message: 'Consent preferences updated successfully',
    })
  } catch (error) {
    logger.error('Batch Consent API', 'Failed to update consent preferences', error)
    return NextResponse.json({ error: 'Failed to update consent preferences' }, { status: 500 })
  }
}
