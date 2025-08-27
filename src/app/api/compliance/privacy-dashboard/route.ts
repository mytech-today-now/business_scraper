/**
 * Privacy Dashboard API
 * Provides comprehensive privacy data and controls for users
 */

import { NextRequest, NextResponse } from 'next/server'
import { Pool } from 'pg'
import { logger } from '@/utils/logger'
import { consentService } from '@/lib/compliance/consent'
import { auditService, AuditEventType, AuditSeverity } from '@/lib/compliance/audit'

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
})

/**
 * GET /api/compliance/privacy-dashboard
 * Get comprehensive privacy dashboard data for a user
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const email = searchParams.get('email')
    const sessionId = searchParams.get('sessionId')

    if (!email && !sessionId) {
      return NextResponse.json(
        { error: 'Either email or sessionId is required' },
        { status: 400 }
      )
    }

    // Get data categories
    const dataCategories = await getDataCategories(email, sessionId)
    
    // Get privacy rights
    const privacyRights = await getPrivacyRights(email)
    
    // Get DSAR requests
    const dsarRequests = await getDSARRequests(email)
    
    // Get privacy settings
    const privacySettings = await getPrivacySettings(email, sessionId)

    // Log access to privacy dashboard
    await auditService.logEvent({
      eventType: AuditEventType.DATA_ACCESSED,
      severity: AuditSeverity.LOW,
      resource: 'privacy_dashboard',
      action: 'view',
      details: {
        email,
        sessionId,
        categoriesCount: dataCategories.length,
        rightsCount: privacyRights.length
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true
      }
    })

    return NextResponse.json({
      success: true,
      dataCategories,
      privacyRights,
      dsarRequests,
      privacySettings,
      lastUpdated: new Date().toISOString()
    })

  } catch (error) {
    logger.error('Privacy Dashboard', 'Failed to get privacy dashboard data', error)
    return NextResponse.json(
      { error: 'Failed to retrieve privacy dashboard data' },
      { status: 500 }
    )
  }
}

/**
 * Get data categories for user
 */
async function getDataCategories(email?: string, sessionId?: string) {
  try {
    const categories = []

    // Business contact data
    if (email) {
      const businessResult = await pool.query(
        'SELECT COUNT(*) as count, MAX(updated_at) as last_updated FROM businesses WHERE email ILIKE $1',
        [`%${email}%`]
      )
      
      if (parseInt(businessResult.rows[0].count) > 0) {
        categories.push({
          id: 'business_contacts',
          name: 'Business Contact Data',
          description: 'Scraped business information and contact details',
          dataCount: parseInt(businessResult.rows[0].count),
          lastUpdated: businessResult.rows[0].last_updated || new Date(),
          retentionPeriod: 1095, // 3 years
          canDelete: true,
          canExport: true,
          canModify: true
        })
      }
    }

    // Consent records
    const consentResult = await pool.query(
      'SELECT COUNT(*) as count, MAX(timestamp) as last_updated FROM consent_records WHERE user_id = (SELECT id FROM users WHERE email = $1) OR session_id = $2',
      [email, sessionId]
    )
    
    if (parseInt(consentResult.rows[0].count) > 0) {
      categories.push({
        id: 'consent_records',
        name: 'Consent Records',
        description: 'Your privacy consent preferences and history',
        dataCount: parseInt(consentResult.rows[0].count),
        lastUpdated: consentResult.rows[0].last_updated || new Date(),
        retentionPeriod: 2190, // 6 years
        canDelete: false, // Legal requirement to keep
        canExport: true,
        canModify: true
      })
    }

    // Audit logs
    const auditResult = await pool.query(
      'SELECT COUNT(*) as count, MAX(timestamp) as last_updated FROM audit_log WHERE user_id = (SELECT id FROM users WHERE email = $1)',
      [email]
    )
    
    if (parseInt(auditResult.rows[0].count) > 0) {
      categories.push({
        id: 'audit_logs',
        name: 'Activity Logs',
        description: 'Your account activity and security events',
        dataCount: parseInt(auditResult.rows[0].count),
        lastUpdated: auditResult.rows[0].last_updated || new Date(),
        retentionPeriod: 2555, // 7 years
        canDelete: false, // Security requirement
        canExport: true,
        canModify: false
      })
    }

    // Session data
    if (sessionId) {
      const sessionResult = await pool.query(
        'SELECT COUNT(*) as count, MAX(created_at) as last_updated FROM user_sessions WHERE session_token = $1',
        [sessionId]
      )
      
      if (parseInt(sessionResult.rows[0].count) > 0) {
        categories.push({
          id: 'session_data',
          name: 'Session Data',
          description: 'Your current and recent session information',
          dataCount: parseInt(sessionResult.rows[0].count),
          lastUpdated: sessionResult.rows[0].last_updated || new Date(),
          retentionPeriod: 90,
          canDelete: true,
          canExport: true,
          canModify: false
        })
      }
    }

    return categories

  } catch (error) {
    logger.error('Privacy Dashboard', 'Failed to get data categories', error)
    return []
  }
}

/**
 * Get privacy rights for user
 */
async function getPrivacyRights(email?: string) {
  const rights = [
    {
      id: 'access',
      name: 'Right to Access',
      description: 'Request a copy of all personal data we hold about you',
      available: true,
      status: 'available'
    },
    {
      id: 'rectification',
      name: 'Right to Rectification',
      description: 'Request correction of inaccurate or incomplete personal data',
      available: true,
      status: 'available'
    },
    {
      id: 'erasure',
      name: 'Right to Erasure',
      description: 'Request deletion of your personal data (right to be forgotten)',
      available: true,
      status: 'available'
    },
    {
      id: 'portability',
      name: 'Right to Data Portability',
      description: 'Request your data in a structured, machine-readable format',
      available: true,
      status: 'available'
    },
    {
      id: 'restriction',
      name: 'Right to Restriction',
      description: 'Request limitation of processing of your personal data',
      available: true,
      status: 'available'
    },
    {
      id: 'objection',
      name: 'Right to Object',
      description: 'Object to processing of your personal data for specific purposes',
      available: true,
      status: 'available'
    }
  ]

  // Check for recent usage of rights
  if (email) {
    try {
      const recentRequests = await pool.query(
        'SELECT request_type, MAX(submitted_at) as last_used FROM dsar_requests WHERE subject_email = $1 GROUP BY request_type',
        [email]
      )

      recentRequests.rows.forEach(row => {
        const right = rights.find(r => r.id === row.request_type)
        if (right) {
          right.lastUsed = row.last_used
        }
      })
    } catch (error) {
      logger.error('Privacy Dashboard', 'Failed to get recent DSAR requests', error)
    }
  }

  return rights
}

/**
 * Get DSAR requests for user
 */
async function getDSARRequests(email?: string) {
  if (!email) return []

  try {
    const result = await pool.query(
      'SELECT * FROM dsar_requests WHERE subject_email = $1 ORDER BY submitted_at DESC LIMIT 10',
      [email]
    )

    return result.rows.map(row => ({
      id: row.id,
      type: row.request_type,
      status: row.status,
      submittedAt: row.submitted_at,
      completedAt: row.completed_at,
      description: row.description
    }))

  } catch (error) {
    logger.error('Privacy Dashboard', 'Failed to get DSAR requests', error)
    return []
  }
}

/**
 * Get privacy settings for user
 */
async function getPrivacySettings(email?: string, sessionId?: string) {
  try {
    // Get consent preferences
    const consentPreferences = await consentService.getConsentPreferences(undefined, sessionId)
    
    // Get CCPA opt-out status
    let ccpaOptOut = false
    if (email) {
      const ccpaResult = await pool.query(
        'SELECT COUNT(*) as count FROM ccpa_opt_out_requests WHERE consumer_email = $1 AND status = $2',
        [email, 'processed']
      )
      ccpaOptOut = parseInt(ccpaResult.rows[0].count) > 0
    }

    // Default privacy settings
    const settings = {
      consentPreferences: consentPreferences?.preferences || {},
      ccpaOptOut,
      marketingOptOut: false,
      dataRetentionPreference: 'standard' as const,
      notificationPreferences: {
        email: true,
        sms: false,
        dataUpdates: true,
        securityAlerts: true
      }
    }

    return settings

  } catch (error) {
    logger.error('Privacy Dashboard', 'Failed to get privacy settings', error)
    return null
  }
}

/**
 * PUT /api/compliance/privacy-settings
 * Update privacy settings for user
 */
export async function PUT(request: NextRequest) {
  try {
    const body = await request.json()
    const { userEmail, sessionId, settings } = body

    if (!userEmail && !sessionId) {
      return NextResponse.json(
        { error: 'Either userEmail or sessionId is required' },
        { status: 400 }
      )
    }

    // Update consent preferences if provided
    if (settings.consentPreferences) {
      await consentService.updateConsentPreferences(
        undefined,
        sessionId,
        settings.consentPreferences,
        request.headers.get('x-forwarded-for') || 'unknown',
        request.headers.get('user-agent') || 'unknown'
      )
    }

    // Handle CCPA opt-out if provided
    if (settings.ccpaOptOut !== undefined && userEmail) {
      if (settings.ccpaOptOut) {
        // Submit CCPA opt-out request
        await pool.query(`
          INSERT INTO ccpa_opt_out_requests (
            consumer_email, categories, verification_method, verification_data,
            ip_address, user_agent, status
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT DO NOTHING
        `, [
          userEmail,
          JSON.stringify(['all']),
          'email',
          JSON.stringify({ email: userEmail }),
          request.headers.get('x-forwarded-for'),
          request.headers.get('user-agent'),
          'processed'
        ])
      }
    }

    // Log privacy settings update
    await auditService.logEvent({
      eventType: AuditEventType.PRIVACY_MANAGE,
      severity: AuditSeverity.MEDIUM,
      details: {
        userEmail,
        sessionId,
        settingsUpdated: Object.keys(settings)
      },
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true
      }
    })

    return NextResponse.json({
      success: true,
      message: 'Privacy settings updated successfully'
    })

  } catch (error) {
    logger.error('Privacy Dashboard', 'Failed to update privacy settings', error)
    return NextResponse.json(
      { error: 'Failed to update privacy settings' },
      { status: 500 }
    )
  }
}
