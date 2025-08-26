/**
 * Consent Management API Routes
 * Handles GDPR consent recording and retrieval
 */

import { NextRequest, NextResponse } from 'next/server'
import { Pool } from 'pg'
import crypto from 'crypto'
import { logger } from '@/utils/logger'
import { securityAuditService, AuditEventType } from '@/lib/security-audit'

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
})

// Consent types
const CONSENT_TYPES = [
  'necessary',
  'scraping', 
  'storage',
  'enrichment',
  'analytics',
  'marketing'
] as const

type ConsentType = typeof CONSENT_TYPES[number]

interface ConsentPreferences {
  necessary: boolean
  scraping: boolean
  storage: boolean
  enrichment: boolean
  analytics: boolean
  marketing: boolean
}

/**
 * POST /api/compliance/consent
 * Record user consent preferences
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { preferences, timestamp, method = 'banner' } = body

    // Validate preferences
    if (!preferences || typeof preferences !== 'object') {
      return NextResponse.json(
        { error: 'Invalid consent preferences' },
        { status: 400 }
      )
    }

    // Get client information
    const clientIP = getClientIP(request)
    const userAgent = request.headers.get('user-agent') || 'Unknown'
    
    // Get user email from session or request
    const userEmail = await getUserEmail(request)
    
    // Record each consent type
    const consentRecords = []
    
    for (const [consentType, consentGiven] of Object.entries(preferences)) {
      if (!CONSENT_TYPES.includes(consentType as ConsentType)) {
        continue
      }

      // Determine legal basis
      const legalBasis = consentType === 'necessary' ? 'legal_obligation' : 'consent'
      
      // Insert consent record
      const result = await pool.query(`
        INSERT INTO consent_records (
          id, user_id, email, consent_type, consent_given, consent_date,
          consent_method, ip_address, user_agent, legal_basis, purpose,
          data_categories, retention_period
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id
      `, [
        crypto.randomUUID(),
        null, // user_id - would be set if user is logged in
        userEmail,
        consentType,
        consentGiven,
        new Date(timestamp || Date.now()),
        method,
        clientIP,
        userAgent,
        legalBasis,
        getConsentPurpose(consentType as ConsentType),
        getDataCategories(consentType as ConsentType),
        getRetentionPeriod(consentType as ConsentType)
      ])

      consentRecords.push({
        id: result.rows[0].id,
        type: consentType,
        given: consentGiven
      })
    }

    // Log consent event for audit
    await securityAuditService.logComplianceEvent(
      AuditEventType.CONSENT_GIVEN,
      null, // No user ID for anonymous users
      clientIP,
      userAgent,
      {
        preferences,
        method,
        recordCount: consentRecords.length,
        email: userEmail
      }
    )

    // Set consent cookie
    const response = NextResponse.json({
      success: true,
      consentRecords,
      message: 'Consent preferences saved successfully'
    })

    // Set a consent cookie that expires in 1 year
    const consentCookie = Buffer.from(JSON.stringify({
      preferences,
      timestamp: new Date().toISOString(),
      version: '1.0'
    })).toString('base64')

    response.cookies.set('consent-preferences', consentCookie, {
      maxAge: 365 * 24 * 60 * 60, // 1 year
      httpOnly: false, // Allow client-side access
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    })

    logger.info('Consent API', 'Consent preferences saved', {
      email: userEmail,
      preferences,
      recordCount: consentRecords.length
    })

    return response

  } catch (error) {
    logger.error('Consent API', 'Failed to save consent preferences', error)
    return NextResponse.json(
      { error: 'Failed to save consent preferences' },
      { status: 500 }
    )
  }
}

/**
 * GET /api/compliance/consent
 * Retrieve user consent status and preferences
 */
export async function GET(request: NextRequest) {
  try {
    const clientIP = getClientIP(request)
    const userEmail = await getUserEmail(request)

    // Check for consent cookie first
    const consentCookie = request.cookies.get('consent-preferences')?.value
    let cookiePreferences = null

    if (consentCookie) {
      try {
        const decoded = JSON.parse(Buffer.from(consentCookie, 'base64').toString())
        cookiePreferences = decoded.preferences
      } catch {
        // Invalid cookie, ignore
      }
    }

    // Get latest consent records from database
    let dbPreferences = null
    let hasConsent = false

    if (userEmail || clientIP) {
      const result = await pool.query(`
        SELECT DISTINCT ON (consent_type) 
          consent_type, consent_given, consent_date
        FROM consent_records 
        WHERE (email = $1 OR ip_address = $2)
        ORDER BY consent_type, consent_date DESC
      `, [userEmail, clientIP])

      if (result.rows.length > 0) {
        hasConsent = true
        dbPreferences = {}
        
        // Set defaults
        CONSENT_TYPES.forEach(type => {
          dbPreferences[type] = type === 'necessary' // Necessary is always true by default
        })

        // Apply database preferences
        result.rows.forEach(row => {
          dbPreferences[row.consent_type] = row.consent_given
        })
      }
    }

    // Use database preferences if available, otherwise cookie preferences
    const preferences = dbPreferences || cookiePreferences

    return NextResponse.json({
      hasConsent: hasConsent || !!cookiePreferences,
      preferences,
      source: dbPreferences ? 'database' : cookiePreferences ? 'cookie' : 'none'
    })

  } catch (error) {
    logger.error('Consent API', 'Failed to get consent status', error)
    return NextResponse.json(
      { error: 'Failed to get consent status' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/compliance/consent
 * Withdraw all consent (GDPR right to withdraw consent)
 */
export async function DELETE(request: NextRequest) {
  try {
    const clientIP = getClientIP(request)
    const userAgent = request.headers.get('user-agent') || 'Unknown'
    const userEmail = await getUserEmail(request)

    // Record consent withdrawal
    const withdrawalRecords = []

    for (const consentType of CONSENT_TYPES) {
      if (consentType === 'necessary') continue // Cannot withdraw necessary consent

      const result = await pool.query(`
        INSERT INTO consent_records (
          id, user_id, email, consent_type, consent_given, consent_date,
          consent_method, ip_address, user_agent, legal_basis, purpose,
          withdrawal_reason
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id
      `, [
        crypto.randomUUID(),
        null,
        userEmail,
        consentType,
        false, // Withdrawing consent
        new Date(),
        'api_withdrawal',
        clientIP,
        userAgent,
        'consent',
        getConsentPurpose(consentType),
        'User requested consent withdrawal'
      ])

      withdrawalRecords.push({
        id: result.rows[0].id,
        type: consentType,
        withdrawn: true
      })
    }

    // Log withdrawal event
    await securityAuditService.logComplianceEvent(
      AuditEventType.CONSENT_WITHDRAWN,
      null,
      clientIP,
      userAgent,
      {
        email: userEmail,
        withdrawnTypes: CONSENT_TYPES.filter(t => t !== 'necessary'),
        recordCount: withdrawalRecords.length
      }
    )

    // Clear consent cookie
    const response = NextResponse.json({
      success: true,
      withdrawalRecords,
      message: 'Consent withdrawn successfully'
    })

    response.cookies.delete('consent-preferences')

    logger.info('Consent API', 'Consent withdrawn', {
      email: userEmail,
      recordCount: withdrawalRecords.length
    })

    return response

  } catch (error) {
    logger.error('Consent API', 'Failed to withdraw consent', error)
    return NextResponse.json(
      { error: 'Failed to withdraw consent' },
      { status: 500 }
    )
  }
}

/**
 * Get client IP address
 */
function getClientIP(request: NextRequest): string {
  return request.headers.get('x-forwarded-for') ||
         request.headers.get('x-real-ip') ||
         'unknown'
}

/**
 * Get user email from session or request
 */
async function getUserEmail(request: NextRequest): Promise<string | null> {
  // Try to get from query parameter (for anonymous users)
  const url = new URL(request.url)
  const emailParam = url.searchParams.get('email')
  
  if (emailParam && isValidEmail(emailParam)) {
    return emailParam
  }

  // TODO: Get from NextAuth session when user is logged in
  // const session = await getServerSession(authOptions)
  // return session?.user?.email || null

  return null
}

/**
 * Validate email format
 */
function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}

/**
 * Get consent purpose description
 */
function getConsentPurpose(consentType: ConsentType): string {
  const purposes = {
    necessary: 'Essential website functionality',
    scraping: 'Business data scraping from public sources',
    storage: 'Data storage and retrieval',
    enrichment: 'Data enhancement and analysis',
    analytics: 'Website usage analytics',
    marketing: 'Marketing communications'
  }
  return purposes[consentType]
}

/**
 * Get data categories for consent type
 */
function getDataCategories(consentType: ConsentType): string[] {
  const categories = {
    necessary: ['session_data', 'security_data'],
    scraping: ['business_data', 'public_data'],
    storage: ['user_data', 'search_history'],
    enrichment: ['enhanced_data', 'third_party_data'],
    analytics: ['usage_data', 'performance_data'],
    marketing: ['contact_data', 'preference_data']
  }
  return categories[consentType]
}

/**
 * Get retention period for consent type
 */
function getRetentionPeriod(consentType: ConsentType): string {
  const periods = {
    necessary: '30 days',
    scraping: '2 years',
    storage: '7 years',
    enrichment: '2 years',
    analytics: '2 years',
    marketing: '3 years'
  }
  return periods[consentType]
}
