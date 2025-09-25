/**
 * Consent Status API Route
 * Provides consent status checking for the consent banner
 */

export const dynamic = 'force-dynamic'

import { NextRequest, NextResponse } from 'next/server'
import { Pool } from 'pg'
import { logger } from '@/utils/logger'
import { isDatabaseConnectionAllowed } from '@/lib/build-time-guard'

// Database connection (protected against build-time execution)
let pool: Pool | null = null

function getPool(): Pool | null {
  if (!isDatabaseConnectionAllowed()) {
    return null
  }

  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    })
  }

  return pool
}

// Consent types
const CONSENT_TYPES = [
  'necessary',
  'scraping',
  'storage',
  'enrichment',
  'analytics',
  'marketing',
] as const

/**
 * GET /api/compliance/consent/status
 * Check if user has given consent and return current preferences
 */
export async function GET(request: NextRequest) {
  try {
    const clientIP = getClientIP(request)
    const userEmail = getUserEmailFromQuery(request)

    // Check for consent cookie first (fastest method)
    const consentCookie = request.cookies.get('consent-preferences')?.value
    let cookiePreferences = null
    let cookieTimestamp = null

    if (consentCookie) {
      try {
        const decoded = JSON.parse(Buffer.from(consentCookie, 'base64').toString())
        cookiePreferences = decoded.preferences
        cookieTimestamp = decoded.timestamp
      } catch {
        // Invalid cookie, ignore
      }
    }

    // Get latest consent records from database
    let dbPreferences = null
    let dbTimestamp = null
    let hasDbConsent = false

    const dbPool = getPool()
    if (dbPool && (userEmail || clientIP)) {
      try {
        const result = await dbPool.query(
          `
          SELECT DISTINCT ON (consent_type)
            consent_type, consent_given, consent_date
          FROM consent_records
          WHERE (email = $1 OR ip_address = $2)
            AND consent_date > NOW() - INTERVAL '1 year'
          ORDER BY consent_type, consent_date DESC
        `,
          [userEmail, clientIP]
        )

        if (result.rows.length > 0) {
          hasDbConsent = true
          dbPreferences = {}

          // Set defaults
          CONSENT_TYPES.forEach(type => {
            dbPreferences[type] = type === 'necessary' // Necessary is always true by default
          })

          // Apply database preferences
          result.rows.forEach(row => {
            dbPreferences[row.consent_type] = row.consent_given
            if (!dbTimestamp || row.consent_date > dbTimestamp) {
              dbTimestamp = row.consent_date
            }
          })
        }
      } catch (error) {
        logger.warn('Consent Status API', 'Database query failed, falling back to cookie only', error)
      }
    }

    // Determine which source to use (database takes precedence)
    const hasConsent = hasDbConsent || !!cookiePreferences
    const preferences = dbPreferences || cookiePreferences
    const timestamp = dbTimestamp || cookieTimestamp
    const source = dbPreferences ? 'database' : cookiePreferences ? 'cookie' : 'none'

    // Check if consent is still valid (not older than 1 year)
    let isValid = true
    if (timestamp) {
      const consentDate = new Date(timestamp)
      const oneYearAgo = new Date()
      oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1)
      isValid = consentDate > oneYearAgo
    }

    return NextResponse.json({
      hasConsent: hasConsent && isValid,
      preferences: isValid ? preferences : null,
      timestamp,
      source,
      isValid,
      requiresRefresh: !isValid && hasConsent,
    })
  } catch (error) {
    logger.error('Consent Status API', 'Failed to get consent status', error)
    return NextResponse.json(
      {
        hasConsent: false,
        preferences: null,
        error: 'Failed to check consent status',
      },
      { status: 500 }
    )
  }
}

/**
 * Get client IP address
 */
function getClientIP(request: NextRequest): string {
  return request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'
}

/**
 * Get user email from query parameters
 */
function getUserEmailFromQuery(request: NextRequest): string | null {
  const url = new URL(request.url)
  const email = url.searchParams.get('email')

  if (email && isValidEmail(email)) {
    return email
  }

  return null
}

/**
 * Validate email format
 */
function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(email)
}
