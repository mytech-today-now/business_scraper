/**
 * Consent Management Service
 * Handles GDPR and CCPA consent requirements with granular control
 */

import { Pool } from 'pg'
import { logger } from '@/utils/logger'
import { auditService, AuditEventType, AuditSeverity } from './audit'

// Consent types
export enum ConsentType {
  DATA_COLLECTION = 'data_collection',
  DATA_PROCESSING = 'data_processing',
  DATA_SHARING = 'data_sharing',
  MARKETING = 'marketing',
  ANALYTICS = 'analytics',
  SCRAPING = 'scraping',
  STORAGE = 'storage',
  THIRD_PARTY = 'third_party',
}

// Consent status
export enum ConsentStatus {
  GRANTED = 'granted',
  DENIED = 'denied',
  WITHDRAWN = 'withdrawn',
  PENDING = 'pending',
}

// Legal basis for processing (GDPR Article 6)
export enum LegalBasis {
  CONSENT = 'consent',
  CONTRACT = 'contract',
  LEGAL_OBLIGATION = 'legal_obligation',
  VITAL_INTERESTS = 'vital_interests',
  PUBLIC_TASK = 'public_task',
  LEGITIMATE_INTERESTS = 'legitimate_interests',
}

// Consent record interface
export interface ConsentRecord {
  id?: string
  userId?: string
  sessionId?: string
  consentType: ConsentType
  status: ConsentStatus
  legalBasis: LegalBasis
  purpose: string
  dataCategories: string[]
  retentionPeriod?: number // in days
  thirdParties?: string[]
  ipAddress?: string
  userAgent?: string
  timestamp: Date
  expiresAt?: Date
  withdrawnAt?: Date
  version: string // consent version for tracking changes
  metadata?: Record<string, any>
}

// Consent preferences interface
export interface ConsentPreferences {
  userId?: string
  sessionId?: string
  preferences: Record<
    ConsentType,
    {
      status: ConsentStatus
      timestamp: Date
      version: string
    }
  >
  gdprApplies: boolean
  ccpaApplies: boolean
  lastUpdated: Date
}

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
})

/**
 * Consent management service
 */
export class ConsentService {
  private currentConsentVersion = '1.0.0'

  /**
   * Record consent for a user or session
   */
  async recordConsent(consent: ConsentRecord): Promise<string> {
    try {
      // Set version if not provided
      if (!consent.version) {
        consent.version = this.currentConsentVersion
      }

      // Calculate expiration if retention period is specified
      if (consent.retentionPeriod) {
        consent.expiresAt = new Date(Date.now() + consent.retentionPeriod * 24 * 60 * 60 * 1000)
      }

      const result = await pool.query(
        `
        INSERT INTO consent_records (
          user_id, session_id, consent_type, status, legal_basis, purpose,
          data_categories, retention_period, third_parties, ip_address,
          user_agent, timestamp, expires_at, version, metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING id
      `,
        [
          consent.userId,
          consent.sessionId,
          consent.consentType,
          consent.status,
          consent.legalBasis,
          consent.purpose,
          JSON.stringify(consent.dataCategories),
          consent.retentionPeriod,
          JSON.stringify(consent.thirdParties || []),
          consent.ipAddress,
          consent.userAgent,
          consent.timestamp,
          consent.expiresAt,
          consent.version,
          JSON.stringify(consent.metadata || {}),
        ]
      )

      const consentId = result.rows[0].id

      // Log audit event
      await auditService.logEvent({
        eventType: AuditEventType.CONSENT_GIVEN,
        severity: AuditSeverity.MEDIUM,
        userId: consent.userId,
        sessionId: consent.sessionId,
        ipAddress: consent.ipAddress,
        userAgent: consent.userAgent,
        details: {
          consentId,
          consentType: consent.consentType,
          status: consent.status,
          legalBasis: consent.legalBasis,
          purpose: consent.purpose,
        },
        timestamp: new Date(),
        complianceFlags: {
          gdprRelevant: true,
          ccpaRelevant: true,
          soc2Relevant: true,
        },
      })

      logger.info('Consent', `Consent recorded: ${consent.consentType} - ${consent.status}`, {
        consentId,
        userId: consent.userId,
        sessionId: consent.sessionId,
      })

      return consentId
    } catch (error) {
      logger.error('Consent', 'Failed to record consent', error)
      throw new Error('Failed to record consent')
    }
  }

  /**
   * Withdraw consent
   */
  async withdrawConsent(
    userId: string | undefined,
    sessionId: string | undefined,
    consentType: ConsentType,
    reason?: string
  ): Promise<void> {
    try {
      const withdrawnAt = new Date()

      await pool.query(
        `
        UPDATE consent_records 
        SET status = $1, withdrawn_at = $2, metadata = metadata || $3
        WHERE (user_id = $4 OR session_id = $5) 
        AND consent_type = $6 
        AND status = $7
      `,
        [
          ConsentStatus.WITHDRAWN,
          withdrawnAt,
          JSON.stringify({ withdrawalReason: reason }),
          userId,
          sessionId,
          consentType,
          ConsentStatus.GRANTED,
        ]
      )

      // Log audit event
      await auditService.logEvent({
        eventType: AuditEventType.CONSENT_WITHDRAWN,
        severity: AuditSeverity.MEDIUM,
        userId,
        sessionId,
        details: {
          consentType,
          reason,
          withdrawnAt: withdrawnAt.toISOString(),
        },
        timestamp: new Date(),
        complianceFlags: {
          gdprRelevant: true,
          ccpaRelevant: true,
          soc2Relevant: true,
        },
      })

      logger.info('Consent', `Consent withdrawn: ${consentType}`, {
        userId,
        sessionId,
        reason,
      })
    } catch (error) {
      logger.error('Consent', 'Failed to withdraw consent', error)
      throw new Error('Failed to withdraw consent')
    }
  }

  /**
   * Get current consent status
   */
  async getConsentStatus(
    userId: string | undefined,
    sessionId: string | undefined,
    consentType?: ConsentType
  ): Promise<ConsentRecord[]> {
    try {
      let query = `
        SELECT * FROM consent_records 
        WHERE (user_id = $1 OR session_id = $2)
        AND (expires_at IS NULL OR expires_at > NOW())
      `
      const params: any[] = [userId, sessionId]

      if (consentType) {
        query += ' AND consent_type = $3'
        params.push(consentType)
      }

      query += ' ORDER BY timestamp DESC'

      const result = await pool.query(query, params)

      return result.rows.map(row => ({
        id: row.id,
        userId: row.user_id,
        sessionId: row.session_id,
        consentType: row.consent_type,
        status: row.status,
        legalBasis: row.legal_basis,
        purpose: row.purpose,
        dataCategories: JSON.parse(row.data_categories || '[]'),
        retentionPeriod: row.retention_period,
        thirdParties: JSON.parse(row.third_parties || '[]'),
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        timestamp: row.timestamp,
        expiresAt: row.expires_at,
        withdrawnAt: row.withdrawn_at,
        version: row.version,
        metadata: JSON.parse(row.metadata || '{}'),
      }))
    } catch (error) {
      logger.error('Consent', 'Failed to get consent status', error)
      throw new Error('Failed to retrieve consent status')
    }
  }

  /**
   * Check if specific consent is granted
   */
  async hasValidConsent(
    userId: string | undefined,
    sessionId: string | undefined,
    consentType: ConsentType
  ): Promise<boolean> {
    try {
      const result = await pool.query(
        `
        SELECT COUNT(*) as count FROM consent_records 
        WHERE (user_id = $1 OR session_id = $2)
        AND consent_type = $3 
        AND status = $4
        AND (expires_at IS NULL OR expires_at > NOW())
      `,
        [userId, sessionId, consentType, ConsentStatus.GRANTED]
      )

      return parseInt(result.rows[0].count) > 0
    } catch (error) {
      logger.error('Consent', 'Failed to check consent validity', error)
      return false
    }
  }

  /**
   * Get user's consent preferences
   */
  async getConsentPreferences(
    userId: string | undefined,
    sessionId: string | undefined
  ): Promise<ConsentPreferences | null> {
    try {
      const consents = await this.getConsentStatus(userId, sessionId)

      if (consents.length === 0) {
        return null
      }

      const preferences: Record<ConsentType, any> = {}
      let lastUpdated = new Date(0)

      // Get the latest consent for each type
      Object.values(ConsentType).forEach(type => {
        const latestConsent = consents
          .filter(c => c.consentType === type)
          .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())[0]

        if (latestConsent) {
          preferences[type] = {
            status: latestConsent.status,
            timestamp: latestConsent.timestamp,
            version: latestConsent.version,
          }

          if (latestConsent.timestamp > lastUpdated) {
            lastUpdated = latestConsent.timestamp
          }
        }
      })

      return {
        userId,
        sessionId,
        preferences,
        gdprApplies: this.isGDPRApplicable(consents[0]?.ipAddress),
        ccpaApplies: this.isCCPAApplicable(consents[0]?.ipAddress),
        lastUpdated,
      }
    } catch (error) {
      logger.error('Consent', 'Failed to get consent preferences', error)
      return null
    }
  }

  /**
   * Update consent preferences in batch
   */
  async updateConsentPreferences(
    userId: string | undefined,
    sessionId: string | undefined,
    preferences: Record<ConsentType, ConsentStatus>,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      const timestamp = new Date()

      for (const [consentType, status] of Object.entries(preferences)) {
        await this.recordConsent({
          userId,
          sessionId,
          consentType: consentType as ConsentType,
          status,
          legalBasis: LegalBasis.CONSENT,
          purpose: `User preference update for ${consentType}`,
          dataCategories: this.getDataCategoriesForConsentType(consentType as ConsentType),
          ipAddress,
          userAgent,
          timestamp,
          version: this.currentConsentVersion,
        })
      }

      logger.info('Consent', 'Consent preferences updated', {
        userId,
        sessionId,
        preferencesCount: Object.keys(preferences).length,
      })
    } catch (error) {
      logger.error('Consent', 'Failed to update consent preferences', error)
      throw new Error('Failed to update consent preferences')
    }
  }

  /**
   * Clean up expired consents
   */
  async cleanupExpiredConsents(): Promise<number> {
    try {
      const result = await pool.query(`
        DELETE FROM consent_records 
        WHERE expires_at IS NOT NULL AND expires_at < NOW()
      `)

      const deletedCount = result.rowCount || 0

      if (deletedCount > 0) {
        await auditService.logEvent({
          eventType: AuditEventType.DATA_PURGED,
          severity: AuditSeverity.LOW,
          details: {
            type: 'expired_consents',
            count: deletedCount,
          },
          timestamp: new Date(),
          complianceFlags: {
            gdprRelevant: true,
            ccpaRelevant: true,
            soc2Relevant: true,
          },
        })

        logger.info('Consent', `Cleaned up ${deletedCount} expired consent records`)
      }

      return deletedCount
    } catch (error) {
      logger.error('Consent', 'Failed to cleanup expired consents', error)
      throw new Error('Failed to cleanup expired consents')
    }
  }

  /**
   * Check if GDPR applies based on IP address
   */
  private isGDPRApplicable(ipAddress?: string): boolean {
    // Simplified check - in production, use a proper IP geolocation service
    // This would check if the IP is from EU/EEA countries
    return true // Default to applying GDPR for safety
  }

  /**
   * Check if CCPA applies based on IP address
   */
  private isCCPAApplicable(ipAddress?: string): boolean {
    // Simplified check - in production, use a proper IP geolocation service
    // This would check if the IP is from California
    return true // Default to applying CCPA for safety
  }

  /**
   * Get data categories for consent type
   */
  private getDataCategoriesForConsentType(consentType: ConsentType): string[] {
    const categoryMap: Record<ConsentType, string[]> = {
      [ConsentType.DATA_COLLECTION]: ['contact_info', 'business_info'],
      [ConsentType.DATA_PROCESSING]: ['contact_info', 'business_info', 'analytics_data'],
      [ConsentType.DATA_SHARING]: ['contact_info', 'business_info'],
      [ConsentType.MARKETING]: ['contact_info', 'preferences'],
      [ConsentType.ANALYTICS]: ['usage_data', 'performance_data'],
      [ConsentType.SCRAPING]: ['public_business_data', 'contact_info'],
      [ConsentType.STORAGE]: ['all_collected_data'],
      [ConsentType.THIRD_PARTY]: ['contact_info', 'business_info'],
    }

    return categoryMap[consentType] || []
  }
}

// Global consent service instance
export const consentService = new ConsentService()

/**
 * Utility functions for consent management
 */
export const ConsentUtils = {
  /**
   * Check if user can perform action based on consent
   */
  canPerformAction: async (
    userId: string | undefined,
    sessionId: string | undefined,
    requiredConsents: ConsentType[]
  ): Promise<boolean> => {
    for (const consentType of requiredConsents) {
      const hasConsent = await consentService.hasValidConsent(userId, sessionId, consentType)
      if (!hasConsent) {
        return false
      }
    }
    return true
  },

  /**
   * Get required consents for scraping operation
   */
  getScrapingConsents: (): ConsentType[] => [
    ConsentType.DATA_COLLECTION,
    ConsentType.SCRAPING,
    ConsentType.STORAGE,
  ],

  /**
   * Get required consents for data export
   */
  getExportConsents: (): ConsentType[] => [ConsentType.DATA_PROCESSING, ConsentType.DATA_SHARING],

  /**
   * Validate consent before data processing
   */
  validateConsentForProcessing: async (
    userId: string | undefined,
    sessionId: string | undefined,
    operation: 'scraping' | 'export' | 'storage' | 'sharing'
  ): Promise<{ valid: boolean; missingConsents: ConsentType[] }> => {
    const requiredConsents = {
      scraping: ConsentUtils.getScrapingConsents(),
      export: ConsentUtils.getExportConsents(),
      storage: [ConsentType.STORAGE, ConsentType.DATA_PROCESSING],
      sharing: [ConsentType.DATA_SHARING, ConsentType.THIRD_PARTY],
    }[operation]

    const missingConsents: ConsentType[] = []

    for (const consentType of requiredConsents) {
      const hasConsent = await consentService.hasValidConsent(userId, sessionId, consentType)
      if (!hasConsent) {
        missingConsents.push(consentType)
      }
    }

    return {
      valid: missingConsents.length === 0,
      missingConsents,
    }
  },
}
