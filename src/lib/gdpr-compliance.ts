/**
 * GDPR Compliance Framework
 * Implements automated workflows for Data Subject Access Requests (DSARs)
 * and GDPR compliance management
 */

import { Pool } from 'pg'
import crypto from 'crypto'
import { logger } from '@/utils/logger'
import { securityAuditService, AuditEventType } from '@/lib/security-audit'

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
})

// GDPR request types
export enum GDPRRequestType {
  ACCESS = 'access',           // Article 15 - Right of access
  RECTIFICATION = 'rectification', // Article 16 - Right to rectification
  ERASURE = 'erasure',         // Article 17 - Right to erasure (right to be forgotten)
  PORTABILITY = 'portability', // Article 20 - Right to data portability
  RESTRICTION = 'restriction', // Article 18 - Right to restriction of processing
  OBJECTION = 'objection'      // Article 21 - Right to object
}

// Request status
export enum RequestStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  REJECTED = 'rejected',
  EXPIRED = 'expired'
}

// GDPR request interface
export interface GDPRRequest {
  id?: string
  requestType: GDPRRequestType
  subjectEmail: string
  subjectName?: string
  requestDetails: {
    reason?: string
    specificData?: string[]
    preferredFormat?: 'json' | 'csv' | 'pdf'
    deliveryMethod?: 'email' | 'download' | 'postal'
  }
  status: RequestStatus
  requestedAt: Date
  processedAt?: Date
  processedBy?: string
  responseData?: any
  notes?: string
  verificationToken?: string
  expiresAt: Date
}

// Data categories for GDPR processing
export enum DataCategory {
  PERSONAL_IDENTIFIERS = 'personal_identifiers',
  CONTACT_INFORMATION = 'contact_information',
  BUSINESS_INFORMATION = 'business_information',
  BEHAVIORAL_DATA = 'behavioral_data',
  TECHNICAL_DATA = 'technical_data',
  USAGE_DATA = 'usage_data'
}

// GDPR compliance service
export class GDPRComplianceService {
  
  /**
   * Submit a new GDPR request
   */
  async submitRequest(
    requestType: GDPRRequestType,
    subjectEmail: string,
    subjectName: string,
    requestDetails: any,
    clientIP: string,
    userAgent: string
  ): Promise<{ success: boolean; requestId?: string; error?: string }> {
    try {
      // Validate email format
      if (!this.isValidEmail(subjectEmail)) {
        return { success: false, error: 'Invalid email address' }
      }

      // Check for duplicate recent requests
      const recentRequest = await this.checkRecentRequest(subjectEmail, requestType)
      if (recentRequest) {
        return { 
          success: false, 
          error: 'A similar request was submitted recently. Please wait before submitting another request.' 
        }
      }

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex')
      
      // Calculate expiry date (30 days from now as per GDPR)
      const expiresAt = new Date()
      expiresAt.setDate(expiresAt.getDate() + 30)

      // Insert request into database
      const result = await pool.query(`
        INSERT INTO gdpr_requests (
          id, request_type, subject_email, subject_name, request_details,
          status, requested_at, verification_token, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
      `, [
        crypto.randomUUID(),
        requestType,
        subjectEmail,
        subjectName,
        JSON.stringify(requestDetails),
        RequestStatus.PENDING,
        new Date(),
        verificationToken,
        expiresAt
      ])

      const requestId = result.rows[0].id

      // Log the request for audit trail
      await securityAuditService.logComplianceEvent(
        AuditEventType.GDPR_REQUEST,
        null, // No user ID for external requests
        clientIP,
        userAgent,
        {
          requestType,
          subjectEmail,
          requestId
        }
      )

      // Send verification email
      await this.sendVerificationEmail(subjectEmail, verificationToken, requestType)

      logger.info('GDPR', `New ${requestType} request submitted`, {
        requestId,
        subjectEmail,
        clientIP
      })

      return { success: true, requestId }

    } catch (error) {
      logger.error('GDPR', 'Failed to submit GDPR request', error)
      return { success: false, error: 'Failed to submit request' }
    }
  }

  /**
   * Verify a GDPR request using the verification token
   */
  async verifyRequest(token: string): Promise<{ success: boolean; error?: string }> {
    try {
      const result = await pool.query(`
        UPDATE gdpr_requests 
        SET status = $1 
        WHERE verification_token = $2 AND status = $3 AND expires_at > NOW()
        RETURNING id, request_type, subject_email
      `, [RequestStatus.PROCESSING, token, RequestStatus.PENDING])

      if (result.rows.length === 0) {
        return { success: false, error: 'Invalid or expired verification token' }
      }

      const request = result.rows[0]

      // Start automated processing
      await this.processRequest(request.id)

      logger.info('GDPR', `Request verified and processing started`, {
        requestId: request.id,
        requestType: request.request_type,
        subjectEmail: request.subject_email
      })

      return { success: true }

    } catch (error) {
      logger.error('GDPR', 'Failed to verify GDPR request', error)
      return { success: false, error: 'Verification failed' }
    }
  }

  /**
   * Process a verified GDPR request
   */
  async processRequest(requestId: string): Promise<void> {
    try {
      // Get request details
      const result = await pool.query(`
        SELECT * FROM gdpr_requests WHERE id = $1
      `, [requestId])

      if (result.rows.length === 0) {
        throw new Error('Request not found')
      }

      const request = result.rows[0]
      const requestDetails = JSON.parse(request.request_details)

      let responseData: any = {}

      switch (request.request_type) {
        case GDPRRequestType.ACCESS:
          responseData = await this.processAccessRequest(request.subject_email)
          break
        case GDPRRequestType.ERASURE:
          responseData = await this.processErasureRequest(request.subject_email)
          break
        case GDPRRequestType.PORTABILITY:
          responseData = await this.processPortabilityRequest(request.subject_email, requestDetails.preferredFormat)
          break
        case GDPRRequestType.RECTIFICATION:
          responseData = await this.processRectificationRequest(request.subject_email, requestDetails)
          break
        default:
          throw new Error(`Unsupported request type: ${request.request_type}`)
      }

      // Update request status
      await pool.query(`
        UPDATE gdpr_requests 
        SET status = $1, processed_at = NOW(), response_data = $2
        WHERE id = $3
      `, [RequestStatus.COMPLETED, JSON.stringify(responseData), requestId])

      // Send response to data subject
      await this.sendResponseEmail(request.subject_email, request.request_type, responseData)

      logger.info('GDPR', `Request processed successfully`, {
        requestId,
        requestType: request.request_type,
        subjectEmail: request.subject_email
      })

    } catch (error) {
      logger.error('GDPR', `Failed to process request ${requestId}`, error)
      
      // Mark request as failed
      await pool.query(`
        UPDATE gdpr_requests 
        SET status = $1, notes = $2, processed_at = NOW()
        WHERE id = $3
      `, [RequestStatus.REJECTED, error.message, requestId])
    }
  }

  /**
   * Process access request (Article 15)
   */
  private async processAccessRequest(email: string): Promise<any> {
    const data: any = {
      personalData: {},
      processingActivities: [],
      dataCategories: [],
      recipients: [],
      retentionPeriods: {},
      rights: this.getDataSubjectRights()
    }

    // Collect personal data from various tables
    try {
      // User data
      const userResult = await pool.query(`
        SELECT id, email, name, created_at, last_login, gdpr_consent, ccpa_opt_out
        FROM users WHERE email = $1
      `, [email])

      if (userResult.rows.length > 0) {
        data.personalData.userAccount = userResult.rows[0]
        data.dataCategories.push(DataCategory.PERSONAL_IDENTIFIERS)
      }

      // Consent records
      const consentResult = await pool.query(`
        SELECT consent_type, consent_given, consent_date, legal_basis, purpose
        FROM consent_records WHERE email = $1
      `, [email])

      data.personalData.consentRecords = consentResult.rows
      if (consentResult.rows.length > 0) {
        data.dataCategories.push(DataCategory.BEHAVIORAL_DATA)
      }

      // Audit logs (limited to user's own actions)
      const auditResult = await pool.query(`
        SELECT event_type, timestamp, resource, action
        FROM security_audit_log 
        WHERE user_id = (SELECT id FROM users WHERE email = $1)
        ORDER BY timestamp DESC LIMIT 100
      `, [email])

      data.personalData.activityLog = auditResult.rows
      if (auditResult.rows.length > 0) {
        data.dataCategories.push(DataCategory.USAGE_DATA)
      }

      // Processing activities
      data.processingActivities = [
        {
          purpose: 'User authentication and authorization',
          legalBasis: 'Contract',
          categories: ['Identity data', 'Contact data'],
          retention: '2 years after account closure'
        },
        {
          purpose: 'Business data scraping and analysis',
          legalBasis: 'Legitimate interest',
          categories: ['Usage data', 'Technical data'],
          retention: '7 years for business purposes'
        }
      ]

      // Recipients
      data.recipients = [
        'Internal staff for customer support',
        'Cloud hosting providers (AWS/Azure)',
        'Analytics service providers'
      ]

      return data

    } catch (error) {
      logger.error('GDPR', 'Failed to collect access request data', error)
      throw error
    }
  }

  /**
   * Process erasure request (Article 17 - Right to be forgotten)
   */
  private async processErasureRequest(email: string): Promise<any> {
    const deletedData: any = {
      deletedRecords: [],
      retainedRecords: [],
      reason: 'Data subject erasure request'
    }

    try {
      // Start transaction
      await pool.query('BEGIN')

      // Delete user account
      const userResult = await pool.query(`
        DELETE FROM users WHERE email = $1 RETURNING id
      `, [email])

      if (userResult.rows.length > 0) {
        deletedData.deletedRecords.push({
          table: 'users',
          recordId: userResult.rows[0].id,
          deletedAt: new Date()
        })
      }

      // Delete consent records
      const consentResult = await pool.query(`
        DELETE FROM consent_records WHERE email = $1 RETURNING id
      `, [email])

      deletedData.deletedRecords.push({
        table: 'consent_records',
        count: consentResult.rowCount,
        deletedAt: new Date()
      })

      // Anonymize audit logs (retain for legal compliance but remove personal identifiers)
      await pool.query(`
        UPDATE security_audit_log 
        SET user_id = NULL, encrypted_details = 'ANONYMIZED_BY_GDPR_REQUEST'
        WHERE user_id = $1
      `, [userResult.rows[0]?.id])

      deletedData.retainedRecords.push({
        table: 'security_audit_log',
        reason: 'Legal obligation to retain audit logs',
        anonymized: true
      })

      // Commit transaction
      await pool.query('COMMIT')

      return deletedData

    } catch (error) {
      await pool.query('ROLLBACK')
      logger.error('GDPR', 'Failed to process erasure request', error)
      throw error
    }
  }

  /**
   * Process data portability request (Article 20)
   */
  private async processPortabilityRequest(email: string, format: string = 'json'): Promise<any> {
    const portableData = await this.processAccessRequest(email)
    
    // Format data for portability
    const exportData = {
      exportedAt: new Date().toISOString(),
      format,
      dataSubject: email,
      data: portableData.personalData
    }

    return exportData
  }

  /**
   * Process rectification request (Article 16)
   */
  private async processRectificationRequest(email: string, requestDetails: any): Promise<any> {
    // This would typically require manual review
    // For now, we'll mark it for manual processing
    return {
      status: 'pending_manual_review',
      requestedChanges: requestDetails.requestedChanges,
      reviewRequired: true,
      message: 'Rectification requests require manual review by our data protection team.'
    }
  }

  /**
   * Get data subject rights information
   */
  private getDataSubjectRights(): any {
    return {
      rightOfAccess: 'You have the right to obtain confirmation of whether we process your personal data and access to such data.',
      rightToRectification: 'You have the right to obtain rectification of inaccurate personal data.',
      rightToErasure: 'You have the right to obtain erasure of your personal data under certain circumstances.',
      rightToRestriction: 'You have the right to obtain restriction of processing under certain circumstances.',
      rightToDataPortability: 'You have the right to receive your personal data in a structured, commonly used format.',
      rightToObject: 'You have the right to object to processing based on legitimate interests.',
      rightsRelatedToAutomatedDecisionMaking: 'You have rights related to automated decision-making including profiling.',
      rightToWithdrawConsent: 'Where processing is based on consent, you have the right to withdraw consent at any time.',
      rightToLodgeComplaint: 'You have the right to lodge a complaint with a supervisory authority.'
    }
  }

  /**
   * Check for recent duplicate requests
   */
  private async checkRecentRequest(email: string, requestType: GDPRRequestType): Promise<boolean> {
    const result = await pool.query(`
      SELECT id FROM gdpr_requests 
      WHERE subject_email = $1 AND request_type = $2 
      AND requested_at > NOW() - INTERVAL '7 days'
      AND status IN ('pending', 'processing')
    `, [email, requestType])

    return result.rows.length > 0
  }

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }

  /**
   * Send verification email (placeholder - implement with your email service)
   */
  private async sendVerificationEmail(email: string, token: string, requestType: GDPRRequestType): Promise<void> {
    // TODO: Implement email sending
    logger.info('GDPR', `Verification email would be sent to ${email} for ${requestType} request with token ${token}`)
  }

  /**
   * Send response email (placeholder - implement with your email service)
   */
  private async sendResponseEmail(email: string, requestType: GDPRRequestType, responseData: any): Promise<void> {
    // TODO: Implement email sending
    logger.info('GDPR', `Response email would be sent to ${email} for ${requestType} request`)
  }

  /**
   * Get all pending requests for admin review
   */
  async getPendingRequests(): Promise<GDPRRequest[]> {
    try {
      const result = await pool.query(`
        SELECT * FROM gdpr_requests 
        WHERE status IN ('pending', 'processing')
        ORDER BY requested_at DESC
      `)

      return result.rows.map(row => ({
        id: row.id,
        requestType: row.request_type,
        subjectEmail: row.subject_email,
        subjectName: row.subject_name,
        requestDetails: JSON.parse(row.request_details || '{}'),
        status: row.status,
        requestedAt: row.requested_at,
        processedAt: row.processed_at,
        processedBy: row.processed_by,
        responseData: row.response_data ? JSON.parse(row.response_data) : null,
        notes: row.notes,
        expiresAt: row.expires_at
      }))

    } catch (error) {
      logger.error('GDPR', 'Failed to get pending requests', error)
      return []
    }
  }

  /**
   * Manually process a request (for admin use)
   */
  async manuallyProcessRequest(
    requestId: string,
    processedBy: string,
    responseData: any,
    notes?: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      await pool.query(`
        UPDATE gdpr_requests 
        SET status = $1, processed_at = NOW(), processed_by = $2, response_data = $3, notes = $4
        WHERE id = $5
      `, [RequestStatus.COMPLETED, processedBy, JSON.stringify(responseData), notes, requestId])

      return { success: true }

    } catch (error) {
      logger.error('GDPR', 'Failed to manually process request', error)
      return { success: false, error: 'Failed to process request' }
    }
  }
}

// Export singleton instance
export const gdprComplianceService = new GDPRComplianceService()
