/**
 * CCPA Compliance Framework
 * Implements California Consumer Privacy Act compliance tools
 * Including "Do Not Sell My Info" opt-out portal and automated data purging
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

// CCPA request types
export enum CCPARequestType {
  OPT_OUT = 'opt_out', // Do Not Sell My Personal Information
  DELETE = 'delete', // Delete Personal Information
  KNOW = 'know', // Know What Personal Information is Collected
  ACCESS = 'access', // Access Personal Information
  CORRECT = 'correct', // Correct Inaccurate Personal Information
  LIMIT = 'limit', // Limit Use of Sensitive Personal Information
}

// Request status
export enum CCPARequestStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  REJECTED = 'rejected',
  VERIFIED = 'verified',
}

// Verification methods
export enum VerificationMethod {
  EMAIL = 'email',
  PHONE = 'phone',
  IDENTITY_DOCUMENT = 'identity_document',
  ACCOUNT_LOGIN = 'account_login',
}

// CCPA request interface
export interface CCPARequest {
  id?: string
  requestType: CCPARequestType
  consumerEmail: string
  consumerName?: string
  requestDetails: {
    reason?: string
    specificData?: string[]
    timeRange?: {
      startDate: string
      endDate: string
    }
    verificationData?: any
  }
  status: CCPARequestStatus
  requestedAt: Date
  processedAt?: Date
  processedBy?: string
  responseData?: any
  verificationMethod?: VerificationMethod
  verifiedAt?: Date
  notes?: string
}

// Personal information categories under CCPA
export enum PersonalInfoCategory {
  IDENTIFIERS = 'identifiers',
  PERSONAL_RECORDS = 'personal_records',
  PROTECTED_CHARACTERISTICS = 'protected_characteristics',
  COMMERCIAL_INFO = 'commercial_info',
  BIOMETRIC_INFO = 'biometric_info',
  INTERNET_ACTIVITY = 'internet_activity',
  GEOLOCATION_DATA = 'geolocation_data',
  SENSORY_DATA = 'sensory_data',
  PROFESSIONAL_INFO = 'professional_info',
  EDUCATION_INFO = 'education_info',
  INFERENCES = 'inferences',
}

// CCPA compliance service
export class CCPAComplianceService {
  /**
   * Submit a new CCPA request
   */
  async submitRequest(
    requestType: CCPARequestType,
    consumerEmail: string,
    consumerName: string,
    requestDetails: any,
    clientIP: string,
    userAgent: string
  ): Promise<{ success: boolean; requestId?: string; error?: string }> {
    try {
      // Validate California residency (simplified check)
      const isCaliforniaResident = await this.validateCaliforniaResidency(clientIP, consumerEmail)
      if (!isCaliforniaResident) {
        return {
          success: false,
          error: 'CCPA rights are only available to California residents',
        }
      }

      // Check for duplicate recent requests
      const recentRequest = await this.checkRecentRequest(consumerEmail, requestType)
      if (recentRequest) {
        return {
          success: false,
          error:
            'A similar request was submitted recently. Please wait before submitting another request.',
        }
      }

      // Generate request ID
      const requestId = crypto.randomUUID()

      // Insert request into database
      await pool.query(
        `
        INSERT INTO ccpa_requests (
          id, request_type, consumer_email, consumer_name, request_details,
          status, requested_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
        [
          requestId,
          requestType,
          consumerEmail,
          consumerName,
          JSON.stringify(requestDetails),
          CCPARequestStatus.PENDING,
          new Date(),
        ]
      )

      // Log the request for audit trail
      await securityAuditService.logComplianceEvent(
        AuditEventType.CCPA_REQUEST,
        null,
        clientIP,
        userAgent,
        {
          requestType,
          consumerEmail,
          requestId,
        }
      )

      // Start verification process
      await this.initiateVerification(requestId, consumerEmail, requestType)

      logger.info('CCPA', `New ${requestType} request submitted`, {
        requestId,
        consumerEmail,
        clientIP,
      })

      return { success: true, requestId }
    } catch (error) {
      logger.error('CCPA', 'Failed to submit CCPA request', error)
      return { success: false, error: 'Failed to submit request' }
    }
  }

  /**
   * Process "Do Not Sell My Info" opt-out request
   */
  async processOptOutRequest(
    consumerEmail: string,
    clientIP: string,
    userAgent: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Validate California residency
      const isCaliforniaResident = await this.validateCaliforniaResidency(clientIP, consumerEmail)
      if (!isCaliforniaResident) {
        return {
          success: false,
          error: 'CCPA opt-out is only available to California residents',
        }
      }

      // Record opt-out preference
      await pool.query(
        `
        INSERT INTO ccpa_requests (
          id, request_type, consumer_email, request_details, status, 
          requested_at, processed_at, verification_method, verified_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (consumer_email, request_type) 
        DO UPDATE SET 
          status = $5, 
          processed_at = $7,
          request_details = $4
      `,
        [
          crypto.randomUUID(),
          CCPARequestType.OPT_OUT,
          consumerEmail,
          JSON.stringify({
            optOutDate: new Date().toISOString(),
            method: 'web_portal',
            ipAddress: clientIP,
          }),
          CCPARequestStatus.COMPLETED,
          new Date(),
          new Date(),
          VerificationMethod.EMAIL,
          new Date(),
        ]
      )

      // Update user preferences if they have an account
      await pool.query(
        `
        UPDATE users 
        SET ccpa_opt_out = true, ccpa_opt_out_date = NOW()
        WHERE email = $1
      `,
        [consumerEmail]
      )

      // Log opt-out event
      await securityAuditService.logComplianceEvent(
        AuditEventType.CCPA_REQUEST,
        null,
        clientIP,
        userAgent,
        {
          requestType: CCPARequestType.OPT_OUT,
          consumerEmail,
          status: 'completed',
        }
      )

      // Send confirmation email
      await this.sendOptOutConfirmation(consumerEmail)

      logger.info('CCPA', 'Opt-out request processed', {
        consumerEmail,
        clientIP,
      })

      return { success: true }
    } catch (error) {
      logger.error('CCPA', 'Failed to process opt-out request', error)
      return { success: false, error: 'Failed to process opt-out request' }
    }
  }

  /**
   * Get consumer's privacy dashboard data
   */
  async getPrivacyDashboard(
    consumerEmail: string,
    clientIP: string
  ): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      // Validate California residency
      const isCaliforniaResident = await this.validateCaliforniaResidency(clientIP, consumerEmail)
      if (!isCaliforniaResident) {
        return {
          success: false,
          error: 'Privacy dashboard is only available to California residents',
        }
      }

      // Get personal information collected
      const personalInfo = await this.getCollectedPersonalInfo(consumerEmail)

      // Get data sharing information
      const dataSharingInfo = await this.getDataSharingInfo(consumerEmail)

      // Get request history
      const requestHistory = await this.getRequestHistory(consumerEmail)

      // Get current privacy settings
      const privacySettings = await this.getPrivacySettings(consumerEmail)

      const dashboardData = {
        consumerRights: this.getConsumerRights(),
        personalInformation: personalInfo,
        dataSharingAndSales: dataSharingInfo,
        requestHistory,
        privacySettings,
        lastUpdated: new Date().toISOString(),
      }

      return { success: true, data: dashboardData }
    } catch (error) {
      logger.error('CCPA', 'Failed to get privacy dashboard', error)
      return { success: false, error: 'Failed to load privacy dashboard' }
    }
  }

  /**
   * Process deletion request
   */
  async processDeleteRequest(requestId: string): Promise<void> {
    try {
      // Get request details
      const result = await pool.query(
        `
        SELECT * FROM ccpa_requests WHERE id = $1
      `,
        [requestId]
      )

      if (result.rows.length === 0) {
        throw new Error('Request not found')
      }

      const request = result.rows[0]
      const consumerEmail = request.consumer_email

      // Start transaction for data deletion
      await pool.query('BEGIN')

      const deletedData: any = {
        deletedRecords: [],
        retainedRecords: [],
        reason: 'CCPA deletion request',
      }

      // Delete user account data
      const userResult = await pool.query(
        `
        DELETE FROM users WHERE email = $1 RETURNING id
      `,
        [consumerEmail]
      )

      if (userResult.rows.length > 0) {
        deletedData.deletedRecords.push({
          table: 'users',
          recordId: userResult.rows[0].id,
          deletedAt: new Date(),
        })
      }

      // Delete consent records
      const consentResult = await pool.query(
        `
        DELETE FROM consent_records WHERE email = $1 RETURNING id
      `,
        [consumerEmail]
      )

      deletedData.deletedRecords.push({
        table: 'consent_records',
        count: consentResult.rowCount,
        deletedAt: new Date(),
      })

      // Retain audit logs for legal compliance (anonymized)
      await pool.query(
        `
        UPDATE security_audit_log 
        SET user_id = NULL, encrypted_details = 'ANONYMIZED_BY_CCPA_REQUEST'
        WHERE user_id = $1
      `,
        [userResult.rows[0]?.id]
      )

      deletedData.retainedRecords.push({
        table: 'security_audit_log',
        reason: 'Legal obligation to retain audit logs',
        anonymized: true,
      })

      // Update request status
      await pool.query(
        `
        UPDATE ccpa_requests 
        SET status = $1, processed_at = NOW(), response_data = $2
        WHERE id = $3
      `,
        [CCPARequestStatus.COMPLETED, JSON.stringify(deletedData), requestId]
      )

      // Commit transaction
      await pool.query('COMMIT')

      // Send confirmation email
      await this.sendDeletionConfirmation(consumerEmail, deletedData)

      logger.info('CCPA', 'Deletion request processed', {
        requestId,
        consumerEmail,
        deletedRecords: deletedData.deletedRecords.length,
      })
    } catch (error) {
      await pool.query('ROLLBACK')
      logger.error('CCPA', `Failed to process deletion request ${requestId}`, error)

      // Mark request as failed
      await pool.query(
        `
        UPDATE ccpa_requests 
        SET status = $1, notes = $2, processed_at = NOW()
        WHERE id = $3
      `,
        [CCPARequestStatus.REJECTED, error.message, requestId]
      )
    }
  }

  /**
   * Validate California residency (simplified)
   */
  private async validateCaliforniaResidency(clientIP: string, email: string): Promise<boolean> {
    // In a real implementation, this would use geolocation services
    // and potentially additional verification methods

    // For now, we'll use a simple check
    // You could also check user's address if they have an account

    try {
      // Check if user has explicitly indicated California residency
      const result = await pool.query(
        `
        SELECT id FROM users 
        WHERE email = $1 AND (
          address_state = 'CA' OR 
          address_state = 'California' OR
          ccpa_opt_out IS NOT NULL
        )
      `,
        [email]
      )

      if (result.rows.length > 0) {
        return true
      }

      // TODO: Implement IP geolocation check for California
      // For now, assume all requests are from California residents
      return true
    } catch (error) {
      logger.error('CCPA', 'Failed to validate California residency', error)
      return false
    }
  }

  /**
   * Check for recent duplicate requests
   */
  private async checkRecentRequest(email: string, requestType: CCPARequestType): Promise<boolean> {
    const result = await pool.query(
      `
      SELECT id FROM ccpa_requests 
      WHERE consumer_email = $1 AND request_type = $2 
      AND requested_at > NOW() - INTERVAL '30 days'
      AND status IN ('pending', 'processing')
    `,
      [email, requestType]
    )

    return result.rows.length > 0
  }

  /**
   * Initiate verification process
   */
  private async initiateVerification(
    requestId: string,
    email: string,
    requestType: CCPARequestType
  ): Promise<void> {
    // For high-risk requests (delete, access), require additional verification
    const requiresVerification = [CCPARequestType.DELETE, CCPARequestType.ACCESS].includes(
      requestType
    )

    if (requiresVerification) {
      // Send verification email
      await this.sendVerificationEmail(email, requestId, requestType)
    } else {
      // Auto-verify for low-risk requests
      await pool.query(
        `
        UPDATE ccpa_requests 
        SET verification_method = $1, verified_at = NOW()
        WHERE id = $2
      `,
        [VerificationMethod.EMAIL, requestId]
      )
    }
  }

  /**
   * Get collected personal information
   */
  private async getCollectedPersonalInfo(email: string): Promise<any> {
    const categories = {
      [PersonalInfoCategory.IDENTIFIERS]: [],
      [PersonalInfoCategory.COMMERCIAL_INFO]: [],
      [PersonalInfoCategory.INTERNET_ACTIVITY]: [],
      [PersonalInfoCategory.INFERENCES]: [],
    }

    // Get user data
    const userResult = await pool.query(
      `
      SELECT email, name, created_at FROM users WHERE email = $1
    `,
      [email]
    )

    if (userResult.rows.length > 0) {
      categories[PersonalInfoCategory.IDENTIFIERS] = [
        { type: 'Email Address', value: userResult.rows[0].email },
        { type: 'Name', value: userResult.rows[0].name },
      ]
    }

    // Get activity data
    const activityResult = await pool.query(
      `
      SELECT event_type, timestamp FROM security_audit_log 
      WHERE user_id = (SELECT id FROM users WHERE email = $1)
      ORDER BY timestamp DESC LIMIT 10
    `,
      [email]
    )

    categories[PersonalInfoCategory.INTERNET_ACTIVITY] = activityResult.rows.map(row => ({
      type: 'Website Activity',
      activity: row.event_type,
      timestamp: row.timestamp,
    }))

    return categories
  }

  /**
   * Get data sharing information
   */
  private async getDataSharingInfo(email: string): Promise<any> {
    return {
      salesOfPersonalInfo: {
        sold: false,
        lastSaleDate: null,
        buyers: [],
      },
      sharingForBusinessPurposes: {
        shared: true,
        purposes: ['Analytics', 'Customer Support', 'Security'],
        recipients: ['Cloud Hosting Provider', 'Analytics Service'],
      },
      optOutStatus: {
        optedOut: false,
        optOutDate: null,
      },
    }
  }

  /**
   * Get request history
   */
  private async getRequestHistory(email: string): Promise<any[]> {
    const result = await pool.query(
      `
      SELECT request_type, status, requested_at, processed_at
      FROM ccpa_requests 
      WHERE consumer_email = $1
      ORDER BY requested_at DESC
    `,
      [email]
    )

    return result.rows.map(row => ({
      type: row.request_type,
      status: row.status,
      requestedAt: row.requested_at,
      processedAt: row.processed_at,
    }))
  }

  /**
   * Get privacy settings
   */
  private async getPrivacySettings(email: string): Promise<any> {
    const result = await pool.query(
      `
      SELECT ccpa_opt_out, ccpa_opt_out_date FROM users WHERE email = $1
    `,
      [email]
    )

    if (result.rows.length > 0) {
      return {
        doNotSell: result.rows[0].ccpa_opt_out || false,
        doNotSellDate: result.rows[0].ccpa_opt_out_date,
      }
    }

    return {
      doNotSell: false,
      doNotSellDate: null,
    }
  }

  /**
   * Get consumer rights information
   */
  private getConsumerRights(): any {
    return {
      rightToKnow:
        'You have the right to know what personal information we collect, use, disclose, and sell.',
      rightToDelete: 'You have the right to request deletion of your personal information.',
      rightToOptOut: 'You have the right to opt out of the sale of your personal information.',
      rightToNonDiscrimination:
        'You have the right not to receive discriminatory treatment for exercising your privacy rights.',
      rightToCorrect: 'You have the right to correct inaccurate personal information.',
      rightToLimit:
        'You have the right to limit the use and disclosure of sensitive personal information.',
    }
  }

  /**
   * Send opt-out confirmation email
   */
  private async sendOptOutConfirmation(email: string): Promise<void> {
    // TODO: Implement email sending
    logger.info('CCPA', `Opt-out confirmation would be sent to ${email}`)
  }

  /**
   * Send verification email
   */
  private async sendVerificationEmail(
    email: string,
    requestId: string,
    requestType: CCPARequestType
  ): Promise<void> {
    // TODO: Implement email sending
    logger.info(
      'CCPA',
      `Verification email would be sent to ${email} for ${requestType} request ${requestId}`
    )
  }

  /**
   * Send deletion confirmation email
   */
  private async sendDeletionConfirmation(email: string, deletedData: any): Promise<void> {
    // TODO: Implement email sending
    logger.info('CCPA', `Deletion confirmation would be sent to ${email}`)
  }
}

// Export singleton instance
export const ccpaComplianceService = new CCPAComplianceService()
