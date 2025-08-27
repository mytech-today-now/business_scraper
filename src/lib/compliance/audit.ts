/**
 * Enterprise Audit Logging Service
 * Provides comprehensive audit trails for SOC 2, GDPR, and CCPA compliance
 */

import { Pool } from 'pg'
import { logger } from '@/utils/logger'
import { encryptionService, EncryptedData } from './encryption'

// Audit event types
export enum AuditEventType {
  // Authentication events
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  USER_LOGIN_FAILED = 'USER_LOGIN_FAILED',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_DISABLED = 'MFA_DISABLED',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',

  // Data access events
  DATA_ACCESSED = 'DATA_ACCESSED',
  DATA_EXPORTED = 'DATA_EXPORTED',
  DATA_MODIFIED = 'DATA_MODIFIED',
  DATA_DELETED = 'DATA_DELETED',
  DATA_CREATED = 'DATA_CREATED',

  // Scraping events
  SCRAPING_STARTED = 'SCRAPING_STARTED',
  SCRAPING_COMPLETED = 'SCRAPING_COMPLETED',
  SCRAPING_FAILED = 'SCRAPING_FAILED',
  SCRAPING_STOPPED = 'SCRAPING_STOPPED',

  // Compliance events
  CONSENT_GIVEN = 'CONSENT_GIVEN',
  CONSENT_WITHDRAWN = 'CONSENT_WITHDRAWN',
  DSAR_REQUEST = 'DSAR_REQUEST',
  DSAR_FULFILLED = 'DSAR_FULFILLED',
  CCPA_OPT_OUT = 'CCPA_OPT_OUT',
  DATA_RETENTION_APPLIED = 'DATA_RETENTION_APPLIED',
  DATA_PURGED = 'DATA_PURGED',

  // Security events
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',

  // System events
  SYSTEM_CONFIG_CHANGED = 'SYSTEM_CONFIG_CHANGED',
  BACKUP_CREATED = 'BACKUP_CREATED',
  BACKUP_RESTORED = 'BACKUP_RESTORED',
  MAINTENANCE_STARTED = 'MAINTENANCE_STARTED',
  MAINTENANCE_COMPLETED = 'MAINTENANCE_COMPLETED',
}

// Audit event severity levels
export enum AuditSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

// Audit event interface
export interface AuditEvent {
  id?: string
  eventType: AuditEventType
  severity: AuditSeverity
  userId?: string
  sessionId?: string
  ipAddress?: string
  userAgent?: string
  resource?: string
  action?: string
  details: Record<string, any>
  timestamp: Date
  correlationId?: string
  complianceFlags?: {
    gdprRelevant: boolean
    ccpaRelevant: boolean
    soc2Relevant: boolean
  }
}

// Database connection for audit logging
const auditPool = new Pool({
  connectionString: process.env.AUDIT_DATABASE_URL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 5, // Separate connection pool for audit logs
})

/**
 * Audit logging service
 */
export class AuditService {
  private encryptSensitiveData: boolean

  constructor(encryptSensitiveData = true) {
    this.encryptSensitiveData = encryptSensitiveData
  }

  /**
   * Log an audit event
   */
  async logEvent(event: AuditEvent): Promise<void> {
    try {
      // Generate correlation ID if not provided
      if (!event.correlationId) {
        event.correlationId = encryptionService.generateSecureToken(16)
      }

      // Encrypt sensitive details if enabled
      let encryptedDetails: EncryptedData | Record<string, any> = event.details
      if (this.encryptSensitiveData && this.containsSensitiveData(event.details)) {
        encryptedDetails = encryptionService.encrypt(JSON.stringify(event.details))
      }

      // Insert audit event into database
      await auditPool.query(
        `
        INSERT INTO audit_log (
          event_type, severity, user_id, session_id, ip_address, user_agent,
          resource, action, details, encrypted_details, timestamp, correlation_id,
          gdpr_relevant, ccpa_relevant, soc2_relevant
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      `,
        [
          event.eventType,
          event.severity,
          event.userId,
          event.sessionId,
          event.ipAddress,
          event.userAgent,
          event.resource,
          event.action,
          this.encryptSensitiveData ? null : JSON.stringify(event.details),
          this.encryptSensitiveData ? JSON.stringify(encryptedDetails) : null,
          event.timestamp,
          event.correlationId,
          event.complianceFlags?.gdprRelevant || false,
          event.complianceFlags?.ccpaRelevant || false,
          event.complianceFlags?.soc2Relevant || true, // Default to SOC 2 relevant
        ]
      )

      // Log to application logger as well
      logger.info('Audit', `${event.eventType}: ${event.action || 'N/A'}`, {
        userId: event.userId,
        severity: event.severity,
        correlationId: event.correlationId,
      })

      // Send critical events to monitoring system
      if (event.severity === AuditSeverity.CRITICAL) {
        await this.sendCriticalAlert(event)
      }
    } catch (error) {
      logger.error('Audit', 'Failed to log audit event', error)
      // Don't throw error to avoid breaking the main application flow
    }
  }

  /**
   * Query audit events with filters
   */
  async queryEvents(filters: {
    eventTypes?: AuditEventType[]
    userId?: string
    startDate?: Date
    endDate?: Date
    severity?: AuditSeverity
    correlationId?: string
    limit?: number
    offset?: number
  }): Promise<AuditEvent[]> {
    try {
      let query = 'SELECT * FROM audit_log WHERE 1=1'
      const params: any[] = []
      let paramIndex = 1

      if (filters.eventTypes?.length) {
        query += ` AND event_type = ANY($${paramIndex})`
        params.push(filters.eventTypes)
        paramIndex++
      }

      if (filters.userId) {
        query += ` AND user_id = $${paramIndex}`
        params.push(filters.userId)
        paramIndex++
      }

      if (filters.startDate) {
        query += ` AND timestamp >= $${paramIndex}`
        params.push(filters.startDate)
        paramIndex++
      }

      if (filters.endDate) {
        query += ` AND timestamp <= $${paramIndex}`
        params.push(filters.endDate)
        paramIndex++
      }

      if (filters.severity) {
        query += ` AND severity = $${paramIndex}`
        params.push(filters.severity)
        paramIndex++
      }

      if (filters.correlationId) {
        query += ` AND correlation_id = $${paramIndex}`
        params.push(filters.correlationId)
        paramIndex++
      }

      query += ' ORDER BY timestamp DESC'

      if (filters.limit) {
        query += ` LIMIT $${paramIndex}`
        params.push(filters.limit)
        paramIndex++
      }

      if (filters.offset) {
        query += ` OFFSET $${paramIndex}`
        params.push(filters.offset)
        paramIndex++
      }

      const result = await auditPool.query(query, params)

      return result.rows.map(row => ({
        id: row.id,
        eventType: row.event_type,
        severity: row.severity,
        userId: row.user_id,
        sessionId: row.session_id,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        resource: row.resource,
        action: row.action,
        details: row.encrypted_details
          ? JSON.parse(
              encryptionService.decrypt(JSON.parse(row.encrypted_details)).toString('utf8')
            )
          : JSON.parse(row.details || '{}'),
        timestamp: row.timestamp,
        correlationId: row.correlation_id,
        complianceFlags: {
          gdprRelevant: row.gdpr_relevant,
          ccpaRelevant: row.ccpa_relevant,
          soc2Relevant: row.soc2_relevant,
        },
      }))
    } catch (error) {
      logger.error('Audit', 'Failed to query audit events', error)
      throw new Error('Failed to retrieve audit events')
    }
  }

  /**
   * Check if data contains sensitive information
   */
  private containsSensitiveData(data: Record<string, any>): boolean {
    const sensitiveKeys = [
      'password',
      'email',
      'phone',
      'ssn',
      'credit_card',
      'bank_account',
      'api_key',
      'token',
      'secret',
      'private_key',
      'address',
    ]

    const dataString = JSON.stringify(data).toLowerCase()
    return sensitiveKeys.some(key => dataString.includes(key))
  }

  /**
   * Send critical alert to monitoring system
   */
  private async sendCriticalAlert(event: AuditEvent): Promise<void> {
    try {
      // Implementation would depend on your monitoring system
      // This could be Slack, PagerDuty, email, etc.
      logger.error('Audit Critical', `Critical audit event: ${event.eventType}`, {
        userId: event.userId,
        details: event.details,
        correlationId: event.correlationId,
      })
    } catch (error) {
      logger.error('Audit', 'Failed to send critical alert', error)
    }
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(
    startDate: Date,
    endDate: Date,
    complianceType: 'gdpr' | 'ccpa' | 'soc2'
  ): Promise<{
    totalEvents: number
    eventsByType: Record<string, number>
    criticalEvents: AuditEvent[]
    summary: string
  }> {
    try {
      const relevantField = `${complianceType}_relevant`

      const result = await auditPool.query(
        `
        SELECT 
          COUNT(*) as total_events,
          event_type,
          COUNT(*) as event_count,
          severity
        FROM audit_log 
        WHERE timestamp BETWEEN $1 AND $2 
        AND ${relevantField} = true
        GROUP BY event_type, severity
        ORDER BY event_count DESC
      `,
        [startDate, endDate]
      )

      const criticalEvents = await this.queryEvents({
        startDate,
        endDate,
        severity: AuditSeverity.CRITICAL,
      })

      const eventsByType: Record<string, number> = {}
      let totalEvents = 0

      result.rows.forEach(row => {
        eventsByType[row.event_type] = row.event_count
        totalEvents += parseInt(row.event_count)
      })

      const summary = `Compliance report for ${complianceType.toUpperCase()} from ${startDate.toISOString()} to ${endDate.toISOString()}: ${totalEvents} total events, ${criticalEvents.length} critical events`

      return {
        totalEvents,
        eventsByType,
        criticalEvents,
        summary,
      }
    } catch (error) {
      logger.error('Audit', 'Failed to generate compliance report', error)
      throw new Error('Failed to generate compliance report')
    }
  }
}

// Global audit service instance
export const auditService = new AuditService()

/**
 * Utility functions for common audit operations
 */
export const AuditUtils = {
  /**
   * Log user authentication event
   */
  logAuth: async (
    eventType: AuditEventType,
    userId: string,
    details: Record<string, any>,
    request?: any
  ) => {
    await auditService.logEvent({
      eventType,
      severity: eventType.includes('FAILED') ? AuditSeverity.HIGH : AuditSeverity.MEDIUM,
      userId,
      ipAddress: request?.ip,
      userAgent: request?.headers?.['user-agent'],
      details,
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true,
      },
    })
  },

  /**
   * Log data access event
   */
  logDataAccess: async (
    action: string,
    resource: string,
    userId: string,
    details: Record<string, any>
  ) => {
    await auditService.logEvent({
      eventType: AuditEventType.DATA_ACCESSED,
      severity: AuditSeverity.LOW,
      userId,
      resource,
      action,
      details,
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: true,
        ccpaRelevant: true,
        soc2Relevant: true,
      },
    })
  },

  /**
   * Log compliance event
   */
  logCompliance: async (
    eventType: AuditEventType,
    userId: string,
    details: Record<string, any>
  ) => {
    await auditService.logEvent({
      eventType,
      severity: AuditSeverity.MEDIUM,
      userId,
      details,
      timestamp: new Date(),
      complianceFlags: {
        gdprRelevant: eventType.includes('DSAR') || eventType.includes('CONSENT'),
        ccpaRelevant: eventType.includes('CCPA') || eventType.includes('OPT_OUT'),
        soc2Relevant: true,
      },
    })
  },
}
