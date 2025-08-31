/**
 * Security Audit and Monitoring System
 * Implements continuous security monitoring with encrypted audit logs for SOC 2 compliance
 */

import { Pool } from 'pg'
import crypto from 'crypto'
import { logger } from '@/utils/logger'
import { ExtendedSession } from '@/lib/auth'

// Database connection for audit logs
const auditPool = new Pool({
  connectionString: process.env.AUDIT_DATABASE_URL || process.env.DATABASE_URL,
  ssl: false, // Explicitly disable SSL for local PostgreSQL container
})

// Audit event types
export enum AuditEventType {
  // Authentication events
  USER_LOGIN = 'USER_LOGIN',
  USER_LOGOUT = 'USER_LOGOUT',
  USER_LOGIN_FAILED = 'USER_LOGIN_FAILED',
  USER_LOCKED = 'USER_LOCKED',
  USER_UNLOCKED = 'USER_UNLOCKED',

  // Authorization events
  ACCESS_GRANTED = 'ACCESS_GRANTED',
  ACCESS_DENIED = 'ACCESS_DENIED',
  PERMISSION_ESCALATION = 'PERMISSION_ESCALATION',

  // Data events
  DATA_ACCESS = 'DATA_ACCESS',
  DATA_EXPORT = 'DATA_EXPORT',
  DATA_DELETE = 'DATA_DELETE',
  DATA_MODIFY = 'DATA_MODIFY',

  // Scraping events
  SCRAPING_STARTED = 'SCRAPING_STARTED',
  SCRAPING_COMPLETED = 'SCRAPING_COMPLETED',
  SCRAPING_FAILED = 'SCRAPING_FAILED',
  SCRAPING_BLOCKED = 'SCRAPING_BLOCKED',

  // Compliance events
  GDPR_REQUEST = 'GDPR_REQUEST',
  CCPA_REQUEST = 'CCPA_REQUEST',
  CONSENT_GIVEN = 'CONSENT_GIVEN',
  CONSENT_WITHDRAWN = 'CONSENT_WITHDRAWN',
  DATA_RETENTION_EXPIRED = 'DATA_RETENTION_EXPIRED',

  // Security events
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
  CONFIGURATION_CHANGED = 'CONFIGURATION_CHANGED',

  // System events
  SYSTEM_STARTUP = 'SYSTEM_STARTUP',
  SYSTEM_SHUTDOWN = 'SYSTEM_SHUTDOWN',
  BACKUP_CREATED = 'BACKUP_CREATED',
  BACKUP_RESTORED = 'BACKUP_RESTORED',
}

// Risk levels
export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

// Audit event interface
export interface AuditEvent {
  id?: string
  eventType: AuditEventType
  riskLevel: RiskLevel
  userId?: string
  sessionId?: string
  clientIP: string
  userAgent: string
  resource?: string
  action?: string
  details: Record<string, any>
  timestamp: Date
  correlationId?: string
}

// Audit service class
export class SecurityAuditService {
  private encryptionKey: Buffer
  private algorithm = 'aes-256-gcm'

  constructor() {
    // Initialize encryption key from environment or generate one
    const keyString = process.env.AUDIT_ENCRYPTION_KEY
    if (keyString) {
      this.encryptionKey = Buffer.from(keyString, 'hex')
    } else {
      // Generate a new key (should be stored securely in production)
      this.encryptionKey = crypto.randomBytes(32)
      logger.warn('Security Audit', 'Generated new encryption key - store securely!')
    }
  }

  /**
   * Log an audit event
   */
  async logEvent(event: AuditEvent): Promise<void> {
    try {
      // Encrypt sensitive details
      const encryptedDetails = this.encryptData(JSON.stringify(event.details))

      // Generate correlation ID if not provided
      const correlationId = event.correlationId || crypto.randomUUID()

      // Insert into audit log
      await auditPool.query(
        `
        INSERT INTO security_audit_log (
          id, event_type, risk_level, user_id, session_id, 
          client_ip, user_agent, resource, action, 
          encrypted_details, timestamp, correlation_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `,
        [
          crypto.randomUUID(),
          event.eventType,
          event.riskLevel,
          event.userId,
          event.sessionId,
          event.clientIP,
          event.userAgent,
          event.resource,
          event.action,
          encryptedDetails,
          event.timestamp,
          correlationId,
        ]
      )

      // Log to application logger as well
      logger.info('Security Audit', `${event.eventType}: ${event.action || 'N/A'}`, {
        userId: event.userId,
        resource: event.resource,
        riskLevel: event.riskLevel,
        correlationId,
      })

      // Check for high-risk events and trigger alerts
      if (event.riskLevel === RiskLevel.HIGH || event.riskLevel === RiskLevel.CRITICAL) {
        await this.triggerSecurityAlert(event)
      }
    } catch (error) {
      logger.error('Security Audit', 'Failed to log audit event', error)
      // Don't throw - audit logging should not break application flow
    }
  }

  /**
   * Log authentication event
   */
  async logAuthEvent(
    eventType: AuditEventType,
    session: ExtendedSession | null,
    clientIP: string,
    userAgent: string,
    details: Record<string, any> = {}
  ): Promise<void> {
    const riskLevel = this.determineAuthRiskLevel(eventType, details)

    await this.logEvent({
      eventType,
      riskLevel,
      userId: session?.user?.id,
      sessionId: session?.user?.id, // Use user ID as session identifier
      clientIP,
      userAgent,
      resource: 'authentication',
      action: eventType,
      details,
      timestamp: new Date(),
    })
  }

  /**
   * Log access event
   */
  async logAccessEvent(
    session: ExtendedSession,
    resource: string,
    action: string,
    clientIP: string,
    userAgent: string,
    granted: boolean,
    details: Record<string, any> = {}
  ): Promise<void> {
    const eventType = granted ? AuditEventType.ACCESS_GRANTED : AuditEventType.ACCESS_DENIED
    const riskLevel = granted ? RiskLevel.LOW : RiskLevel.MEDIUM

    await this.logEvent({
      eventType,
      riskLevel,
      userId: session.user.id,
      sessionId: session.user.id,
      clientIP,
      userAgent,
      resource,
      action,
      details: {
        ...details,
        userRole: session.user.role,
        permissions: session.user.permissions,
      },
      timestamp: new Date(),
    })
  }

  /**
   * Log data operation event
   */
  async logDataEvent(
    eventType: AuditEventType,
    session: ExtendedSession,
    resource: string,
    clientIP: string,
    userAgent: string,
    details: Record<string, any> = {}
  ): Promise<void> {
    const riskLevel = this.determineDataRiskLevel(eventType, details)

    await this.logEvent({
      eventType,
      riskLevel,
      userId: session.user.id,
      sessionId: session.user.id,
      clientIP,
      userAgent,
      resource,
      action: eventType,
      details,
      timestamp: new Date(),
    })
  }

  /**
   * Log compliance event
   */
  async logComplianceEvent(
    eventType: AuditEventType,
    userId: string | null,
    clientIP: string,
    userAgent: string,
    details: Record<string, any> = {}
  ): Promise<void> {
    await this.logEvent({
      eventType,
      riskLevel: RiskLevel.HIGH, // Compliance events are always high priority
      userId,
      clientIP,
      userAgent,
      resource: 'compliance',
      action: eventType,
      details,
      timestamp: new Date(),
    })
  }

  /**
   * Encrypt sensitive data
   */
  private encryptData(data: string): string {
    try {
      const iv = crypto.randomBytes(16)
      const cipher = crypto.createCipher(this.algorithm, this.encryptionKey)

      let encrypted = cipher.update(data, 'utf8', 'hex')
      encrypted += cipher.final('hex')

      const authTag = cipher.getAuthTag()

      return JSON.stringify({
        iv: iv.toString('hex'),
        data: encrypted,
        authTag: authTag.toString('hex'),
      })
    } catch (error) {
      logger.error('Security Audit', 'Failed to encrypt audit data', error)
      return JSON.stringify({ error: 'Encryption failed' })
    }
  }

  /**
   * Decrypt sensitive data
   */
  private decryptData(encryptedData: string): string {
    try {
      const { iv, data, authTag } = JSON.parse(encryptedData)

      const decipher = crypto.createDecipher(this.algorithm, this.encryptionKey)
      decipher.setAuthTag(Buffer.from(authTag, 'hex'))

      let decrypted = decipher.update(data, 'hex', 'utf8')
      decrypted += decipher.final('utf8')

      return decrypted
    } catch (error) {
      logger.error('Security Audit', 'Failed to decrypt audit data', error)
      return '{"error": "Decryption failed"}'
    }
  }

  /**
   * Determine risk level for authentication events
   */
  private determineAuthRiskLevel(
    eventType: AuditEventType,
    details: Record<string, any>
  ): RiskLevel {
    switch (eventType) {
      case AuditEventType.USER_LOGIN_FAILED:
        return details.consecutiveFailures > 3 ? RiskLevel.HIGH : RiskLevel.MEDIUM
      case AuditEventType.USER_LOCKED:
        return RiskLevel.HIGH
      case AuditEventType.USER_LOGIN:
        return details.newLocation ? RiskLevel.MEDIUM : RiskLevel.LOW
      default:
        return RiskLevel.LOW
    }
  }

  /**
   * Determine risk level for data events
   */
  private determineDataRiskLevel(
    eventType: AuditEventType,
    details: Record<string, any>
  ): RiskLevel {
    switch (eventType) {
      case AuditEventType.DATA_DELETE:
        return RiskLevel.HIGH
      case AuditEventType.DATA_EXPORT:
        return details.recordCount > 1000 ? RiskLevel.HIGH : RiskLevel.MEDIUM
      case AuditEventType.DATA_MODIFY:
        return RiskLevel.MEDIUM
      default:
        return RiskLevel.LOW
    }
  }

  /**
   * Trigger security alert for high-risk events
   */
  private async triggerSecurityAlert(event: AuditEvent): Promise<void> {
    try {
      // TODO: Implement alerting mechanism (email, Slack, etc.)
      logger.warn('Security Alert', `High-risk event detected: ${event.eventType}`, {
        userId: event.userId,
        resource: event.resource,
        riskLevel: event.riskLevel,
        timestamp: event.timestamp,
      })

      // Store alert in database
      await auditPool.query(
        `
        INSERT INTO security_alerts (
          id, event_id, alert_type, severity, message, created_at, resolved_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      `,
        [
          crypto.randomUUID(),
          event.id,
          'SECURITY_EVENT',
          event.riskLevel,
          `High-risk security event: ${event.eventType}`,
          new Date(),
          null,
        ]
      )
    } catch (error) {
      logger.error('Security Audit', 'Failed to trigger security alert', error)
    }
  }
}

// Export singleton instance
export const securityAuditService = new SecurityAuditService()

/**
 * Helper function to get client IP from request
 */
function getClientIP(request: any): string {
  return (
    request.headers.get('x-forwarded-for') ||
    request.headers.get('x-real-ip') ||
    request.connection?.remoteAddress ||
    request.socket?.remoteAddress ||
    'unknown'
  )
}
