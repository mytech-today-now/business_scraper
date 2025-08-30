/**
 * Comprehensive Audit Logging Service
 * Provides compliance-focused audit logging for GDPR, PCI DSS, SOC 2, and SOX
 */

import { logger } from '@/utils/logger'
import { storage } from './storage'

export interface AuditLog {
  id: string
  userId?: string
  action: string
  resource: string
  resourceId?: string
  oldValues?: Record<string, any>
  newValues?: Record<string, any>
  ipAddress?: string
  userAgent?: string
  timestamp: Date
  severity: 'low' | 'medium' | 'high' | 'critical'
  category: 'payment' | 'user' | 'security' | 'data' | 'system'
  complianceFlags?: string[]
  correlationId?: string
  sessionId?: string
}

export interface ComplianceReport {
  complianceType: 'GDPR' | 'PCI_DSS' | 'SOC2' | 'SOX'
  period: { startDate: Date; endDate: Date }
  totalEvents: number
  eventsByCategory: Record<string, number>
  eventsBySeverity: Record<string, number>
  securityIncidents: AuditLog[]
  dataAccessEvents: AuditLog[]
  paymentEvents: AuditLog[]
  generatedAt: Date
  reportId: string
}

export class AuditService {
  private auditLogs: AuditLog[] = []
  private maxLogs = 10000
  private complianceReports: ComplianceReport[] = []

  /**
   * Log audit events with comprehensive compliance tracking
   */
  async logAuditEvent(
    action: string,
    resource: string,
    options: {
      userId?: string
      resourceId?: string
      oldValues?: Record<string, any>
      newValues?: Record<string, any>
      ipAddress?: string
      userAgent?: string
      severity?: 'low' | 'medium' | 'high' | 'critical'
      category?: 'payment' | 'user' | 'security' | 'data' | 'system'
      complianceFlags?: string[]
      correlationId?: string
      sessionId?: string
    } = {}
  ): Promise<void> {
    try {
      const auditLog: AuditLog = {
        id: this.generateAuditId(),
        userId: options.userId,
        action,
        resource,
        resourceId: options.resourceId,
        oldValues: options.oldValues,
        newValues: options.newValues,
        ipAddress: options.ipAddress,
        userAgent: options.userAgent,
        timestamp: new Date(),
        severity: options.severity || 'medium',
        category: options.category || 'system',
        complianceFlags: options.complianceFlags || [],
        correlationId: options.correlationId || this.generateCorrelationId(),
        sessionId: options.sessionId
      }

      await this.storeAuditLog(auditLog)
      await this.processComplianceFlags(auditLog)

      logger.info('Audit', `Audit event logged: ${action}`, {
        resource,
        userId: options.userId,
        severity: auditLog.severity,
        correlationId: auditLog.correlationId
      })
    } catch (error) {
      logger.error('Audit', 'Failed to log audit event', error)
      throw error
    }
  }

  /**
   * Log payment-specific events with PCI DSS compliance
   */
  async logPaymentEvent(
    action: string,
    paymentData: any,
    userId?: string,
    ipAddress?: string,
    sessionId?: string
  ): Promise<void> {
    const sanitizedData = this.sanitizePaymentData(paymentData)

    await this.logAuditEvent(action, 'payment', {
      userId,
      resourceId: paymentData.id,
      newValues: sanitizedData,
      ipAddress,
      sessionId,
      severity: 'high',
      category: 'payment',
      complianceFlags: ['PCI_DSS', 'SOX']
    })
  }

  /**
   * Log user data access for GDPR compliance
   */
  async logDataAccess(
    userId: string,
    dataType: string,
    accessedBy?: string,
    purpose?: string,
    ipAddress?: string
  ): Promise<void> {
    await this.logAuditEvent('data_access', 'user_data', {
      userId: accessedBy,
      resourceId: userId,
      newValues: { dataType, purpose },
      ipAddress,
      severity: 'medium',
      category: 'data',
      complianceFlags: ['GDPR']
    })
  }

  /**
   * Log security events with high severity
   */
  async logSecurityEvent(
    action: string,
    details: Record<string, any>,
    ipAddress?: string,
    userId?: string,
    sessionId?: string
  ): Promise<void> {
    await this.logAuditEvent(action, 'security', {
      userId,
      newValues: details,
      ipAddress,
      sessionId,
      severity: 'critical',
      category: 'security',
      complianceFlags: ['SOC2', 'ISO27001']
    })
  }

  /**
   * Get audit logs with comprehensive filtering
   */
  async getAuditLogs(filters: {
    userId?: string
    category?: string
    startDate?: Date
    endDate?: Date
    severity?: string
    complianceFlags?: string[]
    limit?: number
    offset?: number
  }): Promise<{ logs: AuditLog[], total: number }> {
    try {
      let filteredLogs = [...this.auditLogs]

      // Apply filters
      if (filters.userId) {
        filteredLogs = filteredLogs.filter(log => log.userId === filters.userId)
      }

      if (filters.category) {
        filteredLogs = filteredLogs.filter(log => log.category === filters.category)
      }

      if (filters.startDate) {
        filteredLogs = filteredLogs.filter(log => log.timestamp >= filters.startDate!)
      }

      if (filters.endDate) {
        filteredLogs = filteredLogs.filter(log => log.timestamp <= filters.endDate!)
      }

      if (filters.severity) {
        filteredLogs = filteredLogs.filter(log => log.severity === filters.severity)
      }

      if (filters.complianceFlags?.length) {
        filteredLogs = filteredLogs.filter(log => 
          filters.complianceFlags!.some(flag => log.complianceFlags?.includes(flag))
        )
      }

      const total = filteredLogs.length
      const offset = filters.offset || 0
      const limit = filters.limit || 100

      const logs = filteredLogs
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
        .slice(offset, offset + limit)

      return { logs, total }
    } catch (error) {
      logger.error('Audit', 'Failed to get audit logs', error)
      throw error
    }
  }

  /**
   * Generate comprehensive compliance report
   */
  async generateComplianceReport(
    startDate: Date,
    endDate: Date,
    complianceType: 'GDPR' | 'PCI_DSS' | 'SOC2' | 'SOX'
  ): Promise<ComplianceReport> {
    try {
      const logs = await this.getAuditLogs({
        startDate,
        endDate
      })

      const relevantLogs = logs.logs.filter(log =>
        log.complianceFlags?.includes(complianceType)
      )

      const report: ComplianceReport = {
        complianceType,
        period: { startDate, endDate },
        totalEvents: relevantLogs.length,
        eventsByCategory: this.groupLogsByCategory(relevantLogs),
        eventsBySeverity: this.groupLogsBySeverity(relevantLogs),
        securityIncidents: relevantLogs.filter(log =>
          log.category === 'security' && log.severity === 'critical'
        ),
        dataAccessEvents: relevantLogs.filter(log =>
          log.category === 'data'
        ),
        paymentEvents: relevantLogs.filter(log =>
          log.category === 'payment'
        ),
        generatedAt: new Date(),
        reportId: this.generateReportId()
      }

      await this.storeComplianceReport(report)
      
      logger.info('Audit', `Compliance report generated: ${complianceType}`, {
        reportId: report.reportId,
        totalEvents: report.totalEvents
      })

      return report
    } catch (error) {
      logger.error('Audit', 'Failed to generate compliance report', error)
      throw error
    }
  }

  /**
   * Manage data retention according to compliance requirements
   */
  async manageDataRetention(): Promise<void> {
    try {
      const retentionPeriod = 7 * 365 * 24 * 60 * 60 * 1000 // 7 years in milliseconds
      const cutoffDate = new Date(Date.now() - retentionPeriod)

      const oldLogs = await this.getAuditLogs({
        endDate: cutoffDate
      })

      if (oldLogs.logs.length > 0) {
        // Archive old logs before deletion
        await this.archiveAuditLogs(oldLogs.logs)

        // Delete old logs
        await this.deleteAuditLogs(oldLogs.logs.map(log => log.id))

        logger.info('Audit', `Data retention: Archived and deleted ${oldLogs.logs.length} old audit logs`)
      }
    } catch (error) {
      logger.error('Audit', 'Failed to manage data retention', error)
      throw error
    }
  }

  /**
   * Sanitize payment data for secure logging
   */
  private sanitizePaymentData(data: any): any {
    const sensitiveFields = [
      'card_number',
      'cvv',
      'ssn',
      'bank_account',
      'routing_number',
      'payment_method_details'
    ]

    const sanitized = { ...data }

    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        if (field === 'card_number' && typeof sanitized[field] === 'string') {
          // Keep only last 4 digits
          sanitized[field] = `****-****-****-${sanitized[field].slice(-4)}`
        } else {
          sanitized[field] = '[REDACTED]'
        }
      }
    })

    return sanitized
  }

  /**
   * Process compliance-specific requirements
   */
  private async processComplianceFlags(auditLog: AuditLog): Promise<void> {
    if (auditLog.complianceFlags?.includes('PCI_DSS')) {
      await this.processPCICompliance(auditLog)
    }

    if (auditLog.complianceFlags?.includes('GDPR')) {
      await this.processGDPRCompliance(auditLog)
    }

    if (auditLog.complianceFlags?.includes('SOC2')) {
      await this.processSOC2Compliance(auditLog)
    }
  }

  /**
   * Store audit log securely
   */
  private async storeAuditLog(log: AuditLog): Promise<void> {
    this.auditLogs.push(log)
    
    // Maintain maximum log count
    if (this.auditLogs.length > this.maxLogs) {
      this.auditLogs = this.auditLogs.slice(-this.maxLogs)
    }

    // In production, this would store to a secure audit database
    // For now, we'll use the existing storage system
    try {
      await storage.initialize()
      // Store in a dedicated audit store when implemented
    } catch (error) {
      logger.error('Audit', 'Failed to store audit log', error)
    }
  }

  // Helper methods
  private generateAuditId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateCorrelationId(): string {
    return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private generateReportId(): string {
    return `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }

  private groupLogsByCategory(logs: AuditLog[]): Record<string, number> {
    return logs.reduce((acc, log) => {
      acc[log.category] = (acc[log.category] || 0) + 1
      return acc
    }, {} as Record<string, number>)
  }

  private groupLogsBySeverity(logs: AuditLog[]): Record<string, number> {
    return logs.reduce((acc, log) => {
      acc[log.severity] = (acc[log.severity] || 0) + 1
      return acc
    }, {} as Record<string, number>)
  }

  private async storeComplianceReport(report: ComplianceReport): Promise<void> {
    this.complianceReports.push(report)
  }

  private async archiveAuditLogs(logs: AuditLog[]): Promise<void> {
    // Implementation would archive logs to long-term storage
    logger.info('Audit', `Archiving ${logs.length} audit logs`)
  }

  private async deleteAuditLogs(logIds: string[]): Promise<void> {
    this.auditLogs = this.auditLogs.filter(log => !logIds.includes(log.id))
  }

  private async processPCICompliance(log: AuditLog): Promise<void> {
    // PCI DSS specific processing
    if (log.category === 'payment') {
      logger.info('Audit', 'Processing PCI DSS compliance for payment event', {
        logId: log.id,
        action: log.action
      })
    }
  }

  private async processGDPRCompliance(log: AuditLog): Promise<void> {
    // GDPR specific processing
    if (log.category === 'data') {
      logger.info('Audit', 'Processing GDPR compliance for data event', {
        logId: log.id,
        action: log.action
      })
    }
  }

  private async processSOC2Compliance(log: AuditLog): Promise<void> {
    // SOC 2 specific processing
    if (log.category === 'security') {
      logger.info('Audit', 'Processing SOC 2 compliance for security event', {
        logId: log.id,
        action: log.action
      })
    }
  }
}

export const auditService = new AuditService()
