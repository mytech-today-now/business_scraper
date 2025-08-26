/**
 * Automated Data Purging Service
 * Implements TypeScript-scheduled cron jobs for time-bound deletion rules
 * Supports GDPR, CCPA, and custom data retention policies
 */

import cron from 'node-cron'
import { Pool } from 'pg'
import crypto from 'crypto'
import { logger } from '@/utils/logger'
import { securityAuditService, AuditEventType } from '@/lib/security-audit'

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
})

// Purging job status
export enum PurgingJobStatus {
  SCHEDULED = 'scheduled',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
}

// Data category for purging
export enum DataCategory {
  PERSONAL_DATA = 'personal_data',
  BUSINESS_DATA = 'business_data',
  SESSION_DATA = 'session_data',
  AUDIT_LOGS = 'audit_logs',
  CONSENT_RECORDS = 'consent_records',
  SCRAPING_DATA = 'scraping_data',
  ANALYTICS_DATA = 'analytics_data',
  TEMPORARY_FILES = 'temporary_files'
}

// Purging rule interface
export interface PurgingRule {
  id: string
  name: string
  dataCategory: DataCategory
  retentionPeriod: number // in days
  tableName: string
  dateColumn: string
  conditions?: Record<string, any>
  isActive: boolean
  legalBasis: string
  description: string
  createdAt: Date
  lastRun?: Date
  nextRun?: Date
}

// Purging job result
export interface PurgingJobResult {
  jobId: string
  ruleId: string
  status: PurgingJobStatus
  recordsProcessed: number
  recordsDeleted: number
  recordsRetained: number
  errors: string[]
  startTime: Date
  endTime?: Date
  duration?: number
}

// Data purging service
export class DataPurgingService {
  private scheduledJobs: Map<string, cron.ScheduledTask> = new Map()
  private isInitialized = false

  /**
   * Initialize the data purging service
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) return

    try {
      // Load purging rules from database
      const rules = await this.loadPurgingRules()
      
      // Schedule cron jobs for each active rule
      for (const rule of rules) {
        if (rule.isActive) {
          await this.scheduleRule(rule)
        }
      }

      // Schedule daily cleanup job
      this.scheduleDailyCleanup()

      // Schedule weekly retention policy check
      this.scheduleWeeklyRetentionCheck()

      this.isInitialized = true
      logger.info('Data Purging', 'Service initialized successfully', {
        rulesLoaded: rules.length,
        activeRules: rules.filter(r => r.isActive).length
      })

    } catch (error) {
      logger.error('Data Purging', 'Failed to initialize service', error)
      throw error
    }
  }

  /**
   * Load purging rules from database
   */
  private async loadPurgingRules(): Promise<PurgingRule[]> {
    try {
      const result = await pool.query(`
        SELECT * FROM data_retention_policies 
        WHERE is_active = true
        ORDER BY policy_name
      `)

      return result.rows.map(row => ({
        id: row.id,
        name: row.policy_name,
        dataCategory: row.data_category as DataCategory,
        retentionPeriod: this.intervalToDays(row.retention_period),
        tableName: this.getCategoryTableName(row.data_category),
        dateColumn: this.getCategoryDateColumn(row.data_category),
        isActive: row.is_active,
        legalBasis: row.legal_basis,
        description: row.description,
        createdAt: row.created_at,
        lastRun: row.last_run,
        nextRun: row.next_run
      }))

    } catch (error) {
      logger.error('Data Purging', 'Failed to load purging rules', error)
      return []
    }
  }

  /**
   * Schedule a purging rule as a cron job
   */
  private async scheduleRule(rule: PurgingRule): Promise<void> {
    try {
      // Run daily at 2 AM
      const cronExpression = '0 2 * * *'
      
      const task = cron.schedule(cronExpression, async () => {
        await this.executePurgingRule(rule)
      }, {
        scheduled: false,
        timezone: 'UTC'
      })

      this.scheduledJobs.set(rule.id, task)
      task.start()

      logger.info('Data Purging', `Scheduled purging rule: ${rule.name}`, {
        ruleId: rule.id,
        cronExpression,
        retentionPeriod: rule.retentionPeriod
      })

    } catch (error) {
      logger.error('Data Purging', `Failed to schedule rule: ${rule.name}`, error)
    }
  }

  /**
   * Execute a purging rule
   */
  async executePurgingRule(rule: PurgingRule): Promise<PurgingJobResult> {
    const jobId = crypto.randomUUID()
    const startTime = new Date()

    logger.info('Data Purging', `Starting purging job for rule: ${rule.name}`, {
      jobId,
      ruleId: rule.id
    })

    const result: PurgingJobResult = {
      jobId,
      ruleId: rule.id,
      status: PurgingJobStatus.RUNNING,
      recordsProcessed: 0,
      recordsDeleted: 0,
      recordsRetained: 0,
      errors: [],
      startTime
    }

    try {
      // Calculate cutoff date
      const cutoffDate = new Date()
      cutoffDate.setDate(cutoffDate.getDate() - rule.retentionPeriod)

      // Start transaction
      await pool.query('BEGIN')

      // Get records to be purged
      const countQuery = `
        SELECT COUNT(*) as total 
        FROM ${rule.tableName} 
        WHERE ${rule.dateColumn} < $1
        ${rule.conditions ? this.buildConditionsClause(rule.conditions) : ''}
      `
      
      const countResult = await pool.query(countQuery, [cutoffDate])
      result.recordsProcessed = parseInt(countResult.rows[0].total)

      if (result.recordsProcessed === 0) {
        result.status = PurgingJobStatus.COMPLETED
        await pool.query('COMMIT')
        logger.info('Data Purging', `No records to purge for rule: ${rule.name}`, { jobId })
        return result
      }

      // Handle different data categories with specific logic
      switch (rule.dataCategory) {
        case DataCategory.PERSONAL_DATA:
          result.recordsDeleted = await this.purgePersonalData(rule, cutoffDate)
          break
        case DataCategory.SESSION_DATA:
          result.recordsDeleted = await this.purgeSessionData(rule, cutoffDate)
          break
        case DataCategory.AUDIT_LOGS:
          result.recordsDeleted = await this.purgeAuditLogs(rule, cutoffDate)
          break
        case DataCategory.SCRAPING_DATA:
          result.recordsDeleted = await this.purgeScrapingData(rule, cutoffDate)
          break
        default:
          result.recordsDeleted = await this.purgeGenericData(rule, cutoffDate)
      }

      result.recordsRetained = result.recordsProcessed - result.recordsDeleted
      result.status = PurgingJobStatus.COMPLETED

      // Commit transaction
      await pool.query('COMMIT')

      // Update rule last run time
      await pool.query(`
        UPDATE data_retention_policies 
        SET last_run = NOW(), next_run = NOW() + INTERVAL '1 day'
        WHERE id = $1
      `, [rule.id])

      // Log audit event
      await securityAuditService.logComplianceEvent(
        AuditEventType.DATA_RETENTION_EXPIRED,
        null,
        'system',
        'data-purging-service',
        {
          ruleId: rule.id,
          ruleName: rule.name,
          recordsDeleted: result.recordsDeleted,
          recordsRetained: result.recordsRetained,
          cutoffDate: cutoffDate.toISOString()
        }
      )

    } catch (error) {
      await pool.query('ROLLBACK')
      result.status = PurgingJobStatus.FAILED
      result.errors.push(error.message)
      logger.error('Data Purging', `Purging job failed for rule: ${rule.name}`, error)
    }

    result.endTime = new Date()
    result.duration = result.endTime.getTime() - result.startTime.getTime()

    logger.info('Data Purging', `Completed purging job for rule: ${rule.name}`, {
      jobId,
      status: result.status,
      recordsDeleted: result.recordsDeleted,
      duration: result.duration
    })

    return result
  }

  /**
   * Purge personal data with GDPR/CCPA compliance
   */
  private async purgePersonalData(rule: PurgingRule, cutoffDate: Date): Promise<number> {
    let deletedCount = 0

    // Check for active consent or legal holds
    const protectedRecords = await pool.query(`
      SELECT DISTINCT user_id FROM consent_records 
      WHERE consent_given = true 
      AND consent_date > $1
      AND consent_type IN ('storage', 'processing')
    `, [cutoffDate])

    const protectedUserIds = protectedRecords.rows.map(row => row.user_id)

    // Delete unprotected personal data
    const deleteQuery = `
      DELETE FROM ${rule.tableName} 
      WHERE ${rule.dateColumn} < $1
      ${protectedUserIds.length > 0 ? `AND user_id NOT IN (${protectedUserIds.map((_, i) => `$${i + 2}`).join(',')})` : ''}
    `

    const params = [cutoffDate, ...protectedUserIds]
    const result = await pool.query(deleteQuery, params)
    deletedCount = result.rowCount || 0

    return deletedCount
  }

  /**
   * Purge session data
   */
  private async purgeSessionData(rule: PurgingRule, cutoffDate: Date): Promise<number> {
    const result = await pool.query(`
      DELETE FROM ${rule.tableName} 
      WHERE ${rule.dateColumn} < $1
    `, [cutoffDate])

    return result.rowCount || 0
  }

  /**
   * Purge audit logs (with retention requirements)
   */
  private async purgeAuditLogs(rule: PurgingRule, cutoffDate: Date): Promise<number> {
    // Keep critical security events longer
    const result = await pool.query(`
      DELETE FROM ${rule.tableName} 
      WHERE ${rule.dateColumn} < $1
      AND risk_level NOT IN ('HIGH', 'CRITICAL')
      AND event_type NOT IN ('USER_LOGIN_FAILED', 'SECURITY_VIOLATION', 'DATA_DELETE')
    `, [cutoffDate])

    return result.rowCount || 0
  }

  /**
   * Purge scraping data
   */
  private async purgeScrapingData(rule: PurgingRule, cutoffDate: Date): Promise<number> {
    // Archive valuable data before deletion
    await pool.query(`
      INSERT INTO archived_scraping_data 
      SELECT *, NOW() as archived_at 
      FROM ${rule.tableName} 
      WHERE ${rule.dateColumn} < $1
      AND business_value = 'high'
    `, [cutoffDate])

    const result = await pool.query(`
      DELETE FROM ${rule.tableName} 
      WHERE ${rule.dateColumn} < $1
    `, [cutoffDate])

    return result.rowCount || 0
  }

  /**
   * Purge generic data
   */
  private async purgeGenericData(rule: PurgingRule, cutoffDate: Date): Promise<number> {
    const result = await pool.query(`
      DELETE FROM ${rule.tableName} 
      WHERE ${rule.dateColumn} < $1
    `, [cutoffDate])

    return result.rowCount || 0
  }

  /**
   * Schedule daily cleanup job
   */
  private scheduleDailyCleanup(): void {
    // Run at 3 AM daily
    cron.schedule('0 3 * * *', async () => {
      await this.performDailyCleanup()
    }, {
      timezone: 'UTC'
    })
  }

  /**
   * Schedule weekly retention policy check
   */
  private scheduleWeeklyRetentionCheck(): void {
    // Run every Sunday at 1 AM
    cron.schedule('0 1 * * 0', async () => {
      await this.performWeeklyRetentionCheck()
    }, {
      timezone: 'UTC'
    })
  }

  /**
   * Perform daily cleanup tasks
   */
  private async performDailyCleanup(): Promise<void> {
    try {
      logger.info('Data Purging', 'Starting daily cleanup')

      // Clean up temporary files
      await this.cleanupTemporaryFiles()

      // Clean up expired sessions
      await this.cleanupExpiredSessions()

      // Clean up old job logs
      await this.cleanupJobLogs()

      logger.info('Data Purging', 'Daily cleanup completed')

    } catch (error) {
      logger.error('Data Purging', 'Daily cleanup failed', error)
    }
  }

  /**
   * Perform weekly retention policy check
   */
  private async performWeeklyRetentionCheck(): Promise<void> {
    try {
      logger.info('Data Purging', 'Starting weekly retention check')

      // Check for data approaching retention limits
      await this.checkUpcomingExpirations()

      // Validate retention policy compliance
      await this.validateRetentionCompliance()

      logger.info('Data Purging', 'Weekly retention check completed')

    } catch (error) {
      logger.error('Data Purging', 'Weekly retention check failed', error)
    }
  }

  /**
   * Helper methods
   */
  private intervalToDays(interval: string): number {
    // Convert PostgreSQL interval to days
    const match = interval.match(/(\d+)\s*(day|month|year)s?/)
    if (!match) return 30 // Default to 30 days

    const value = parseInt(match[1])
    const unit = match[2]

    switch (unit) {
      case 'day': return value
      case 'month': return value * 30
      case 'year': return value * 365
      default: return 30
    }
  }

  private getCategoryTableName(category: string): string {
    const tableMap = {
      'personal_data': 'users',
      'session_data': 'sessions',
      'audit_logs': 'security_audit_log',
      'consent_records': 'consent_records',
      'scraping_data': 'scraping_sessions',
      'analytics_data': 'analytics_events'
    }
    return tableMap[category] || 'data_retention_schedule'
  }

  private getCategoryDateColumn(category: string): string {
    const columnMap = {
      'personal_data': 'created_at',
      'session_data': 'created_at',
      'audit_logs': 'timestamp',
      'consent_records': 'consent_date',
      'scraping_data': 'created_at',
      'analytics_data': 'event_timestamp'
    }
    return columnMap[category] || 'created_at'
  }

  private buildConditionsClause(conditions: Record<string, any>): string {
    const clauses = Object.entries(conditions).map(([key, value]) => {
      if (Array.isArray(value)) {
        return `AND ${key} IN (${value.map(v => `'${v}'`).join(',')})`
      } else {
        return `AND ${key} = '${value}'`
      }
    })
    return clauses.join(' ')
  }

  private async cleanupTemporaryFiles(): Promise<void> {
    // Implementation for cleaning up temporary files
  }

  private async cleanupExpiredSessions(): Promise<void> {
    await pool.query(`
      DELETE FROM sessions WHERE expires < NOW()
    `)
  }

  private async cleanupJobLogs(): Promise<void> {
    // Keep job logs for 90 days
    await pool.query(`
      DELETE FROM purging_job_logs 
      WHERE created_at < NOW() - INTERVAL '90 days'
    `)
  }

  private async checkUpcomingExpirations(): Promise<void> {
    // Check for data that will expire in the next 7 days
    const result = await pool.query(`
      SELECT table_name, COUNT(*) as count
      FROM data_retention_schedule 
      WHERE expires_at BETWEEN NOW() AND NOW() + INTERVAL '7 days'
      AND status = 'active'
      GROUP BY table_name
    `)

    for (const row of result.rows) {
      logger.info('Data Purging', `Upcoming expirations in ${row.table_name}: ${row.count} records`)
    }
  }

  private async validateRetentionCompliance(): Promise<void> {
    // Check for overdue data that should have been purged
    const result = await pool.query(`
      SELECT table_name, COUNT(*) as overdue_count
      FROM data_retention_schedule 
      WHERE expires_at < NOW()
      AND status = 'active'
      GROUP BY table_name
    `)

    for (const row of result.rows) {
      if (row.overdue_count > 0) {
        logger.warn('Data Purging', `Overdue data found in ${row.table_name}: ${row.overdue_count} records`)
      }
    }
  }

  /**
   * Stop all scheduled jobs
   */
  async shutdown(): Promise<void> {
    for (const [ruleId, task] of this.scheduledJobs) {
      task.stop()
      logger.info('Data Purging', `Stopped scheduled job for rule: ${ruleId}`)
    }
    this.scheduledJobs.clear()
    this.isInitialized = false
  }
}

// Export singleton instance
export const dataPurgingService = new DataPurgingService()
