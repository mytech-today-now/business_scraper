/**
 * Data Retention and Purging Service
 * Implements automated data lifecycle management for GDPR, CCPA, and SOC 2 compliance
 */

import { Pool } from 'pg'
import cron from 'node-cron'
import { logger } from '@/utils/logger'
import { auditService, AuditEventType, AuditSeverity } from './audit'
import { encryptionService } from './encryption'

// Data retention policies
export interface RetentionPolicy {
  id: string
  name: string
  description: string
  dataType: string
  retentionPeriodDays: number
  legalBasis: string
  autoDelete: boolean
  archiveBeforeDelete: boolean
  notificationDays: number[] // Days before deletion to send notifications
  isActive: boolean
  createdAt: Date
  updatedAt: Date
}

// Data purge record
export interface PurgeRecord {
  id?: string
  policyId: string
  dataType: string
  recordsAffected: number
  purgeDate: Date
  reason: string
  initiatedBy?: string
  status: 'pending' | 'completed' | 'failed'
  details: Record<string, any>
}

// Retention schedule
export interface RetentionSchedule {
  id: string
  policyId: string
  nextRunDate: Date
  cronExpression: string
  isActive: boolean
}

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
})

/**
 * Data retention service
 */
export class DataRetentionService {
  private scheduledJobs: Map<string, cron.ScheduledTask> = new Map()

  constructor() {
    this.initializeDefaultPolicies()
    this.loadRetentionSchedules()
  }

  /**
   * Initialize default retention policies
   */
  private async initializeDefaultPolicies(): Promise<void> {
    const defaultPolicies: Omit<RetentionPolicy, 'id' | 'createdAt' | 'updatedAt'>[] = [
      {
        name: 'Business Contact Data',
        description: 'Scraped business contact information',
        dataType: 'business_contacts',
        retentionPeriodDays: 1095, // 3 years
        legalBasis: 'legitimate_interests',
        autoDelete: true,
        archiveBeforeDelete: true,
        notificationDays: [30, 7, 1],
        isActive: true
      },
      {
        name: 'User Session Data',
        description: 'User session and activity logs',
        dataType: 'user_sessions',
        retentionPeriodDays: 90,
        legalBasis: 'legitimate_interests',
        autoDelete: true,
        archiveBeforeDelete: false,
        notificationDays: [7, 1],
        isActive: true
      },
      {
        name: 'Audit Logs',
        description: 'Security and compliance audit logs',
        dataType: 'audit_logs',
        retentionPeriodDays: 2555, // 7 years for SOC 2
        legalBasis: 'legal_obligation',
        autoDelete: false, // Manual review required
        archiveBeforeDelete: true,
        notificationDays: [90, 30, 7],
        isActive: true
      },
      {
        name: 'Consent Records',
        description: 'GDPR and CCPA consent records',
        dataType: 'consent_records',
        retentionPeriodDays: 2190, // 6 years
        legalBasis: 'legal_obligation',
        autoDelete: false,
        archiveBeforeDelete: true,
        notificationDays: [90, 30, 7],
        isActive: true
      },
      {
        name: 'Scraping Cache',
        description: 'Temporary scraping data and cache',
        dataType: 'scraping_cache',
        retentionPeriodDays: 30,
        legalBasis: 'legitimate_interests',
        autoDelete: true,
        archiveBeforeDelete: false,
        notificationDays: [7, 1],
        isActive: true
      }
    ]

    try {
      for (const policy of defaultPolicies) {
        await this.createOrUpdatePolicy(policy)
      }
      logger.info('Retention', 'Default retention policies initialized')
    } catch (error) {
      logger.error('Retention', 'Failed to initialize default policies', error)
    }
  }

  /**
   * Create or update retention policy
   */
  async createOrUpdatePolicy(policy: Omit<RetentionPolicy, 'id' | 'createdAt' | 'updatedAt'>): Promise<string> {
    try {
      const result = await pool.query(`
        INSERT INTO retention_policies (
          name, description, data_type, retention_period_days, legal_basis,
          auto_delete, archive_before_delete, notification_days, is_active
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (data_type) DO UPDATE SET
          name = EXCLUDED.name,
          description = EXCLUDED.description,
          retention_period_days = EXCLUDED.retention_period_days,
          legal_basis = EXCLUDED.legal_basis,
          auto_delete = EXCLUDED.auto_delete,
          archive_before_delete = EXCLUDED.archive_before_delete,
          notification_days = EXCLUDED.notification_days,
          is_active = EXCLUDED.is_active,
          updated_at = NOW()
        RETURNING id
      `, [
        policy.name,
        policy.description,
        policy.dataType,
        policy.retentionPeriodDays,
        policy.legalBasis,
        policy.autoDelete,
        policy.archiveBeforeDelete,
        JSON.stringify(policy.notificationDays),
        policy.isActive
      ])

      const policyId = result.rows[0].id

      // Create or update retention schedule
      await this.createRetentionSchedule(policyId, '0 2 * * *') // Daily at 2 AM

      logger.info('Retention', `Retention policy created/updated: ${policy.name}`, { policyId })
      return policyId

    } catch (error) {
      logger.error('Retention', 'Failed to create/update retention policy', error)
      throw new Error('Failed to create retention policy')
    }
  }

  /**
   * Create retention schedule
   */
  private async createRetentionSchedule(policyId: string, cronExpression: string): Promise<void> {
    try {
      await pool.query(`
        INSERT INTO retention_schedules (policy_id, cron_expression, next_run_date, is_active)
        VALUES ($1, $2, NOW() + INTERVAL '1 day', true)
        ON CONFLICT (policy_id) DO UPDATE SET
          cron_expression = EXCLUDED.cron_expression,
          is_active = EXCLUDED.is_active,
          updated_at = NOW()
      `, [policyId, cronExpression])

    } catch (error) {
      logger.error('Retention', 'Failed to create retention schedule', error)
      throw new Error('Failed to create retention schedule')
    }
  }

  /**
   * Load and start retention schedules
   */
  private async loadRetentionSchedules(): Promise<void> {
    try {
      const result = await pool.query(`
        SELECT rs.*, rp.data_type, rp.auto_delete
        FROM retention_schedules rs
        JOIN retention_policies rp ON rs.policy_id = rp.id
        WHERE rs.is_active = true AND rp.is_active = true
      `)

      for (const schedule of result.rows) {
        this.scheduleRetentionJob(schedule)
      }

      logger.info('Retention', `Loaded ${result.rows.length} retention schedules`)

    } catch (error) {
      logger.error('Retention', 'Failed to load retention schedules', error)
    }
  }

  /**
   * Schedule retention job
   */
  private scheduleRetentionJob(schedule: any): void {
    try {
      const task = cron.schedule(schedule.cron_expression, async () => {
        await this.executeRetentionPolicy(schedule.policy_id)
      }, {
        scheduled: true,
        timezone: 'UTC'
      })

      this.scheduledJobs.set(schedule.policy_id, task)

      logger.info('Retention', `Scheduled retention job for policy: ${schedule.policy_id}`, {
        cronExpression: schedule.cron_expression,
        dataType: schedule.data_type
      })

    } catch (error) {
      logger.error('Retention', 'Failed to schedule retention job', error)
    }
  }

  /**
   * Execute retention policy
   */
  async executeRetentionPolicy(policyId: string): Promise<PurgeRecord> {
    try {
      // Get policy details
      const policyResult = await pool.query(
        'SELECT * FROM retention_policies WHERE id = $1 AND is_active = true',
        [policyId]
      )

      if (policyResult.rows.length === 0) {
        throw new Error(`Retention policy not found: ${policyId}`)
      }

      const policy = policyResult.rows[0]
      const cutoffDate = new Date(Date.now() - policy.retention_period_days * 24 * 60 * 60 * 1000)

      logger.info('Retention', `Executing retention policy: ${policy.name}`, {
        policyId,
        dataType: policy.data_type,
        cutoffDate: cutoffDate.toISOString()
      })

      // Check for records to purge
      const recordsToDelete = await this.identifyRecordsForDeletion(policy.data_type, cutoffDate)

      if (recordsToDelete.length === 0) {
        logger.info('Retention', `No records to purge for policy: ${policy.name}`)
        return {
          policyId,
          dataType: policy.data_type,
          recordsAffected: 0,
          purgeDate: new Date(),
          reason: 'No records found for deletion',
          status: 'completed',
          details: { cutoffDate: cutoffDate.toISOString() }
        }
      }

      // Archive before delete if required
      if (policy.archive_before_delete) {
        await this.archiveRecords(policy.data_type, recordsToDelete)
      }

      // Delete records if auto-delete is enabled
      let deletedCount = 0
      if (policy.auto_delete) {
        deletedCount = await this.deleteRecords(policy.data_type, recordsToDelete)
      }

      // Create purge record
      const purgeRecord: PurgeRecord = {
        policyId,
        dataType: policy.data_type,
        recordsAffected: deletedCount,
        purgeDate: new Date(),
        reason: `Automatic retention policy execution`,
        status: 'completed',
        details: {
          cutoffDate: cutoffDate.toISOString(),
          archived: policy.archive_before_delete,
          autoDeleted: policy.auto_delete,
          recordIds: recordsToDelete.slice(0, 100) // Store first 100 IDs for audit
        }
      }

      await this.recordPurgeActivity(purgeRecord)

      // Log audit event
      await auditService.logEvent({
        eventType: AuditEventType.DATA_RETENTION_APPLIED,
        severity: AuditSeverity.MEDIUM,
        details: {
          policyId,
          dataType: policy.data_type,
          recordsAffected: deletedCount,
          archived: policy.archive_before_delete
        },
        timestamp: new Date(),
        complianceFlags: {
          gdprRelevant: true,
          ccpaRelevant: true,
          soc2Relevant: true
        }
      })

      logger.info('Retention', `Retention policy executed successfully`, {
        policyId,
        recordsAffected: deletedCount,
        archived: policy.archive_before_delete
      })

      return purgeRecord

    } catch (error) {
      logger.error('Retention', 'Failed to execute retention policy', error)
      
      const errorRecord: PurgeRecord = {
        policyId,
        dataType: 'unknown',
        recordsAffected: 0,
        purgeDate: new Date(),
        reason: `Execution failed: ${error.message}`,
        status: 'failed',
        details: { error: error.message }
      }

      await this.recordPurgeActivity(errorRecord)
      throw error
    }
  }

  /**
   * Identify records for deletion based on data type and cutoff date
   */
  private async identifyRecordsForDeletion(dataType: string, cutoffDate: Date): Promise<string[]> {
    const queries: Record<string, string> = {
      business_contacts: 'SELECT id FROM businesses WHERE created_at < $1',
      user_sessions: 'SELECT id FROM user_sessions WHERE created_at < $1',
      audit_logs: 'SELECT id FROM audit_log WHERE timestamp < $1',
      consent_records: 'SELECT id FROM consent_records WHERE timestamp < $1 AND status = \'withdrawn\'',
      scraping_cache: 'SELECT id FROM scraping_cache WHERE created_at < $1'
    }

    const query = queries[dataType]
    if (!query) {
      throw new Error(`Unknown data type for retention: ${dataType}`)
    }

    try {
      const result = await pool.query(query, [cutoffDate])
      return result.rows.map(row => row.id)
    } catch (error) {
      logger.error('Retention', `Failed to identify records for deletion: ${dataType}`, error)
      throw error
    }
  }

  /**
   * Archive records before deletion
   */
  private async archiveRecords(dataType: string, recordIds: string[]): Promise<void> {
    try {
      const archiveData = {
        dataType,
        recordIds,
        archivedAt: new Date().toISOString(),
        archiveId: encryptionService.generateSecureToken(16)
      }

      // In a real implementation, this would export to secure archive storage
      // For now, we'll log the archive operation
      logger.info('Retention', `Archived ${recordIds.length} records of type: ${dataType}`, {
        archiveId: archiveData.archiveId
      })

      // Store archive metadata
      await pool.query(`
        INSERT INTO data_archives (archive_id, data_type, record_count, archived_at, metadata)
        VALUES ($1, $2, $3, $4, $5)
      `, [
        archiveData.archiveId,
        dataType,
        recordIds.length,
        new Date(),
        JSON.stringify(archiveData)
      ])

    } catch (error) {
      logger.error('Retention', 'Failed to archive records', error)
      throw error
    }
  }

  /**
   * Delete records
   */
  private async deleteRecords(dataType: string, recordIds: string[]): Promise<number> {
    const deleteQueries: Record<string, string> = {
      business_contacts: 'DELETE FROM businesses WHERE id = ANY($1)',
      user_sessions: 'DELETE FROM user_sessions WHERE id = ANY($1)',
      audit_logs: 'DELETE FROM audit_log WHERE id = ANY($1)',
      consent_records: 'DELETE FROM consent_records WHERE id = ANY($1)',
      scraping_cache: 'DELETE FROM scraping_cache WHERE id = ANY($1)'
    }

    const query = deleteQueries[dataType]
    if (!query) {
      throw new Error(`Unknown data type for deletion: ${dataType}`)
    }

    try {
      const result = await pool.query(query, [recordIds])
      return result.rowCount || 0
    } catch (error) {
      logger.error('Retention', `Failed to delete records: ${dataType}`, error)
      throw error
    }
  }

  /**
   * Record purge activity
   */
  private async recordPurgeActivity(purgeRecord: PurgeRecord): Promise<void> {
    try {
      await pool.query(`
        INSERT INTO purge_records (
          policy_id, data_type, records_affected, purge_date, reason,
          initiated_by, status, details
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [
        purgeRecord.policyId,
        purgeRecord.dataType,
        purgeRecord.recordsAffected,
        purgeRecord.purgeDate,
        purgeRecord.reason,
        purgeRecord.initiatedBy,
        purgeRecord.status,
        JSON.stringify(purgeRecord.details)
      ])
    } catch (error) {
      logger.error('Retention', 'Failed to record purge activity', error)
    }
  }

  /**
   * Get retention policies
   */
  async getRetentionPolicies(): Promise<RetentionPolicy[]> {
    try {
      const result = await pool.query('SELECT * FROM retention_policies ORDER BY data_type')
      
      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        description: row.description,
        dataType: row.data_type,
        retentionPeriodDays: row.retention_period_days,
        legalBasis: row.legal_basis,
        autoDelete: row.auto_delete,
        archiveBeforeDelete: row.archive_before_delete,
        notificationDays: JSON.parse(row.notification_days || '[]'),
        isActive: row.is_active,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }))

    } catch (error) {
      logger.error('Retention', 'Failed to get retention policies', error)
      throw new Error('Failed to retrieve retention policies')
    }
  }

  /**
   * Stop all scheduled jobs
   */
  stopAllJobs(): void {
    this.scheduledJobs.forEach((task, policyId) => {
      task.stop()
      logger.info('Retention', `Stopped retention job for policy: ${policyId}`)
    })
    this.scheduledJobs.clear()
  }

  /**
   * Calculate retention date
   */
  calculateRetentionDate(createdDate: Date, retentionDays: number): Date {
    const retentionDate = new Date(createdDate)
    retentionDate.setDate(retentionDate.getDate() + retentionDays)
    return retentionDate
  }
}

// Global retention service instance
export const dataRetentionService = new DataRetentionService()
