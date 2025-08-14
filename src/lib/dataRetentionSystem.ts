/**
 * Data Retention and Cleanup System
 * Automated system for managing data lifecycle and cleanup policies
 */

import { logger } from '@/utils/logger'
import { database } from '@/lib/postgresql-database'

export interface RetentionPolicy {
  name: string
  description: string
  enabled: boolean
  rules: RetentionRule[]
  schedule: RetentionSchedule
}

export interface RetentionRule {
  type: 'age' | 'count' | 'size' | 'condition'
  field?: string
  operator?: 'gt' | 'lt' | 'eq' | 'gte' | 'lte'
  value: any
  action: 'delete' | 'archive' | 'anonymize' | 'compress'
}

export interface RetentionSchedule {
  frequency: 'daily' | 'weekly' | 'monthly'
  time: string // HH:MM format
  timezone: string
}

export interface CleanupResult {
  policy: string
  recordsProcessed: number
  recordsDeleted: number
  recordsArchived: number
  recordsAnonymized: number
  recordsCompressed: number
  bytesFreed: number
  duration: number
  errors: string[]
}

export interface DataUsageStats {
  totalRecords: number
  totalSize: number
  oldestRecord: Date
  newestRecord: Date
  recordsByAge: Record<string, number>
  recordsByIndustry: Record<string, number>
  recordsByConfidence: Record<string, number>
}

/**
 * Data Retention and Cleanup System
 */
export class DataRetentionSystem {
  private policies: Map<string, RetentionPolicy> = new Map()

  private scheduledJobs: Map<string, NodeJS.Timeout> = new Map()

  constructor() {
    this.initializeDefaultPolicies()
  }

  /**
   * Initialize default retention policies
   */
  private initializeDefaultPolicies(): void {
    // Policy 1: Delete old low-confidence records
    this.addPolicy({
      name: 'cleanup_low_confidence',
      description: 'Delete records older than 90 days with confidence < 0.3',
      enabled: true,
      rules: [
        {
          type: 'age',
          field: 'scrapedAt',
          operator: 'lt',
          value: 90, // days
          action: 'delete',
        },
        {
          type: 'condition',
          field: 'confidence',
          operator: 'lt',
          value: 0.3,
          action: 'delete',
        },
      ],
      schedule: {
        frequency: 'weekly',
        time: '02:00',
        timezone: 'UTC',
      },
    })

    // Policy 2: Archive old records
    this.addPolicy({
      name: 'archive_old_records',
      description: 'Archive records older than 1 year',
      enabled: true,
      rules: [
        {
          type: 'age',
          field: 'scrapedAt',
          operator: 'lt',
          value: 365, // days
          action: 'archive',
        },
      ],
      schedule: {
        frequency: 'monthly',
        time: '01:00',
        timezone: 'UTC',
      },
    })

    // Policy 3: Anonymize old personal data
    this.addPolicy({
      name: 'anonymize_personal_data',
      description: 'Anonymize personal contact info in records older than 2 years',
      enabled: false, // Disabled by default
      rules: [
        {
          type: 'age',
          field: 'scrapedAt',
          operator: 'lt',
          value: 730, // days
          action: 'anonymize',
        },
      ],
      schedule: {
        frequency: 'monthly',
        time: '03:00',
        timezone: 'UTC',
      },
    })

    // Policy 4: Limit total record count
    this.addPolicy({
      name: 'limit_total_records',
      description: 'Keep only the most recent 100,000 records',
      enabled: true,
      rules: [
        {
          type: 'count',
          value: 100000,
          action: 'delete',
        },
      ],
      schedule: {
        frequency: 'daily',
        time: '04:00',
        timezone: 'UTC',
      },
    })
  }

  /**
   * Add a retention policy
   */
  addPolicy(policy: RetentionPolicy): void {
    this.policies.set(policy.name, policy)
    
    if (policy.enabled) {
      this.schedulePolicy(policy)
    }
    
    logger.info('DataRetention', `Added policy: ${policy.name}`)
  }

  /**
   * Remove a retention policy
   */
  removePolicy(policyName: string): boolean {
    const policy = this.policies.get(policyName)
    if (!policy) return false

    this.unschedulePolicy(policyName)
    this.policies.delete(policyName)
    
    logger.info('DataRetention', `Removed policy: ${policyName}`)
    return true
  }

  /**
   * Enable or disable a policy
   */
  togglePolicy(policyName: string, enabled: boolean): boolean {
    const policy = this.policies.get(policyName)
    if (!policy) return false

    policy.enabled = enabled
    
    if (enabled) {
      this.schedulePolicy(policy)
    } else {
      this.unschedulePolicy(policyName)
    }
    
    logger.info('DataRetention', `${enabled ? 'Enabled' : 'Disabled'} policy: ${policyName}`)
    return true
  }

  /**
   * Execute a specific policy manually
   */
  async executePolicy(policyName: string): Promise<CleanupResult> {
    const policy = this.policies.get(policyName)
    if (!policy) {
      throw new Error(`Policy not found: ${policyName}`)
    }

    logger.info('DataRetention', `Executing policy: ${policyName}`)
    const startTime = Date.now()

    const result: CleanupResult = {
      policy: policyName,
      recordsProcessed: 0,
      recordsDeleted: 0,
      recordsArchived: 0,
      recordsAnonymized: 0,
      recordsCompressed: 0,
      bytesFreed: 0,
      duration: 0,
      errors: [],
    }

    try {
      for (const rule of policy.rules) {
        await this.executeRule(rule, result)
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      result.errors.push(errorMessage)
      logger.error('DataRetention', `Policy execution failed: ${policyName}`, error)
    }

    result.duration = Date.now() - startTime
    logger.info('DataRetention', `Policy execution completed: ${policyName}`, result)
    
    return result
  }

  /**
   * Execute all enabled policies
   */
  async executeAllPolicies(): Promise<CleanupResult[]> {
    const results: CleanupResult[] = []
    
    for (const [name, policy] of Array.from(this.policies.entries())) {
      if (policy.enabled) {
        try {
          const result = await this.executePolicy(name)
          results.push(result)
        } catch (error) {
          logger.error('DataRetention', `Failed to execute policy ${name}`, error)
        }
      }
    }
    
    return results
  }

  /**
   * Get data usage statistics
   */
  async getDataUsageStats(): Promise<DataUsageStats> {
    try {
      const query = `
        SELECT 
          COUNT(*) as total_records,
          MIN(scraped_at) as oldest_record,
          MAX(scraped_at) as newest_record,
          SUM(LENGTH(business_name) + LENGTH(COALESCE(email, '')) + LENGTH(COALESCE(phone, ''))) as estimated_size
        FROM businesses
      `
      
      const result = await database.executeQuery(query)
      const row = result.rows[0]

      // Get records by age
      const ageQuery = `
        SELECT
          CASE
            WHEN scraped_at > NOW() - INTERVAL '30 days' THEN 'last_30_days'
            WHEN scraped_at > NOW() - INTERVAL '90 days' THEN 'last_90_days'
            WHEN scraped_at > NOW() - INTERVAL '365 days' THEN 'last_year'
            ELSE 'older_than_year'
          END as age_group,
          COUNT(*) as count
        FROM businesses
        GROUP BY age_group
      `

      const ageResult = await database.executeQuery(ageQuery)
      const recordsByAge: Record<string, number> = {}
      ageResult.rows.forEach((row: any) => {
        recordsByAge[row.age_group] = parseInt(row.count)
      })

      // Get records by industry
      const industryQuery = `
        SELECT industry, COUNT(*) as count
        FROM businesses
        GROUP BY industry
        ORDER BY count DESC
        LIMIT 10
      `
      
      const industryResult = await database.executeQuery(industryQuery)
      const recordsByIndustry: Record<string, number> = {}
      industryResult.rows.forEach((row: any) => {
        recordsByIndustry[row.industry] = parseInt(row.count)
      })

      // Get records by confidence
      const confidenceQuery = `
        SELECT 
          CASE 
            WHEN confidence >= 0.8 THEN 'high'
            WHEN confidence >= 0.5 THEN 'medium'
            WHEN confidence >= 0.3 THEN 'low'
            ELSE 'very_low'
          END as confidence_group,
          COUNT(*) as count
        FROM businesses
        WHERE confidence IS NOT NULL
        GROUP BY confidence_group
      `
      
      const confidenceResult = await database.executeQuery(confidenceQuery)
      const recordsByConfidence: Record<string, number> = {}
      confidenceResult.rows.forEach((row: any) => {
        recordsByConfidence[row.confidence_group] = parseInt(row.count)
      })

      return {
        totalRecords: parseInt(row.total_records),
        totalSize: parseInt(row.estimated_size) || 0,
        oldestRecord: new Date(row.oldest_record),
        newestRecord: new Date(row.newest_record),
        recordsByAge,
        recordsByIndustry,
        recordsByConfidence,
      }
    } catch (error) {
      logger.error('DataRetention', 'Failed to get data usage stats', error)
      throw error
    }
  }

  /**
   * Get all policies
   */
  getPolicies(): RetentionPolicy[] {
    return Array.from(this.policies.values())
  }

  /**
   * Schedule a policy for automatic execution
   */
  private schedulePolicy(policy: RetentionPolicy): void {
    this.unschedulePolicy(policy.name) // Clear existing schedule
    
    const intervalMs = this.getScheduleInterval(policy.schedule.frequency)
    
    const job = setInterval(async () => {
      try {
        await this.executePolicy(policy.name)
      } catch (error) {
        logger.error('DataRetention', `Scheduled execution failed for policy ${policy.name}`, error)
      }
    }, intervalMs)
    
    this.scheduledJobs.set(policy.name, job)
    logger.debug('DataRetention', `Scheduled policy: ${policy.name}`)
  }

  /**
   * Unschedule a policy
   */
  private unschedulePolicy(policyName: string): void {
    const job = this.scheduledJobs.get(policyName)
    if (job) {
      clearInterval(job)
      this.scheduledJobs.delete(policyName)
      logger.debug('DataRetention', `Unscheduled policy: ${policyName}`)
    }
  }

  /**
   * Get schedule interval in milliseconds
   */
  private getScheduleInterval(frequency: RetentionSchedule['frequency']): number {
    switch (frequency) {
      case 'daily':
        return 24 * 60 * 60 * 1000 // 24 hours
      case 'weekly':
        return 7 * 24 * 60 * 60 * 1000 // 7 days
      case 'monthly':
        return 30 * 24 * 60 * 60 * 1000 // 30 days
      default:
        return 24 * 60 * 60 * 1000 // Default to daily
    }
  }

  /**
   * Execute a single retention rule
   */
  private async executeRule(rule: RetentionRule, result: CleanupResult): Promise<void> {
    switch (rule.type) {
      case 'age':
        await this.executeAgeRule(rule, result)
        break
      case 'count':
        await this.executeCountRule(rule, result)
        break
      case 'condition':
        await this.executeConditionRule(rule, result)
        break
      default:
        logger.warn('DataRetention', `Unknown rule type: ${rule.type}`)
    }
  }

  /**
   * Execute age-based retention rule
   */
  private async executeAgeRule(rule: RetentionRule, result: CleanupResult): Promise<void> {
    const daysAgo = rule.value
    const cutoffDate = new Date()
    cutoffDate.setDate(cutoffDate.getDate() - daysAgo)

    const query = `
      SELECT id FROM businesses 
      WHERE ${rule.field} < $1
    `
    
    const records = await database.executeQuery(query, [cutoffDate])
    result.recordsProcessed += records.rows.length

    if (records.rows.length > 0) {
      await this.executeAction(rule.action, records.rows.map((r: any) => r.id), result)
    }
  }

  /**
   * Execute count-based retention rule
   */
  private async executeCountRule(rule: RetentionRule, result: CleanupResult): Promise<void> {
    const maxRecords = rule.value
    
    const countQuery = 'SELECT COUNT(*) as total FROM businesses'
    const countResult = await database.executeQuery(countQuery)
    const totalRecords = parseInt(countResult.rows[0].total)

    if (totalRecords > maxRecords) {
      const excessRecords = totalRecords - maxRecords
      
      const query = `
        SELECT id FROM businesses 
        ORDER BY scraped_at ASC 
        LIMIT $1
      `
      
      const records = await database.executeQuery(query, [excessRecords])
      result.recordsProcessed += records.rows.length

      if (records.rows.length > 0) {
        await this.executeAction(rule.action, records.rows.map((r: any) => r.id), result)
      }
    }
  }

  /**
   * Execute condition-based retention rule
   */
  private async executeConditionRule(rule: RetentionRule, result: CleanupResult): Promise<void> {
    if (!rule.operator) {
      logger.warn('DataRetentionSystem', 'Condition rule missing operator, skipping', { rule })
      return
    }

    const query = `
      SELECT id FROM businesses
      WHERE ${rule.field} ${this.getOperatorSql(rule.operator)} $1
    `

    const records = await database.executeQuery(query, [rule.value])
    result.recordsProcessed += records.rows.length

    if (records.rows.length > 0) {
      await this.executeAction(rule.action, records.rows.map((r: any) => r.id), result)
    }
  }

  /**
   * Execute retention action on records
   */
  private async executeAction(action: string, recordIds: string[], result: CleanupResult): Promise<void> {
    switch (action) {
      case 'delete':
        await this.deleteRecords(recordIds)
        result.recordsDeleted += recordIds.length
        break
      case 'archive':
        await this.archiveRecords(recordIds)
        result.recordsArchived += recordIds.length
        break
      case 'anonymize':
        await this.anonymizeRecords(recordIds)
        result.recordsAnonymized += recordIds.length
        break
      default:
        logger.warn('DataRetention', `Unknown action: ${action}`)
    }
  }

  /**
   * Delete records from database
   */
  private async deleteRecords(recordIds: string[]): Promise<void> {
    const query = 'DELETE FROM businesses WHERE id = ANY($1)'
    await database.executeQuery(query, [recordIds])
    logger.info('DataRetention', `Deleted ${recordIds.length} records`)
  }

  /**
   * Archive records (move to archive table)
   */
  private async archiveRecords(recordIds: string[]): Promise<void> {
    // Create archive table if it doesn't exist
    await database.executeQuery(`
      CREATE TABLE IF NOT EXISTS businesses_archive (
        LIKE businesses INCLUDING ALL
      )
    `)

    // Move records to archive
    await database.executeQuery(`
      INSERT INTO businesses_archive
      SELECT * FROM businesses WHERE id = ANY($1)
    `, [recordIds])

    // Delete from main table
    await this.deleteRecords(recordIds)
    logger.info('DataRetention', `Archived ${recordIds.length} records`)
  }

  /**
   * Anonymize records (remove personal data)
   */
  private async anonymizeRecords(recordIds: string[]): Promise<void> {
    const query = `
      UPDATE businesses 
      SET 
        email = '{}',
        phone = NULL,
        contact_person = NULL
      WHERE id = ANY($1)
    `
    await database.executeQuery(query, [recordIds])
    logger.info('DataRetention', `Anonymized ${recordIds.length} records`)
  }

  /**
   * Convert operator to SQL
   */
  private getOperatorSql(operator: string): string {
    switch (operator) {
      case 'gt': return '>'
      case 'lt': return '<'
      case 'eq': return '='
      case 'gte': return '>='
      case 'lte': return '<='
      default: return '='
    }
  }

  /**
   * Shutdown the retention system
   */
  shutdown(): void {
    for (const [name, job] of Array.from(this.scheduledJobs.entries())) {
      clearInterval(job)
      logger.debug('DataRetention', `Stopped scheduled job: ${name}`)
    }
    this.scheduledJobs.clear()
    logger.info('DataRetention', 'Data retention system shutdown')
  }
}

/**
 * Default data retention system instance
 */
export const dataRetentionSystem = new DataRetentionSystem()
