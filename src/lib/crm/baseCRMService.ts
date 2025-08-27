/**
 * Base CRM Service Interface
 * Abstract base class for all CRM integrations
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMProvider,
  CRMConfiguration,
  CRMSyncRecord,
  CRMSyncBatch,
  CRMSyncMetrics,
  CRMDataQuality,
  CRMWebhookEvent,
  CRMWebhookSubscription
} from '@/types/crm'
import { logger } from '@/utils/logger'

export abstract class BaseCRMService {
  protected provider: CRMProvider
  protected isInitialized: boolean = false

  constructor(provider: CRMProvider) {
    this.provider = provider
  }

  // Abstract methods that must be implemented by each CRM service
  abstract initialize(): Promise<void>
  abstract authenticate(): Promise<boolean>
  abstract validateConnection(): Promise<boolean>
  abstract syncBusinessRecord(record: BusinessRecord): Promise<CRMSyncRecord>
  abstract syncBusinessRecords(records: BusinessRecord[]): Promise<CRMSyncBatch>
  abstract pullUpdates(since?: Date): Promise<BusinessRecord[]>
  abstract setupWebhooks(): Promise<CRMWebhookSubscription[]>
  abstract handleWebhookEvent(event: CRMWebhookEvent): Promise<void>

  // Common utility methods
  async isReady(): Promise<boolean> {
    return this.isInitialized && await this.validateConnection()
  }

  getProvider(): CRMProvider {
    return this.provider
  }

  getConfiguration(): CRMConfiguration {
    return this.provider.configuration
  }

  // Rate limiting helper
  protected async respectRateLimit(): Promise<void> {
    const rateLimits = this.provider.configuration.rateLimits
    const delay = Math.ceil(60000 / rateLimits.requestsPerMinute)
    
    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay))
    }
  }

  // Error handling helper
  protected handleError(operation: string, error: any): never {
    logger.error('CRMService', `${this.provider.name} ${operation} failed`, {
      providerId: this.provider.id,
      error: error.message,
      stack: error.stack
    })
    throw new Error(`CRM ${operation} failed: ${error.message}`)
  }

  // Data validation helper
  protected validateBusinessRecord(record: BusinessRecord): boolean {
    if (!record.id || !record.businessName || !record.websiteUrl) {
      return false
    }

    if (!record.email || record.email.length === 0) {
      return false
    }

    return true
  }

  // Field mapping helper
  protected mapBusinessRecordToTarget(record: BusinessRecord): Record<string, any> {
    const mappings = this.provider.configuration.fieldMappings
    const targetData: Record<string, any> = {}

    for (const mapping of mappings) {
      const sourceValue = this.getNestedValue(record, mapping.sourceField)
      if (sourceValue !== undefined) {
        targetData[mapping.targetField] = this.transformValue(
          sourceValue,
          mapping.transformation,
          mapping.dataType
        )
      }
    }

    return targetData
  }

  // Helper to get nested object values
  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj)
  }

  // Value transformation helper
  private transformValue(value: any, transformation?: string, dataType?: string): any {
    if (transformation) {
      switch (transformation) {
        case 'uppercase':
          return typeof value === 'string' ? value.toUpperCase() : value
        case 'lowercase':
          return typeof value === 'string' ? value.toLowerCase() : value
        case 'trim':
          return typeof value === 'string' ? value.trim() : value
        case 'phone_format':
          return this.formatPhoneNumber(value)
        case 'email_primary':
          return Array.isArray(value) ? value[0] : value
        default:
          return value
      }
    }

    // Type conversion
    if (dataType) {
      switch (dataType) {
        case 'string':
          return String(value)
        case 'number':
          return Number(value)
        case 'boolean':
          return Boolean(value)
        case 'date':
          return new Date(value)
        case 'array':
          return Array.isArray(value) ? value : [value]
        default:
          return value
      }
    }

    return value
  }

  // Phone number formatting helper
  private formatPhoneNumber(phone: string): string {
    if (!phone) return ''
    
    // Remove all non-digit characters
    const digits = phone.replace(/\D/g, '')
    
    // Format as (XXX) XXX-XXXX for US numbers
    if (digits.length === 10) {
      return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`
    }
    
    // Format as +X (XXX) XXX-XXXX for international numbers
    if (digits.length === 11 && digits.startsWith('1')) {
      return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`
    }
    
    return phone // Return original if can't format
  }

  // Deduplication helper
  protected async checkForDuplicates(record: BusinessRecord): Promise<string[]> {
    // This should be implemented by each CRM service based on their deduplication logic
    // Return array of existing record IDs that might be duplicates
    return []
  }

  // Data quality assessment
  protected assessDataQuality(record: BusinessRecord): CRMDataQuality {
    const issues: any[] = []
    const suggestions: any[] = []
    let qualityScore = 100

    // Check for missing required fields
    if (!record.businessName) {
      issues.push({
        field: 'businessName',
        issueType: 'missing',
        severity: 'critical',
        description: 'Business name is required'
      })
      qualityScore -= 20
    }

    if (!record.email || record.email.length === 0) {
      issues.push({
        field: 'email',
        issueType: 'missing',
        severity: 'high',
        description: 'Email address is required'
      })
      qualityScore -= 15
    }

    if (!record.phone) {
      issues.push({
        field: 'phone',
        issueType: 'missing',
        severity: 'medium',
        description: 'Phone number is recommended'
      })
      qualityScore -= 10
    }

    // Check for data format issues
    if (record.email && record.email.length > 0) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      const invalidEmails = record.email.filter(email => !emailRegex.test(email))
      
      if (invalidEmails.length > 0) {
        issues.push({
          field: 'email',
          issueType: 'invalid',
          severity: 'high',
          description: `Invalid email format: ${invalidEmails.join(', ')}`
        })
        qualityScore -= 10
      }
    }

    // Check for incomplete address
    if (!record.address.street || !record.address.city || !record.address.state) {
      issues.push({
        field: 'address',
        issueType: 'missing',
        severity: 'medium',
        description: 'Incomplete address information'
      })
      qualityScore -= 5
    }

    return {
      recordId: record.id,
      qualityScore: Math.max(0, qualityScore),
      issues,
      suggestions
    }
  }

  // Sync metrics calculation
  protected calculateSyncMetrics(
    syncRecords: CRMSyncRecord[],
    timeRange: { start: Date; end: Date }
  ): CRMSyncMetrics {
    const totalSyncs = syncRecords.length
    const successfulSyncs = syncRecords.filter(r => r.syncStatus === 'synced').length
    const failedSyncs = syncRecords.filter(r => r.syncStatus === 'failed').length
    
    const syncTimes = syncRecords
      .filter(r => r.lastSyncAt)
      .map(r => r.lastSyncAt!.getTime() - r.businessRecord.scrapedAt.getTime())
    
    const averageSyncTime = syncTimes.length > 0 
      ? syncTimes.reduce((a, b) => a + b, 0) / syncTimes.length 
      : 0

    const qualityScores = syncRecords.map(r => this.assessDataQuality(r.businessRecord).qualityScore)
    const dataQualityScore = qualityScores.length > 0
      ? qualityScores.reduce((a, b) => a + b, 0) / qualityScores.length
      : 0

    return {
      crmProviderId: this.provider.id,
      timeRange,
      totalSyncs,
      successfulSyncs,
      failedSyncs,
      averageSyncTime,
      dataQualityScore,
      deduplicationRate: 0, // To be calculated by specific implementations
      validationErrors: failedSyncs
    }
  }

  // Webhook signature validation
  protected validateWebhookSignature(payload: string, signature: string, secret: string): boolean {
    const crypto = require('crypto')
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex')
    
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    )
  }

  // Batch processing helper
  protected async processBatch<T, R>(
    items: T[],
    processor: (item: T) => Promise<R>,
    batchSize: number = 10
  ): Promise<R[]> {
    const results: R[] = []
    
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize)
      const batchResults = await Promise.allSettled(
        batch.map(item => processor(item))
      )
      
      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.push(result.value)
        } else {
          logger.error('CRMService', 'Batch processing error', {
            providerId: this.provider.id,
            error: result.reason
          })
        }
      }
      
      // Respect rate limits between batches
      if (i + batchSize < items.length) {
        await this.respectRateLimit()
      }
    }
    
    return results
  }
}
