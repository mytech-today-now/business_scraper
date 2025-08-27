/**
 * Salesforce CRM Service Implementation
 * Handles Salesforce integration with managed package support
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMSyncRecord,
  CRMSyncBatch,
  CRMWebhookEvent,
  CRMWebhookSubscription,
  SalesforceConfiguration,
} from '@/types/crm'
import { BaseCRMService } from './baseCRMService'
import { logger } from '@/utils/logger'

export class SalesforceService extends BaseCRMService {
  private accessToken?: string
  private instanceUrl?: string
  private apiVersion: string = 'v58.0'

  async initialize(): Promise<void> {
    try {
      logger.info('SalesforceService', 'Initializing Salesforce service', {
        providerId: this.provider.id,
      })

      const config = this.provider.configuration as SalesforceConfiguration
      this.instanceUrl = config.instanceUrl
      this.apiVersion = config.apiVersion || 'v58.0'

      await this.authenticate()
      this.isInitialized = true

      logger.info('SalesforceService', 'Salesforce service initialized successfully')
    } catch (error) {
      this.handleError('initialization', error)
    }
  }

  async authenticate(): Promise<boolean> {
    try {
      const auth = this.provider.configuration.authentication

      if (auth.type === 'oauth2') {
        return await this.authenticateOAuth2()
      } else {
        throw new Error(`Unsupported authentication type: ${auth.type}`)
      }
    } catch (error) {
      logger.error('SalesforceService', 'Authentication failed', error)
      return false
    }
  }

  private async authenticateOAuth2(): Promise<boolean> {
    try {
      const auth = this.provider.configuration.authentication
      const config = this.provider.configuration as SalesforceConfiguration

      const tokenUrl = `${config.instanceUrl}/services/oauth2/token`

      const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: auth.credentials.clientId,
          client_secret: auth.credentials.clientSecret,
        }),
      })

      if (!response.ok) {
        throw new Error(`Authentication failed: ${response.statusText}`)
      }

      const tokenData = await response.json()
      this.accessToken = tokenData.access_token
      this.instanceUrl = tokenData.instance_url || config.instanceUrl

      logger.info('SalesforceService', 'OAuth2 authentication successful')
      return true
    } catch (error) {
      logger.error('SalesforceService', 'OAuth2 authentication failed', error)
      return false
    }
  }

  async validateConnection(): Promise<boolean> {
    try {
      if (!this.accessToken || !this.instanceUrl) {
        return false
      }

      const response = await this.makeApiCall('GET', '/services/data')
      return response.ok
    } catch (error) {
      logger.error('SalesforceService', 'Connection validation failed', error)
      return false
    }
  }

  async syncBusinessRecord(record: BusinessRecord): Promise<CRMSyncRecord> {
    try {
      if (!this.validateBusinessRecord(record)) {
        throw new Error('Invalid business record')
      }

      await this.respectRateLimit()

      // Check for duplicates
      const duplicateIds = await this.checkForDuplicates(record)
      if (duplicateIds.length > 0) {
        return this.createSyncRecord(
          record,
          'conflict',
          undefined,
          `Duplicate records found: ${duplicateIds.join(', ')}`
        )
      }

      // Map business record to Salesforce format
      const salesforceData = this.mapToSalesforceFormat(record)

      // Create Lead or Contact based on configuration
      const objectType = this.getTargetObjectType(record)
      const response = await this.createSalesforceRecord(objectType, salesforceData)

      if (response.success) {
        return this.createSyncRecord(record, 'synced', response.id)
      } else {
        return this.createSyncRecord(record, 'failed', undefined, response.errors?.join(', '))
      }
    } catch (error) {
      logger.error('SalesforceService', 'Failed to sync business record', error)
      return this.createSyncRecord(record, 'failed', undefined, error.message)
    }
  }

  async syncBusinessRecords(records: BusinessRecord[]): Promise<CRMSyncBatch> {
    const batchId = crypto.randomUUID()
    const syncRecords: CRMSyncRecord[] = []

    try {
      logger.info('SalesforceService', `Starting batch sync of ${records.length} records`)

      // Process records in batches to respect API limits
      const batchSize = this.provider.configuration.syncSettings.batchSize || 10

      for (let i = 0; i < records.length; i += batchSize) {
        const batch = records.slice(i, i + batchSize)
        const batchResults = await this.processBatch(
          batch,
          record => this.syncBusinessRecord(record),
          batchSize
        )
        syncRecords.push(...batchResults)
      }

      const successfulRecords = syncRecords.filter(r => r.syncStatus === 'synced').length
      const failedRecords = syncRecords.filter(r => r.syncStatus === 'failed').length

      return {
        id: batchId,
        crmProviderId: this.provider.id,
        records: syncRecords,
        status: failedRecords === 0 ? 'completed' : 'partial',
        startedAt: new Date(),
        completedAt: new Date(),
        totalRecords: records.length,
        successfulRecords,
        failedRecords,
        errors: [],
      }
    } catch (error) {
      logger.error('SalesforceService', 'Batch sync failed', error)
      throw error
    }
  }

  async pullUpdates(since?: Date): Promise<BusinessRecord[]> {
    try {
      const sinceDate = since || new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
      const soqlQuery = this.buildUpdateQuery(sinceDate)

      const response = await this.makeApiCall('GET', `/services/data/v${this.apiVersion}/query`, {
        q: soqlQuery,
      })

      if (response.ok) {
        const data = await response.json()
        return this.mapSalesforceRecordsToBusinessRecords(data.records)
      } else {
        throw new Error(`Failed to pull updates: ${response.statusText}`)
      }
    } catch (error) {
      logger.error('SalesforceService', 'Failed to pull updates', error)
      return []
    }
  }

  async setupWebhooks(): Promise<CRMWebhookSubscription[]> {
    try {
      // Salesforce uses Platform Events or Streaming API for real-time updates
      // This would typically involve setting up PushTopic or Platform Event subscriptions
      logger.info('SalesforceService', 'Setting up Salesforce webhooks/streaming')

      // Implementation would depend on specific Salesforce streaming requirements
      return []
    } catch (error) {
      logger.error('SalesforceService', 'Failed to setup webhooks', error)
      return []
    }
  }

  async handleWebhookEvent(event: CRMWebhookEvent): Promise<void> {
    try {
      logger.info('SalesforceService', 'Handling Salesforce webhook event', {
        eventType: event.eventType,
        objectType: event.objectType,
        objectId: event.objectId,
      })

      // Process the webhook event based on type
      switch (event.eventType) {
        case 'created':
        case 'updated':
          await this.handleRecordUpdate(event)
          break
        case 'deleted':
          await this.handleRecordDeletion(event)
          break
        default:
          logger.warn('SalesforceService', `Unhandled event type: ${event.eventType}`)
      }
    } catch (error) {
      logger.error('SalesforceService', 'Failed to handle webhook event', error)
    }
  }

  private async makeApiCall(
    method: string,
    endpoint: string,
    params?: Record<string, any>
  ): Promise<Response> {
    if (!this.accessToken || !this.instanceUrl) {
      throw new Error('Not authenticated')
    }

    const url = new URL(endpoint, this.instanceUrl)
    if (params && method === 'GET') {
      Object.entries(params).forEach(([key, value]) => {
        url.searchParams.append(key, String(value))
      })
    }

    const options: RequestInit = {
      method,
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
      },
    }

    if (params && method !== 'GET') {
      options.body = JSON.stringify(params)
    }

    return fetch(url.toString(), options)
  }

  private mapToSalesforceFormat(record: BusinessRecord): Record<string, any> {
    const mapped = this.mapBusinessRecordToTarget(record)

    // Add Salesforce-specific mappings
    return {
      Name: record.businessName,
      Email: record.email[0], // Primary email
      Phone: record.phone,
      Website: record.websiteUrl,
      Street: record.address.street,
      City: record.address.city,
      State: record.address.state,
      PostalCode: record.address.zipCode,
      Industry: record.industry,
      ...mapped,
    }
  }

  private getTargetObjectType(record: BusinessRecord): string {
    // Determine whether to create a Lead or Contact based on business logic
    // This could be configurable in the provider settings
    return 'Lead' // Default to Lead for new business records
  }

  private async createSalesforceRecord(
    objectType: string,
    data: Record<string, any>
  ): Promise<any> {
    const response = await this.makeApiCall(
      'POST',
      `/services/data/v${this.apiVersion}/sobjects/${objectType}`,
      data
    )

    return response.json()
  }

  private createSyncRecord(
    record: BusinessRecord,
    status: 'pending' | 'syncing' | 'synced' | 'failed' | 'conflict',
    targetRecordId?: string,
    errorMessage?: string
  ): CRMSyncRecord {
    return {
      id: crypto.randomUUID(),
      crmProviderId: this.provider.id,
      sourceRecordId: record.id,
      targetRecordId,
      businessRecord: record,
      syncStatus: status,
      syncDirection: 'push',
      lastSyncAt: new Date(),
      syncAttempts: 1,
      errors: errorMessage
        ? [
            {
              timestamp: new Date(),
              errorCode: 'SYNC_ERROR',
              errorMessage,
              isRetryable: status !== 'conflict',
            },
          ]
        : [],
      metadata: {},
    }
  }

  private buildUpdateQuery(since: Date): string {
    const sinceIso = since.toISOString()
    return `SELECT Id, Name, Email, Phone, Website, LastModifiedDate FROM Lead WHERE LastModifiedDate > ${sinceIso} ORDER BY LastModifiedDate DESC LIMIT 1000`
  }

  private mapSalesforceRecordsToBusinessRecords(salesforceRecords: any[]): BusinessRecord[] {
    return salesforceRecords.map(record => ({
      id: record.Id,
      businessName: record.Name,
      email: record.Email ? [record.Email] : [],
      phone: record.Phone,
      websiteUrl: record.Website || '',
      address: {
        street: record.Street || '',
        city: record.City || '',
        state: record.State || '',
        zipCode: record.PostalCode || '',
      },
      industry: record.Industry || '',
      scrapedAt: new Date(record.LastModifiedDate),
    }))
  }

  private async handleRecordUpdate(event: CRMWebhookEvent): Promise<void> {
    // Handle record creation or update from Salesforce
    logger.info('SalesforceService', 'Processing record update', {
      objectId: event.objectId,
      objectType: event.objectType,
    })
  }

  private async handleRecordDeletion(event: CRMWebhookEvent): Promise<void> {
    // Handle record deletion from Salesforce
    logger.info('SalesforceService', 'Processing record deletion', {
      objectId: event.objectId,
      objectType: event.objectType,
    })
  }
}
