/**
 * Custom CRM Service Implementation
 * Handles custom CRM integrations with REST/GraphQL endpoints
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMSyncRecord,
  CRMSyncBatch,
  CRMWebhookEvent,
  CRMWebhookSubscription,
  CustomCRMAdapter,
  CRMEndpoint,
  ResponseMapping,
} from '@/types/crm'
import { BaseCRMService } from './baseCRMService'
import { logger } from '@/utils/logger'

export class CustomCRMService extends BaseCRMService {
  private adapter?: CustomCRMAdapter
  private authToken?: string

  async initialize(): Promise<void> {
    try {
      logger.info('CustomCRMService', 'Initializing Custom CRM service', {
        providerId: this.provider.id,
      })

      // Load custom adapter configuration
      this.adapter = this.provider.configuration as any as CustomCRMAdapter

      if (!this.adapter) {
        throw new Error('Custom CRM adapter configuration not found')
      }

      await this.authenticate()
      this.isInitialized = true

      logger.info('CustomCRMService', 'Custom CRM service initialized successfully')
    } catch (error) {
      this.handleError('initialization', error)
    }
  }

  async authenticate(): Promise<boolean> {
    try {
      if (!this.adapter) {
        throw new Error('Adapter not initialized')
      }

      const auth = this.adapter.authentication

      switch (auth.type) {
        case 'oauth2':
          return await this.authenticateOAuth2()
        case 'api_key':
          return await this.authenticateApiKey()
        case 'basic':
          return await this.authenticateBasic()
        case 'custom':
          return await this.authenticateCustom()
        default:
          throw new Error(`Unsupported authentication type: ${auth.type}`)
      }
    } catch (error) {
      logger.error('CustomCRMService', 'Authentication failed', error)
      return false
    }
  }

  private async authenticateOAuth2(): Promise<boolean> {
    try {
      const auth = this.adapter!.authentication
      const tokenEndpoint = this.findEndpoint('token') || this.findEndpoint('auth')

      if (!tokenEndpoint) {
        throw new Error('Token endpoint not found in adapter configuration')
      }

      const response = await this.makeCustomApiCall(tokenEndpoint, {
        grant_type: 'client_credentials',
        client_id: auth.credentials.clientId,
        client_secret: auth.credentials.clientSecret,
      })

      if (response.ok) {
        const tokenData = await response.json()
        this.authToken = tokenData.access_token || tokenData.token
        logger.info('CustomCRMService', 'OAuth2 authentication successful')
        return true
      } else {
        throw new Error(`Authentication failed: ${response.statusText}`)
      }
    } catch (error) {
      logger.error('CustomCRMService', 'OAuth2 authentication failed', error)
      return false
    }
  }

  private async authenticateApiKey(): Promise<boolean> {
    try {
      const auth = this.adapter!.authentication
      this.authToken = auth.credentials.apiKey

      // Test the API key with a validation endpoint
      const isValid = await this.validateConnection()
      if (isValid) {
        logger.info('CustomCRMService', 'API key authentication successful')
        return true
      } else {
        throw new Error('Invalid API key')
      }
    } catch (error) {
      logger.error('CustomCRMService', 'API key authentication failed', error)
      return false
    }
  }

  private async authenticateBasic(): Promise<boolean> {
    try {
      const auth = this.adapter!.authentication
      const credentials = Buffer.from(
        `${auth.credentials.username}:${auth.credentials.password}`
      ).toString('base64')
      this.authToken = `Basic ${credentials}`

      const isValid = await this.validateConnection()
      if (isValid) {
        logger.info('CustomCRMService', 'Basic authentication successful')
        return true
      } else {
        throw new Error('Invalid credentials')
      }
    } catch (error) {
      logger.error('CustomCRMService', 'Basic authentication failed', error)
      return false
    }
  }

  private async authenticateCustom(): Promise<boolean> {
    try {
      // Custom authentication logic would be implemented based on specific requirements
      logger.info('CustomCRMService', 'Custom authentication not implemented')
      return false
    } catch (error) {
      logger.error('CustomCRMService', 'Custom authentication failed', error)
      return false
    }
  }

  async validateConnection(): Promise<boolean> {
    try {
      if (!this.authToken || !this.adapter) {
        return false
      }

      const testEndpoint =
        this.findEndpoint('test') || this.findEndpoint('validate') || this.findEndpoint('me')

      if (!testEndpoint) {
        // If no test endpoint, assume connection is valid if we have a token
        return !!this.authToken
      }

      const response = await this.makeCustomApiCall(testEndpoint)
      return response.ok
    } catch (error) {
      logger.error('CustomCRMService', 'Connection validation failed', error)
      return false
    }
  }

  async syncBusinessRecord(record: BusinessRecord): Promise<CRMSyncRecord> {
    try {
      if (!this.validateBusinessRecord(record)) {
        throw new Error('Invalid business record')
      }

      if (!this.adapter) {
        throw new Error('Adapter not initialized')
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

      // Map business record to target format
      const targetData = this.mapBusinessRecordToCustomFormat(record)

      // Find create endpoint
      const createEndpoint = this.findEndpoint('create') || this.findEndpoint('post')

      if (!createEndpoint) {
        throw new Error('Create endpoint not found in adapter configuration')
      }

      const response = await this.makeCustomApiCall(createEndpoint, targetData)

      if (response.ok) {
        const responseData = await response.json()
        const targetRecordId = this.extractRecordId(responseData, createEndpoint.responseMapping)

        return this.createSyncRecord(record, 'synced', targetRecordId)
      } else {
        const errorText = await response.text()
        return this.createSyncRecord(record, 'failed', undefined, errorText)
      }
    } catch (error) {
      logger.error('CustomCRMService', 'Failed to sync business record', error)
      return this.createSyncRecord(record, 'failed', undefined, error.message)
    }
  }

  async syncBusinessRecords(records: BusinessRecord[]): Promise<CRMSyncBatch> {
    const batchId = `custom-batch-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    const syncRecords: CRMSyncRecord[] = []

    try {
      logger.info('CustomCRMService', `Starting batch sync of ${records.length} records`)

      // Check if adapter supports batch operations
      const batchEndpoint = this.findEndpoint('batch') || this.findEndpoint('bulk')

      if (batchEndpoint) {
        // Use batch endpoint
        const batchResults = await this.processBatchSync(records, batchEndpoint)
        syncRecords.push(...batchResults)
      } else {
        // Process individually
        const batchSize = this.provider.configuration.syncSettings.batchSize || 5

        for (let i = 0; i < records.length; i += batchSize) {
          const batch = records.slice(i, i + batchSize)
          const batchResults = await this.processBatch(
            batch,
            record => this.syncBusinessRecord(record),
            batchSize
          )
          syncRecords.push(...batchResults)
        }
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
      logger.error('CustomCRMService', 'Batch sync failed', error)
      throw error
    }
  }

  async pullUpdates(since?: Date): Promise<BusinessRecord[]> {
    try {
      if (!this.adapter) {
        throw new Error('Adapter not initialized')
      }

      const listEndpoint = this.findEndpoint('list') || this.findEndpoint('get')

      if (!listEndpoint) {
        throw new Error('List endpoint not found in adapter configuration')
      }

      const params: Record<string, any> = {}

      if (since) {
        // Add since parameter based on endpoint configuration
        params.since = since.toISOString()
        params.updated_after = since.toISOString()
        params.modified_since = since.getTime()
      }

      const response = await this.makeCustomApiCall(listEndpoint, params)

      if (response.ok) {
        const data = await response.json()
        return this.mapCustomRecordsToBusinessRecords(data, listEndpoint.responseMapping)
      } else {
        throw new Error(`Failed to pull updates: ${response.statusText}`)
      }
    } catch (error) {
      logger.error('CustomCRMService', 'Failed to pull updates', error)
      return []
    }
  }

  async setupWebhooks(): Promise<CRMWebhookSubscription[]> {
    try {
      logger.info('CustomCRMService', 'Setting up Custom CRM webhooks')

      const webhookUrl = this.provider.configuration.webhookUrl
      if (!webhookUrl) {
        throw new Error('Webhook URL not configured')
      }

      const webhookEndpoint = this.findEndpoint('webhook') || this.findEndpoint('subscribe')

      if (!webhookEndpoint) {
        logger.warn('CustomCRMService', 'Webhook endpoint not found in adapter configuration')
        return []
      }

      const subscriptions: CRMWebhookSubscription[] = []

      // Create webhook subscription
      const webhookData = {
        url: webhookUrl,
        events: ['create', 'update', 'delete'],
        active: true,
      }

      const response = await this.makeCustomApiCall(webhookEndpoint, webhookData)

      if (response.ok) {
        const data = await response.json()
        const subscriptionId = this.extractRecordId(data, webhookEndpoint.responseMapping)

        subscriptions.push({
          id: subscriptionId || `custom-webhook-${Date.now()}`,
          crmProviderId: this.provider.id,
          eventTypes: ['create', 'update', 'delete'],
          callbackUrl: webhookUrl,
          isActive: true,
          secret: this.adapter?.authentication.credentials.webhookSecret || '',
          createdAt: new Date(),
          lastTriggeredAt: undefined,
        })
      }

      return subscriptions
    } catch (error) {
      logger.error('CustomCRMService', 'Failed to setup webhooks', error)
      return []
    }
  }

  async handleWebhookEvent(event: CRMWebhookEvent): Promise<void> {
    try {
      logger.info('CustomCRMService', 'Handling Custom CRM webhook event', {
        eventType: event.eventType,
        objectType: event.objectType,
        objectId: event.objectId,
      })

      // Validate webhook signature if configured
      const webhookSecret = this.adapter?.authentication.credentials.webhookSecret
      if (webhookSecret && event.signature) {
        const isValid = this.validateWebhookSignature(
          JSON.stringify(event.data),
          event.signature,
          webhookSecret
        )

        if (!isValid) {
          throw new Error('Invalid webhook signature')
        }
      }

      // Process the webhook event based on type
      switch (event.eventType) {
        case 'create':
        case 'update':
          await this.handleRecordUpdate(event)
          break
        case 'delete':
          await this.handleRecordDeletion(event)
          break
        default:
          logger.warn('CustomCRMService', `Unhandled event type: ${event.eventType}`)
      }
    } catch (error) {
      logger.error('CustomCRMService', 'Failed to handle webhook event', error)
    }
  }

  private findEndpoint(name: string): CRMEndpoint | undefined {
    return this.adapter?.endpoints.find(endpoint =>
      endpoint.name.toLowerCase().includes(name.toLowerCase())
    )
  }

  private async makeCustomApiCall(
    endpoint: CRMEndpoint,
    data?: Record<string, any>
  ): Promise<Response> {
    if (!this.authToken) {
      throw new Error('Not authenticated')
    }

    const url = new URL(endpoint.url)
    const headers = { ...endpoint.headers }

    // Add authentication header
    const auth = this.adapter!.authentication
    if (auth.type === 'oauth2') {
      headers['Authorization'] = `Bearer ${this.authToken}`
    } else if (auth.type === 'api_key') {
      headers['Authorization'] = `ApiKey ${this.authToken}`
    } else if (auth.type === 'basic') {
      headers['Authorization'] = this.authToken
    }

    // Add query parameters for GET requests
    if (endpoint.method === 'GET' && data) {
      Object.entries(data).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value))
        }
      })
    }

    // Add configured query parameters
    if (endpoint.queryParams) {
      Object.entries(endpoint.queryParams).forEach(([key, value]) => {
        url.searchParams.append(key, value)
      })
    }

    const options: RequestInit = {
      method: endpoint.method,
      headers,
    }

    // Add body for non-GET requests
    if (endpoint.method !== 'GET' && data) {
      if (endpoint.bodyTemplate) {
        // Use template if provided
        options.body = this.processTemplate(endpoint.bodyTemplate, data)
      } else {
        options.body = JSON.stringify(data)
      }
    }

    return fetch(url.toString(), options)
  }

  private mapBusinessRecordToCustomFormat(record: BusinessRecord): Record<string, any> {
    if (!this.adapter) {
      return {}
    }

    const mapped: Record<string, any> = {}

    for (const mapping of this.adapter.dataMapping.businessToTarget) {
      const sourceValue = this.getNestedValue(record, mapping.sourceField)
      if (sourceValue !== undefined) {
        mapped[mapping.targetField] = this.transformValue(
          sourceValue,
          mapping.transformation,
          mapping.dataType
        )
      }
    }

    return mapped
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj)
  }

  private transformValue(value: any, transformation?: string, dataType?: string): any {
    // Apply transformations defined in the adapter
    if (transformation) {
      const transform = this.adapter?.dataMapping.transformations.find(
        t => t.name === transformation
      )
      if (transform) {
        // Execute transformation logic
        // This would be implemented based on the transformation type
        return value
      }
    }

    // Apply data type conversion
    if (dataType) {
      switch (dataType) {
        case 'string':
          return String(value)
        case 'number':
          return Number(value)
        case 'boolean':
          return Boolean(value)
        case 'date':
          return new Date(value).toISOString()
        case 'array':
          return Array.isArray(value) ? value : [value]
        default:
          return value
      }
    }

    return value
  }

  private extractRecordId(responseData: any, responseMapping: ResponseMapping): string | undefined {
    const idPath = responseMapping.fields.find(f => f.targetField === 'id')?.sourceField || 'id'
    return this.getNestedValue(responseData, idPath)
  }

  private mapCustomRecordsToBusinessRecords(
    data: any,
    responseMapping: ResponseMapping
  ): BusinessRecord[] {
    const records = this.getNestedValue(data, responseMapping.dataPath) || []

    return records.map((record: any) => ({
      id:
        this.getNestedValue(record, 'id') ||
        `custom-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      businessName:
        this.getNestedValue(record, 'name') || this.getNestedValue(record, 'company') || '',
      email: this.getNestedValue(record, 'email') ? [this.getNestedValue(record, 'email')] : [],
      phone: this.getNestedValue(record, 'phone'),
      websiteUrl: this.getNestedValue(record, 'website') || '',
      address: {
        street: this.getNestedValue(record, 'address.street') || '',
        city: this.getNestedValue(record, 'address.city') || '',
        state: this.getNestedValue(record, 'address.state') || '',
        zipCode: this.getNestedValue(record, 'address.zipCode') || '',
      },
      contactPerson: this.getNestedValue(record, 'contactPerson'),
      industry: this.getNestedValue(record, 'industry') || '',
      scrapedAt: new Date(
        this.getNestedValue(record, 'updatedAt') ||
          this.getNestedValue(record, 'createdAt') ||
          Date.now()
      ),
    }))
  }

  private processTemplate(template: string, data: Record<string, any>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      return data[key] || match
    })
  }

  private createSyncRecord(
    record: BusinessRecord,
    status: 'pending' | 'syncing' | 'synced' | 'failed' | 'conflict',
    targetRecordId?: string,
    errorMessage?: string
  ): CRMSyncRecord {
    return {
      id: `custom-sync-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
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

  private async processBatchSync(
    records: BusinessRecord[],
    batchEndpoint: CRMEndpoint
  ): Promise<CRMSyncRecord[]> {
    const batchData = records.map(record => this.mapBusinessRecordToCustomFormat(record))

    const response = await this.makeCustomApiCall(batchEndpoint, { records: batchData })
    const results: CRMSyncRecord[] = []

    if (response.ok) {
      const responseData = await response.json()
      const batchResults =
        this.getNestedValue(responseData, batchEndpoint.responseMapping.dataPath) || []

      batchResults.forEach((result: any, index: number) => {
        const targetRecordId = this.extractRecordId(result, batchEndpoint.responseMapping)
        results.push(this.createSyncRecord(records[index], 'synced', targetRecordId))
      })
    } else {
      // Handle batch errors
      records.forEach(record => {
        results.push(this.createSyncRecord(record, 'failed', undefined, 'Batch sync failed'))
      })
    }

    return results
  }

  private async handleRecordUpdate(event: CRMWebhookEvent): Promise<void> {
    logger.info('CustomCRMService', 'Processing record update', {
      objectId: event.objectId,
      objectType: event.objectType,
    })
    // Implementation for handling record updates
  }

  private async handleRecordDeletion(event: CRMWebhookEvent): Promise<void> {
    logger.info('CustomCRMService', 'Processing record deletion', {
      objectId: event.objectId,
      objectType: event.objectType,
    })
    // Implementation for handling record deletions
  }
}
