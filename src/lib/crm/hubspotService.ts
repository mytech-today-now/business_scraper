/**
 * HubSpot CRM Service Implementation
 * Handles HubSpot integration with OAuth2 and marketplace connector
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMSyncRecord,
  CRMSyncBatch,
  CRMWebhookEvent,
  CRMWebhookSubscription,
  HubSpotConfiguration
} from '@/types/crm'
import { BaseCRMService } from './baseCRMService'
import { logger } from '@/utils/logger'

export class HubSpotService extends BaseCRMService {
  private accessToken?: string
  private refreshToken?: string
  private portalId?: string
  private apiBaseUrl = 'https://api.hubapi.com'

  async initialize(): Promise<void> {
    try {
      logger.info('HubSpotService', 'Initializing HubSpot service', {
        providerId: this.provider.id
      })

      const config = this.provider.configuration as HubSpotConfiguration
      this.portalId = config.portalId

      await this.authenticate()
      this.isInitialized = true

      logger.info('HubSpotService', 'HubSpot service initialized successfully')
    } catch (error) {
      this.handleError('initialization', error)
    }
  }

  async authenticate(): Promise<boolean> {
    try {
      const auth = this.provider.configuration.authentication
      
      if (auth.type === 'oauth2') {
        return await this.authenticateOAuth2()
      } else if (auth.type === 'api_key') {
        return await this.authenticateApiKey()
      } else {
        throw new Error(`Unsupported authentication type: ${auth.type}`)
      }
    } catch (error) {
      logger.error('HubSpotService', 'Authentication failed', error)
      return false
    }
  }

  private async authenticateOAuth2(): Promise<boolean> {
    try {
      const auth = this.provider.configuration.authentication

      if (auth.refreshToken) {
        return await this.refreshAccessToken()
      }

      // If no refresh token, would need to go through OAuth flow
      // This would typically be handled by the frontend OAuth component
      throw new Error('OAuth2 flow not implemented - use refresh token')
    } catch (error) {
      logger.error('HubSpotService', 'OAuth2 authentication failed', error)
      return false
    }
  }

  private async refreshAccessToken(): Promise<boolean> {
    try {
      const auth = this.provider.configuration.authentication
      
      const response = await fetch(`${this.apiBaseUrl}/oauth/v1/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: auth.credentials.clientId,
          client_secret: auth.credentials.clientSecret,
          refresh_token: auth.refreshToken!
        })
      })

      if (!response.ok) {
        throw new Error(`Token refresh failed: ${response.statusText}`)
      }

      const tokenData = await response.json()
      this.accessToken = tokenData.access_token
      this.refreshToken = tokenData.refresh_token || auth.refreshToken

      logger.info('HubSpotService', 'Access token refreshed successfully')
      return true
    } catch (error) {
      logger.error('HubSpotService', 'Token refresh failed', error)
      return false
    }
  }

  private async authenticateApiKey(): Promise<boolean> {
    try {
      const auth = this.provider.configuration.authentication
      this.accessToken = auth.credentials.apiKey

      // Test the API key
      const isValid = await this.validateConnection()
      if (isValid) {
        logger.info('HubSpotService', 'API key authentication successful')
        return true
      } else {
        throw new Error('Invalid API key')
      }
    } catch (error) {
      logger.error('HubSpotService', 'API key authentication failed', error)
      return false
    }
  }

  async validateConnection(): Promise<boolean> {
    try {
      if (!this.accessToken) {
        return false
      }

      const response = await this.makeApiCall('GET', '/crm/v3/objects/contacts', { limit: 1 })
      return response.ok
    } catch (error) {
      logger.error('HubSpotService', 'Connection validation failed', error)
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
        return this.createSyncRecord(record, 'conflict', undefined, 
          `Duplicate records found: ${duplicateIds.join(', ')}`)
      }

      // Map business record to HubSpot format
      const hubspotData = this.mapToHubSpotFormat(record)

      // Create Contact and Company
      const contactResponse = await this.createHubSpotContact(hubspotData.contact)
      const companyResponse = await this.createHubSpotCompany(hubspotData.company)

      // Associate contact with company
      if (contactResponse.id && companyResponse.id) {
        await this.associateContactWithCompany(contactResponse.id, companyResponse.id)
      }

      if (contactResponse.id) {
        return this.createSyncRecord(record, 'synced', contactResponse.id)
      } else {
        return this.createSyncRecord(record, 'failed', undefined, 'Failed to create contact')
      }
    } catch (error) {
      logger.error('HubSpotService', 'Failed to sync business record', error)
      return this.createSyncRecord(record, 'failed', undefined, error.message)
    }
  }

  async syncBusinessRecords(records: BusinessRecord[]): Promise<CRMSyncBatch> {
    const batchId = `hs-batch-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    const syncRecords: CRMSyncRecord[] = []

    try {
      logger.info('HubSpotService', `Starting batch sync of ${records.length} records`)

      // HubSpot supports batch operations
      const batchSize = Math.min(this.provider.configuration.syncSettings.batchSize || 100, 100)
      
      for (let i = 0; i < records.length; i += batchSize) {
        const batch = records.slice(i, i + batchSize)
        const batchResults = await this.processBatchCreate(batch)
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
        errors: []
      }
    } catch (error) {
      logger.error('HubSpotService', 'Batch sync failed', error)
      throw error
    }
  }

  async pullUpdates(since?: Date): Promise<BusinessRecord[]> {
    try {
      const sinceTimestamp = since ? since.getTime() : Date.now() - 24 * 60 * 60 * 1000
      
      const response = await this.makeApiCall('GET', '/crm/v3/objects/contacts', {
        properties: 'email,firstname,lastname,company,phone,website,city,state,zip',
        limit: 100,
        after: sinceTimestamp
      })

      if (response.ok) {
        const data = await response.json()
        return this.mapHubSpotContactsToBusinessRecords(data.results || [])
      } else {
        throw new Error(`Failed to pull updates: ${response.statusText}`)
      }
    } catch (error) {
      logger.error('HubSpotService', 'Failed to pull updates', error)
      return []
    }
  }

  async setupWebhooks(): Promise<CRMWebhookSubscription[]> {
    try {
      logger.info('HubSpotService', 'Setting up HubSpot webhooks')
      
      const webhookUrl = this.provider.configuration.webhookUrl
      if (!webhookUrl) {
        throw new Error('Webhook URL not configured')
      }

      const subscriptions: CRMWebhookSubscription[] = []

      // Create webhook subscriptions for different events
      const eventTypes = ['contact.creation', 'contact.propertyChange', 'company.creation', 'company.propertyChange']
      
      for (const eventType of eventTypes) {
        const subscription = await this.createWebhookSubscription(eventType, webhookUrl)
        if (subscription) {
          subscriptions.push(subscription)
        }
      }

      return subscriptions
    } catch (error) {
      logger.error('HubSpotService', 'Failed to setup webhooks', error)
      return []
    }
  }

  async handleWebhookEvent(event: CRMWebhookEvent): Promise<void> {
    try {
      logger.info('HubSpotService', 'Handling HubSpot webhook event', {
        eventType: event.eventType,
        objectType: event.objectType,
        objectId: event.objectId
      })

      // Validate webhook signature
      if (!this.validateWebhookSignature(
        JSON.stringify(event.data),
        event.signature || '',
        this.provider.configuration.authentication.credentials.webhookSecret || ''
      )) {
        throw new Error('Invalid webhook signature')
      }

      // Process the webhook event
      switch (event.eventType) {
        case 'contact.creation':
        case 'contact.propertyChange':
          await this.handleContactUpdate(event)
          break
        case 'company.creation':
        case 'company.propertyChange':
          await this.handleCompanyUpdate(event)
          break
        default:
          logger.warn('HubSpotService', `Unhandled event type: ${event.eventType}`)
      }
    } catch (error) {
      logger.error('HubSpotService', 'Failed to handle webhook event', error)
    }
  }

  private async makeApiCall(method: string, endpoint: string, params?: Record<string, any>): Promise<Response> {
    if (!this.accessToken) {
      throw new Error('Not authenticated')
    }

    const url = new URL(endpoint, this.apiBaseUrl)
    if (params && method === 'GET') {
      Object.entries(params).forEach(([key, value]) => {
        url.searchParams.append(key, String(value))
      })
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    }

    // Use different auth header based on auth type
    const auth = this.provider.configuration.authentication
    if (auth.type === 'oauth2') {
      headers['Authorization'] = `Bearer ${this.accessToken}`
    } else if (auth.type === 'api_key') {
      url.searchParams.append('hapikey', this.accessToken)
    }

    const options: RequestInit = {
      method,
      headers
    }

    if (params && method !== 'GET') {
      options.body = JSON.stringify(params)
    }

    return fetch(url.toString(), options)
  }

  private mapToHubSpotFormat(record: BusinessRecord): { contact: any; company: any } {
    const contact = {
      properties: {
        email: record.email[0],
        firstname: record.contactPerson?.split(' ')[0] || '',
        lastname: record.contactPerson?.split(' ').slice(1).join(' ') || '',
        phone: record.phone,
        city: record.address.city,
        state: record.address.state,
        zip: record.address.zipCode,
        hs_lead_status: 'NEW'
      }
    }

    const company = {
      properties: {
        name: record.businessName,
        domain: new URL(record.websiteUrl).hostname,
        website: record.websiteUrl,
        industry: record.industry,
        city: record.address.city,
        state: record.address.state,
        zip: record.address.zipCode,
        address: record.address.street,
        phone: record.phone
      }
    }

    return { contact, company }
  }

  private async createHubSpotContact(contactData: any): Promise<any> {
    const response = await this.makeApiCall('POST', '/crm/v3/objects/contacts', contactData)
    return response.ok ? await response.json() : { error: await response.text() }
  }

  private async createHubSpotCompany(companyData: any): Promise<any> {
    const response = await this.makeApiCall('POST', '/crm/v3/objects/companies', companyData)
    return response.ok ? await response.json() : { error: await response.text() }
  }

  private async associateContactWithCompany(contactId: string, companyId: string): Promise<void> {
    await this.makeApiCall('PUT', `/crm/v3/objects/contacts/${contactId}/associations/companies/${companyId}/1`)
  }

  private createSyncRecord(
    record: BusinessRecord,
    status: 'pending' | 'syncing' | 'synced' | 'failed' | 'conflict',
    targetRecordId?: string,
    errorMessage?: string
  ): CRMSyncRecord {
    return {
      id: `hs-sync-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      crmProviderId: this.provider.id,
      sourceRecordId: record.id,
      targetRecordId,
      businessRecord: record,
      syncStatus: status,
      syncDirection: 'push',
      lastSyncAt: new Date(),
      syncAttempts: 1,
      errors: errorMessage ? [{
        timestamp: new Date(),
        errorCode: 'SYNC_ERROR',
        errorMessage,
        isRetryable: status !== 'conflict'
      }] : [],
      metadata: {}
    }
  }

  private async processBatchCreate(records: BusinessRecord[]): Promise<CRMSyncRecord[]> {
    // HubSpot batch API implementation
    const contacts = records.map(record => this.mapToHubSpotFormat(record).contact)
    
    const response = await this.makeApiCall('POST', '/crm/v3/objects/contacts/batch/create', {
      inputs: contacts
    })

    const results: CRMSyncRecord[] = []
    
    if (response.ok) {
      const data = await response.json()
      data.results?.forEach((result: any, index: number) => {
        results.push(this.createSyncRecord(records[index], 'synced', result.id))
      })
    } else {
      // Handle batch errors
      records.forEach(record => {
        results.push(this.createSyncRecord(record, 'failed', undefined, 'Batch create failed'))
      })
    }

    return results
  }

  private mapHubSpotContactsToBusinessRecords(contacts: any[]): BusinessRecord[] {
    return contacts.map(contact => ({
      id: contact.id,
      businessName: contact.properties.company || '',
      email: contact.properties.email ? [contact.properties.email] : [],
      phone: contact.properties.phone,
      websiteUrl: contact.properties.website || '',
      address: {
        street: contact.properties.address || '',
        city: contact.properties.city || '',
        state: contact.properties.state || '',
        zipCode: contact.properties.zip || ''
      },
      contactPerson: `${contact.properties.firstname || ''} ${contact.properties.lastname || ''}`.trim(),
      industry: contact.properties.industry || '',
      scrapedAt: new Date(contact.properties.lastmodifieddate || contact.properties.createdate)
    }))
  }

  private async createWebhookSubscription(eventType: string, callbackUrl: string): Promise<CRMWebhookSubscription | null> {
    try {
      const response = await this.makeApiCall('POST', '/webhooks/v3/subscriptions', {
        eventType,
        active: true,
        propertyName: eventType.includes('propertyChange') ? 'email' : undefined
      })

      if (response.ok) {
        const data = await response.json()
        return {
          id: data.id,
          crmProviderId: this.provider.id,
          eventTypes: [eventType],
          callbackUrl,
          isActive: true,
          secret: this.provider.configuration.authentication.credentials.webhookSecret || '',
          createdAt: new Date(),
          lastTriggeredAt: undefined
        }
      }
    } catch (error) {
      logger.error('HubSpotService', `Failed to create webhook subscription for ${eventType}`, error)
    }
    
    return null
  }

  private async handleContactUpdate(event: CRMWebhookEvent): Promise<void> {
    logger.info('HubSpotService', 'Processing contact update', {
      objectId: event.objectId
    })
    // Implementation for handling contact updates
  }

  private async handleCompanyUpdate(event: CRMWebhookEvent): Promise<void> {
    logger.info('HubSpotService', 'Processing company update', {
      objectId: event.objectId
    })
    // Implementation for handling company updates
  }
}
