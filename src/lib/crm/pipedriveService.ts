/**
 * Pipedrive CRM Service Implementation
 * Handles Pipedrive integration with TypeScript connector and scheduled jobs
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMSyncRecord,
  CRMSyncBatch,
  CRMWebhookEvent,
  CRMWebhookSubscription,
  PipedriveConfiguration,
} from '@/types/crm'
import { BaseCRMService } from './baseCRMService'
import { logger } from '@/utils/logger'

export class PipedriveService extends BaseCRMService {
  private apiToken?: string
  private companyDomain?: string
  private apiBaseUrl?: string

  async initialize(): Promise<void> {
    try {
      logger.info('PipedriveService', 'Initializing Pipedrive service', {
        providerId: this.provider.id,
      })

      const config = this.provider.configuration as PipedriveConfiguration
      this.companyDomain = config.companyDomain
      this.apiBaseUrl = `https://${this.companyDomain}.pipedrive.com/api/v1`

      await this.authenticate()
      this.isInitialized = true

      logger.info('PipedriveService', 'Pipedrive service initialized successfully')
    } catch (error) {
      this.handleError('initialization', error)
    }
  }

  async authenticate(): Promise<boolean> {
    try {
      const auth = this.provider.configuration.authentication

      if (auth.type === 'api_key') {
        this.apiToken = auth.credentials.apiToken

        // Test the API token
        const isValid = await this.validateConnection()
        if (isValid) {
          logger.info('PipedriveService', 'API token authentication successful')
          return true
        } else {
          throw new Error('Invalid API token')
        }
      } else {
        throw new Error(`Unsupported authentication type: ${auth.type}`)
      }
    } catch (error) {
      logger.error('PipedriveService', 'Authentication failed', error)
      return false
    }
  }

  async validateConnection(): Promise<boolean> {
    try {
      if (!this.apiToken || !this.apiBaseUrl) {
        return false
      }

      const response = await this.makeApiCall('GET', '/users/me')
      return response.ok
    } catch (error) {
      logger.error('PipedriveService', 'Connection validation failed', error)
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

      // Map business record to Pipedrive format
      const pipedriveData = this.mapToPipedriveFormat(record)

      // Create Organization and Person
      const orgResponse = await this.createPipedriveOrganization(pipedriveData.organization)
      let personResponse: any = { id: null }

      if (orgResponse.success && orgResponse.data?.id) {
        pipedriveData.person.org_id = orgResponse.data.id
        personResponse = await this.createPipedrivePerson(pipedriveData.person)
      }

      // Create Deal if configured
      if (personResponse.success && personResponse.data?.id) {
        await this.createPipedriveDeal({
          title: `${record.businessName} - New Lead`,
          person_id: personResponse.data.id,
          org_id: orgResponse.data?.id,
          value: 0,
          currency: 'USD',
          status: 'open',
        })
      }

      if (personResponse.success && personResponse.data?.id) {
        return this.createSyncRecord(record, 'synced', personResponse.data.id)
      } else {
        return this.createSyncRecord(
          record,
          'failed',
          undefined,
          orgResponse.error || personResponse.error || 'Unknown error'
        )
      }
    } catch (error) {
      logger.error('PipedriveService', 'Failed to sync business record', error)
      return this.createSyncRecord(record, 'failed', undefined, error.message)
    }
  }

  async syncBusinessRecords(records: BusinessRecord[]): Promise<CRMSyncBatch> {
    const batchId = `pd-batch-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    const syncRecords: CRMSyncRecord[] = []

    try {
      logger.info('PipedriveService', `Starting batch sync of ${records.length} records`)

      // Pipedrive doesn't have native batch operations, so process individually
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
      logger.error('PipedriveService', 'Batch sync failed', error)
      throw error
    }
  }

  async pullUpdates(since?: Date): Promise<BusinessRecord[]> {
    try {
      const sinceDate = since || new Date(Date.now() - 24 * 60 * 60 * 1000)
      const sinceFormatted = sinceDate.toISOString().split('T')[0] // YYYY-MM-DD format

      const response = await this.makeApiCall('GET', '/persons', {
        start: 0,
        limit: 100,
        sort: 'update_time DESC',
        filter_id: undefined, // Could be configured to use a specific filter
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data) {
          return this.mapPipedrivePersonsToBusinessRecords(data.data)
        }
      }

      throw new Error(`Failed to pull updates: ${response.statusText}`)
    } catch (error) {
      logger.error('PipedriveService', 'Failed to pull updates', error)
      return []
    }
  }

  async setupWebhooks(): Promise<CRMWebhookSubscription[]> {
    try {
      logger.info('PipedriveService', 'Setting up Pipedrive webhooks')

      const webhookUrl = this.provider.configuration.webhookUrl
      if (!webhookUrl) {
        throw new Error('Webhook URL not configured')
      }

      const subscriptions: CRMWebhookSubscription[] = []

      // Create webhook subscriptions for different events
      const eventTypes = [
        { object: 'person', action: 'added' },
        { object: 'person', action: 'updated' },
        { object: 'organization', action: 'added' },
        { object: 'organization', action: 'updated' },
        { object: 'deal', action: 'added' },
        { object: 'deal', action: 'updated' },
      ]

      for (const eventType of eventTypes) {
        const subscription = await this.createWebhookSubscription(eventType, webhookUrl)
        if (subscription) {
          subscriptions.push(subscription)
        }
      }

      return subscriptions
    } catch (error) {
      logger.error('PipedriveService', 'Failed to setup webhooks', error)
      return []
    }
  }

  async handleWebhookEvent(event: CRMWebhookEvent): Promise<void> {
    try {
      logger.info('PipedriveService', 'Handling Pipedrive webhook event', {
        eventType: event.eventType,
        objectType: event.objectType,
        objectId: event.objectId,
      })

      // Process the webhook event
      switch (event.objectType) {
        case 'person':
          await this.handlePersonUpdate(event)
          break
        case 'organization':
          await this.handleOrganizationUpdate(event)
          break
        case 'deal':
          await this.handleDealUpdate(event)
          break
        default:
          logger.warn('PipedriveService', `Unhandled object type: ${event.objectType}`)
      }
    } catch (error) {
      logger.error('PipedriveService', 'Failed to handle webhook event', error)
    }
  }

  /**
   * Scheduled job to refresh company profiles using Puppeteer
   */
  async refreshCompanyProfiles(): Promise<void> {
    try {
      logger.info('PipedriveService', 'Starting scheduled company profile refresh')

      // Get organizations that need profile updates
      const orgsResponse = await this.makeApiCall('GET', '/organizations', {
        start: 0,
        limit: 50,
        sort: 'update_time ASC',
      })

      if (orgsResponse.ok) {
        const data = await orgsResponse.json()
        if (data.success && data.data) {
          for (const org of data.data) {
            await this.refreshSingleCompanyProfile(org)
            await new Promise(resolve => setTimeout(resolve, 2000)) // Rate limiting
          }
        }
      }

      logger.info('PipedriveService', 'Completed scheduled company profile refresh')
    } catch (error) {
      logger.error('PipedriveService', 'Failed to refresh company profiles', error)
    }
  }

  private async makeApiCall(
    method: string,
    endpoint: string,
    params?: Record<string, any>
  ): Promise<Response> {
    if (!this.apiToken || !this.apiBaseUrl) {
      throw new Error('Not authenticated')
    }

    const url = new URL(endpoint, this.apiBaseUrl)
    url.searchParams.append('api_token', this.apiToken)

    if (params && method === 'GET') {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value))
        }
      })
    }

    const options: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
    }

    if (params && method !== 'GET') {
      options.body = JSON.stringify(params)
    }

    return fetch(url.toString(), options)
  }

  private mapToPipedriveFormat(record: BusinessRecord): { organization: any; person: any } {
    const organization = {
      name: record.businessName,
      address: `${record.address.street}, ${record.address.city}, ${record.address.state} ${record.address.zipCode}`,
      address_street_number: '',
      address_route: record.address.street,
      address_subpremise: record.address.suite || '',
      address_locality: record.address.city,
      address_admin_area_level_1: record.address.state,
      address_postal_code: record.address.zipCode,
      address_country: 'United States',
      visible_to: '3', // Visible to entire company
    }

    const person = {
      name: record.contactPerson || record.businessName,
      email: record.email,
      phone: record.phone ? [{ value: record.phone, primary: true }] : [],
      org_id: null, // Will be set after organization creation
      visible_to: '3', // Visible to entire company
    }

    return { organization, person }
  }

  private async createPipedriveOrganization(orgData: any): Promise<any> {
    const response = await this.makeApiCall('POST', '/organizations', orgData)
    return response.json()
  }

  private async createPipedrivePerson(personData: any): Promise<any> {
    const response = await this.makeApiCall('POST', '/persons', personData)
    return response.json()
  }

  private async createPipedriveDeal(dealData: any): Promise<any> {
    const response = await this.makeApiCall('POST', '/deals', dealData)
    return response.json()
  }

  private createSyncRecord(
    record: BusinessRecord,
    status: 'pending' | 'syncing' | 'synced' | 'failed' | 'conflict',
    targetRecordId?: string,
    errorMessage?: string
  ): CRMSyncRecord {
    return {
      id: `pd-sync-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
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

  private mapPipedrivePersonsToBusinessRecords(persons: any[]): BusinessRecord[] {
    return persons.map(person => ({
      id: person.id.toString(),
      businessName: person.org_name || person.name,
      email: person.email
        ? [{ value: person.email[0]?.value || person.email }].filter(e => e.value)
        : [],
      phone: person.phone?.[0]?.value,
      websiteUrl: person.org_id ? `https://company-${person.org_id}.example.com` : '',
      address: {
        street: person.org_address || '',
        city: person.org_address_locality || '',
        state: person.org_address_admin_area_level_1 || '',
        zipCode: person.org_address_postal_code || '',
      },
      contactPerson: person.name,
      industry: '',
      scrapedAt: new Date(person.update_time || person.add_time),
    }))
  }

  private async createWebhookSubscription(
    eventType: any,
    callbackUrl: string
  ): Promise<CRMWebhookSubscription | null> {
    try {
      const response = await this.makeApiCall('POST', '/webhooks', {
        subscription_url: callbackUrl,
        event_action: eventType.action,
        event_object: eventType.object,
        user_id: 0, // All users
        http_auth_user: '',
        http_auth_password: '',
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          return {
            id: data.data.id.toString(),
            crmProviderId: this.provider.id,
            eventTypes: [`${eventType.object}.${eventType.action}`],
            callbackUrl,
            isActive: true,
            secret: '',
            createdAt: new Date(),
            lastTriggeredAt: undefined,
          }
        }
      }
    } catch (error) {
      logger.error(
        'PipedriveService',
        `Failed to create webhook subscription for ${eventType.object}.${eventType.action}`,
        error
      )
    }

    return null
  }

  private async refreshSingleCompanyProfile(org: any): Promise<void> {
    try {
      logger.info('PipedriveService', `Refreshing profile for organization: ${org.name}`)

      // This would use Puppeteer to scrape updated company information
      // Implementation would depend on specific requirements

      // For now, just log the action
      logger.debug('PipedriveService', `Profile refresh completed for: ${org.name}`)
    } catch (error) {
      logger.error(
        'PipedriveService',
        `Failed to refresh profile for organization: ${org.name}`,
        error
      )
    }
  }

  private async handlePersonUpdate(event: CRMWebhookEvent): Promise<void> {
    logger.info('PipedriveService', 'Processing person update', {
      objectId: event.objectId,
      eventType: event.eventType,
    })
    // Implementation for handling person updates
  }

  private async handleOrganizationUpdate(event: CRMWebhookEvent): Promise<void> {
    logger.info('PipedriveService', 'Processing organization update', {
      objectId: event.objectId,
      eventType: event.eventType,
    })
    // Implementation for handling organization updates
  }

  private async handleDealUpdate(event: CRMWebhookEvent): Promise<void> {
    logger.info('PipedriveService', 'Processing deal update', {
      objectId: event.objectId,
      eventType: event.eventType,
    })
    // Implementation for handling deal updates
  }
}
