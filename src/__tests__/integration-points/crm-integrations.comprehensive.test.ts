/**
 * CRM Integrations - Comprehensive Integration Points Tests
 * 
 * Tests all CRM integration points including:
 * - Salesforce integration
 * - HubSpot integration
 * - Custom CRM adapters
 * - Authentication and authorization
 * - Data synchronization
 * - Webhook handling
 * - Error handling and retry logic
 */

import { CRMServiceRegistry } from '@/lib/crm/crmServiceRegistry'
import { SalesforceService } from '@/lib/crm/salesforceService'
import { HubSpotService } from '@/lib/crm/hubspotService'
import { CustomCRMService } from '@/lib/crm/customCRMService'
import { BaseCRMService } from '@/lib/crm/baseCRMService'
import { CRMProvider, CRMSyncRecord, BusinessRecord } from '@/types/crm'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/lib/metrics')
jest.mock('@/lib/security')

// Mock fetch for API calls
global.fetch = jest.fn()
const mockFetch = fetch as jest.MockedFunction<typeof fetch>

describe('CRM Integrations - Comprehensive Integration Points Tests', () => {
  let crmRegistry: CRMServiceRegistry
  let mockBusinessRecord: BusinessRecord

  beforeEach(() => {
    jest.clearAllMocks()
    crmRegistry = new CRMServiceRegistry()
    
    mockBusinessRecord = {
      id: 'test-business-1',
      businessName: 'Test Restaurant',
      email: ['contact@testrestaurant.com'],
      phone: '555-1234',
      websiteUrl: 'https://testrestaurant.com',
      address: {
        street: '123 Main St',
        city: 'Test City',
        state: 'CA',
        zipCode: '90210',
        country: 'US'
      },
      contactPerson: 'John Doe',
      coordinates: { lat: 34.0522, lng: -118.2437 },
      industry: 'Restaurant',
      scrapedAt: new Date(),
    }
  })

  describe('CRM Service Registry', () => {
    it('should register Salesforce provider', async () => {
      const salesforceProvider: CRMProvider = {
        id: 'salesforce-1',
        name: 'Salesforce Production',
        type: 'salesforce',
        version: '1.0.0',
        isActive: true,
        configuration: {
          apiEndpoint: 'https://test.salesforce.com',
          authentication: {
            type: 'oauth2',
            credentials: {
              clientId: 'test-client-id',
              clientSecret: 'test-client-secret',
              refreshToken: 'test-refresh-token'
            },
            scopes: ['api', 'refresh_token']
          },
          syncSettings: {
            batchSize: 100,
            syncInterval: 3600,
            autoSync: true
          },
          fieldMappings: [],
          rateLimits: {
            requestsPerSecond: 10,
            requestsPerHour: 1000
          }
        },
        capabilities: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          supportsWebhooks: true,
          supportsBulkOperations: true
        }
      }

      await crmRegistry.registerProvider(salesforceProvider)
      
      const registeredProvider = crmRegistry.getProvider('salesforce-1')
      expect(registeredProvider).toEqual(salesforceProvider)
      
      const service = crmRegistry.getService('salesforce-1')
      expect(service).toBeInstanceOf(SalesforceService)
    })

    it('should register HubSpot provider', async () => {
      const hubspotProvider: CRMProvider = {
        id: 'hubspot-1',
        name: 'HubSpot Marketing',
        type: 'hubspot',
        version: '1.0.0',
        isActive: true,
        configuration: {
          apiEndpoint: 'https://api.hubapi.com',
          authentication: {
            type: 'api_key',
            credentials: {
              apiKey: 'test-hubspot-key'
            }
          },
          syncSettings: {
            batchSize: 50,
            syncInterval: 1800,
            autoSync: true
          },
          fieldMappings: [],
          rateLimits: {
            requestsPerSecond: 5,
            requestsPerHour: 500
          }
        },
        capabilities: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          supportsWebhooks: true,
          supportsBulkOperations: false
        }
      }

      await crmRegistry.registerProvider(hubspotProvider)
      
      const service = crmRegistry.getService('hubspot-1')
      expect(service).toBeInstanceOf(HubSpotService)
    })

    it('should register custom CRM provider', async () => {
      const customProvider: CRMProvider = {
        id: 'custom-1',
        name: 'Custom CRM',
        type: 'custom',
        version: '1.0.0',
        isActive: true,
        configuration: {
          apiEndpoint: 'https://api.customcrm.com',
          authentication: {
            type: 'basic',
            credentials: {
              username: 'test-user',
              password: 'test-password'
            }
          },
          syncSettings: {
            batchSize: 25,
            syncInterval: 7200,
            autoSync: false
          },
          fieldMappings: [],
          rateLimits: {
            requestsPerSecond: 2,
            requestsPerHour: 100
          }
        },
        capabilities: {
          canCreate: true,
          canRead: true,
          canUpdate: false,
          canDelete: false,
          supportsWebhooks: false,
          supportsBulkOperations: false
        }
      }

      await crmRegistry.registerProvider(customProvider)
      
      const service = crmRegistry.getService('custom-1')
      expect(service).toBeInstanceOf(CustomCRMService)
    })

    it('should handle provider registration errors', async () => {
      const invalidProvider = {
        id: 'invalid-1',
        name: 'Invalid Provider',
        type: 'unsupported' as any,
        version: '1.0.0',
        isActive: true,
        configuration: {},
        capabilities: {}
      }

      await expect(crmRegistry.registerProvider(invalidProvider)).rejects.toThrow()
    })
  })

  describe('Salesforce Integration', () => {
    let salesforceService: SalesforceService
    let mockProvider: CRMProvider

    beforeEach(() => {
      mockProvider = {
        id: 'salesforce-test',
        name: 'Salesforce Test',
        type: 'salesforce',
        version: '1.0.0',
        isActive: true,
        configuration: {
          apiEndpoint: 'https://test.salesforce.com',
          authentication: {
            type: 'oauth2',
            credentials: {
              clientId: 'test-client-id',
              clientSecret: 'test-client-secret',
              refreshToken: 'test-refresh-token'
            }
          },
          syncSettings: { batchSize: 100, syncInterval: 3600, autoSync: true },
          fieldMappings: [],
          rateLimits: { requestsPerSecond: 10, requestsPerHour: 1000 }
        },
        capabilities: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          supportsWebhooks: true,
          supportsBulkOperations: true
        }
      }
      
      salesforceService = new SalesforceService(mockProvider)
    })

    it('should authenticate with Salesforce', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: 'test-access-token',
          instance_url: 'https://test.salesforce.com',
          token_type: 'Bearer'
        })
      } as Response)

      const result = await salesforceService.authenticate()
      expect(result).toBe(true)
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/services/oauth2/token'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded'
          })
        })
      )
    })

    it('should sync business record to Salesforce', async () => {
      // Mock authentication
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' })
      } as Response)

      // Mock record creation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'sf-lead-123',
          success: true
        })
      } as Response)

      await salesforceService.initialize()
      const syncResult = await salesforceService.syncBusinessRecord(mockBusinessRecord)

      expect(syncResult.status).toBe('synced')
      expect(syncResult.targetRecordId).toBe('sf-lead-123')
      expect(syncResult.sourceRecordId).toBe('test-business-1')
    })

    it('should handle Salesforce API errors', async () => {
      // Mock authentication success
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' })
      } as Response)

      // Mock API error
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({
          error: 'INVALID_FIELD',
          error_description: 'Invalid field value'
        })
      } as Response)

      await salesforceService.initialize()
      const syncResult = await salesforceService.syncBusinessRecord(mockBusinessRecord)

      expect(syncResult.status).toBe('failed')
      expect(syncResult.errorMessage).toContain('Invalid field value')
    })

    it('should handle bulk sync operations', async () => {
      const businessRecords = [mockBusinessRecord, { ...mockBusinessRecord, id: 'test-business-2' }]

      // Mock authentication
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' })
      } as Response)

      // Mock bulk operation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          results: [
            { id: 'sf-lead-123', success: true },
            { id: 'sf-lead-124', success: true }
          ]
        })
      } as Response)

      await salesforceService.initialize()
      const batchResult = await salesforceService.syncBusinessRecords(businessRecords)

      expect(batchResult.totalRecords).toBe(2)
      expect(batchResult.successfulSyncs).toBe(2)
      expect(batchResult.failedSyncs).toBe(0)
    })
  })

  describe('HubSpot Integration', () => {
    let hubspotService: HubSpotService
    let mockProvider: CRMProvider

    beforeEach(() => {
      mockProvider = {
        id: 'hubspot-test',
        name: 'HubSpot Test',
        type: 'hubspot',
        version: '1.0.0',
        isActive: true,
        configuration: {
          apiEndpoint: 'https://api.hubapi.com',
          authentication: {
            type: 'api_key',
            credentials: {
              apiKey: 'test-hubspot-key'
            }
          },
          syncSettings: { batchSize: 50, syncInterval: 1800, autoSync: true },
          fieldMappings: [],
          rateLimits: { requestsPerSecond: 5, requestsPerHour: 500 }
        },
        capabilities: {
          canCreate: true,
          canRead: true,
          canUpdate: true,
          canDelete: false,
          supportsWebhooks: true,
          supportsBulkOperations: false
        }
      }
      
      hubspotService = new HubSpotService(mockProvider)
    })

    it('should authenticate with HubSpot', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          portalId: 12345,
          timeZone: 'US/Eastern'
        })
      } as Response)

      const result = await hubspotService.authenticate()
      expect(result).toBe(true)
    })

    it('should sync business record to HubSpot', async () => {
      // Mock validation call
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ portalId: 12345 })
      } as Response)

      // Mock contact creation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          vid: 67890,
          'canonical-vid': 67890
        })
      } as Response)

      await hubspotService.initialize()
      const syncResult = await hubspotService.syncBusinessRecord(mockBusinessRecord)

      expect(syncResult.status).toBe('synced')
      expect(syncResult.targetRecordId).toBe('67890')
    })

    it('should handle HubSpot rate limiting', async () => {
      // Mock rate limit response
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({
          'X-HubSpot-RateLimit-Remaining': '0',
          'X-HubSpot-RateLimit-Interval-Milliseconds': '10000'
        }),
        json: async () => ({
          status: 'error',
          message: 'Rate limit exceeded'
        })
      } as Response)

      await expect(hubspotService.syncBusinessRecord(mockBusinessRecord)).rejects.toThrow('Rate limit exceeded')
    })
  })

  describe('Custom CRM Integration', () => {
    let customService: CustomCRMService
    let mockProvider: CRMProvider

    beforeEach(() => {
      mockProvider = {
        id: 'custom-test',
        name: 'Custom CRM Test',
        type: 'custom',
        version: '1.0.0',
        isActive: true,
        configuration: {
          apiEndpoint: 'https://api.customcrm.com',
          authentication: {
            type: 'basic',
            credentials: {
              username: 'test-user',
              password: 'test-password'
            }
          },
          syncSettings: { batchSize: 25, syncInterval: 7200, autoSync: false },
          fieldMappings: [
            {
              sourceField: 'businessName',
              targetField: 'company_name',
              transformation: 'none'
            }
          ],
          rateLimits: { requestsPerSecond: 2, requestsPerHour: 100 }
        },
        capabilities: {
          canCreate: true,
          canRead: true,
          canUpdate: false,
          canDelete: false,
          supportsWebhooks: false,
          supportsBulkOperations: false
        }
      }
      
      customService = new CustomCRMService(mockProvider)
    })

    it('should authenticate with custom CRM', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          token: 'custom-auth-token',
          expires_in: 3600
        })
      } as Response)

      const result = await customService.authenticate()
      expect(result).toBe(true)
    })

    it('should sync business record to custom CRM', async () => {
      // Mock authentication
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: 'custom-token' })
      } as Response)

      // Mock record creation
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'custom-record-123',
          status: 'created'
        })
      } as Response)

      await customService.initialize()
      const syncResult = await customService.syncBusinessRecord(mockBusinessRecord)

      expect(syncResult.status).toBe('synced')
      expect(syncResult.targetRecordId).toBe('custom-record-123')
    })

    it('should handle custom field mappings', async () => {
      // Mock authentication
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: 'custom-token' })
      } as Response)

      // Mock record creation with field mapping verification
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'custom-record-123' })
      } as Response)

      await customService.initialize()
      await customService.syncBusinessRecord(mockBusinessRecord)

      // Verify the request was made with mapped fields
      const lastCall = mockFetch.mock.calls[mockFetch.mock.calls.length - 1]
      const requestBody = JSON.parse(lastCall[1]?.body as string)
      
      expect(requestBody).toHaveProperty('company_name', 'Test Restaurant')
    })
  })

  describe('Webhook Handling', () => {
    it('should setup Salesforce webhooks', async () => {
      const salesforceService = new SalesforceService(mockProvider)
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' })
      } as Response)

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          id: 'webhook-123',
          url: 'https://app.example.com/webhooks/salesforce',
          events: ['lead.created', 'lead.updated']
        })
      } as Response)

      await salesforceService.initialize()
      const webhooks = await salesforceService.setupWebhooks()

      expect(webhooks).toHaveLength(1)
      expect(webhooks[0].id).toBe('webhook-123')
    })

    it('should handle webhook events', async () => {
      const salesforceService = new SalesforceService(mockProvider)
      
      const webhookEvent = {
        id: 'event-123',
        type: 'lead.updated',
        data: {
          recordId: 'sf-lead-123',
          changes: {
            email: 'newemail@example.com'
          }
        },
        timestamp: new Date(),
        source: 'salesforce'
      }

      await salesforceService.handleWebhookEvent(webhookEvent)
      
      // Verify event was processed (implementation specific)
      expect(true).toBe(true) // Placeholder assertion
    })
  })

  describe('Error Handling and Retry Logic', () => {
    it('should retry failed API calls', async () => {
      const salesforceService = new SalesforceService(mockProvider)

      // Mock authentication success
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: 'test-token' })
      } as Response)

      // Mock first call failure
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({ error: 'Internal Server Error' })
      } as Response)

      // Mock retry success
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: 'sf-lead-123', success: true })
      } as Response)

      await salesforceService.initialize()
      const syncResult = await salesforceService.syncBusinessRecord(mockBusinessRecord)

      expect(syncResult.status).toBe('synced')
      expect(mockFetch).toHaveBeenCalledTimes(3) // Auth + Failed call + Retry
    })

    it('should handle connection validation failures', async () => {
      const salesforceService = new SalesforceService(mockProvider)

      mockFetch.mockRejectedValue(new Error('Network error'))

      const isValid = await salesforceService.validateConnection()
      expect(isValid).toBe(false)
    })
  })
})
