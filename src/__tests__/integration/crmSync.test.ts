/**
 * CRM Sync Integration Tests
 * End-to-end tests for CRM synchronization functionality
 */

import { NextRequest } from 'next/server'
import { POST as syncPost, GET as syncGet } from '@/app/api/crm/sync/route'
import { POST as crmPost } from '@/app/api/crm/route'
import { mockBusinessData } from '@/__tests__/fixtures/testData'
import { crmServiceRegistry } from '@/lib/crm/crmServiceRegistry'
import { expectArrayElement } from '../utils/mockTypeHelpers'

// Mock the CRM service registry
jest.mock('@/lib/crm/crmServiceRegistry')
jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn().mockReturnValue('127.0.0.1'),
}))

describe('CRM Sync Integration Tests', () => {
  const mockCrmServiceRegistry = crmServiceRegistry as jest.Mocked<typeof crmServiceRegistry>

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Business Record Sync', () => {
    it('should sync single business record to CRM', async () => {
      // Mock CRM service
      const mockService = {
        getProvider: jest.fn().mockReturnValue({
          id: 'test-provider',
          name: 'Test CRM',
          type: 'custom',
        }),
        syncBusinessRecord: jest.fn().mockResolvedValue({
          id: 'sync-1',
          crmProviderId: 'test-provider',
          sourceRecordId: expectArrayElement(mockBusinessData, 0).id,
          targetRecordId: 'crm-record-1',
          businessRecord: expectArrayElement(mockBusinessData, 0),
          syncStatus: 'synced',
          syncDirection: 'push',
          lastSyncAt: new Date(),
          syncAttempts: 1,
          errors: [],
          metadata: {},
        }),
      }

      mockCrmServiceRegistry.getActiveServices.mockReturnValue([mockService as any])

      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          records: [expectArrayElement(mockBusinessData, 0)],
          syncMode: 'push',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.summary.totalSynced).toBe(1)
      expect(data.data.summary.totalFailed).toBe(0)
      expect(mockService.syncBusinessRecord).toHaveBeenCalledWith(expectArrayElement(mockBusinessData, 0))
    })

    it('should sync multiple business records in batch', async () => {
      const mockService = {
        getProvider: jest.fn().mockReturnValue({
          id: 'test-provider',
          name: 'Test CRM',
          type: 'custom',
        }),
        syncBusinessRecords: jest.fn().mockResolvedValue({
          id: 'batch-1',
          crmProviderId: 'test-provider',
          records: mockBusinessData.map((record, index) => ({
            id: `sync-${index}`,
            crmProviderId: 'test-provider',
            sourceRecordId: record.id,
            targetRecordId: `crm-record-${index}`,
            businessRecord: record,
            syncStatus: 'synced',
            syncDirection: 'push',
            lastSyncAt: new Date(),
            syncAttempts: 1,
            errors: [],
            metadata: {},
          })),
          status: 'completed',
          startedAt: new Date(),
          completedAt: new Date(),
          totalRecords: mockBusinessData.length,
          successfulRecords: mockBusinessData.length,
          failedRecords: 0,
          errors: [],
        }),
      }

      mockCrmServiceRegistry.getActiveServices.mockReturnValue([mockService as any])

      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          records: mockBusinessData,
          syncMode: 'push',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.summary.totalSynced).toBe(mockBusinessData.length)
      expect(mockService.syncBusinessRecords).toHaveBeenCalledWith(mockBusinessData)
    })

    it('should handle sync failures gracefully', async () => {
      const mockService = {
        getProvider: jest.fn().mockReturnValue({
          id: 'test-provider',
          name: 'Test CRM',
          type: 'custom',
        }),
        syncBusinessRecord: jest.fn().mockRejectedValue(new Error('Sync failed')),
      }

      mockCrmServiceRegistry.getActiveServices.mockReturnValue([mockService as any])

      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          records: [expectArrayElement(mockBusinessData, 0)],
          syncMode: 'push',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      const firstSyncResult = expectArrayElement(data.data.syncResults, 0) as any
      expect(firstSyncResult).toBeDefined()
      expect(firstSyncResult.type).toBe('error')
      expect(firstSyncResult.error).toBe('Sync failed')
    })

    it('should sync to multiple CRM providers', async () => {
      const mockService1 = {
        getProvider: jest.fn().mockReturnValue({
          id: 'provider-1',
          name: 'CRM 1',
          type: 'salesforce',
        }),
        syncBusinessRecord: jest.fn().mockResolvedValue({
          id: 'sync-1',
          syncStatus: 'synced',
        }),
      }

      const mockService2 = {
        getProvider: jest.fn().mockReturnValue({
          id: 'provider-2',
          name: 'CRM 2',
          type: 'hubspot',
        }),
        syncBusinessRecord: jest.fn().mockResolvedValue({
          id: 'sync-2',
          syncStatus: 'synced',
        }),
      }

      mockCrmServiceRegistry.getActiveServices.mockReturnValue([
        mockService1 as any,
        mockService2 as any,
      ])

      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          records: [expectArrayElement(mockBusinessData, 0)],
          syncMode: 'push',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.summary.totalProviders).toBe(2)
      expect(data.data.syncResults).toHaveLength(2)
      expect(mockService1.syncBusinessRecord).toHaveBeenCalled()
      expect(mockService2.syncBusinessRecord).toHaveBeenCalled()
    })

    it('should filter by specific provider IDs', async () => {
      const mockService1 = {
        getProvider: jest.fn().mockReturnValue({
          id: 'provider-1',
          name: 'CRM 1',
          type: 'salesforce',
        }),
        syncBusinessRecord: jest.fn().mockResolvedValue({
          id: 'sync-1',
          syncStatus: 'synced',
        }),
      }

      const mockService2 = {
        getProvider: jest.fn().mockReturnValue({
          id: 'provider-2',
          name: 'CRM 2',
          type: 'hubspot',
        }),
        syncBusinessRecord: jest.fn(),
      }

      mockCrmServiceRegistry.getActiveServices.mockReturnValue([
        mockService1 as any,
        mockService2 as any,
      ])

      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          records: [expectArrayElement(mockBusinessData, 0)],
          providerIds: ['provider-1'],
          syncMode: 'push',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.syncResults).toHaveLength(1)
      const firstSyncResult = expectArrayElement(data.data.syncResults, 0) as any
      expect(firstSyncResult).toBeDefined()
      expect(firstSyncResult.providerId).toBe('provider-1')
      expect(mockService1.syncBusinessRecord).toHaveBeenCalled()
      expect(mockService2.syncBusinessRecord).not.toHaveBeenCalled()
    })
  })

  describe('Sync Status and History', () => {
    it('should retrieve sync status and history', async () => {
      mockCrmServiceRegistry.getStatistics.mockReturnValue({
        totalProviders: 2,
        activeProviders: 2,
        providersByType: { salesforce: 1, hubspot: 1 },
        servicesReady: 2,
      })

      const request = new NextRequest('http://localhost/api/crm/sync?limit=10')

      const response = await syncGet(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.statistics).toBeDefined()
      expect(data.data.pagination.limit).toBe(10)
    })

    it('should filter sync history by provider', async () => {
      const request = new NextRequest(
        'http://localhost/api/crm/sync?providerId=test-provider&limit=5'
      )

      const response = await syncGet(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.pagination.limit).toBe(5)
    })
  })

  describe('Error Handling', () => {
    it('should return error for invalid request body', async () => {
      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          invalidField: 'invalid',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.success).toBe(false)
      expect(data.error).toContain('Records array is required')
    })

    it('should return error when no active CRM services found', async () => {
      mockCrmServiceRegistry.getActiveServices.mockReturnValue([])

      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          records: [expectArrayElement(mockBusinessData, 0)],
          syncMode: 'push',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.success).toBe(false)
      expect(data.error).toContain('No active CRM services found')
    })

    it('should handle malformed JSON gracefully', async () => {
      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: 'invalid json',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.success).toBe(false)
    })
  })

  describe('Performance Tests', () => {
    it('should handle large batch sync efficiently', async () => {
      const firstMockData = expectArrayElement(mockBusinessData, 0)
      const largeBatch = Array.from({ length: 100 }, (_, i) => ({
        ...firstMockData,
        id: `business-${i}`,
        businessName: `Business ${i}`,
      }))

      const mockService = {
        getProvider: jest.fn().mockReturnValue({
          id: 'test-provider',
          name: 'Test CRM',
          type: 'custom',
        }),
        syncBusinessRecords: jest.fn().mockResolvedValue({
          id: 'batch-large',
          crmProviderId: 'test-provider',
          records: largeBatch.map((record, index) => ({
            id: `sync-${index}`,
            syncStatus: 'synced',
          })),
          status: 'completed',
          totalRecords: largeBatch.length,
          successfulRecords: largeBatch.length,
          failedRecords: 0,
          errors: [],
        }),
      }

      mockCrmServiceRegistry.getActiveServices.mockReturnValue([mockService as any])

      const startTime = Date.now()

      const request = new NextRequest('http://localhost/api/crm/sync', {
        method: 'POST',
        body: JSON.stringify({
          records: largeBatch,
          syncMode: 'push',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await syncPost(request)
      const data = await response.json()
      const endTime = Date.now()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data.summary.totalSynced).toBe(largeBatch.length)
      expect(endTime - startTime).toBeLessThan(5000) // Should complete within 5 seconds
    })

    it('should handle concurrent sync requests', async () => {
      const mockService = {
        getProvider: jest.fn().mockReturnValue({
          id: 'test-provider',
          name: 'Test CRM',
          type: 'custom',
        }),
        syncBusinessRecord: jest.fn().mockResolvedValue({
          id: 'sync-concurrent',
          syncStatus: 'synced',
        }),
      }

      mockCrmServiceRegistry.getActiveServices.mockReturnValue([mockService as any])

      const createRequest = () =>
        new NextRequest('http://localhost/api/crm/sync', {
          method: 'POST',
          body: JSON.stringify({
            records: [expectArrayElement(mockBusinessData, 0)],
            syncMode: 'push',
          }),
          headers: {
            'Content-Type': 'application/json',
          },
        })

      // Execute multiple concurrent requests
      const promises = Array.from({ length: 5 }, () => syncPost(createRequest()))
      const responses = await Promise.all(promises)

      // All requests should succeed
      for (const response of responses) {
        expect(response.status).toBe(200)
        const data = await response.json()
        expect(data.success).toBe(true)
      }
    })
  })
})
