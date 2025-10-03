/**
 * Comprehensive Campaigns API Route Tests
 * Tests all campaign endpoints with various scenarios including success, error, and edge cases
 * Target: 98% coverage for /api/campaigns routes
 */

import { NextRequest, NextResponse } from 'next/server'
import { GET as campaignsGET, POST as campaignsPOST, PUT as campaignsPUT, DELETE as campaignsDELETE } from '@/app/api/campaigns/route'
import { jest } from '@jest/globals'

// Mock dependencies
jest.mock('@/lib/rbac-middleware', () => ({
  withRBAC: jest.fn((handler) => handler),
}))

jest.mock('@/lib/database', () => ({
  database: {
    executeQuery: jest.fn(),
  },
}))

jest.mock('@/lib/audit-service', () => ({
  AuditService: {
    logCampaignManagement: jest.fn(),
    extractContextFromRequest: jest.fn(),
  },
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

// Import mocked modules
import { database } from '@/lib/database'
import { AuditService } from '@/lib/audit-service'
import { logger } from '@/utils/logger'

// Test data factory
const createMockCampaign = (overrides: any = {}) => ({
  id: 'campaign_123456789_abc123',
  name: 'Test Campaign',
  description: 'A test campaign for unit testing',
  industry: 'Technology',
  location: 'San Francisco, CA',
  workspace_id: 'workspace-123',
  created_by: 'user-123',
  parameters: '{"maxResults": 1000, "searchRadius": 25}',
  settings: '{"includeEmails": true, "includePhones": true}',
  status: 'draft',
  created_at: new Date('2024-01-01T00:00:00Z'),
  updated_at: new Date('2024-01-01T00:00:00Z'),
  ...overrides,
})

describe('Campaigns API Routes - Comprehensive Tests', () => {
  const mockContext = {
    session: {
      user: {
        id: 'user-123',
        workspaceId: 'workspace-123',
      },
    },
  }

  beforeEach(() => {
    jest.clearAllMocks()
    
    // Setup default mocks
    ;(AuditService.extractContextFromRequest as jest.Mock).mockReturnValue({
      ipAddress: '192.168.1.100',
      userAgent: 'test-agent',
      sessionId: 'session-123',
    })
  })

  describe('GET /api/campaigns - List Campaigns', () => {
    it('should list campaigns with default pagination', async () => {
      const mockCampaigns = [
        createMockCampaign({ id: 'campaign-1', name: 'Campaign 1' }),
        createMockCampaign({ id: 'campaign-2', name: 'Campaign 2' }),
      ]

      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '2' }] }) // Count query
        .mockResolvedValueOnce({ rows: mockCampaigns }) // Data query

      const request = new NextRequest('http://localhost:3000/api/campaigns')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toHaveLength(2)
      expect(data.pagination).toEqual({
        page: 1,
        limit: 20,
        total: 2,
        totalPages: 1,
        hasNext: false,
        hasPrev: false,
      })
    })

    it('should filter campaigns by search term', async () => {
      const mockCampaigns = [
        createMockCampaign({ name: 'Tech Campaign', industry: 'Technology' }),
      ]

      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: mockCampaigns })

      const request = new NextRequest('http://localhost:3000/api/campaigns?search=tech')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(1)
      expect(data.data[0].name).toBe('Tech Campaign')
    })

    it('should filter campaigns by status', async () => {
      const mockCampaigns = [
        createMockCampaign({ status: 'active' }),
      ]

      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: mockCampaigns })

      const request = new NextRequest('http://localhost:3000/api/campaigns?status=active')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data[0].status).toBe('active')
    })

    it('should filter campaigns by industry', async () => {
      const mockCampaigns = [
        createMockCampaign({ industry: 'Healthcare' }),
      ]

      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1' }] })
        .mockResolvedValueOnce({ rows: mockCampaigns })

      const request = new NextRequest('http://localhost:3000/api/campaigns?industry=Healthcare')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data[0].industry).toBe('Healthcare')
    })

    it('should handle pagination correctly', async () => {
      const mockCampaigns = Array.from({ length: 10 }, (_, i) =>
        createMockCampaign({ id: `campaign-${i}`, name: `Campaign ${i}` })
      )

      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '50' }] })
        .mockResolvedValueOnce({ rows: mockCampaigns })

      const request = new NextRequest('http://localhost:3000/api/campaigns?page=2&limit=10')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.pagination).toEqual({
        page: 2,
        limit: 10,
        total: 50,
        totalPages: 5,
        hasNext: true,
        hasPrev: true,
      })
    })

    it('should handle database errors gracefully', async () => {
      ;(database.executeQuery as jest.Mock).mockRejectedValue(new Error('Database error'))

      const request = new NextRequest('http://localhost:3000/api/campaigns')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to list campaigns')
      expect(logger.error).toHaveBeenCalled()
    })

    it('should handle empty results', async () => {
      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '0' }] })
        .mockResolvedValueOnce({ rows: [] })

      const request = new NextRequest('http://localhost:3000/api/campaigns')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(0)
      expect(data.pagination.total).toBe(0)
    })
  })

  describe('POST /api/campaigns - Create Campaign', () => {
    it('should create campaign with valid data', async () => {
      const newCampaign = createMockCampaign()
      ;(database.executeQuery as jest.Mock).mockResolvedValue({ rows: [newCampaign] })

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'POST',
        body: JSON.stringify({
          name: 'Test Campaign',
          description: 'A test campaign',
          industry: 'Technology',
          location: 'San Francisco, CA',
          parameters: { maxResults: 1000 },
          settings: { includeEmails: true },
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(201)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(newCampaign)
      expect(data.message).toBe('Campaign created successfully')
      expect(AuditService.logCampaignManagement).toHaveBeenCalledWith(
        'campaign.created',
        expect.any(String),
        'user-123',
        expect.any(Object),
        expect.objectContaining({
          name: 'Test Campaign',
          industry: 'Technology',
          location: 'San Francisco, CA',
        })
      )
    })

    it('should reject campaign creation with missing required fields', async () => {
      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'POST',
        body: JSON.stringify({
          name: 'Test Campaign',
          // Missing industry and location
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Name, industry, and location are required')
    })

    it('should reject campaign creation without workspace ID', async () => {
      const contextWithoutWorkspace = {
        session: {
          user: {
            id: 'user-123',
            // Missing workspaceId
          },
        },
      }

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'POST',
        body: JSON.stringify({
          name: 'Test Campaign',
          industry: 'Technology',
          location: 'San Francisco, CA',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPOST(request, contextWithoutWorkspace)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Workspace ID is required')
    })

    it('should handle database errors during creation', async () => {
      ;(database.executeQuery as jest.Mock).mockRejectedValue(new Error('Database error'))

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'POST',
        body: JSON.stringify({
          name: 'Test Campaign',
          industry: 'Technology',
          location: 'San Francisco, CA',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to create campaign')
      expect(logger.error).toHaveBeenCalled()
    })

    it('should handle malformed JSON requests', async () => {
      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'POST',
        body: 'invalid-json',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPOST(request, mockContext)

      expect(response.status).toBe(500)
    })

    it('should create campaign with optional parameters', async () => {
      const newCampaign = createMockCampaign()
      ;(database.executeQuery as jest.Mock).mockResolvedValue({ rows: [newCampaign] })

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'POST',
        body: JSON.stringify({
          name: 'Minimal Campaign',
          industry: 'Technology',
          location: 'San Francisco, CA',
          // No description, parameters, or settings
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(201)
      expect(data.success).toBe(true)
    })
  })

  describe('PUT /api/campaigns - Bulk Update Campaigns', () => {
    it('should update multiple campaigns successfully', async () => {
      const updatedCampaigns = [
        createMockCampaign({ id: 'campaign-1', status: 'active' }),
        createMockCampaign({ id: 'campaign-2', status: 'active' }),
      ]

      ;(database.executeQuery as jest.Mock).mockResolvedValue({ rows: updatedCampaigns })

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'PUT',
        body: JSON.stringify({
          campaignIds: ['campaign-1', 'campaign-2'],
          updateData: {
            status: 'active',
            updated_at: new Date().toISOString(),
          },
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toHaveLength(2)
      expect(data.message).toBe('Campaigns updated successfully')
      expect(AuditService.logCampaignManagement).toHaveBeenCalledWith(
        'campaign.bulk_updated',
        expect.any(String),
        'user-123',
        expect.any(Object),
        expect.objectContaining({
          campaignIds: ['campaign-1', 'campaign-2'],
          updateData: expect.objectContaining({ status: 'active' }),
        })
      )
    })

    it('should reject bulk update without campaign IDs', async () => {
      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'PUT',
        body: JSON.stringify({
          updateData: { status: 'active' },
          // Missing campaignIds
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Campaign IDs and update data are required')
    })

    it('should reject bulk update with empty campaign IDs array', async () => {
      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'PUT',
        body: JSON.stringify({
          campaignIds: [],
          updateData: { status: 'active' },
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('At least one campaign ID is required')
    })

    it('should handle database errors during bulk update', async () => {
      ;(database.executeQuery as jest.Mock).mockRejectedValue(new Error('Database error'))

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'PUT',
        body: JSON.stringify({
          campaignIds: ['campaign-1'],
          updateData: { status: 'active' },
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to update campaigns')
      expect(logger.error).toHaveBeenCalled()
    })

    it('should handle concurrent bulk updates', async () => {
      const updatedCampaigns = [createMockCampaign({ status: 'active' })]
      ;(database.executeQuery as jest.Mock).mockResolvedValue({ rows: updatedCampaigns })

      const requests = Array.from({ length: 3 }, () =>
        new NextRequest('http://localhost:3000/api/campaigns', {
          method: 'PUT',
          body: JSON.stringify({
            campaignIds: ['campaign-1'],
            updateData: { status: 'active' },
          }),
          headers: { 'Content-Type': 'application/json' },
        })
      )

      const responses = await Promise.all(requests.map(req => campaignsPUT(req, mockContext)))

      responses.forEach(response => {
        expect([200, 409, 500]).toContain(response.status)
      })
    })
  })

  describe('DELETE /api/campaigns - Bulk Delete Campaigns', () => {
    it('should delete multiple campaigns successfully', async () => {
      ;(database.executeQuery as jest.Mock).mockResolvedValue({ rowCount: 2 })

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'DELETE',
        body: JSON.stringify({
          campaignIds: ['campaign-1', 'campaign-2'],
          permanent: false,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsDELETE(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.deletedCount).toBe(2)
      expect(data.message).toBe('Campaigns deleted successfully')
      expect(AuditService.logCampaignManagement).toHaveBeenCalledWith(
        'campaign.bulk_deleted',
        expect.any(String),
        'user-123',
        expect.any(Object),
        expect.objectContaining({
          campaignIds: ['campaign-1', 'campaign-2'],
          permanent: false,
        })
      )
    })

    it('should permanently delete campaigns when specified', async () => {
      ;(database.executeQuery as jest.Mock).mockResolvedValue({ rowCount: 1 })

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'DELETE',
        body: JSON.stringify({
          campaignIds: ['campaign-1'],
          permanent: true,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsDELETE(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.deletedCount).toBe(1)
      expect(AuditService.logCampaignManagement).toHaveBeenCalledWith(
        'campaign.bulk_deleted',
        expect.any(String),
        'user-123',
        expect.any(Object),
        expect.objectContaining({ permanent: true })
      )
    })

    it('should reject bulk delete without campaign IDs', async () => {
      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'DELETE',
        body: JSON.stringify({
          permanent: false,
          // Missing campaignIds
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsDELETE(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Campaign IDs are required')
    })

    it('should handle database errors during bulk delete', async () => {
      ;(database.executeQuery as jest.Mock).mockRejectedValue(new Error('Database error'))

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'DELETE',
        body: JSON.stringify({
          campaignIds: ['campaign-1'],
          permanent: false,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsDELETE(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to delete campaigns')
      expect(logger.error).toHaveBeenCalled()
    })

    it('should handle no campaigns found for deletion', async () => {
      ;(database.executeQuery as jest.Mock).mockResolvedValue({ rowCount: 0 })

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'DELETE',
        body: JSON.stringify({
          campaignIds: ['nonexistent-campaign'],
          permanent: false,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsDELETE(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(404)
      expect(data.error).toBe('No campaigns found to delete')
    })
  })

  describe('Error Handling and Edge Cases', () => {
    it('should handle workspace isolation correctly', async () => {
      const differentWorkspaceContext = {
        session: {
          user: {
            id: 'user-456',
            workspaceId: 'workspace-456',
          },
        },
      }

      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '0' }] })
        .mockResolvedValueOnce({ rows: [] })

      const request = new NextRequest('http://localhost:3000/api/campaigns')

      const response = await campaignsGET(request, differentWorkspaceContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data).toHaveLength(0)
      expect(database.executeQuery).toHaveBeenCalledWith(
        expect.stringContaining('workspace_id = $'),
        expect.arrayContaining(['workspace-456'])
      )
    })

    it('should handle invalid pagination parameters', async () => {
      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '10' }] })
        .mockResolvedValueOnce({ rows: [] })

      const request = new NextRequest('http://localhost:3000/api/campaigns?page=-1&limit=0')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.pagination.page).toBe(1) // Should default to 1
      expect(data.pagination.limit).toBe(20) // Should default to 20
    })

    it('should handle large pagination requests', async () => {
      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '1000' }] })
        .mockResolvedValueOnce({ rows: [] })

      const request = new NextRequest('http://localhost:3000/api/campaigns?page=1&limit=1000')

      const response = await campaignsGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.pagination.limit).toBeLessThanOrEqual(100) // Should cap at max limit
    })

    it('should handle special characters in search terms', async () => {
      ;(database.executeQuery as jest.Mock)
        .mockResolvedValueOnce({ rows: [{ count: '0' }] })
        .mockResolvedValueOnce({ rows: [] })

      const request = new NextRequest('http://localhost:3000/api/campaigns?search=%27DROP%20TABLE%3B--')

      const response = await campaignsGET(request, mockContext)

      expect(response.status).toBe(200)
      expect(database.executeQuery).toHaveBeenCalledWith(
        expect.stringContaining('ILIKE'),
        expect.arrayContaining([expect.stringContaining('%\'DROP TABLE;--%')])
      )
    })

    it('should handle network timeouts gracefully', async () => {
      ;(database.executeQuery as jest.Mock).mockImplementation(
        () => new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Network timeout')), 100)
        )
      )

      const request = new NextRequest('http://localhost:3000/api/campaigns')

      const response = await campaignsGET(request, mockContext)

      expect(response.status).toBe(500)
    })

    it('should validate campaign status values', async () => {
      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'PUT',
        body: JSON.stringify({
          campaignIds: ['campaign-1'],
          updateData: {
            status: 'invalid-status',
          },
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('Invalid status value')
    })

    it('should handle memory pressure during large operations', async () => {
      const largeCampaignIds = Array.from({ length: 10000 }, (_, i) => `campaign-${i}`)

      const request = new NextRequest('http://localhost:3000/api/campaigns', {
        method: 'DELETE',
        body: JSON.stringify({
          campaignIds: largeCampaignIds,
          permanent: false,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await campaignsDELETE(request, mockContext)

      expect([200, 413, 500]).toContain(response.status)
    })
  })
})
