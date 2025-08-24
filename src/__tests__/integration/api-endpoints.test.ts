/**
 * API Endpoints Integration Tests
 * End-to-end tests for API endpoints
 */

import { NextRequest } from 'next/server'
import { GET as getTemplates, POST as createExport } from '@/app/api/v1/exports/route'
import { GET as getTemplatesList } from '@/app/api/v1/templates/route'
import { GET as getAnalytics } from '@/app/api/v1/analytics/route'

// Mock dependencies
jest.mock('@/lib/enhanced-export-service', () => ({
  enhancedExportService: {
    listTemplates: jest.fn(() => [
      {
        id: 'salesforce-leads',
        name: 'Salesforce Leads',
        platform: 'salesforce',
        description: 'Export business data as Salesforce Lead records',
        version: '1.0.0',
        metadata: {
          category: 'crm',
          tags: ['crm', 'salesforce', 'leads'],
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        },
        requiredFields: ['Company'],
        optionalFields: ['Phone', 'Email', 'Website']
      }
    ]),
    getExportStatistics: jest.fn(() => ({
      availableTemplates: 5,
      templatesByPlatform: {
        salesforce: 1,
        hubspot: 1,
        pipedrive: 1,
        mailchimp: 1,
        'constant-contact': 1
      },
      templatesByCategory: {
        crm: 3,
        'email-marketing': 2
      }
    })),
    exportWithTemplate: jest.fn(() => ({
      success: true,
      templateId: 'salesforce-leads',
      recordsProcessed: 2,
      recordsExported: 2,
      recordsSkipped: 0,
      errors: [],
      warnings: [],
      exportData: [
        {
          Company: 'Acme Corp',
          Phone: '(555) 123-4567',
          Email: 'contact@acme.com',
          Website: 'https://acme.com',
          Industry: 'Technology',
          LeadSource: 'Web Scraping',
          Rating: 'Hot'
        },
        {
          Company: 'Beta Industries',
          Phone: '(555) 555-1234',
          Email: 'info@beta.com',
          Website: 'https://beta.com',
          Industry: 'Manufacturing',
          LeadSource: 'Web Scraping',
          Rating: 'Warm'
        }
      ],
      metadata: {
        exportedAt: new Date().toISOString(),
        template: 'Salesforce Leads',
        platform: 'salesforce',
        totalDuration: 150,
        averageProcessingTime: 75
      }
    })),
    convertToDownloadableFormat: jest.fn(() => ({
      blob: new Blob(['test,data\nvalue1,value2'], { type: 'text/csv' }),
      filename: 'salesforce-export-2025-01-24.csv',
      mimeType: 'text/csv'
    }))
  }
}))

jest.mock('@/lib/analytics/usage-analytics', () => ({
  usageAnalyticsService: {
    getRealTimeMetrics: jest.fn(() => ({
      requestsPerMinute: 25,
      averageResponseTime: 150,
      errorRate: 0.5,
      activeClients: 5
    })),
    getClientAnalytics: jest.fn(() => ({
      clientId: 'test-client',
      period: {
        start: '2025-01-23T00:00:00.000Z',
        end: '2025-01-24T00:00:00.000Z'
      },
      metrics: {
        totalRequests: 100,
        successfulRequests: 95,
        failedRequests: 5,
        averageResponseTime: 150,
        dataTransferred: 1024000,
        rateLimitHits: 2
      },
      endpoints: [
        {
          path: '/api/v1/exports',
          method: 'POST',
          requests: 50,
          averageResponseTime: 200,
          errorRate: 2
        }
      ],
      errors: []
    })),
    getSystemAnalytics: jest.fn(() => ({
      totalClients: 10,
      totalRequests: 1000,
      averageResponseTime: 150,
      errorRate: 1.5,
      topEndpoints: [
        {
          endpoint: 'POST /api/v1/exports',
          requests: 500,
          averageResponseTime: 200,
          errorRate: 2
        }
      ],
      topClients: [
        {
          clientId: 'client-1',
          requests: 300,
          dataTransferred: 500000
        }
      ]
    })),
    getHealthStatus: jest.fn(() => [
      {
        service: 'api-framework',
        status: 'healthy',
        lastCheck: new Date().toISOString(),
        responseTime: 45,
        uptime: 86400,
        errors: [],
        metrics: {}
      }
    ])
  }
}))

jest.mock('@/lib/analytics/api-metrics', () => ({
  apiMetricsService: {
    checkRateLimit: jest.fn(() => ({
      allowed: true,
      remaining: { minute: 99, hour: 999, day: 9999 },
      resetTime: { minute: 60, hour: 3600, day: 86400 },
      rateLimitHit: false
    })),
    recordRequest: jest.fn(),
    getPerformanceMetrics: jest.fn(() => ({
      realTime: {
        requestsPerMinute: 25,
        averageResponseTime: 150,
        errorRate: 0.5,
        activeClients: 5
      },
      alerts: [],
      rateLimitStats: {
        totalClients: 10,
        rateLimitHits: 5,
        topRateLimitedClients: []
      }
    })),
    getAlertThresholds: jest.fn(() => ({
      errorRate: 5,
      responseTime: 2000,
      rateLimitHits: 10
    }))
  }
}))

describe('API Endpoints Integration', () => {
  describe('Templates API', () => {
    test('GET /api/v1/templates should return template list', async () => {
      const request = new NextRequest('https://example.com/api/v1/templates')
      const response = await getTemplatesList(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.templates).toHaveLength(1)
      expect(data.data.templates[0].id).toBe('salesforce-leads')
      expect(data.data.statistics).toBeDefined()
    })

    test('GET /api/v1/templates with platform filter', async () => {
      const request = new NextRequest('https://example.com/api/v1/templates?platform=salesforce')
      const response = await getTemplatesList(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.templates).toHaveLength(1)
    })

    test('GET /api/v1/templates with details', async () => {
      const request = new NextRequest('https://example.com/api/v1/templates?details=true')
      const response = await getTemplatesList(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.templates[0].requiredFields).toBeDefined()
      expect(data.data.templates[0].optionalFields).toBeDefined()
    })
  })

  describe('Exports API', () => {
    test('POST /api/v1/exports should create export successfully', async () => {
      const exportRequest = {
        templateId: 'salesforce-leads',
        businesses: [
          {
            businessName: 'Acme Corp',
            email: ['contact@acme.com'],
            phone: ['5551234567'],
            website: 'https://acme.com',
            industry: 'Technology'
          },
          {
            businessName: 'Beta Industries',
            email: ['info@beta.com'],
            phone: ['5555551234'],
            website: 'https://beta.com',
            industry: 'Manufacturing'
          }
        ],
        options: {
          format: 'csv',
          validateData: true,
          includeData: true
        }
      }

      const request = new NextRequest('https://example.com/api/v1/exports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(exportRequest)
      })

      const response = await createExport(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.export.status).toBe('completed')
      expect(data.data.export.recordsProcessed).toBe(2)
      expect(data.data.export.recordsExported).toBe(2)
      expect(data.data.exportData).toHaveLength(2)
      expect(data.data.download).toBeDefined()
    })

    test('POST /api/v1/exports should validate required fields', async () => {
      const invalidRequest = {
        // Missing templateId
        businesses: []
      }

      const request = new NextRequest('https://example.com/api/v1/exports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(invalidRequest)
      })

      const response = await createExport(request)
      
      expect(response.status).toBe(500) // Should be handled by error handling
      
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error.message).toContain('Template ID is required')
    })

    test('POST /api/v1/exports should validate business data', async () => {
      const requestWithInvalidData = {
        templateId: 'salesforce-leads',
        businesses: [] // Empty array
      }

      const request = new NextRequest('https://example.com/api/v1/exports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestWithInvalidData)
      })

      const response = await createExport(request)
      
      expect(response.status).toBe(500)
      
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error.message).toContain('At least one business record is required')
    })
  })

  describe('Analytics API', () => {
    test('GET /api/v1/analytics?type=realtime should return real-time metrics', async () => {
      const request = new NextRequest('https://example.com/api/v1/analytics?type=realtime')
      const response = await getAnalytics(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.type).toBe('realtime')
      expect(data.data.analytics.realTime).toBeDefined()
      expect(data.data.analytics.performance).toBeDefined()
      expect(data.data.analytics.health).toBeDefined()
    })

    test('GET /api/v1/analytics?type=client should return client analytics', async () => {
      const request = new NextRequest('https://example.com/api/v1/analytics?type=client&clientId=test-client')
      const response = await getAnalytics(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.type).toBe('client')
      expect(data.data.analytics.clientId).toBe('test-client')
      expect(data.data.analytics.metrics).toBeDefined()
      expect(data.data.analytics.endpoints).toBeDefined()
    })

    test('GET /api/v1/analytics?type=system should return system analytics', async () => {
      const request = new NextRequest('https://example.com/api/v1/analytics?type=system')
      const response = await getAnalytics(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.type).toBe('system')
      expect(data.data.analytics.totalClients).toBeDefined()
      expect(data.data.analytics.totalRequests).toBeDefined()
      expect(data.data.analytics.topEndpoints).toBeDefined()
      expect(data.data.analytics.topClients).toBeDefined()
    })

    test('GET /api/v1/analytics with date range should filter data', async () => {
      const startDate = '2025-01-23T00:00:00.000Z'
      const endDate = '2025-01-24T00:00:00.000Z'
      
      const request = new NextRequest(
        `https://example.com/api/v1/analytics?type=client&clientId=test-client&startDate=${startDate}&endDate=${endDate}`
      )
      const response = await getAnalytics(request)
      
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.success).toBe(true)
      expect(data.data.period.start).toBe(startDate)
      expect(data.data.period.end).toBe(endDate)
    })
  })

  describe('Error Handling', () => {
    test('should handle invalid JSON in request body', async () => {
      const request = new NextRequest('https://example.com/api/v1/exports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'invalid json'
      })

      const response = await createExport(request)
      
      expect(response.status).toBe(500)
      
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error).toBeDefined()
    })

    test('should handle missing required parameters', async () => {
      const request = new NextRequest('https://example.com/api/v1/analytics?type=client')
      // Missing clientId for client analytics
      
      const response = await getAnalytics(request)
      
      expect(response.status).toBe(500)
      
      const data = await response.json()
      expect(data.success).toBe(false)
      expect(data.error.message).toContain('Client ID is required')
    })
  })

  describe('Response Format', () => {
    test('should include standard response metadata', async () => {
      const request = new NextRequest('https://example.com/api/v1/templates')
      const response = await getTemplatesList(request)
      
      const data = await response.json()
      expect(data.metadata).toBeDefined()
      expect(data.metadata.requestId).toBeDefined()
      expect(data.metadata.timestamp).toBeDefined()
      expect(data.metadata.version).toBe('v1')
    })

    test('should include rate limit headers', async () => {
      const request = new NextRequest('https://example.com/api/v1/templates')
      const response = await getTemplatesList(request)
      
      expect(response.headers.get('X-Request-ID')).toBeTruthy()
      expect(response.headers.get('X-API-Version')).toBe('v1')
      expect(response.headers.get('X-RateLimit-Remaining')).toBeTruthy()
      expect(response.headers.get('X-RateLimit-Reset')).toBeTruthy()
    })

    test('should include CORS headers', async () => {
      const request = new NextRequest('https://example.com/api/v1/templates')
      const response = await getTemplatesList(request)
      
      expect(response.headers.get('Access-Control-Allow-Origin')).toBeTruthy()
    })
  })
})
