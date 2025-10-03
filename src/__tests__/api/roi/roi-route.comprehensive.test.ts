/**
 * Comprehensive ROI API Route Tests
 * Tests all ROI endpoints with various scenarios including success, error, and edge cases
 * Target: 98% coverage for /api/roi routes
 */

import { NextRequest, NextResponse } from 'next/server'
import { POST as roiPOST, PUT as roiPUT } from '@/app/api/roi/route'
import { POST as roiExportPOST, GET as roiExportGET } from '@/app/api/roi/export/route'
import { jest } from '@jest/globals'

// Mock dependencies
jest.mock('@/lib/roi-service', () => ({
  ROIService: {
    generateROIReport: jest.fn(),
    updateConversionData: jest.fn(),
    exportROIReport: jest.fn(),
    getExportFormats: jest.fn(),
  },
}))

jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(),
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

jest.mock('@/lib/audit-service', () => ({
  AuditService: {
    logROIActivity: jest.fn(),
    extractContextFromRequest: jest.fn(),
  },
}))

// Import mocked modules
import { ROIService } from '@/lib/roi-service'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'
import { AuditService } from '@/lib/audit-service'

describe('ROI API Routes - Comprehensive Tests', () => {
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
    ;(getClientIP as jest.Mock).mockReturnValue('192.168.1.100')
    ;(AuditService.extractContextFromRequest as jest.Mock).mockReturnValue({
      ipAddress: '192.168.1.100',
      userAgent: 'test-agent',
      sessionId: 'session-123',
    })
  })

  describe('POST /api/roi - Generate ROI Report', () => {
    it('should generate comprehensive ROI report', async () => {
      const mockROIReport = {
        reportId: 'roi-report-123456789-abc123',
        summary: {
          totalInvestment: 50000,
          totalRevenue: 125000,
          netProfit: 75000,
          roiPercentage: 150,
          paybackPeriod: 8.5,
        },
        campaigns: [
          {
            campaignId: 'campaign-1',
            name: 'Tech Campaign',
            investment: 25000,
            revenue: 75000,
            roi: 200,
            conversions: 150,
            conversionRate: 12.5,
          },
          {
            campaignId: 'campaign-2',
            name: 'Healthcare Campaign',
            investment: 25000,
            revenue: 50000,
            roi: 100,
            conversions: 100,
            conversionRate: 10.0,
          },
        ],
        timeframe: {
          startDate: '2024-01-01',
          endDate: '2024-12-31',
        },
        generatedAt: new Date().toISOString(),
      }

      ;(ROIService.generateROIReport as jest.Mock).mockResolvedValue(mockROIReport)

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: JSON.stringify({
          timeframe: {
            startDate: '2024-01-01',
            endDate: '2024-12-31',
          },
          campaignIds: ['campaign-1', 'campaign-2'],
          includeProjections: true,
          granularity: 'monthly',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(mockROIReport)
      expect(data.message).toBe('ROI report generated successfully')
      expect(ROIService.generateROIReport).toHaveBeenCalledWith(
        'workspace-123',
        expect.objectContaining({
          timeframe: { startDate: '2024-01-01', endDate: '2024-12-31' },
          campaignIds: ['campaign-1', 'campaign-2'],
          includeProjections: true,
          granularity: 'monthly',
        })
      )
      expect(AuditService.logROIActivity).toHaveBeenCalledWith(
        'roi.report_generated',
        expect.any(String),
        'user-123',
        expect.any(Object),
        expect.objectContaining({
          reportId: 'roi-report-123456789-abc123',
          campaignCount: 2,
        })
      )
    })

    it('should generate ROI report with default parameters', async () => {
      const mockROIReport = {
        reportId: 'roi-report-default',
        summary: {
          totalInvestment: 10000,
          totalRevenue: 15000,
          netProfit: 5000,
          roiPercentage: 50,
          paybackPeriod: 12,
        },
        campaigns: [],
        timeframe: {
          startDate: '2024-01-01',
          endDate: '2024-12-31',
        },
        generatedAt: new Date().toISOString(),
      }

      ;(ROIService.generateROIReport as jest.Mock).mockResolvedValue(mockROIReport)

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: JSON.stringify({}),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(ROIService.generateROIReport).toHaveBeenCalledWith(
        'workspace-123',
        expect.objectContaining({
          includeProjections: false,
          granularity: 'monthly',
        })
      )
    })

    it('should handle ROI service errors', async () => {
      ;(ROIService.generateROIReport as jest.Mock).mockRejectedValue(
        new Error('ROI calculation failed')
      )

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: JSON.stringify({
          timeframe: {
            startDate: '2024-01-01',
            endDate: '2024-12-31',
          },
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.success).toBe(false)
      expect(data.error).toBe('Failed to generate ROI report')
      expect(logger.error).toHaveBeenCalledWith(
        'ROI API',
        'Failed to generate ROI report',
        expect.any(Error)
      )
    })

    it('should validate timeframe parameters', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: JSON.stringify({
          timeframe: {
            startDate: '2024-12-31',
            endDate: '2024-01-01', // End date before start date
          },
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.success).toBe(false)
      expect(data.error).toBe('Invalid timeframe: end date must be after start date')
    })

    it('should handle malformed JSON requests', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: 'invalid-json',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPOST(request, mockContext)

      expect(response.status).toBe(500)
    })

    it('should validate granularity parameter', async () => {
      const validGranularities = ['daily', 'weekly', 'monthly', 'quarterly', 'yearly']

      for (const granularity of validGranularities) {
        ;(ROIService.generateROIReport as jest.Mock).mockResolvedValue({
          reportId: `roi-${granularity}`,
          summary: {},
          campaigns: [],
          timeframe: {},
          generatedAt: new Date().toISOString(),
        })

        const request = new NextRequest('http://localhost:3000/api/roi', {
          method: 'POST',
          body: JSON.stringify({ granularity }),
          headers: { 'Content-Type': 'application/json' },
        })

        const response = await roiPOST(request, mockContext)
        expect(response.status).toBe(200)
      }
    })

    it('should reject invalid granularity parameter', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: JSON.stringify({
          granularity: 'invalid-granularity',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('Invalid granularity')
    })
  })

  describe('PUT /api/roi - Update Conversion Data', () => {
    it('should update conversion data successfully', async () => {
      const mockUpdateResult = {
        updatedCampaigns: 2,
        totalConversions: 250,
        totalRevenue: 125000,
      }

      ;(ROIService.updateConversionData as jest.Mock).mockResolvedValue(mockUpdateResult)

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'PUT',
        body: JSON.stringify({
          conversions: [
            {
              campaignId: 'campaign-1',
              conversions: 150,
              revenue: 75000,
              date: '2024-01-15',
            },
            {
              campaignId: 'campaign-2',
              conversions: 100,
              revenue: 50000,
              date: '2024-01-15',
            },
          ],
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(mockUpdateResult)
      expect(data.message).toBe('Conversion data updated successfully')
      expect(ROIService.updateConversionData).toHaveBeenCalledWith(
        'workspace-123',
        expect.arrayContaining([
          expect.objectContaining({
            campaignId: 'campaign-1',
            conversions: 150,
            revenue: 75000,
          }),
        ])
      )
    })

    it('should reject update without conversion data', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'PUT',
        body: JSON.stringify({}),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Conversion data is required')
    })

    it('should handle conversion update service errors', async () => {
      ;(ROIService.updateConversionData as jest.Mock).mockRejectedValue(
        new Error('Update failed')
      )

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'PUT',
        body: JSON.stringify({
          conversions: [
            {
              campaignId: 'campaign-1',
              conversions: 150,
              revenue: 75000,
            },
          ],
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to update conversion data')
      expect(logger.error).toHaveBeenCalled()
    })
  })

  describe('POST /api/roi/export - Export ROI Report', () => {
    it('should export ROI report in JSON format', async () => {
      const mockExportResult = {
        exportId: 'roi-export-123456789-abc123',
        format: 'json',
        downloadUrl: '/api/roi/export/roi-export-123456789-abc123/download',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      }

      ;(ROIService.exportROIReport as jest.Mock).mockResolvedValue(mockExportResult)

      const request = new NextRequest('http://localhost:3000/api/roi/export', {
        method: 'POST',
        body: JSON.stringify({
          reportId: 'roi-report-123456789-abc123',
          format: 'json',
          includeCharts: false,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiExportPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(mockExportResult)
      expect(data.message).toBe('ROI report export started')
      expect(ROIService.exportROIReport).toHaveBeenCalledWith(
        'roi-report-123456789-abc123',
        'json',
        expect.objectContaining({
          includeCharts: false,
          workspaceId: 'workspace-123',
        })
      )
    })

    it('should export ROI report in CSV format', async () => {
      const mockExportResult = {
        exportId: 'roi-export-csv-123',
        format: 'csv',
        downloadUrl: '/api/roi/export/roi-export-csv-123/download',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      }

      ;(ROIService.exportROIReport as jest.Mock).mockResolvedValue(mockExportResult)

      const request = new NextRequest('http://localhost:3000/api/roi/export', {
        method: 'POST',
        body: JSON.stringify({
          reportId: 'roi-report-123456789-abc123',
          format: 'csv',
          includeCharts: false,
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiExportPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data.format).toBe('csv')
    })

    it('should export ROI report in PDF format with charts', async () => {
      const mockExportResult = {
        exportId: 'roi-export-pdf-123',
        format: 'pdf',
        downloadUrl: '/api/roi/export/roi-export-pdf-123/download',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      }

      ;(ROIService.exportROIReport as jest.Mock).mockResolvedValue(mockExportResult)

      const request = new NextRequest('http://localhost:3000/api/roi/export', {
        method: 'POST',
        body: JSON.stringify({
          reportId: 'roi-report-123456789-abc123',
          format: 'pdf',
          includeCharts: true,
          chartTypes: ['roi-trend', 'campaign-comparison', 'revenue-breakdown'],
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiExportPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.data.format).toBe('pdf')
      expect(ROIService.exportROIReport).toHaveBeenCalledWith(
        'roi-report-123456789-abc123',
        'pdf',
        expect.objectContaining({
          includeCharts: true,
          chartTypes: ['roi-trend', 'campaign-comparison', 'revenue-breakdown'],
        })
      )
    })

    it('should reject export without report ID', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi/export', {
        method: 'POST',
        body: JSON.stringify({
          format: 'json',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiExportPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Report ID and format are required')
    })

    it('should reject export with invalid format', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi/export', {
        method: 'POST',
        body: JSON.stringify({
          reportId: 'roi-report-123456789-abc123',
          format: 'invalid-format',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiExportPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Invalid export format. Supported formats: json, csv, pdf')
    })

    it('should handle export service errors', async () => {
      ;(ROIService.exportROIReport as jest.Mock).mockRejectedValue(
        new Error('Export service unavailable')
      )

      const request = new NextRequest('http://localhost:3000/api/roi/export', {
        method: 'POST',
        body: JSON.stringify({
          reportId: 'roi-report-123456789-abc123',
          format: 'json',
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiExportPOST(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to export ROI report')
      expect(logger.error).toHaveBeenCalled()
    })
  })

  describe('GET /api/roi/export - Get Export Formats', () => {
    it('should return available export formats and options', async () => {
      const mockFormats = {
        formats: [
          {
            type: 'json',
            name: 'JSON',
            description: 'Machine-readable JSON format',
            options: {
              includeCharts: false,
              maxFileSize: '10MB',
            },
          },
          {
            type: 'csv',
            name: 'CSV',
            description: 'Comma-separated values for spreadsheet applications',
            options: {
              includeCharts: false,
              maxFileSize: '5MB',
            },
          },
          {
            type: 'pdf',
            name: 'PDF',
            description: 'Formatted PDF report with optional charts',
            options: {
              includeCharts: true,
              chartTypes: ['roi-trend', 'campaign-comparison', 'revenue-breakdown'],
              maxFileSize: '50MB',
            },
          },
        ],
        chartTypes: [
          { id: 'roi-trend', name: 'ROI Trend Over Time' },
          { id: 'campaign-comparison', name: 'Campaign Performance Comparison' },
          { id: 'revenue-breakdown', name: 'Revenue Breakdown by Source' },
        ],
      }

      ;(ROIService.getExportFormats as jest.Mock).mockReturnValue(mockFormats)

      const request = new NextRequest('http://localhost:3000/api/roi/export')

      const response = await roiExportGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.data).toEqual(mockFormats)
      expect(data.message).toBe('Export formats retrieved successfully')
    })

    it('should handle service errors when retrieving formats', async () => {
      ;(ROIService.getExportFormats as jest.Mock).mockImplementation(() => {
        throw new Error('Service error')
      })

      const request = new NextRequest('http://localhost:3000/api/roi/export')

      const response = await roiExportGET(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(500)
      expect(data.error).toBe('Failed to retrieve export formats')
      expect(logger.error).toHaveBeenCalled()
    })
  })

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent ROI report generation', async () => {
      ;(ROIService.generateROIReport as jest.Mock).mockResolvedValue({
        reportId: 'roi-concurrent',
        summary: {},
        campaigns: [],
        timeframe: {},
        generatedAt: new Date().toISOString(),
      })

      const requests = Array.from({ length: 5 }, () =>
        new NextRequest('http://localhost:3000/api/roi', {
          method: 'POST',
          body: JSON.stringify({}),
          headers: { 'Content-Type': 'application/json' },
        })
      )

      const responses = await Promise.all(requests.map(req => roiPOST(req, mockContext)))

      responses.forEach(response => {
        expect([200, 429, 500]).toContain(response.status)
      })
    })

    it('should handle large conversion data updates', async () => {
      const largeConversions = Array.from({ length: 10000 }, (_, i) => ({
        campaignId: `campaign-${i}`,
        conversions: Math.floor(Math.random() * 100),
        revenue: Math.floor(Math.random() * 10000),
        date: '2024-01-15',
      }))

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'PUT',
        body: JSON.stringify({ conversions: largeConversions }),
        headers: { 'Content-Type': 'application/json' },
      })

      const response = await roiPUT(request, mockContext)

      expect([200, 413, 500]).toContain(response.status)
    })

    it('should validate conversion data format', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'PUT',
        body: JSON.stringify({
          conversions: [
            {
              campaignId: 'campaign-1',
              // Missing conversions and revenue
            },
          ],
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('Invalid conversion data format')
    })

    it('should handle network timeouts gracefully', async () => {
      ;(ROIService.generateROIReport as jest.Mock).mockImplementation(
        () => new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Network timeout')), 100)
        )
      )

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: JSON.stringify({}),
        headers: { 'Content-Type': 'application/json' },
      })

      const response = await roiPOST(request, mockContext)

      expect(response.status).toBe(500)
    })

    it('should handle memory pressure during report generation', async () => {
      ;(ROIService.generateROIReport as jest.Mock).mockRejectedValue(
        new Error('Insufficient memory')
      )

      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'POST',
        body: JSON.stringify({
          campaignIds: Array.from({ length: 10000 }, (_, i) => `campaign-${i}`),
        }),
        headers: { 'Content-Type': 'application/json' },
      })

      const response = await roiPOST(request, mockContext)

      expect(response.status).toBe(500)
    })

    it('should validate date formats in conversion data', async () => {
      const request = new NextRequest('http://localhost:3000/api/roi', {
        method: 'PUT',
        body: JSON.stringify({
          conversions: [
            {
              campaignId: 'campaign-1',
              conversions: 150,
              revenue: 75000,
              date: 'invalid-date-format',
            },
          ],
        }),
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const response = await roiPUT(request, mockContext)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('Invalid date format')
    })
  })
})
