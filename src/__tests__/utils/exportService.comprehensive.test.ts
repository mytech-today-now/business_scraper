/**
 * Comprehensive Business Rule Tests for Export Service
 * Tests export functionality, format validation, and CRM integration
 */

import { ExportService } from '@/utils/exportService'
import { CRMExportService } from '@/utils/crm/crmExportService'
import { CRMTemplateManager } from '@/utils/crm/crmTemplateManager'
import { ValidationService } from '@/utils/validation'
import { BusinessRecord } from '@/types/business'
import { CRMTemplate, CRMExportOptions } from '@/utils/crm/types'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/utils/crm/crmExportService')
jest.mock('@/utils/crm/crmTemplateManager')
jest.mock('@/utils/validation')

describe('Export Service - Business Logic Rules', () => {
  let exportService: ExportService
  let mockCRMExportService: jest.Mocked<CRMExportService>
  let mockCRMTemplateManager: jest.Mocked<CRMTemplateManager>
  let mockValidationService: jest.Mocked<ValidationService>

  const mockBusinessRecords: BusinessRecord[] = [
    {
      id: 'business-1',
      businessName: 'Acme Corporation',
      email: ['contact@acme.com', 'sales@acme.com'],
      phone: '+1-555-123-4567',
      websiteUrl: 'https://acme.com',
      address: {
        street: '123 Main Street',
        city: 'San Francisco',
        state: 'CA',
        zipCode: '94105',
      },
      industry: 'Technology',
      description: 'Leading technology solutions provider',
      scrapedAt: new Date(),
    },
    {
      id: 'business-2',
      businessName: 'Beta Industries',
      email: ['info@beta.com'],
      phone: '+1-555-987-6543',
      websiteUrl: 'https://beta.com',
      address: {
        street: '456 Oak Avenue',
        city: 'New York',
        state: 'NY',
        zipCode: '10001',
      },
      industry: 'Manufacturing',
      description: 'Industrial manufacturing company',
      scrapedAt: new Date(),
    },
  ]

  const mockSalesforceTemplate: CRMTemplate = {
    id: 'salesforce-leads',
    name: 'Salesforce Leads',
    platform: 'salesforce',
    description: 'Standard Salesforce lead import template',
    exportFormat: 'csv',
    fieldMappings: [
      {
        sourceField: 'businessName',
        targetField: 'Company',
        required: true,
        validation: { required: true, type: 'string', maxLength: 255 },
        description: 'Company name',
      },
      {
        sourceField: 'email',
        targetField: 'Email',
        required: true,
        validation: { required: true, type: 'email' },
        description: 'Primary email address',
      },
    ],
    customHeaders: {
      businessName: 'Company',
      email: 'Email',
      phone: 'Phone',
    },
    metadata: {
      version: '1.0',
      author: 'System',
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-01T00:00:00Z',
      tags: ['salesforce', 'leads'],
    },
    validation: {
      strictMode: true,
      skipInvalidRecords: false,
      maxErrors: 10,
    },
  }

  beforeEach(() => {
    exportService = new ExportService()
    mockCRMExportService = new CRMExportService() as jest.Mocked<CRMExportService>
    mockCRMTemplateManager = new CRMTemplateManager() as jest.Mocked<CRMTemplateManager>
    mockValidationService = new ValidationService() as jest.Mocked<ValidationService>

    // Setup mocks
    ;(exportService as any).crmExportService = mockCRMExportService
    ;(exportService as any).crmTemplateManager = mockCRMTemplateManager
    ;(exportService as any).validationService = mockValidationService

    jest.clearAllMocks()
  })

  describe('Export Format Generation', () => {
    test('should generate CSV export with proper formatting', async () => {
      const mockBlob = new Blob(['Company,Email,Phone\nAcme Corporation,contact@acme.com,+1-555-123-4567'], {
        type: 'text/csv',
      })

      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: mockBlob,
        filename: 'salesforce-leads-2024-01-01.csv',
        statistics: {
          totalRecords: 2,
          exportedRecords: 2,
          skippedRecords: 0,
          errors: [],
          processingTime: 100,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'csv',
          version: '1.0',
        },
      })

      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        mockSalesforceTemplate,
        { includeHeaders: true }
      )

      expect(result.blob.type).toBe('text/csv')
      expect(result.filename).toMatch(/salesforce-leads-.*\.csv$/)

      const csvContent = await result.blob.text()
      expect(csvContent).toContain('Company,Email,Phone')
      expect(csvContent).toContain('Acme Corporation')
    })

    test('should generate JSON export with proper structure', async () => {
      const jsonTemplate = {
        ...mockSalesforceTemplate,
        exportFormat: 'json' as const,
      }

      const mockJsonData = {
        metadata: {
          platform: 'salesforce',
          template: 'Salesforce Leads',
          exportDate: new Date().toISOString(),
          totalRecords: 2,
        },
        records: [
          {
            Company: 'Acme Corporation',
            Email: 'contact@acme.com',
            Phone: '+1-555-123-4567',
          },
          {
            Company: 'Beta Industries',
            Email: 'info@beta.com',
            Phone: '+1-555-987-6543',
          },
        ],
      }

      const mockBlob = new Blob([JSON.stringify(mockJsonData)], {
        type: 'application/json',
      })

      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: mockBlob,
        filename: 'salesforce-leads-2024-01-01.json',
        statistics: {
          totalRecords: 2,
          exportedRecords: 2,
          skippedRecords: 0,
          errors: [],
          processingTime: 150,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'json',
          version: '1.0',
        },
      })

      const result = await exportService.exportWithCRMTemplate(mockBusinessRecords, jsonTemplate)

      expect(result.blob.type).toBe('application/json')

      const jsonContent = await result.blob.text()
      const parsedData = JSON.parse(jsonContent)

      expect(parsedData.metadata).toBeDefined()
      expect(parsedData.records).toHaveLength(2)
      expect(parsedData.metadata.platform).toBe('salesforce')
    })

    test('should generate XML export with proper structure', async () => {
      const xmlTemplate = {
        ...mockSalesforceTemplate,
        exportFormat: 'xml' as const,
      }

      const mockXmlContent = `<?xml version="1.0" encoding="UTF-8"?>
<export platform="salesforce" template="Salesforce Leads">
  <record>
    <Company>Acme Corporation</Company>
    <Email>contact@acme.com</Email>
    <Phone>+1-555-123-4567</Phone>
  </record>
  <record>
    <Company>Beta Industries</Company>
    <Email>info@beta.com</Email>
    <Phone>+1-555-987-6543</Phone>
  </record>
</export>`

      const mockBlob = new Blob([mockXmlContent], {
        type: 'application/xml',
      })

      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: mockBlob,
        filename: 'salesforce-leads-2024-01-01.xml',
        statistics: {
          totalRecords: 2,
          exportedRecords: 2,
          skippedRecords: 0,
          errors: [],
          processingTime: 120,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'xml',
          version: '1.0',
        },
      })

      const result = await exportService.exportWithCRMTemplate(mockBusinessRecords, xmlTemplate)

      expect(result.blob.type).toBe('application/xml')

      const xmlContent = await result.blob.text()
      expect(xmlContent).toContain('<?xml version="1.0" encoding="UTF-8"?>')
      expect(xmlContent).toContain('<export platform="salesforce"')
      expect(xmlContent).toContain('<Company>Acme Corporation</Company>')
    })
  })

  describe('Data Validation Rules', () => {
    test('should validate required fields before export', async () => {
      const invalidRecords = [
        ...mockBusinessRecords,
        {
          id: 'invalid-1',
          businessName: '', // Missing required field
          email: [],
          phone: '',
          websiteUrl: '',
          address: {
            street: '',
            city: '',
            state: '',
            zipCode: '',
          },
          industry: '',
          description: '',
          scrapedAt: new Date(),
        },
      ]

      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: new Blob([''], { type: 'text/csv' }),
        filename: 'export.csv',
        statistics: {
          totalRecords: 3,
          exportedRecords: 2,
          skippedRecords: 1,
          errors: ['Record 3: Missing required field "businessName"'],
          processingTime: 100,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'csv',
          version: '1.0',
        },
      })

      const result = await exportService.exportWithCRMTemplate(
        invalidRecords,
        mockSalesforceTemplate,
        { skipInvalidRecords: true }
      )

      expect(result.statistics.totalRecords).toBe(3)
      expect(result.statistics.exportedRecords).toBe(2)
      expect(result.statistics.skippedRecords).toBe(1)
      expect(result.statistics.errors).toContain('Record 3: Missing required field "businessName"')
    })

    test('should validate email format in records', async () => {
      const recordsWithInvalidEmail = [
        {
          ...mockBusinessRecords[0],
          email: ['invalid-email-format'],
        },
      ]

      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: new Blob([''], { type: 'text/csv' }),
        filename: 'export.csv',
        statistics: {
          totalRecords: 1,
          exportedRecords: 0,
          skippedRecords: 1,
          errors: ['Record 1: Invalid email format "invalid-email-format"'],
          processingTime: 50,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'csv',
          version: '1.0',
        },
      })

      const result = await exportService.exportWithCRMTemplate(
        recordsWithInvalidEmail,
        mockSalesforceTemplate,
        { skipInvalidRecords: true }
      )

      expect(result.statistics.skippedRecords).toBe(1)
      expect(result.statistics.errors[0]).toContain('Invalid email format')
    })

    test('should handle field length validation', async () => {
      const recordsWithLongFields = [
        {
          ...mockBusinessRecords[0],
          businessName: 'A'.repeat(300), // Exceeds 255 character limit
        },
      ]

      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: new Blob([''], { type: 'text/csv' }),
        filename: 'export.csv',
        statistics: {
          totalRecords: 1,
          exportedRecords: 0,
          skippedRecords: 1,
          errors: ['Record 1: Field "businessName" exceeds maximum length of 255 characters'],
          processingTime: 50,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'csv',
          version: '1.0',
        },
      })

      const result = await exportService.exportWithCRMTemplate(
        recordsWithLongFields,
        mockSalesforceTemplate,
        { skipInvalidRecords: true }
      )

      expect(result.statistics.skippedRecords).toBe(1)
      expect(result.statistics.errors[0]).toContain('exceeds maximum length')
    })
  })

  describe('CRM Integration Logic', () => {
    test('should handle Salesforce template integration', async () => {
      mockCRMTemplateManager.getTemplatesByPlatform.mockReturnValue([mockSalesforceTemplate])

      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        mockSalesforceTemplate
      )

      expect(mockCRMExportService.exportWithCRMTemplate).toHaveBeenCalledWith(
        mockBusinessRecords,
        mockSalesforceTemplate,
        expect.objectContaining({
          template: mockSalesforceTemplate,
          validateData: true,
          skipInvalidRecords: true,
        })
      )
    })

    test('should handle HubSpot template integration', async () => {
      const hubspotTemplate = {
        ...mockSalesforceTemplate,
        id: 'hubspot-contacts',
        name: 'HubSpot Contacts',
        platform: 'hubspot' as const,
        exportFormat: 'json' as const,
      }

      mockCRMTemplateManager.getTemplatesByPlatform.mockReturnValue([hubspotTemplate])

      const result = await exportService.exportWithCRMTemplate(mockBusinessRecords, hubspotTemplate)

      expect(mockCRMExportService.exportWithCRMTemplate).toHaveBeenCalledWith(
        mockBusinessRecords,
        hubspotTemplate,
        expect.objectContaining({
          template: hubspotTemplate,
        })
      )
    })

    test('should handle Pipedrive template integration', async () => {
      const pipedriveTemplate = {
        ...mockSalesforceTemplate,
        id: 'pipedrive-deals',
        name: 'Pipedrive Deals',
        platform: 'pipedrive' as const,
        exportFormat: 'csv' as const,
      }

      const result = await exportService.exportWithCRMTemplate(mockBusinessRecords, pipedriveTemplate)

      expect(mockCRMExportService.exportWithCRMTemplate).toHaveBeenCalledWith(
        mockBusinessRecords,
        pipedriveTemplate,
        expect.any(Object)
      )
    })
  })

  describe('Export Options and Configuration', () => {
    test('should handle custom headers configuration', async () => {
      const customHeadersTemplate = {
        ...mockSalesforceTemplate,
        customHeaders: {
          businessName: 'Organization Name',
          email: 'Primary Email',
          phone: 'Contact Number',
        },
      }

      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        customHeadersTemplate,
        { includeHeaders: true }
      )

      expect(mockCRMExportService.exportWithCRMTemplate).toHaveBeenCalledWith(
        mockBusinessRecords,
        customHeadersTemplate,
        expect.objectContaining({
          includeHeaders: true,
        })
      )
    })

    test('should handle date format configuration', async () => {
      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        mockSalesforceTemplate,
        { dateFormat: 'YYYY-MM-DD' }
      )

      expect(mockCRMExportService.exportWithCRMTemplate).toHaveBeenCalledWith(
        mockBusinessRecords,
        mockSalesforceTemplate,
        expect.objectContaining({
          dateFormat: 'YYYY-MM-DD',
        })
      )
    })

    test('should handle metadata inclusion', async () => {
      const metadata = {
        exportedBy: 'Test User',
        exportPurpose: 'CRM Integration',
        notes: 'Test export with metadata',
      }

      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        mockSalesforceTemplate,
        { metadata }
      )

      expect(mockCRMExportService.exportWithCRMTemplate).toHaveBeenCalledWith(
        mockBusinessRecords,
        mockSalesforceTemplate,
        expect.objectContaining({
          metadata: expect.objectContaining(metadata),
        })
      )
    })
  })

  describe('Error Handling and Edge Cases', () => {
    test('should handle empty business records', async () => {
      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: new Blob(['Company,Email,Phone\n'], { type: 'text/csv' }),
        filename: 'empty-export.csv',
        statistics: {
          totalRecords: 0,
          exportedRecords: 0,
          skippedRecords: 0,
          errors: [],
          processingTime: 10,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'csv',
          version: '1.0',
        },
      })

      const result = await exportService.exportWithCRMTemplate([], mockSalesforceTemplate)

      expect(result.statistics.totalRecords).toBe(0)
      expect(result.statistics.exportedRecords).toBe(0)
      expect(result.blob.size).toBeGreaterThan(0) // Should still have headers
    })

    test('should handle invalid template platform', async () => {
      const invalidTemplate = {
        ...mockSalesforceTemplate,
        platform: 'invalid-platform' as any,
      }

      mockCRMExportService.exportWithCRMTemplate.mockRejectedValue(
        new Error('No adapter found for platform: invalid-platform')
      )

      await expect(
        exportService.exportWithCRMTemplate(mockBusinessRecords, invalidTemplate)
      ).rejects.toThrow('No adapter found for platform')
    })

    test('should handle export service failures gracefully', async () => {
      mockCRMExportService.exportWithCRMTemplate.mockRejectedValue(
        new Error('Export service temporarily unavailable')
      )

      await expect(
        exportService.exportWithCRMTemplate(mockBusinessRecords, mockSalesforceTemplate)
      ).rejects.toThrow('Export service temporarily unavailable')
    })

    test('should handle large datasets efficiently', async () => {
      const largeDataset = Array(1000)
        .fill(0)
        .map((_, i) => ({
          ...mockBusinessRecords[0],
          id: `business-${i}`,
          businessName: `Business ${i}`,
        }))

      mockCRMExportService.exportWithCRMTemplate.mockResolvedValue({
        blob: new Blob(['large dataset'], { type: 'text/csv' }),
        filename: 'large-export.csv',
        statistics: {
          totalRecords: 1000,
          exportedRecords: 1000,
          skippedRecords: 0,
          errors: [],
          processingTime: 2000,
        },
        metadata: {
          exportDate: new Date(),
          platform: 'salesforce',
          format: 'csv',
          version: '1.0',
        },
      })

      const startTime = Date.now()
      const result = await exportService.exportWithCRMTemplate(largeDataset, mockSalesforceTemplate)
      const endTime = Date.now()

      expect(result.statistics.totalRecords).toBe(1000)
      expect(result.statistics.exportedRecords).toBe(1000)
      expect(endTime - startTime).toBeLessThan(5000) // Should complete within 5 seconds
    })
  })

  describe('Performance and Efficiency', () => {
    test('should complete export within reasonable time', async () => {
      const startTime = Date.now()

      await exportService.exportWithCRMTemplate(mockBusinessRecords, mockSalesforceTemplate)

      const endTime = Date.now()
      const processingTime = endTime - startTime

      expect(processingTime).toBeLessThan(1000) // Should complete within 1 second for small datasets
    })

    test('should handle concurrent export requests', async () => {
      const promises = Array(5)
        .fill(0)
        .map(() => exportService.exportWithCRMTemplate(mockBusinessRecords, mockSalesforceTemplate))

      const startTime = Date.now()
      const results = await Promise.all(promises)
      const endTime = Date.now()

      expect(results).toHaveLength(5)
      expect(endTime - startTime).toBeLessThan(3000) // Should handle concurrent requests efficiently
    })
  })
})
