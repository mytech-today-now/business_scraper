/**
 * CRM Export Service Integration Tests
 * Integration tests for the CRM export service
 */

import { CRMExportService } from '@/utils/crm/crmExportService'
import { crmTemplateManager } from '@/utils/crm/crmTemplateManager'
import { BusinessRecord } from '@/types/business'
import { CRMTemplate } from '@/utils/crm/types'

describe('CRMExportService Integration', () => {
  let exportService: CRMExportService
  let mockBusinessRecords: BusinessRecord[]
  let salesforceTemplate: CRMTemplate

  beforeEach(() => {
    exportService = new CRMExportService()

    mockBusinessRecords = [
      {
        id: 'test-1',
        businessName: 'Tech Startup Inc',
        url: 'https://techstartup.com',
        phone: '555-123-4567',
        email: 'contact@techstartup.com',
        address: '123 Innovation Dr',
        city: 'San Francisco',
        state: 'CA',
        zipCode: '94105',
        industry: 'technology',
        confidence: 0.95,
        source: 'web',
        scrapedAt: '2024-01-01T00:00:00.000Z',
      },
      {
        id: 'test-2',
        businessName: 'Local Restaurant',
        url: 'https://localrestaurant.com',
        phone: '555-987-6543',
        email: 'info@localrestaurant.com',
        address: '456 Food St',
        city: 'Los Angeles',
        state: 'CA',
        zipCode: '90210',
        industry: 'restaurants',
        confidence: 0.88,
        source: 'directory',
        scrapedAt: '2024-01-01T00:00:00.000Z',
      },
      {
        id: 'test-3',
        businessName: 'Healthcare Clinic',
        url: 'https://healthcareclinic.com',
        phone: '555-555-5555',
        email: 'appointments@healthcareclinic.com',
        address: '789 Medical Blvd',
        city: 'San Diego',
        state: 'CA',
        zipCode: '92101',
        industry: 'healthcare',
        confidence: 0.92,
        source: 'search',
        scrapedAt: '2024-01-01T00:00:00.000Z',
      },
    ]

    // Get Salesforce template for testing
    salesforceTemplate = crmTemplateManager.getTemplatesByPlatform('salesforce')[0]
  })

  describe('exportWithCRMTemplate', () => {
    it('should export business records using Salesforce template', async () => {
      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        salesforceTemplate,
        { template: salesforceTemplate }
      )

      expect(result).toBeDefined()
      expect(result.blob).toBeInstanceOf(Blob)
      expect(result.filename).toContain('salesforce')
      expect(result.filename).toContain('.csv')
      expect(result.statistics.totalRecords).toBe(3)
      expect(result.statistics.exportedRecords).toBe(3)
      expect(result.template).toEqual(salesforceTemplate)
    })

    it('should handle progress callbacks', async () => {
      const progressUpdates: any[] = []

      await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        salesforceTemplate,
        { template: salesforceTemplate },
        progress => {
          progressUpdates.push(progress)
        }
      )

      expect(progressUpdates.length).toBeGreaterThan(0)
      expect(progressUpdates[0].step).toBe('validating')
      expect(progressUpdates[progressUpdates.length - 1].step).toBe('complete')
      expect(progressUpdates[progressUpdates.length - 1].percentage).toBe(100)
    })

    it('should generate CSV export correctly', async () => {
      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        salesforceTemplate,
        { template: salesforceTemplate, includeHeaders: true }
      )

      const csvText = await result.blob.text()
      const lines = csvText.split('\n').filter(line => line.trim())

      // Should have header + 3 data rows
      expect(lines.length).toBe(4)

      // Check headers
      const headers = lines[0].split(',')
      expect(headers).toContain('Company')
      expect(headers).toContain('Email')
      expect(headers).toContain('Phone')

      // Check data
      expect(csvText).toContain('Tech Startup Inc')
      expect(csvText).toContain('Local Restaurant')
      expect(csvText).toContain('Healthcare Clinic')
    })

    it('should handle HubSpot JSON export', async () => {
      const hubspotTemplates = crmTemplateManager.getTemplatesByPlatform('hubspot')
      const jsonTemplate = hubspotTemplates.find(t => t.exportFormat === 'json')

      if (jsonTemplate) {
        const result = await exportService.exportWithCRMTemplate(
          mockBusinessRecords,
          jsonTemplate,
          { template: jsonTemplate }
        )

        expect(result.blob.type).toBe('application/json')

        const jsonText = await result.blob.text()
        const jsonData = JSON.parse(jsonText)

        expect(jsonData.metadata).toBeDefined()
        expect(jsonData.records).toHaveLength(3)
        expect(jsonData.metadata.platform).toBe('hubspot')
      }
    })

    it('should validate records and skip invalid ones', async () => {
      const invalidRecords = [
        ...mockBusinessRecords,
        {
          id: 'invalid-1',
          businessName: '', // Missing required field
          url: '',
          phone: '',
          email: 'invalid-email', // Invalid email
          address: '',
          city: '',
          state: '',
          zipCode: '',
          industry: '',
          confidence: 0,
          source: 'test',
          scrapedAt: '2024-01-01T00:00:00.000Z',
        },
      ]

      const result = await exportService.exportWithCRMTemplate(invalidRecords, salesforceTemplate, {
        template: salesforceTemplate,
        skipInvalidRecords: true,
      })

      expect(result.statistics.totalRecords).toBe(4)
      expect(result.statistics.exportedRecords).toBe(3) // Only valid records
      expect(result.statistics.skippedRecords).toBe(1)
      expect(result.statistics.errors.length).toBeGreaterThan(0)
    })

    it('should handle empty record set', async () => {
      const result = await exportService.exportWithCRMTemplate([], salesforceTemplate, {
        template: salesforceTemplate,
      })

      expect(result.statistics.totalRecords).toBe(0)
      expect(result.statistics.exportedRecords).toBe(0)
      expect(result.blob.size).toBeGreaterThan(0) // Should still have headers
    })

    it('should generate proper filename with timestamp', async () => {
      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        salesforceTemplate,
        { template: salesforceTemplate }
      )

      expect(result.filename).toMatch(/^salesforce-.*-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.csv$/)
    })

    it('should include export metadata', async () => {
      const result = await exportService.exportWithCRMTemplate(
        mockBusinessRecords,
        salesforceTemplate,
        {
          template: salesforceTemplate,
          metadata: {
            exportedBy: 'Test User',
            exportPurpose: 'Integration Test',
            notes: 'Test export',
          },
        }
      )

      expect(result.metadata.exportDate).toBeDefined()
      expect(result.metadata.platform).toBe('salesforce')
      expect(result.metadata.format).toBe('csv')
      expect(result.metadata.version).toBeDefined()
    })
  })

  describe('getExportPreview', () => {
    it('should generate preview with limited records', async () => {
      const preview = await exportService.getExportPreview(
        mockBusinessRecords,
        salesforceTemplate,
        { template: salesforceTemplate },
        2 // Preview only 2 records
      )

      expect(preview.preview).toHaveLength(2)
      expect(preview.totalRecords).toBe(3)
      expect(preview.errors).toBeDefined()
      expect(preview.warnings).toBeDefined()
    })

    it('should show validation errors in preview', async () => {
      const invalidRecords = [
        { ...mockBusinessRecords[0], businessName: '' }, // Invalid
      ]

      const preview = await exportService.getExportPreview(invalidRecords, salesforceTemplate, {
        template: salesforceTemplate,
      })

      expect(preview.errors.length).toBeGreaterThan(0)
      expect(preview.errors.some(e => e.field === 'Company')).toBe(true)
    })
  })

  describe('validateRecords', () => {
    it('should validate all records against template', async () => {
      const validation = await exportService.validateRecords(
        mockBusinessRecords,
        salesforceTemplate
      )

      expect(validation.validCount).toBe(3)
      expect(validation.invalidCount).toBe(0)
      expect(validation.errors).toHaveLength(0)
      expect(validation.warnings).toHaveLength(0)
    })

    it('should identify invalid records', async () => {
      const invalidRecords = [
        ...mockBusinessRecords,
        { ...mockBusinessRecords[0], businessName: '', email: 'invalid' },
      ]

      const validation = await exportService.validateRecords(invalidRecords, salesforceTemplate)

      expect(validation.validCount).toBe(3)
      expect(validation.invalidCount).toBe(1)
      expect(validation.errors.length).toBeGreaterThan(0)
    })
  })

  describe('platform and template management', () => {
    it('should get available platforms', () => {
      const platforms = exportService.getAvailablePlatforms()

      expect(platforms.length).toBeGreaterThan(0)
      expect(platforms.some(p => p.platform === 'salesforce')).toBe(true)
      expect(platforms.some(p => p.platform === 'hubspot')).toBe(true)
      expect(platforms.some(p => p.platform === 'pipedrive')).toBe(true)
    })

    it('should get templates for specific platform', () => {
      const salesforceTemplates = exportService.getTemplatesForPlatform('salesforce')

      expect(salesforceTemplates.length).toBeGreaterThan(0)
      expect(salesforceTemplates.every(t => t.platform === 'salesforce')).toBe(true)
    })

    it('should get template by ID', () => {
      const template = exportService.getTemplate(salesforceTemplate.id)

      expect(template).toBeDefined()
      expect(template?.id).toBe(salesforceTemplate.id)
    })
  })

  describe('error handling', () => {
    it('should handle invalid template platform', async () => {
      const invalidTemplate = {
        ...salesforceTemplate,
        platform: 'invalid-platform' as any,
      }

      await expect(
        exportService.exportWithCRMTemplate(mockBusinessRecords, invalidTemplate, {
          template: invalidTemplate,
        })
      ).rejects.toThrow('No adapter found for platform')
    })

    it('should handle transformation errors gracefully', async () => {
      // Create a template with invalid field mapping
      const errorTemplate = {
        ...salesforceTemplate,
        fieldMappings: [
          {
            sourceField: 'nonexistent.field.path',
            targetField: 'TestField',
            transformer: () => {
              throw new Error('Test transformation error')
            },
            validation: { required: false, type: 'string' as const },
          },
        ],
      }

      const result = await exportService.exportWithCRMTemplate(mockBusinessRecords, errorTemplate, {
        template: errorTemplate,
        skipInvalidRecords: true,
      })

      expect(result.statistics.errors.length).toBeGreaterThan(0)
      expect(result.statistics.warnings.length).toBeGreaterThan(0)
    })
  })

  describe('performance', () => {
    it('should handle large datasets efficiently', async () => {
      // Create a larger dataset
      const largeDataset = Array.from({ length: 100 }, (_, i) => ({
        ...mockBusinessRecords[0],
        id: `test-${i}`,
        businessName: `Business ${i}`,
        email: `contact${i}@business.com`,
      }))

      const startTime = Date.now()

      const result = await exportService.exportWithCRMTemplate(largeDataset, salesforceTemplate, {
        template: salesforceTemplate,
      })

      const processingTime = Date.now() - startTime

      expect(result.statistics.totalRecords).toBe(100)
      expect(result.statistics.exportedRecords).toBe(100)
      expect(processingTime).toBeLessThan(5000) // Should complete within 5 seconds
      expect(result.statistics.processingTime).toBeGreaterThan(0)
    })

    it('should provide accurate progress updates for large datasets', async () => {
      const largeDataset = Array.from({ length: 50 }, (_, i) => ({
        ...mockBusinessRecords[0],
        id: `test-${i}`,
        businessName: `Business ${i}`,
      }))

      const progressUpdates: any[] = []

      await exportService.exportWithCRMTemplate(
        largeDataset,
        salesforceTemplate,
        { template: salesforceTemplate },
        progress => {
          progressUpdates.push(progress)
        }
      )

      expect(progressUpdates.length).toBeGreaterThan(2)
      expect(progressUpdates[0].percentage).toBe(0)
      expect(progressUpdates[progressUpdates.length - 1].percentage).toBe(100)

      // Progress should be monotonically increasing
      for (let i = 1; i < progressUpdates.length; i++) {
        expect(progressUpdates[i].percentage).toBeGreaterThanOrEqual(
          progressUpdates[i - 1].percentage
        )
      }
    })
  })
})
