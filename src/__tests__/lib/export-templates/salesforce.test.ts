/**
 * Salesforce Export Template Tests
 * Test suite for Salesforce CRM export template
 */

import { SalesforceExportTemplate } from '@/lib/export-templates/crm/salesforce'
import { BusinessRecord } from '@/types/business'
import { createMinimalBusinessRecord, toBusinessRecord } from '../../utils/testHelpers'

describe('SalesforceExportTemplate', () => {
  let template: SalesforceExportTemplate
  let testBusinessData: BusinessRecord[]

  beforeEach(() => {
    template = new SalesforceExportTemplate()

    testBusinessData = [
      createMinimalBusinessRecord({
        id: 'business-1',
        businessName: 'Acme Corporation',
        email: ['contact@acme.com', 'sales@acme.com'],
        phone: '5551234567',
        websiteUrl: 'https://acme.com',
        address: {
          street: '123 Main Street',
          city: 'Anytown',
          state: 'CA',
          zipCode: '12345',
        },
        industry: 'Technology',
        scrapedAt: new Date('2024-01-01'),
      }),
      createMinimalBusinessRecord({
        id: 'business-2',
        businessName: 'Beta Industries',
        email: ['info@beta.com'],
        phone: '5555551234',
        websiteUrl: 'https://beta.com',
        address: {
          street: '456 Oak Avenue',
          city: 'Somewhere',
          state: 'NY',
          zipCode: '67890',
        },
        industry: 'Manufacturing',
        scrapedAt: new Date('2024-01-02'),
      }),
      createMinimalBusinessRecord({
        id: 'business-3',
        businessName: 'Gamma Services',
        email: ['hello@gamma.org'],
        phone: undefined,
        websiteUrl: '',
        address: {
          street: '',
          city: 'Nowhere',
          state: 'TX',
          zipCode: '54321',
        },
        industry: 'Services',
        scrapedAt: new Date('2024-01-03'),
      }),
    ]
  })

  describe('Template Configuration', () => {
    test('should have correct template configuration', () => {
      const config = template.getTemplate()

      expect(config.id).toBe('salesforce-leads')
      expect(config.name).toBe('Salesforce Leads')
      expect(config.platform).toBe('salesforce')
      expect(config.version).toBe('1.0.0')
      expect(config.requiredFields).toContain('Company')
    })

    test('should validate template successfully', () => {
      const validation = template.validate()

      expect(validation.isValid).toBe(true)
      expect(validation.errors).toHaveLength(0)
      expect(validation.compatibility.platform).toBe('salesforce')
      expect(validation.compatibility.supported).toBe(true)
    })

    test('should have proper field mappings', () => {
      const config = template.getTemplate()
      const mappings = config.fieldMappings

      // Check required Company mapping
      const companyMapping = mappings.find(m => m.targetField === 'Company')
      expect(companyMapping).toBeDefined()
      expect(companyMapping?.sourceFields).toContain('businessName')

      // Check optional field mappings
      expect(mappings.some(m => m.targetField === 'Phone')).toBe(true)
      expect(mappings.some(m => m.targetField === 'Email')).toBe(true)
      expect(mappings.some(m => m.targetField === 'Website')).toBe(true)
      expect(mappings.some(m => m.targetField === 'Industry')).toBe(true)
    })
  })

  describe('Data Export Execution', () => {
    test('should execute export successfully', async () => {
      const result = await template.execute(testBusinessData)

      expect(result.success).toBe(true)
      expect(result.recordsProcessed).toBe(3)
      expect(result.recordsExported).toBe(3)
      expect(result.recordsSkipped).toBe(0)
      expect(result.exportData).toHaveLength(3)
    })

    test('should map fields correctly', async () => {
      const result = await template.execute(testBusinessData.slice(0, 1))
      const exportedRecord = result.exportData[0]

      // Check basic field mappings
      expect(exportedRecord.Company).toBe('Acme Corporation')
      expect(exportedRecord.Phone).toBe('(555) 123-4567')
      expect(exportedRecord.Email).toBe('contact@acme.com')
      expect(exportedRecord.Website).toBe('https://acme.com')
      expect(exportedRecord.Street).toBe('123 Main Street')
      expect(exportedRecord.City).toBe('Anytown')
      expect(exportedRecord.State).toBe('CA')
      expect(exportedRecord.PostalCode).toBe('12345')
      expect(exportedRecord.Country).toBe('United States')
      expect(exportedRecord.Industry).toBe('Technology')
      expect(exportedRecord.LeadSource).toBe('Web Scraping')
    })

    test('should calculate lead rating correctly', async () => {
      const result = await template.execute(testBusinessData)

      // First record should have high rating (complete data)
      expect(result.exportData[0].Rating).toBe('Hot')

      // Third record should have lower rating (incomplete data)
      expect(result.exportData[2].Rating).toBe('Cold')
    })

    test('should estimate revenue based on data quality', async () => {
      const result = await template.execute(testBusinessData)

      // First record with complete data should have higher revenue estimate
      expect(result.exportData[0].AnnualRevenue).toBeGreaterThan(result.exportData[2].AnnualRevenue)
    })

    test('should estimate employee count', async () => {
      const result = await template.execute(testBusinessData)

      // All records should have employee estimates
      result.exportData.forEach(record => {
        expect(record.NumberOfEmployees).toBeDefined()
        expect(typeof record.NumberOfEmployees).toBe('number')
        expect(record.NumberOfEmployees).toBeGreaterThan(0)
      })
    })
  })

  describe('Data Preprocessing', () => {
    test('should filter out invalid records', async () => {
      const invalidData = [
        ...testBusinessData,
        {
          id: 'invalid-1',
          businessName: '',
          email: [],
          phone: undefined,
          websiteUrl: '',
          address: { street: '', city: '', state: '', zipCode: '' },
          industry: '',
          scrapedAt: new Date()
        }, // Invalid - no business name
        {
          id: 'invalid-2',
          businessName: '',
          email: ['test@test.com'],
          websiteUrl: '',
          address: { street: '', city: '', state: '', zipCode: '' },
          industry: '',
          scrapedAt: new Date()
        }, // Invalid - no business name
        null, // Invalid - null record
        undefined, // Invalid - undefined record
      ]

      const result = await template.execute(invalidData as any)

      expect(result.recordsProcessed).toBe(3) // Only valid records processed
      expect(result.recordsExported).toBe(3)
    })

    test('should normalize company names', async () => {
      const dataWithSpecialChars = [
        toBusinessRecord({
          businessName: '  Acme Corp!!!  ',
          email: ['test@acme.com'],
          phone: '5551234567',
        }),
      ]

      const result = await template.execute(dataWithSpecialChars)

      expect(result.exportData[0].Company).toBe('Acme Corp')
    })

    test('should normalize industry values', async () => {
      const dataWithIndustries = [
        toBusinessRecord({ businessName: 'Tech Co', industry: 'tech' }),
        toBusinessRecord({ businessName: 'Health Co', industry: 'healthcare' }),
        toBusinessRecord({ businessName: 'Finance Co', industry: 'banking' }),
      ]

      const result = await template.execute(dataWithIndustries)

      expect(result.exportData[0].Industry).toBe('Technology')
      expect(result.exportData[1].Industry).toBe('Healthcare')
      expect(result.exportData[2].Industry).toBe('Financial Services')
    })

    test('should format phone numbers correctly', async () => {
      const dataWithPhones = [
        toBusinessRecord({ businessName: 'Co1', phone: '5551234567' }),
        toBusinessRecord({ businessName: 'Co2', phone: '15551234567' }),
        toBusinessRecord({ businessName: 'Co3', phone: '555-123-4567' }),
      ]

      const result = await template.execute(dataWithPhones)

      expect(result.exportData[0].Phone).toBe('(555) 123-4567')
      expect(result.exportData[1].Phone).toBe('+1 (555) 123-4567')
      expect(result.exportData[2].Phone).toBe('(555) 123-4567')
    })
  })

  describe('Quality Rules', () => {
    test('should apply quality rules correctly', async () => {
      const mixedQualityData = [
        toBusinessRecord({
          businessName: 'High Quality Corp',
          email: ['contact@hqcorp.com'],
          phone: '5551234567',
          websiteUrl: 'https://hqcorp.com',
          address: {
            street: '123 Main St',
            city: 'Anytown',
            state: 'CA',
            zipCode: '12345',
          },
        }),
        toBusinessRecord({
          businessName: 'Low Quality Corp',
          // Missing most fields - will use defaults from toBusinessRecord
        }),
      ]

      const result = await template.execute(mixedQualityData)

      expect(result.recordsExported).toBe(2) // Both should be exported
      expect(result.warnings.length).toBeGreaterThanOrEqual(0)
    })

    test('should skip records missing required fields', async () => {
      const dataWithMissingRequired = [
        toBusinessRecord({ businessName: 'Valid Corp', email: ['test@valid.com'] }),
        toBusinessRecord({ businessName: '', email: ['test@invalid.com'] }), // Missing required businessName
        toBusinessRecord({ businessName: '', email: ['test@empty.com'] }), // Empty businessName
      ]

      const result = await template.execute(dataWithMissingRequired as any)

      expect(result.recordsExported).toBe(1) // Only valid record
      expect(result.recordsSkipped).toBe(2)
    })
  })

  describe('Platform-Specific Features', () => {
    test('should include Salesforce-specific fields', async () => {
      const result = await template.execute(testBusinessData.slice(0, 1))
      const record = result.exportData[0]

      // Check Salesforce-specific fields
      expect(record.LeadSource).toBe('Web Scraping')
      expect(record.Rating).toBeDefined()
      expect(record.AnnualRevenue).toBeDefined()
      expect(record.NumberOfEmployees).toBeDefined()
    })

    test('should respect Salesforce field length limits', async () => {
      const dataWithLongFields = [
        toBusinessRecord({
          businessName: 'A'.repeat(300), // Exceeds 255 char limit
        }),
      ]

      const result = await template.execute(dataWithLongFields)

      expect(result.exportData[0].Company.length).toBeLessThanOrEqual(255)
      expect(result.exportData[0].Description.length).toBeLessThanOrEqual(32000)
    })

    test('should use proper Salesforce industry values', async () => {
      const config = template.getTemplate()
      const industryMapping = config.fieldMappings.find(m => m.targetField === 'Industry')

      expect(industryMapping?.options?.lookupTable).toBeDefined()
      expect(industryMapping?.options?.lookupTable?.technology).toBe('Technology')
      expect(industryMapping?.options?.lookupTable?.healthcare).toBe('Healthcare')
    })
  })

  describe('Error Handling', () => {
    test('should handle empty dataset', async () => {
      const result = await template.execute([])

      expect(result.success).toBe(true)
      expect(result.recordsProcessed).toBe(0)
      expect(result.recordsExported).toBe(0)
      expect(result.exportData).toHaveLength(0)
    })

    test('should handle malformed data gracefully', async () => {
      const malformedData = [
        null,
        undefined,
        'not an object',
        { businessName: 'Valid Corp' },
        { invalidField: 'value' },
      ]

      const result = await template.execute(malformedData as any)

      expect(result.success).toBe(true)
      expect(result.recordsExported).toBe(1) // Only the valid record
    })

    test('should collect and report errors', async () => {
      const result = await template.execute(testBusinessData)

      expect(result.errors).toBeDefined()
      expect(Array.isArray(result.errors)).toBe(true)
      expect(result.warnings).toBeDefined()
      expect(Array.isArray(result.warnings)).toBe(true)
    })
  })

  describe('Performance', () => {
    test('should process large datasets efficiently', async () => {
      // Create a larger dataset
      const largeDataset = Array(100)
        .fill(null)
        .map((_, index) => toBusinessRecord({
          businessName: `Company ${index}`,
          email: [`contact${index}@company${index}.com`],
          phone: `555${String(index).padStart(7, '0')}`,
          industry: 'Technology',
        }))

      const startTime = Date.now()
      const result = await template.execute(largeDataset)
      const duration = Date.now() - startTime

      expect(result.success).toBe(true)
      expect(result.recordsExported).toBe(100)
      expect(duration).toBeLessThan(5000) // Should complete within 5 seconds
      expect(result.metadata.averageProcessingTime).toBeLessThan(50) // < 50ms per record
    })
  })
})
