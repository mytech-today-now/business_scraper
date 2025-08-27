/**
 * Salesforce Adapter Tests
 * Unit tests for the Salesforce CRM adapter
 */

import { SalesforceAdapter } from '@/utils/crm/adapters/salesforceAdapter'
import { BusinessRecord } from '@/types/business'

describe('SalesforceAdapter', () => {
  let adapter: SalesforceAdapter
  let mockBusinessRecord: BusinessRecord

  beforeEach(() => {
    adapter = new SalesforceAdapter()

    mockBusinessRecord = {
      id: 'test-1',
      businessName: 'Test Restaurant',
      url: 'https://testrestaurant.com',
      phone: '555-123-4567',
      email: 'contact@testrestaurant.com',
      address: '123 Main St',
      city: 'Test City',
      state: 'CA',
      zipCode: '90210',
      industry: 'restaurants',
      confidence: 0.85,
      source: 'web',
      scrapedAt: '2024-01-01T00:00:00.000Z',
    }
  })

  describe('platform configuration', () => {
    it('should have correct platform configuration', () => {
      expect(adapter.platform).toBe('salesforce')
      expect(adapter.displayName).toBe('Salesforce')
      expect(adapter.templates).toBeDefined()
      expect(adapter.templates.length).toBeGreaterThan(0)
    })

    it('should provide default template', () => {
      const defaultTemplate = adapter.getDefaultTemplate()

      expect(defaultTemplate).toBeDefined()
      expect(defaultTemplate.platform).toBe('salesforce')
      expect(defaultTemplate.id).toBe('salesforce-lead-basic')
    })
  })

  describe('templates', () => {
    it('should have Salesforce Lead template', () => {
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')

      expect(leadTemplate).toBeDefined()
      expect(leadTemplate?.name).toBe('Salesforce Lead (Basic)')
      expect(leadTemplate?.exportFormat).toBe('csv')
      expect(leadTemplate?.fieldMappings.length).toBeGreaterThan(0)
    })

    it('should have Salesforce Account & Contact template', () => {
      const accountTemplate = adapter.templates.find(t => t.id === 'salesforce-account-contact')

      expect(accountTemplate).toBeDefined()
      expect(accountTemplate?.name).toBe('Salesforce Account & Contact')
      expect(accountTemplate?.exportFormat).toBe('csv')
    })

    it('should have required field mappings', () => {
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')
      const requiredFields = leadTemplate?.fieldMappings.filter(m => m.required)

      expect(requiredFields?.length).toBeGreaterThan(0)
      expect(requiredFields?.some(f => f.targetField === 'Company')).toBe(true)
      expect(requiredFields?.some(f => f.targetField === 'LastName')).toBe(true)
    })
  })

  describe('transformRecords', () => {
    it('should transform business record to Salesforce Lead format', async () => {
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!
      const result = await adapter.transformRecords([mockBusinessRecord], leadTemplate)

      expect(result.summary.total).toBe(1)
      expect(result.summary.valid).toBe(1)
      expect(result.validRecords).toHaveLength(1)

      const transformedRecord = result.validRecords[0]
      expect(transformedRecord.Company).toBe('Test Restaurant')
      expect(transformedRecord.Email).toBe('contact@testrestaurant.com')
      expect(transformedRecord.Phone).toBe('(555) 123-4567')
      expect(transformedRecord.Industry).toBe('Food & Beverage')
      expect(transformedRecord.LeadSource).toBe('Web')
    })

    it('should transform business record to Salesforce Account & Contact format', async () => {
      const accountTemplate = adapter.templates.find(t => t.id === 'salesforce-account-contact')!
      const result = await adapter.transformRecords([mockBusinessRecord], accountTemplate)

      expect(result.summary.total).toBe(1)
      expect(result.summary.valid).toBe(1)
      expect(result.validRecords).toHaveLength(1)

      const transformedRecord = result.validRecords[0]
      expect(transformedRecord['Account Name']).toBe('Test Restaurant')
      expect(transformedRecord['Contact Email']).toBe('contact@testrestaurant.com')
      expect(transformedRecord['Account Industry']).toBe('Food & Beverage')
    })

    it('should handle missing business name gracefully', async () => {
      const invalidRecord = { ...mockBusinessRecord, businessName: '' }
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!

      const result = await adapter.transformRecords([invalidRecord], leadTemplate)

      expect(result.summary.invalid).toBe(1)
      expect(result.invalidRecords).toHaveLength(1)
      expect(result.invalidRecords[0].errors.some(e => e.field === 'Company')).toBe(true)
    })

    it('should apply Salesforce-specific transformations', async () => {
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!
      const result = await adapter.transformRecords([mockBusinessRecord], leadTemplate)

      const transformedRecord = result.validRecords[0]

      // Industry should be mapped to Salesforce values
      expect(transformedRecord.Industry).toBe('Food & Beverage')

      // Phone should be formatted
      expect(transformedRecord.Phone).toBe('(555) 123-4567')

      // Lead source should be mapped
      expect(transformedRecord.LeadSource).toBe('Web')
    })
  })

  describe('validateRecord', () => {
    it('should validate required fields for Lead template', () => {
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!
      const errors = adapter.validateRecord(mockBusinessRecord, leadTemplate)

      expect(errors).toHaveLength(0)
    })

    it('should return errors for missing required fields', () => {
      const invalidRecord = { ...mockBusinessRecord, businessName: '' }
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!

      const errors = adapter.validateRecord(invalidRecord, leadTemplate)

      expect(errors.length).toBeGreaterThan(0)
      expect(errors.some(e => e.rule === 'salesforce-lead-required')).toBe(true)
    })

    it('should validate Account template requirements', () => {
      const accountTemplate = adapter.templates.find(t => t.id === 'salesforce-account-contact')!
      const errors = adapter.validateRecord(mockBusinessRecord, accountTemplate)

      expect(errors).toHaveLength(0)
    })
  })

  describe('createCustomTemplate', () => {
    it('should create custom Salesforce template', () => {
      const customMappings = [
        {
          sourceField: 'businessName',
          targetField: 'Custom_Company__c',
          required: true,
          validation: { required: true, type: 'string' as const },
        },
      ]

      const customTemplate = adapter.createCustomTemplate(
        'Custom Salesforce Template',
        customMappings,
        { description: 'Custom template for testing' }
      )

      expect(customTemplate.name).toBe('Custom Salesforce Template')
      expect(customTemplate.platform).toBe('salesforce')
      expect(customTemplate.fieldMappings).toEqual(customMappings)
      expect(customTemplate.description).toBe('Custom template for testing')
      expect(customTemplate.id).toContain('salesforce-custom-')
    })

    it('should set default values for custom template', () => {
      const customTemplate = adapter.createCustomTemplate('Test Template', [])

      expect(customTemplate.exportFormat).toBe('csv')
      expect(customTemplate.validation.strictMode).toBe(false)
      expect(customTemplate.validation.skipInvalidRecords).toBe(true)
      expect(customTemplate.metadata.author).toBe('User')
      expect(customTemplate.metadata.tags).toContain('custom')
    })
  })

  describe('industry mapping', () => {
    it('should map common industries to Salesforce values', async () => {
      const testCases = [
        { input: 'restaurants', expected: 'Food & Beverage' },
        { input: 'technology', expected: 'Technology' },
        { input: 'healthcare', expected: 'Healthcare' },
        { input: 'finance', expected: 'Financial Services' },
        { input: 'unknown', expected: 'Other' },
      ]

      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!

      for (const testCase of testCases) {
        const record = { ...mockBusinessRecord, industry: testCase.input }
        const result = await adapter.transformRecords([record], leadTemplate)

        expect(result.validRecords[0].Industry).toBe(testCase.expected)
      }
    })
  })

  describe('field formatting', () => {
    it('should format phone numbers correctly', async () => {
      const testPhones = [
        { input: '5551234567', expected: '(555) 123-4567' },
        { input: '555-123-4567', expected: '(555) 123-4567' },
        { input: '(555) 123-4567', expected: '(555) 123-4567' },
        { input: 'invalid', expected: 'invalid' },
      ]

      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!

      for (const testCase of testPhones) {
        const record = { ...mockBusinessRecord, phone: testCase.input }
        const result = await adapter.transformRecords([record], leadTemplate)

        expect(result.validRecords[0].Phone).toBe(testCase.expected)
      }
    })

    it('should format email addresses correctly', async () => {
      const testEmails = [
        { input: 'TEST@EXAMPLE.COM', expected: 'test@example.com' },
        { input: '  test@example.com  ', expected: 'test@example.com' },
        { input: 'invalid-email', expected: '' },
        { input: '', expected: '' },
      ]

      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!

      for (const testCase of testEmails) {
        const record = { ...mockBusinessRecord, email: testCase.input }
        const result = await adapter.transformRecords([record], leadTemplate)

        expect(result.validRecords[0].Email).toBe(testCase.expected)
      }
    })
  })

  describe('error handling', () => {
    it('should handle transformation errors gracefully', async () => {
      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!

      // Create a template with a transformer that throws an error
      const errorTemplate = {
        ...leadTemplate,
        fieldMappings: [
          {
            sourceField: 'businessName',
            targetField: 'Company',
            transformer: () => {
              throw new Error('Test error')
            },
            required: true,
            validation: { required: true, type: 'string' as const },
          },
        ],
      }

      const result = await adapter.transformRecords([mockBusinessRecord], errorTemplate)

      expect(result.summary.invalid).toBe(1)
      expect(result.invalidRecords[0].errors.some(e => e.message.includes('Test error'))).toBe(true)
    })

    it('should continue processing other records when one fails', async () => {
      const records = [
        mockBusinessRecord,
        { ...mockBusinessRecord, id: 'test-2', businessName: 'Valid Business' },
      ]

      const leadTemplate = adapter.templates.find(t => t.id === 'salesforce-lead-basic')!

      // Make first record invalid
      records[0].businessName = ''

      const result = await adapter.transformRecords(records, leadTemplate)

      expect(result.summary.total).toBe(2)
      expect(result.summary.valid).toBe(1)
      expect(result.summary.invalid).toBe(1)
    })
  })
})
