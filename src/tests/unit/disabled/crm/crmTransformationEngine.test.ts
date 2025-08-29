/**
 * CRM Transformation Engine Tests
 * Unit tests for the CRM transformation engine
 */

import { CRMTransformationEngine } from '@/utils/crm/transformationEngine'
import { CRMTemplate, CRMFieldMapping, CommonTransformers } from '@/utils/crm/types'
import { BusinessRecord } from '@/types/business'

describe('CRMTransformationEngine', () => {
  let engine: CRMTransformationEngine
  let mockBusinessRecord: BusinessRecord
  let mockTemplate: CRMTemplate

  beforeEach(() => {
    engine = new CRMTransformationEngine()

    mockBusinessRecord = {
      id: 'test-1',
      businessName: 'Test Business',
      url: 'https://testbusiness.com',
      phone: '555-123-4567',
      email: 'contact@testbusiness.com',
      address: 'Test Address',
      city: 'Test City',
      state: 'TS',
      zipCode: '12345',
      industry: 'technology',
      confidence: 0.85,
      source: 'test',
      scrapedAt: '2024-01-01T00:00:00.000Z',
    }

    mockTemplate = {
      id: 'test-template',
      name: 'Test Template',
      platform: 'salesforce',
      description: 'Test template for unit tests',
      exportFormat: 'csv',
      fieldMappings: [
        {
          sourceField: 'businessName',
          targetField: 'Company',
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
        },
        {
          sourceField: 'email',
          targetField: 'Email',
          transformer: CommonTransformers.formatEmail,
          validation: { required: false, type: 'email' },
        },
        {
          sourceField: 'phone',
          targetField: 'Phone',
          transformer: CommonTransformers.formatPhone,
          validation: { required: false, type: 'phone' },
        },
      ],
      customHeaders: {},
      metadata: {
        version: '1.0.0',
        author: 'Test',
        createdAt: '2024-01-01T00:00:00.000Z',
        updatedAt: '2024-01-01T00:00:00.000Z',
        tags: ['test'],
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100,
      },
    }
  })

  describe('transformRecord', () => {
    it('should transform a valid business record', async () => {
      const result = await engine.transformRecord(mockBusinessRecord, mockTemplate)

      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
      expect(result.data).toEqual({
        Company: 'Test Business',
        Email: 'contact@testbusiness.com',
        Phone: '(555) 123-4567',
      })
    })

    it('should handle missing required fields', async () => {
      const invalidRecord = { ...mockBusinessRecord, businessName: '' }
      const result = await engine.transformRecord(invalidRecord, mockTemplate)

      expect(result.isValid).toBe(false)
      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].field).toBe('Company')
      expect(result.errors[0].rule).toBe('required')
    })

    it('should apply field transformations', async () => {
      const result = await engine.transformRecord(mockBusinessRecord, mockTemplate)

      expect(result.data.Email).toBe('contact@testbusiness.com') // Email transformer
      expect(result.data.Phone).toBe('(555) 123-4567') // Phone transformer
    })

    it('should use default values when source field is empty', async () => {
      const templateWithDefault: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'missingField',
            targetField: 'DefaultField',
            defaultValue: 'Default Value',
            validation: { required: false, type: 'string' },
          },
        ],
      }

      const result = await engine.transformRecord(mockBusinessRecord, templateWithDefault)

      expect(result.data.DefaultField).toBe('Default Value')
    })

    it('should validate field types', async () => {
      const templateWithValidation: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'businessName',
            targetField: 'NumberField',
            validation: { required: false, type: 'number' },
          },
        ],
      }

      const result = await engine.transformRecord(mockBusinessRecord, templateWithValidation)

      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].rule).toBe('type')
    })

    it('should handle dot notation field paths', async () => {
      const recordWithNestedData = {
        ...mockBusinessRecord,
        address: {
          street: '123 Main St',
          city: 'Test City',
          state: 'TS',
        },
      }

      const templateWithDotNotation: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'address.street',
            targetField: 'Street',
            validation: { required: false, type: 'string' },
          },
        ],
      }

      const result = await engine.transformRecord(recordWithNestedData, templateWithDotNotation)

      expect(result.data.Street).toBe('123 Main St')
    })
  })

  describe('transformBatch', () => {
    it('should transform multiple records', async () => {
      const records = [
        mockBusinessRecord,
        { ...mockBusinessRecord, id: 'test-2', businessName: 'Test Business 2' },
      ]

      const result = await engine.transformBatch(records, mockTemplate)

      expect(result.summary.total).toBe(2)
      expect(result.summary.valid).toBe(2)
      expect(result.summary.invalid).toBe(0)
      expect(result.validRecords).toHaveLength(2)
    })

    it('should handle mixed valid and invalid records', async () => {
      const records = [
        mockBusinessRecord,
        { ...mockBusinessRecord, id: 'test-2', businessName: '' }, // Invalid
      ]

      const result = await engine.transformBatch(records, mockTemplate)

      expect(result.summary.total).toBe(2)
      expect(result.summary.valid).toBe(1)
      expect(result.summary.invalid).toBe(1)
      expect(result.validRecords).toHaveLength(1)
      expect(result.invalidRecords).toHaveLength(1)
    })

    it('should respect strict mode validation', async () => {
      const strictTemplate = {
        ...mockTemplate,
        validation: { ...mockTemplate.validation, strictMode: true },
      }

      const records = [
        { ...mockBusinessRecord, email: 'invalid-email' }, // Invalid email
      ]

      const result = await engine.transformBatch(records, strictTemplate)

      expect(result.summary.valid).toBe(0)
      expect(result.summary.invalid).toBe(1)
    })

    it('should generate performance metrics', async () => {
      const records = Array.from({ length: 10 }, (_, i) => ({
        ...mockBusinessRecord,
        id: `test-${i}`,
        businessName: `Test Business ${i}`,
      }))

      const result = await engine.transformBatch(records, mockTemplate)

      expect(result.summary.processingTime).toBeGreaterThan(0)
      expect(result.summary.total).toBe(10)
    })
  })

  describe('field validation', () => {
    it('should validate email format', async () => {
      const templateWithEmail: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'email',
            targetField: 'Email',
            validation: { required: false, type: 'email' },
          },
        ],
      }

      const invalidEmailRecord = { ...mockBusinessRecord, email: 'invalid-email' }
      const result = await engine.transformRecord(invalidEmailRecord, templateWithEmail)

      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].rule).toBe('type')
    })

    it('should validate phone format', async () => {
      const templateWithPhone: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'phone',
            targetField: 'Phone',
            validation: { required: false, type: 'phone' },
          },
        ],
      }

      const invalidPhoneRecord = { ...mockBusinessRecord, phone: 'invalid' }
      const result = await engine.transformRecord(invalidPhoneRecord, templateWithPhone)

      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].rule).toBe('type')
    })

    it('should validate string length', async () => {
      const templateWithLength: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'businessName',
            targetField: 'Company',
            validation: { required: false, type: 'string', maxLength: 5 },
          },
        ],
      }

      const result = await engine.transformRecord(mockBusinessRecord, templateWithLength)

      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].rule).toBe('maxLength')
    })

    it('should validate allowed values', async () => {
      const templateWithAllowedValues: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'industry',
            targetField: 'Industry',
            validation: {
              required: false,
              type: 'string',
              allowedValues: ['finance', 'healthcare'],
            },
          },
        ],
      }

      const result = await engine.transformRecord(mockBusinessRecord, templateWithAllowedValues)

      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].rule).toBe('allowedValues')
    })

    it('should validate custom validation functions', async () => {
      const templateWithCustomValidation: CRMTemplate = {
        ...mockTemplate,
        fieldMappings: [
          {
            sourceField: 'businessName',
            targetField: 'Company',
            validation: {
              required: false,
              type: 'string',
              customValidator: value => value.includes('Test') || 'Must contain "Test"',
            },
          },
        ],
      }

      const invalidRecord = { ...mockBusinessRecord, businessName: 'Invalid Business' }
      const result = await engine.transformRecord(invalidRecord, templateWithCustomValidation)

      expect(result.errors).toHaveLength(1)
      expect(result.errors[0].rule).toBe('custom')
      expect(result.errors[0].message).toBe('Must contain "Test"')
    })
  })

  describe('createSummaryReport', () => {
    it('should generate a comprehensive summary report', async () => {
      const records = [
        mockBusinessRecord,
        { ...mockBusinessRecord, id: 'test-2', businessName: '' }, // Invalid
      ]

      const result = await engine.transformBatch(records, mockTemplate)
      const report = engine.createSummaryReport(result)

      expect(report).toContain('CRM Export Transformation Summary')
      expect(report).toContain('Total Records: 2')
      expect(report).toContain('Valid Records: 1')
      expect(report).toContain('Invalid Records: 1')
      expect(report).toContain('Invalid Records Details')
    })

    it('should limit error details in report', async () => {
      const invalidRecords = Array.from({ length: 15 }, (_, i) => ({
        ...mockBusinessRecord,
        id: `test-${i}`,
        businessName: '', // Invalid
      }))

      const result = await engine.transformBatch(invalidRecords, mockTemplate)
      const report = engine.createSummaryReport(result)

      expect(report).toContain('... and 5 more invalid records')
    })
  })
})
