/**
 * Field Mapping Engine Tests
 * Comprehensive test suite for the field mapping engine
 */

import { FieldMappingEngineImpl } from '@/lib/field-mapping/mapping-engine'
import { FieldMappingSchema, DataTransformation } from '@/types/field-mapping'
import { BusinessRecord } from '@/types/business'

describe('FieldMappingEngine', () => {
  let engine: FieldMappingEngineImpl
  let testSchema: FieldMappingSchema
  let testBusinessData: BusinessRecord[]

  beforeEach(() => {
    engine = new FieldMappingEngineImpl()

    // Test schema for business to CRM mapping
    testSchema = {
      id: 'test-crm-mapping',
      name: 'Test CRM Mapping',
      description: 'Test mapping for CRM export',
      sourceSchema: {
        name: 'Business Record',
        fields: [
          { path: 'businessName', type: 'string', required: true },
          { path: 'email.0', type: 'string', required: false },
          { path: 'phone.0', type: 'string', required: false },
          { path: 'website', type: 'string', required: false },
          { path: 'address.street', type: 'string', required: false },
          { path: 'address.city', type: 'string', required: false },
          { path: 'address.state', type: 'string', required: false },
          { path: 'industry', type: 'string', required: false },
        ],
      },
      targetSchema: {
        name: 'CRM Record',
        fields: [
          { name: 'Company', type: 'string', required: true, maxLength: 255 },
          { name: 'Email', type: 'string', required: false },
          { name: 'Phone', type: 'string', required: false },
          { name: 'Website', type: 'string', required: false },
          { name: 'Address', type: 'string', required: false },
          { name: 'Industry', type: 'string', required: false },
        ],
      },
      mappingRules: [
        {
          id: 'company-mapping',
          sourceFields: [{ path: 'businessName' }],
          targetField: { name: 'Company', type: 'string' },
          transformation: { id: 'direct_copy', parameters: {} },
          priority: 1,
          enabled: true,
          conditions: [],
        },
        {
          id: 'email-mapping',
          sourceFields: [{ path: 'email.0' }],
          targetField: { name: 'Email', type: 'string' },
          transformation: { id: 'format_email', parameters: {} },
          priority: 1,
          enabled: true,
          conditions: [],
        },
        {
          id: 'phone-mapping',
          sourceFields: [{ path: 'phone.0' }],
          targetField: { name: 'Phone', type: 'string' },
          transformation: { id: 'format_phone', parameters: { format: '(###) ###-####' } },
          priority: 1,
          enabled: true,
          conditions: [],
        },
        {
          id: 'address-mapping',
          sourceFields: [
            { path: 'address.street' },
            { path: 'address.city' },
            { path: 'address.state' },
          ],
          targetField: { name: 'Address', type: 'string' },
          transformation: { id: 'concatenate', parameters: { separator: ', ' } },
          priority: 1,
          enabled: true,
          conditions: [],
        },
      ],
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        version: '1.0.0',
      },
    }

    testBusinessData = [
      {
        businessName: 'Acme Corporation',
        email: ['contact@acme.com', 'info@acme.com'],
        phone: ['5551234567', '5559876543'],
        website: 'https://acme.com',
        address: {
          street: '123 Main Street',
          city: 'Anytown',
          state: 'CA',
          zipCode: '12345',
          country: 'United States',
        },
        industry: 'Technology',
        description: 'Leading technology company',
      },
      {
        businessName: 'Beta Industries',
        email: ['hello@beta.com'],
        phone: ['5555551234'],
        website: 'beta.com',
        address: {
          street: '456 Oak Avenue',
          city: 'Somewhere',
          state: 'NY',
          zipCode: '67890',
        },
        industry: 'Manufacturing',
      },
    ]

    // Register test transformations
    engine.registerTransformation({
      id: 'format_email',
      name: 'Format Email',
      description: 'Format email address',
      inputTypes: ['string'],
      outputType: 'string',
      transform: (input: string) => (input ? input.toLowerCase().trim() : ''),
    })
  })

  describe('Schema Management', () => {
    test('should register and retrieve schema', () => {
      engine.registerSchema(testSchema)
      const retrieved = engine.getSchema(testSchema.id)

      expect(retrieved).toBeDefined()
      expect(retrieved?.id).toBe(testSchema.id)
      expect(retrieved?.name).toBe(testSchema.name)
    })

    test('should validate valid schema', () => {
      const validation = engine.validateSchema(testSchema)

      expect(validation.isValid).toBe(true)
      expect(validation.errors).toHaveLength(0)
    })

    test('should detect invalid schema', () => {
      const invalidSchema = {
        ...testSchema,
        mappingRules: [
          {
            ...testSchema.mappingRules[0],
            transformation: { id: 'nonexistent_transform', parameters: {} },
          },
        ],
      }

      const validation = engine.validateSchema(invalidSchema)

      expect(validation.isValid).toBe(false)
      expect(validation.errors.length).toBeGreaterThan(0)
      expect(validation.errors[0]).toContain('unknown transformation')
    })
  })

  describe('Transformation Management', () => {
    test('should register and retrieve transformation', () => {
      const testTransform: DataTransformation = {
        id: 'test_transform',
        name: 'Test Transform',
        description: 'Test transformation',
        inputTypes: ['string'],
        outputType: 'string',
        transform: (input: string) => input.toUpperCase(),
      }

      engine.registerTransformation(testTransform)
      const retrieved = engine.getTransformation('test_transform')

      expect(retrieved).toBeDefined()
      expect(retrieved?.id).toBe('test_transform')
      expect(retrieved?.transform('hello')).toBe('HELLO')
    })

    test('should list all transformations', () => {
      const transformations = engine.listTransformations()

      expect(transformations.length).toBeGreaterThan(0)
      expect(transformations.some(t => t.id === 'direct_copy')).toBe(true)
      expect(transformations.some(t => t.id === 'concatenate')).toBe(true)
    })
  })

  describe('Field Mapping Execution', () => {
    beforeEach(() => {
      engine.registerSchema(testSchema)
    })

    test('should execute mapping successfully', async () => {
      const result = await engine.executeMapping(testSchema.id, testBusinessData)

      expect(result.success).toBe(true)
      expect(result.recordsProcessed).toBe(2)
      expect(result.recordsSuccessful).toBe(2)
      expect(result.mappedData).toHaveLength(2)

      // Check first record mapping
      const firstRecord = result.mappedData[0]
      expect(firstRecord.Company).toBe('Acme Corporation')
      expect(firstRecord.Email).toBe('contact@acme.com')
      expect(firstRecord.Phone).toBe('(555) 123-4567')
      expect(firstRecord.Address).toBe('123 Main Street, Anytown, CA')
    })

    test('should handle missing source data gracefully', async () => {
      const incompleteData = [
        {
          businessName: 'Incomplete Corp',
          // Missing other fields
        },
      ]

      const result = await engine.executeMapping(testSchema.id, incompleteData)

      expect(result.success).toBe(true)
      expect(result.recordsProcessed).toBe(1)
      expect(result.mappedData[0].Company).toBe('Incomplete Corp')
      expect(result.mappedData[0].Email).toBe('')
      expect(result.mappedData[0].Phone).toBe('')
    })

    test('should apply transformations correctly', async () => {
      const result = await engine.executeMapping(testSchema.id, testBusinessData)

      // Check email formatting (lowercase)
      expect(result.mappedData[0].Email).toBe('contact@acme.com')

      // Check phone formatting
      expect(result.mappedData[0].Phone).toBe('(555) 123-4567')

      // Check address concatenation
      expect(result.mappedData[0].Address).toBe('123 Main Street, Anytown, CA')
    })

    test('should collect and report errors', async () => {
      // Create schema with invalid transformation
      const errorSchema = {
        ...testSchema,
        mappingRules: [
          {
            id: 'error-rule',
            sourceFields: [{ path: 'businessName' }],
            targetField: { name: 'Company', type: 'string' },
            transformation: { id: 'nonexistent_transform', parameters: {} },
            priority: 1,
            enabled: true,
            conditions: [],
          },
        ],
      }

      engine.registerSchema(errorSchema)
      const result = await engine.executeMapping(errorSchema.id, testBusinessData)

      expect(result.success).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
      expect(result.errors[0].errorType).toBe('transformation')
    })

    test('should calculate execution statistics', async () => {
      const result = await engine.executeMapping(testSchema.id, testBusinessData)

      expect(result.statistics).toBeDefined()
      expect(result.statistics.executionTime).toBeGreaterThan(0)
      expect(result.statistics.averageRecordTime).toBeGreaterThan(0)
      expect(result.statistics.transformationsApplied).toBeGreaterThan(0)
    })
  })

  describe('Validation and Quality Control', () => {
    beforeEach(() => {
      engine.registerSchema(testSchema)
    })

    test('should validate mapping configuration', async () => {
      const validation = await engine.validateMapping(testSchema, testBusinessData.slice(0, 1))

      expect(validation.isValid).toBe(true)
      expect(validation.coverage.coveragePercentage).toBeGreaterThan(0)
    })

    test('should test mapping with sample data', async () => {
      const testResult = await engine.testMapping(testSchema, testBusinessData.slice(0, 1))

      expect(testResult.testCases).toHaveLength(1)
      expect(testResult.summary.totalTests).toBe(1)
      expect(testResult.summary.successRate).toBeGreaterThanOrEqual(0)
    })
  })

  describe('Built-in Transformations', () => {
    test('direct_copy should copy values directly', () => {
      const transform = engine.getTransformation('direct_copy')
      expect(transform?.transform('test value')).toBe('test value')
      expect(transform?.transform(123)).toBe(123)
    })

    test('concatenate should join values with separator', () => {
      const transform = engine.getTransformation('concatenate')
      const result = transform?.transform(['hello', 'world'], { separator: ' ' })
      expect(result).toBe('hello world')
    })

    test('format_phone should format phone numbers', () => {
      const transform = engine.getTransformation('format_phone')
      const result = transform?.transform('5551234567')
      expect(result).toBe('(555) 123-4567')
    })

    test('extract_domain should extract domain from URL', () => {
      const transform = engine.getTransformation('extract_domain')
      expect(transform?.transform('https://example.com/path')).toBe('example.com')
      expect(transform?.transform('user@example.com')).toBe('example.com')
    })
  })

  describe('Error Handling', () => {
    test('should handle invalid schema ID', async () => {
      await expect(engine.executeMapping('nonexistent', testBusinessData)).rejects.toThrow(
        'Schema not found'
      )
    })

    test('should handle empty data gracefully', async () => {
      engine.registerSchema(testSchema)
      const result = await engine.executeMapping(testSchema.id, [])

      expect(result.success).toBe(true)
      expect(result.recordsProcessed).toBe(0)
      expect(result.mappedData).toHaveLength(0)
    })

    test('should handle malformed input data', async () => {
      engine.registerSchema(testSchema)
      const malformedData = [null, undefined, 'not an object', {}]

      const result = await engine.executeMapping(testSchema.id, malformedData as any)

      expect(result.recordsProcessed).toBe(4)
      expect(result.recordsSuccessful).toBeLessThan(4) // Some should fail validation
    })
  })
})
