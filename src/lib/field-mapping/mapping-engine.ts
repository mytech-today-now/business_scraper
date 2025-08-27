/**
 * Field Mapping Engine
 * Core engine for flexible data transformation and field mapping
 */

import { logger } from '@/utils/logger'
import {
  FieldMappingEngine,
  FieldMappingSchema,
  DataTransformation,
  MappingExecutionResult,
  MappingError,
  MappingWarning,
  SchemaValidationResult,
  MappingValidationResult,
  MappingTestResult,
  BuiltInTransformation,
  TransformationParams,
} from '@/types/field-mapping'

/**
 * Core field mapping engine implementation
 */
export class FieldMappingEngineImpl implements FieldMappingEngine {
  private schemas: Map<string, FieldMappingSchema> = new Map()
  private transformations: Map<string, DataTransformation> = new Map()

  constructor() {
    this.initializeBuiltInTransformations()
  }

  /**
   * Register a field mapping schema
   */
  registerSchema(schema: FieldMappingSchema): void {
    const validation = this.validateSchema(schema)
    if (!validation.isValid) {
      throw new Error(`Invalid schema: ${validation.errors.join(', ')}`)
    }

    this.schemas.set(schema.id, schema)
    logger.info('FieldMapping', `Registered schema: ${schema.name} (${schema.id})`)
  }

  /**
   * Get a registered schema
   */
  getSchema(id: string): FieldMappingSchema | null {
    return this.schemas.get(id) || null
  }

  /**
   * Validate a field mapping schema
   */
  validateSchema(schema: FieldMappingSchema): SchemaValidationResult {
    const errors: string[] = []
    const warnings: string[] = []
    const suggestions: string[] = []

    // Basic validation
    if (!schema.id || !schema.name) {
      errors.push('Schema must have id and name')
    }

    if (!schema.sourceSchema.fields.length) {
      errors.push('Source schema must have at least one field')
    }

    if (!schema.targetSchema.fields.length) {
      errors.push('Target schema must have at least one field')
    }

    // Validate mapping rules
    for (const rule of schema.mappingRules) {
      if (!rule.sourceFields.length) {
        errors.push(`Rule ${rule.id} must have at least one source field`)
      }

      if (!this.transformations.has(rule.transformation.id)) {
        errors.push(`Rule ${rule.id} references unknown transformation: ${rule.transformation.id}`)
      }

      // Check if source fields exist
      for (const sourceField of rule.sourceFields) {
        const exists = schema.sourceSchema.fields.some(f => f.path === sourceField.path)
        if (!exists) {
          warnings.push(`Rule ${rule.id} references non-existent source field: ${sourceField.path}`)
        }
      }

      // Check if target field exists
      const targetExists = schema.targetSchema.fields.some(f => f.name === rule.targetField.name)
      if (!targetExists) {
        warnings.push(`Rule ${rule.id} targets non-existent field: ${rule.targetField.name}`)
      }
    }

    // Check coverage
    const requiredTargetFields = schema.targetSchema.fields.filter(f => f.required)
    const mappedTargetFields = schema.mappingRules.map(r => r.targetField.name)

    for (const requiredField of requiredTargetFields) {
      if (!mappedTargetFields.includes(requiredField.name)) {
        warnings.push(`Required target field '${requiredField.name}' is not mapped`)
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      suggestions,
      compatibility: {
        sourceCompatible: true,
        targetCompatible: true,
        transformationsSupported: schema.mappingRules.every(r =>
          this.transformations.has(r.transformation.id)
        ),
      },
    }
  }

  /**
   * Register a data transformation
   */
  registerTransformation(transformation: DataTransformation): void {
    this.transformations.set(transformation.id, transformation)
    logger.info(
      'FieldMapping',
      `Registered transformation: ${transformation.name} (${transformation.id})`
    )
  }

  /**
   * Get a registered transformation
   */
  getTransformation(id: string): DataTransformation | null {
    return this.transformations.get(id) || null
  }

  /**
   * List all registered transformations
   */
  listTransformations(): DataTransformation[] {
    return Array.from(this.transformations.values())
  }

  /**
   * Execute field mapping with schema ID
   */
  async executeMapping(schemaId: string, sourceData: any[]): Promise<MappingExecutionResult> {
    const schema = this.getSchema(schemaId)
    if (!schema) {
      throw new Error(`Schema not found: ${schemaId}`)
    }

    return this.executeMappingWithSchema(schema, sourceData)
  }

  /**
   * Execute field mapping with schema object
   */
  async executeMappingWithSchema(
    schema: FieldMappingSchema,
    sourceData: any[]
  ): Promise<MappingExecutionResult> {
    const startTime = Date.now()
    const mappedData: any[] = []
    const errors: MappingError[] = []
    const warnings: MappingWarning[] = []
    let recordsSuccessful = 0
    let transformationsApplied = 0

    logger.info(
      'FieldMapping',
      `Starting mapping execution for ${sourceData.length} records with schema: ${schema.name}`
    )

    for (let recordIndex = 0; recordIndex < sourceData.length; recordIndex++) {
      const sourceRecord = sourceData[recordIndex]
      const targetRecord: any = {}
      let recordHasErrors = false

      // Sort rules by priority (higher priority first)
      const sortedRules = [...schema.mappingRules]
        .filter(rule => rule.enabled)
        .sort((a, b) => b.priority - a.priority)

      for (const rule of sortedRules) {
        try {
          // Check conditions
          if (rule.conditions && !this.evaluateConditions(rule.conditions, sourceRecord)) {
            continue
          }

          // Extract source values
          const sourceValues = rule.sourceFields.map(field =>
            this.extractFieldValue(sourceRecord, field.path, field.defaultValue)
          )

          // Apply transformation
          const transformation = this.transformations.get(rule.transformation.id)
          if (!transformation) {
            errors.push({
              recordIndex,
              ruleId: rule.id,
              sourceField: rule.sourceFields[0]?.path || 'unknown',
              targetField: rule.targetField.name,
              errorType: 'transformation',
              message: `Transformation not found: ${rule.transformation.id}`,
              originalValue: sourceValues,
            })
            recordHasErrors = true
            continue
          }

          const transformedValue = transformation.transform(
            sourceValues.length === 1 ? sourceValues[0] : sourceValues,
            rule.transformation.parameters
          )

          // Validate transformed value
          const validationResult = this.validateFieldValue(transformedValue, rule.targetField)

          if (!validationResult.isValid) {
            errors.push({
              recordIndex,
              ruleId: rule.id,
              sourceField: rule.sourceFields[0]?.path || 'unknown',
              targetField: rule.targetField.name,
              errorType: 'validation',
              message: validationResult.error || 'Validation failed',
              originalValue: sourceValues,
              suggestedFix: validationResult.suggestedFix,
            })
            recordHasErrors = true
            continue
          }

          // Set target field value
          targetRecord[rule.targetField.name] = transformedValue
          transformationsApplied++

          // Check for warnings
          if (validationResult.warnings) {
            warnings.push(
              ...validationResult.warnings.map(warning => ({
                recordIndex,
                ruleId: rule.id,
                sourceField: rule.sourceFields[0]?.path || 'unknown',
                targetField: rule.targetField.name,
                warningType: warning.type as any,
                message: warning.message,
                originalValue: sourceValues,
                mappedValue: transformedValue,
              }))
            )
          }
        } catch (error) {
          errors.push({
            recordIndex,
            ruleId: rule.id,
            sourceField: rule.sourceFields[0]?.path || 'unknown',
            targetField: rule.targetField.name,
            errorType: 'transformation',
            message: error instanceof Error ? error.message : 'Unknown error',
            originalValue: rule.sourceFields.map(field =>
              this.extractFieldValue(sourceRecord, field.path)
            ),
          })
          recordHasErrors = true
        }
      }

      if (!recordHasErrors) {
        recordsSuccessful++
      }

      mappedData.push(targetRecord)
    }

    const endTime = Date.now()
    const executionTime = endTime - startTime

    const result: MappingExecutionResult = {
      success: errors.length === 0,
      recordsProcessed: sourceData.length,
      recordsSuccessful,
      recordsFailed: sourceData.length - recordsSuccessful,
      mappedData,
      errors,
      warnings,
      statistics: {
        executionTime,
        averageRecordTime: executionTime / sourceData.length,
        memoryUsage: process.memoryUsage().heapUsed,
        transformationsApplied,
      },
    }

    logger.info('FieldMapping', `Mapping execution completed`, {
      recordsProcessed: result.recordsProcessed,
      recordsSuccessful: result.recordsSuccessful,
      recordsFailed: result.recordsFailed,
      executionTime: result.statistics.executionTime,
      transformationsApplied: result.statistics.transformationsApplied,
    })

    return result
  }

  /**
   * Validate mapping configuration
   */
  async validateMapping(
    schema: FieldMappingSchema,
    sampleData: any[]
  ): Promise<MappingValidationResult> {
    const schemaValidation = this.validateSchema(schema)

    if (!schemaValidation.isValid) {
      return {
        isValid: false,
        coverage: {
          sourceFieldsCovered: 0,
          targetFieldsMapped: 0,
          requiredFieldsMapped: 0,
          coveragePercentage: 0,
        },
        issues: schemaValidation.errors.map(error => ({
          type: 'error',
          message: error,
        })),
        recommendations: [],
      }
    }

    // Analyze coverage
    const sourceFields = schema.sourceSchema.fields
    const targetFields = schema.targetSchema.fields
    const requiredTargetFields = targetFields.filter(f => f.required)
    const mappedTargetFields = schema.mappingRules.map(r => r.targetField.name)
    const requiredFieldsMapped = requiredTargetFields.filter(f =>
      mappedTargetFields.includes(f.name)
    ).length

    const coverage = {
      sourceFieldsCovered: sourceFields.length,
      targetFieldsMapped: mappedTargetFields.length,
      requiredFieldsMapped,
      coveragePercentage: (mappedTargetFields.length / targetFields.length) * 100,
    }

    const issues = schemaValidation.warnings.map(warning => ({
      type: 'warning' as const,
      message: warning,
    }))

    const recommendations: string[] = []

    if (coverage.coveragePercentage < 80) {
      recommendations.push('Consider mapping more target fields to improve coverage')
    }

    if (requiredFieldsMapped < requiredTargetFields.length) {
      recommendations.push('Map all required target fields to ensure data completeness')
    }

    return {
      isValid: schemaValidation.isValid && requiredFieldsMapped === requiredTargetFields.length,
      coverage,
      issues,
      recommendations,
    }
  }

  /**
   * Test mapping with sample data
   */
  async testMapping(schema: FieldMappingSchema, testData: any[]): Promise<MappingTestResult> {
    const testCases = []
    let passedTests = 0

    for (let i = 0; i < Math.min(testData.length, 10); i++) {
      const input = testData[i]
      const result = await this.executeMappingWithSchema(schema, [input])
      const actualOutput = result.mappedData[0]
      const errors = result.errors.map(e => e.message)
      const passed = result.errors.length === 0

      if (passed) passedTests++

      testCases.push({
        input,
        expectedOutput: {}, // Would need to be provided for proper testing
        actualOutput,
        passed,
        errors,
      })
    }

    return {
      passed: passedTests === testCases.length,
      testCases,
      summary: {
        totalTests: testCases.length,
        passedTests,
        failedTests: testCases.length - passedTests,
        successRate: (passedTests / testCases.length) * 100,
      },
    }
  }

  /**
   * Initialize built-in transformations
   */
  private initializeBuiltInTransformations(): void {
    // Direct copy transformation
    this.registerTransformation({
      id: 'direct_copy',
      name: 'Direct Copy',
      description: 'Copy value directly from source to target',
      inputTypes: ['any'],
      outputType: 'any',
      transform: (input: any) => input,
    })

    // Concatenate transformation
    this.registerTransformation({
      id: 'concatenate',
      name: 'Concatenate',
      description: 'Concatenate multiple values with separator',
      inputTypes: ['array'],
      outputType: 'string',
      transform: (input: any[], params?: TransformationParams) => {
        const separator = params?.separator || ' '
        const prefix = params?.prefix || ''
        const suffix = params?.suffix || ''

        const values = Array.isArray(input) ? input : [input]
        const filtered = values.filter(v => v != null && v !== '')

        if (filtered.length === 0) return ''

        return prefix + filtered.join(separator) + suffix
      },
    })

    // Format phone transformation
    this.registerTransformation({
      id: 'format_phone',
      name: 'Format Phone',
      description: 'Format phone number to standard format',
      inputTypes: ['string'],
      outputType: 'string',
      transform: (input: string, params?: TransformationParams) => {
        if (!input) return ''

        const digits = input.replace(/\D/g, '')
        const format = params?.format || '(###) ###-####'

        if (digits.length === 10) {
          let result = format
          result = result.replace('###', digits.substr(0, 3))
          result = result.replace('###', digits.substr(3, 3))
          result = result.replace('####', digits.substr(6, 4))
          return result
        }

        return input // Return original if can't format
      },
    })

    // Extract domain transformation
    this.registerTransformation({
      id: 'extract_domain',
      name: 'Extract Domain',
      description: 'Extract domain from URL or email',
      inputTypes: ['string'],
      outputType: 'string',
      transform: (input: string) => {
        if (!input) return ''

        try {
          if (input.includes('@')) {
            // Email address
            return input.split('@')[1]
          } else if (input.includes('://')) {
            // URL
            return new URL(input).hostname
          } else {
            // Assume it's already a domain
            return input
          }
        } catch {
          return input
        }
      },
    })

    logger.info('FieldMapping', 'Initialized built-in transformations')
  }

  /**
   * Extract field value using dot notation path
   */
  private extractFieldValue(obj: any, path: string, defaultValue?: any): any {
    const keys = path.split('.')
    let current = obj

    for (const key of keys) {
      if (current == null || typeof current !== 'object') {
        return defaultValue
      }
      current = current[key]
    }

    return current !== undefined ? current : defaultValue
  }

  /**
   * Evaluate mapping conditions
   */
  private evaluateConditions(conditions: any[], record: any): boolean {
    return conditions.every(condition => {
      const fieldValue = this.extractFieldValue(record, condition.field)

      switch (condition.operator) {
        case 'equals':
          return fieldValue === condition.value
        case 'not_equals':
          return fieldValue !== condition.value
        case 'contains':
          return String(fieldValue).includes(String(condition.value))
        case 'not_contains':
          return !String(fieldValue).includes(String(condition.value))
        case 'exists':
          return fieldValue !== undefined && fieldValue !== null
        case 'not_exists':
          return fieldValue === undefined || fieldValue === null
        default:
          return true
      }
    })
  }

  /**
   * Validate field value against target field specification
   */
  private validateFieldValue(
    value: any,
    targetField: any
  ): {
    isValid: boolean
    error?: string
    suggestedFix?: string
    warnings?: Array<{ type: string; message: string }>
  } {
    const warnings: Array<{ type: string; message: string }> = []

    // Required field check
    if (targetField.required && (value === undefined || value === null || value === '')) {
      return {
        isValid: false,
        error: `Required field '${targetField.name}' is missing or empty`,
        suggestedFix: 'Provide a default value or ensure source data contains this field',
      }
    }

    // Type validation
    if (value !== undefined && value !== null) {
      const actualType = Array.isArray(value) ? 'array' : typeof value
      if (targetField.type !== 'any' && actualType !== targetField.type) {
        warnings.push({
          type: 'type_coercion',
          message: `Type mismatch: expected ${targetField.type}, got ${actualType}`,
        })
      }

      // Length validation
      if (targetField.maxLength && String(value).length > targetField.maxLength) {
        warnings.push({
          type: 'truncation',
          message: `Value exceeds maximum length of ${targetField.maxLength}`,
        })
      }
    }

    return {
      isValid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
    }
  }
}

// Export singleton instance
export const fieldMappingEngine = new FieldMappingEngineImpl()
