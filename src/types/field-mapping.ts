/**
 * Field Mapping System Type Definitions
 * Core types for flexible data transformation and mapping
 */

import { BusinessRecord } from './business'

/**
 * Source field reference
 */
export interface SourceField {
  path: string              // Dot notation path (e.g., 'contact.email', 'address.street')
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'date'
  required: boolean
  defaultValue?: any
  description?: string
}

/**
 * Target field specification
 */
export interface TargetField {
  name: string
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'date'
  required: boolean
  format?: string           // Format specification (e.g., 'YYYY-MM-DD', '(###) ###-####')
  maxLength?: number
  validation?: FieldValidator[]
  description?: string
}

/**
 * Field validator configuration
 */
export interface FieldValidator {
  type: 'required' | 'email' | 'phone' | 'url' | 'length' | 'pattern' | 'range' | 'custom'
  params?: {
    min?: number
    max?: number
    pattern?: string | RegExp
    message?: string
    customFn?: string       // Serialized function for custom validation
  }
  errorMessage: string
}

/**
 * Data transformation function
 */
export interface DataTransformation {
  id: string
  name: string
  description: string
  inputTypes: string[]
  outputType: string
  parameters?: Record<string, any>
  transform: (input: any, params?: Record<string, any>) => any
}

/**
 * Field mapping rule
 */
export interface FieldMappingRule {
  id: string
  sourceFields: SourceField[]
  targetField: TargetField
  transformation: DataTransformation
  conditions?: MappingCondition[]
  priority: number          // Higher priority rules are applied first
  enabled: boolean
}

/**
 * Conditional mapping logic
 */
export interface MappingCondition {
  field: string
  operator: 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'starts_with' | 'ends_with' | 'regex' | 'exists' | 'not_exists'
  value: any
  caseSensitive?: boolean
}

/**
 * Field mapping schema
 */
export interface FieldMappingSchema {
  id: string
  name: string
  version: string
  description: string
  sourceSchema: {
    name: string
    version: string
    fields: SourceField[]
  }
  targetSchema: {
    name: string
    version: string
    fields: TargetField[]
  }
  mappingRules: FieldMappingRule[]
  metadata: {
    createdAt: string
    updatedAt: string
    createdBy: string
    tags: string[]
  }
}

/**
 * Mapping execution result
 */
export interface MappingExecutionResult {
  success: boolean
  recordsProcessed: number
  recordsSuccessful: number
  recordsFailed: number
  mappedData: any[]
  errors: MappingError[]
  warnings: MappingWarning[]
  statistics: {
    executionTime: number
    averageRecordTime: number
    memoryUsage: number
    transformationsApplied: number
  }
}

/**
 * Mapping error details
 */
export interface MappingError {
  recordIndex: number
  ruleId: string
  sourceField: string
  targetField: string
  errorType: 'validation' | 'transformation' | 'missing_field' | 'type_mismatch'
  message: string
  originalValue: any
  suggestedFix?: string
}

/**
 * Mapping warning details
 */
export interface MappingWarning {
  recordIndex: number
  ruleId: string
  sourceField: string
  targetField: string
  warningType: 'data_loss' | 'type_coercion' | 'default_value_used' | 'truncation'
  message: string
  originalValue: any
  mappedValue: any
}

/**
 * Field mapping engine interface
 */
export interface FieldMappingEngine {
  // Schema management
  registerSchema(schema: FieldMappingSchema): void
  getSchema(id: string): FieldMappingSchema | null
  validateSchema(schema: FieldMappingSchema): SchemaValidationResult
  
  // Transformation management
  registerTransformation(transformation: DataTransformation): void
  getTransformation(id: string): DataTransformation | null
  listTransformations(): DataTransformation[]
  
  // Mapping execution
  executeMapping(schemaId: string, sourceData: any[]): Promise<MappingExecutionResult>
  executeMappingWithSchema(schema: FieldMappingSchema, sourceData: any[]): Promise<MappingExecutionResult>
  
  // Validation and testing
  validateMapping(schema: FieldMappingSchema, sampleData: any[]): Promise<MappingValidationResult>
  testMapping(schema: FieldMappingSchema, testData: any[]): Promise<MappingTestResult>
}

/**
 * Schema validation result
 */
export interface SchemaValidationResult {
  isValid: boolean
  errors: string[]
  warnings: string[]
  suggestions: string[]
  compatibility: {
    sourceCompatible: boolean
    targetCompatible: boolean
    transformationsSupported: boolean
  }
}

/**
 * Mapping validation result
 */
export interface MappingValidationResult {
  isValid: boolean
  coverage: {
    sourceFieldsCovered: number
    targetFieldsMapped: number
    requiredFieldsMapped: number
    coveragePercentage: number
  }
  issues: Array<{
    type: 'error' | 'warning' | 'info'
    message: string
    ruleId?: string
    field?: string
  }>
  recommendations: string[]
}

/**
 * Mapping test result
 */
export interface MappingTestResult {
  passed: boolean
  testCases: Array<{
    input: any
    expectedOutput: any
    actualOutput: any
    passed: boolean
    errors: string[]
  }>
  summary: {
    totalTests: number
    passedTests: number
    failedTests: number
    successRate: number
  }
}

/**
 * Built-in transformation types
 */
export type BuiltInTransformation = 
  | 'direct_copy'
  | 'concatenate'
  | 'split'
  | 'format_phone'
  | 'format_email'
  | 'format_date'
  | 'format_address'
  | 'normalize_text'
  | 'extract_domain'
  | 'calculate_age'
  | 'lookup_value'
  | 'conditional_value'

/**
 * Transformation parameter types
 */
export interface TransformationParams {
  // Concatenation
  separator?: string
  prefix?: string
  suffix?: string
  
  // Splitting
  delimiter?: string
  index?: number
  
  // Formatting
  format?: string
  locale?: string
  
  // Lookup
  lookupTable?: Record<string, any>
  defaultValue?: any
  
  // Conditional
  conditions?: Array<{
    condition: string
    value: any
  }>
}

/**
 * Field mapping builder interface
 */
export interface FieldMappingBuilder {
  setBasicInfo(name: string, description: string): FieldMappingBuilder
  setSourceSchema(name: string, fields: SourceField[]): FieldMappingBuilder
  setTargetSchema(name: string, fields: TargetField[]): FieldMappingBuilder
  addMappingRule(rule: Omit<FieldMappingRule, 'id'>): FieldMappingBuilder
  addTransformation(transformation: DataTransformation): FieldMappingBuilder
  build(): FieldMappingSchema
  validate(): SchemaValidationResult
}
