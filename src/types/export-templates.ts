/**
 * Export Templates Type Definitions
 * Comprehensive types for CRM and email marketing platform integrations
 */

import { BusinessRecord } from './business'

/**
 * Supported export template platforms
 */
export type ExportPlatform = 
  | 'salesforce'
  | 'hubspot'
  | 'pipedrive'
  | 'mailchimp'
  | 'constant-contact'
  | 'custom'

/**
 * Field transformation types
 */
export type FieldTransformationType = 
  | 'direct'           // Direct field mapping
  | 'concatenate'      // Combine multiple fields
  | 'split'           // Split field into multiple
  | 'format'          // Apply formatting (phone, date, etc.)
  | 'conditional'     // Conditional logic
  | 'lookup'          // Lookup table mapping
  | 'calculate'       // Calculated field

/**
 * Data validation rules
 */
export interface ValidationRule {
  type: 'required' | 'email' | 'phone' | 'url' | 'length' | 'pattern' | 'custom'
  value?: string | number | RegExp
  message?: string
  customValidator?: (value: any) => boolean | string
}

/**
 * Field transformation configuration
 */
export interface FieldTransformation {
  type: FieldTransformationType
  sourceFields: string[]
  targetField: string
  options?: {
    separator?: string
    format?: string
    conditions?: Array<{
      condition: string
      value: any
      defaultValue?: any
    }>
    lookupTable?: Record<string, any>
    calculation?: string
  }
  validation?: ValidationRule[]
}

/**
 * Export template configuration
 */
export interface ExportTemplate {
  id: string
  name: string
  platform: ExportPlatform
  description: string
  version: string
  
  // Field mappings and transformations
  fieldMappings: FieldTransformation[]
  requiredFields: string[]
  optionalFields: string[]
  
  // Platform-specific configuration
  platformConfig: {
    fileFormat: 'csv' | 'json' | 'xml' | 'xlsx'
    headers: Record<string, string>
    delimiter?: string
    encoding?: string
    dateFormat?: string
    booleanFormat?: { true: string; false: string }
    nullValue?: string
  }
  
  // Metadata and settings
  metadata: {
    createdAt: string
    updatedAt: string
    createdBy: string
    tags: string[]
    category: 'crm' | 'email-marketing' | 'custom'
  }
  
  // Validation and quality rules
  qualityRules?: {
    minimumFields: number
    duplicateHandling: 'skip' | 'merge' | 'include'
    dataValidation: ValidationRule[]
  }
}

/**
 * Export template result
 */
export interface ExportTemplateResult {
  success: boolean
  templateId: string
  recordsProcessed: number
  recordsExported: number
  recordsSkipped: number
  errors: Array<{
    recordIndex: number
    field: string
    error: string
    value: any
  }>
  warnings: Array<{
    recordIndex: number
    field: string
    warning: string
    value: any
  }>
  exportData: any[]
  metadata: {
    exportedAt: string
    template: string
    platform: ExportPlatform
    totalDuration: number
    averageProcessingTime: number
  }
}

/**
 * Template validation result
 */
export interface TemplateValidationResult {
  isValid: boolean
  errors: string[]
  warnings: string[]
  suggestions: string[]
  compatibility: {
    platform: ExportPlatform
    version: string
    supported: boolean
    limitations: string[]
  }
}

/**
 * Export template registry
 */
export interface ExportTemplateRegistry {
  templates: Map<string, ExportTemplate>
  getTemplate(id: string): ExportTemplate | null
  registerTemplate(template: ExportTemplate): void
  validateTemplate(template: ExportTemplate): TemplateValidationResult
  listTemplates(platform?: ExportPlatform): ExportTemplate[]
  searchTemplates(query: string): ExportTemplate[]
}

/**
 * Template execution context
 */
export interface TemplateExecutionContext {
  template: ExportTemplate
  sourceData: BusinessRecord[]
  options: {
    validateData?: boolean
    skipErrors?: boolean
    includeMetadata?: boolean
    customTransformations?: Record<string, (value: any) => any>
  }
  progress?: (processed: number, total: number) => void
}

/**
 * CRM-specific field mappings
 */
export interface CRMFieldMapping {
  // Common CRM fields
  companyName: string
  contactName?: string
  email: string
  phone?: string
  website?: string
  address?: string
  city?: string
  state?: string
  zipCode?: string
  country?: string
  industry?: string
  description?: string
  
  // Platform-specific fields
  customFields?: Record<string, any>
}

/**
 * Email marketing platform field mappings
 */
export interface EmailMarketingFieldMapping {
  // Required fields
  email: string
  
  // Optional fields
  firstName?: string
  lastName?: string
  companyName?: string
  phone?: string
  address?: string
  city?: string
  state?: string
  zipCode?: string
  country?: string
  
  // Marketing-specific fields
  optInStatus?: 'subscribed' | 'unsubscribed' | 'pending'
  listId?: string
  tags?: string[]
  customFields?: Record<string, any>
}

/**
 * Export template builder interface
 */
export interface ExportTemplateBuilder {
  setBasicInfo(name: string, platform: ExportPlatform, description: string): ExportTemplateBuilder
  addFieldMapping(transformation: FieldTransformation): ExportTemplateBuilder
  setRequiredFields(fields: string[]): ExportTemplateBuilder
  setPlatformConfig(config: ExportTemplate['platformConfig']): ExportTemplateBuilder
  addValidationRule(rule: ValidationRule): ExportTemplateBuilder
  build(): ExportTemplate
  validate(): TemplateValidationResult
}
