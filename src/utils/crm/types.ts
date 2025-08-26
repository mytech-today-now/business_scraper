/**
 * CRM Export Templates - Type Definitions
 * Defines types for CRM-specific export functionality
 */

import { BusinessRecord } from '@/types/business'

/**
 * Supported CRM platforms
 */
export type CRMPlatform = 'salesforce' | 'hubspot' | 'pipedrive' | 'generic'

/**
 * Field transformation function type
 */
export type FieldTransformer = (value: any, record: BusinessRecord) => any

/**
 * Validation rule for CRM fields
 */
export interface ValidationRule {
  required: boolean
  type: 'string' | 'number' | 'boolean' | 'date' | 'email' | 'phone' | 'url'
  maxLength?: number
  minLength?: number
  pattern?: RegExp
  allowedValues?: string[]
  customValidator?: (value: any) => boolean | string
}

/**
 * CRM field mapping definition
 */
export interface CRMFieldMapping {
  /** Source field path in BusinessRecord (supports dot notation) */
  sourceField: string
  /** Target field name in CRM */
  targetField: string
  /** Optional transformation function */
  transformer?: FieldTransformer
  /** Default value if source field is empty */
  defaultValue?: any
  /** Validation rules for the field */
  validation?: ValidationRule
  /** Whether this field is required by the CRM */
  required?: boolean
  /** Field description for UI */
  description?: string
}

/**
 * CRM template configuration
 */
export interface CRMTemplate {
  /** Template identifier */
  id: string
  /** Display name */
  name: string
  /** CRM platform this template is for */
  platform: CRMPlatform
  /** Template description */
  description: string
  /** Field mappings */
  fieldMappings: CRMFieldMapping[]
  /** Export format (csv, json, xml) */
  exportFormat: 'csv' | 'json' | 'xml'
  /** Custom headers for CSV export */
  customHeaders?: Record<string, string>
  /** Template metadata */
  metadata: {
    version: string
    author: string
    createdAt: string
    updatedAt: string
    tags: string[]
  }
  /** Validation settings */
  validation: {
    strictMode: boolean
    skipInvalidRecords: boolean
    maxErrors: number
  }
}

/**
 * Transformation result for a single record
 */
export interface TransformationResult {
  /** Transformed data */
  data: Record<string, any>
  /** Validation errors */
  errors: ValidationError[]
  /** Warnings */
  warnings: string[]
  /** Whether the record is valid */
  isValid: boolean
}

/**
 * Validation error details
 */
export interface ValidationError {
  field: string
  message: string
  value: any
  rule: string
}

/**
 * Batch transformation result
 */
export interface BatchTransformationResult {
  /** Successfully transformed records */
  validRecords: Record<string, any>[]
  /** Invalid records with errors */
  invalidRecords: Array<{
    originalRecord: BusinessRecord
    errors: ValidationError[]
    warnings: string[]
  }>
  /** Summary statistics */
  summary: {
    total: number
    valid: number
    invalid: number
    warnings: number
    processingTime: number
  }
}

/**
 * CRM export options
 */
export interface CRMExportOptions {
  /** Selected CRM template */
  template: CRMTemplate
  /** Whether to include headers in CSV export */
  includeHeaders?: boolean
  /** Date format for date fields */
  dateFormat?: string
  /** Timezone for date conversions */
  timezone?: string
  /** Whether to validate data before export */
  validateData?: boolean
  /** Whether to skip invalid records or fail */
  skipInvalidRecords?: boolean
  /** Custom field transformations */
  customTransformers?: Record<string, FieldTransformer>
  /** Export metadata */
  metadata?: {
    exportedBy: string
    exportPurpose: string
    notes: string
  }
}

/**
 * CRM adapter interface
 */
export interface CRMAdapter {
  /** Platform identifier */
  platform: CRMPlatform
  /** Platform display name */
  displayName: string
  /** Available templates for this platform */
  templates: CRMTemplate[]
  
  /**
   * Transform business records for this CRM platform
   */
  transformRecords(
    records: BusinessRecord[],
    template: CRMTemplate,
    options?: CRMExportOptions
  ): Promise<BatchTransformationResult>
  
  /**
   * Validate a single record against CRM requirements
   */
  validateRecord(
    record: BusinessRecord,
    template: CRMTemplate
  ): ValidationError[]
  
  /**
   * Get default template for this platform
   */
  getDefaultTemplate(): CRMTemplate
  
  /**
   * Create custom template based on user requirements
   */
  createCustomTemplate(
    name: string,
    fieldMappings: CRMFieldMapping[],
    options?: Partial<CRMTemplate>
  ): CRMTemplate
}

/**
 * Template manager interface
 */
export interface CRMTemplateManager {
  /**
   * Get all available templates
   */
  getAllTemplates(): CRMTemplate[]
  
  /**
   * Get templates for specific platform
   */
  getTemplatesByPlatform(platform: CRMPlatform): CRMTemplate[]
  
  /**
   * Get template by ID
   */
  getTemplate(id: string): CRMTemplate | null
  
  /**
   * Save custom template
   */
  saveTemplate(template: CRMTemplate): Promise<void>
  
  /**
   * Delete custom template
   */
  deleteTemplate(id: string): Promise<void>
  
  /**
   * Clone existing template
   */
  cloneTemplate(id: string, newName: string): CRMTemplate
  
  /**
   * Validate template configuration
   */
  validateTemplate(template: CRMTemplate): ValidationError[]
}

/**
 * Export progress tracking
 */
export interface CRMExportProgress {
  /** Current step */
  step: 'validating' | 'transforming' | 'exporting' | 'complete'
  /** Records processed */
  processed: number
  /** Total records */
  total: number
  /** Progress percentage */
  percentage: number
  /** Current operation */
  currentOperation: string
  /** Estimated time remaining (ms) */
  estimatedTimeRemaining: number
  /** Errors encountered */
  errors: ValidationError[]
  /** Warnings */
  warnings: string[]
}

/**
 * CRM export result
 */
export interface CRMExportResult {
  /** Export blob */
  blob: Blob
  /** Filename */
  filename: string
  /** Export statistics */
  statistics: {
    totalRecords: number
    exportedRecords: number
    skippedRecords: number
    errors: ValidationError[]
    warnings: string[]
    processingTime: number
  }
  /** Template used */
  template: CRMTemplate
  /** Export metadata */
  metadata: {
    exportDate: string
    platform: CRMPlatform
    format: string
    version: string
  }
}

/**
 * Common field transformers
 */
export const CommonTransformers = {
  /** Convert to uppercase */
  toUpperCase: (value: any): string => String(value || '').toUpperCase(),
  
  /** Convert to lowercase */
  toLowerCase: (value: any): string => String(value || '').toLowerCase(),
  
  /** Format phone number */
  formatPhone: (value: any): string => {
    const phone = String(value || '').replace(/\D/g, '')
    if (phone.length === 10) {
      return `(${phone.slice(0, 3)}) ${phone.slice(3, 6)}-${phone.slice(6)}`
    }
    return phone
  },
  
  /** Format date to ISO string */
  formatDateISO: (value: any): string => {
    if (!value) return ''
    const date = new Date(value)
    return isNaN(date.getTime()) ? '' : date.toISOString()
  },
  
  /** Format date to MM/DD/YYYY */
  formatDateUS: (value: any): string => {
    if (!value) return ''
    const date = new Date(value)
    return isNaN(date.getTime()) ? '' : date.toLocaleDateString('en-US')
  },
  
  /** Clean and validate email */
  formatEmail: (value: any): string => {
    const email = String(value || '').toLowerCase().trim()
    return email.includes('@') ? email : ''
  },
  
  /** Format currency */
  formatCurrency: (value: any): number => {
    const num = parseFloat(String(value || '0').replace(/[^0-9.-]/g, ''))
    return isNaN(num) ? 0 : num
  },
  
  /** Boolean converter */
  toBoolean: (value: any): boolean => {
    if (typeof value === 'boolean') return value
    const str = String(value || '').toLowerCase()
    return ['true', '1', 'yes', 'y', 'on'].includes(str)
  }
} as const
