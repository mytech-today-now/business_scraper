/**
 * Base Export Template
 * Foundation class for all export templates
 */

import { 
  ExportTemplate, 
  ExportTemplateResult, 
  TemplateValidationResult,
  ExportPlatform,
  FieldTransformation
} from '@/types/export-templates'
import { BusinessRecord } from '@/types/business'
import { fieldMappingEngine } from '@/lib/field-mapping/mapping-engine'
import { logger } from '@/utils/logger'

/**
 * Abstract base class for export templates
 */
export abstract class BaseExportTemplate {
  protected template: ExportTemplate

  constructor(template: ExportTemplate) {
    this.template = template
  }

  /**
   * Get template configuration
   */
  getTemplate(): ExportTemplate {
    return this.template
  }

  /**
   * Validate template configuration
   */
  validate(): TemplateValidationResult {
    const errors: string[] = []
    const warnings: string[] = []
    const suggestions: string[] = []

    // Basic validation
    if (!this.template.id || !this.template.name) {
      errors.push('Template must have id and name')
    }

    if (!this.template.fieldMappings.length) {
      errors.push('Template must have at least one field mapping')
    }

    // Validate required fields are mapped
    for (const requiredField of this.template.requiredFields) {
      const isMapped = this.template.fieldMappings.some(
        mapping => mapping.targetField === requiredField
      )
      
      if (!isMapped) {
        errors.push(`Required field '${requiredField}' is not mapped`)
      }
    }

    // Platform-specific validation
    const platformValidation = this.validatePlatformSpecific()
    errors.push(...platformValidation.errors)
    warnings.push(...platformValidation.warnings)
    suggestions.push(...platformValidation.suggestions)

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      suggestions,
      compatibility: {
        platform: this.template.platform,
        version: this.template.version,
        supported: errors.length === 0,
        limitations: warnings
      }
    }
  }

  /**
   * Execute template transformation
   */
  async execute(businesses: BusinessRecord[]): Promise<ExportTemplateResult> {
    const startTime = Date.now()
    
    logger.info('ExportTemplate', `Starting template execution: ${this.template.name}`, {
      templateId: this.template.id,
      platform: this.template.platform,
      recordCount: businesses.length
    })

    try {
      // Validate template before execution
      const validation = this.validate()
      if (!validation.isValid) {
        throw new Error(`Template validation failed: ${validation.errors.join(', ')}`)
      }

      // Pre-process data
      const preprocessedData = await this.preprocessData(businesses)

      // Apply field mappings
      const mappedData = await this.applyFieldMappings(preprocessedData)

      // Post-process data
      const postprocessedData = await this.postprocessData(mappedData)

      // Apply quality rules
      const qualityResult = await this.applyQualityRules(postprocessedData)

      const endTime = Date.now()
      const duration = endTime - startTime

      const result: ExportTemplateResult = {
        success: true,
        templateId: this.template.id,
        recordsProcessed: businesses.length,
        recordsExported: qualityResult.validRecords.length,
        recordsSkipped: qualityResult.skippedRecords.length,
        errors: qualityResult.errors,
        warnings: qualityResult.warnings,
        exportData: qualityResult.validRecords,
        metadata: {
          exportedAt: new Date().toISOString(),
          template: this.template.name,
          platform: this.template.platform,
          totalDuration: duration,
          averageProcessingTime: duration / businesses.length
        }
      }

      logger.info('ExportTemplate', `Template execution completed`, {
        templateId: this.template.id,
        recordsProcessed: result.recordsProcessed,
        recordsExported: result.recordsExported,
        recordsSkipped: result.recordsSkipped,
        duration
      })

      return result

    } catch (error) {
      const endTime = Date.now()
      const duration = endTime - startTime

      logger.error('ExportTemplate', `Template execution failed: ${this.template.name}`, error)

      return {
        success: false,
        templateId: this.template.id,
        recordsProcessed: businesses.length,
        recordsExported: 0,
        recordsSkipped: businesses.length,
        errors: [{
          recordIndex: -1,
          field: 'template',
          error: error instanceof Error ? error.message : 'Unknown error',
          value: null
        }],
        warnings: [],
        exportData: [],
        metadata: {
          exportedAt: new Date().toISOString(),
          template: this.template.name,
          platform: this.template.platform,
          totalDuration: duration,
          averageProcessingTime: 0
        }
      }
    }
  }

  /**
   * Pre-process business data before mapping
   */
  protected async preprocessData(businesses: BusinessRecord[]): Promise<BusinessRecord[]> {
    // Default implementation - can be overridden by subclasses
    return businesses.filter(business => {
      // Basic filtering - ensure business has minimum required data
      return business.businessName && business.businessName.trim().length > 0
    })
  }

  /**
   * Apply field mappings to data
   */
  protected async applyFieldMappings(businesses: BusinessRecord[]): Promise<any[]> {
    const mappedData: any[] = []

    for (let i = 0; i < businesses.length; i++) {
      const business = businesses[i]
      const mappedRecord: any = {}

      for (const mapping of this.template.fieldMappings) {
        try {
          const value = await this.applyFieldMapping(business, mapping)
          mappedRecord[mapping.targetField] = value
        } catch (error) {
          logger.warn('ExportTemplate', `Field mapping failed for record ${i}`, {
            templateId: this.template.id,
            mapping: mapping.targetField,
            error: error instanceof Error ? error.message : 'Unknown error'
          })
          
          // Use default value if available
          if (mapping.options?.defaultValue !== undefined) {
            mappedRecord[mapping.targetField] = mapping.options.defaultValue
          }
        }
      }

      mappedData.push(mappedRecord)
    }

    return mappedData
  }

  /**
   * Apply a single field mapping
   */
  protected async applyFieldMapping(business: BusinessRecord, mapping: FieldTransformation): Promise<any> {
    const sourceValues = mapping.sourceFields.map(field => 
      this.extractFieldValue(business, field)
    )

    switch (mapping.type) {
      case 'direct':
        return sourceValues[0]
      
      case 'concatenate':
        const separator = mapping.options?.separator || ' '
        return sourceValues.filter(v => v != null && v !== '').join(separator)
      
      case 'format':
        return this.formatValue(sourceValues[0], mapping.options?.format || '')
      
      case 'conditional':
        return this.applyConditionalMapping(sourceValues[0], mapping.options?.conditions || [])
      
      case 'lookup':
        return this.applyLookupMapping(sourceValues[0], mapping.options?.lookupTable || {})
      
      default:
        return sourceValues[0]
    }
  }

  /**
   * Extract field value from business record
   */
  protected extractFieldValue(business: BusinessRecord, fieldPath: string): any {
    const keys = fieldPath.split('.')
    let current: any = business
    
    for (const key of keys) {
      if (current == null || typeof current !== 'object') {
        return undefined
      }
      current = current[key]
    }
    
    return current
  }

  /**
   * Format value according to format specification
   */
  protected formatValue(value: any, format: string): any {
    if (!value || !format) return value

    switch (format) {
      case 'phone':
        return this.formatPhone(String(value))
      case 'email':
        return String(value).toLowerCase().trim()
      case 'url':
        return this.formatUrl(String(value))
      case 'uppercase':
        return String(value).toUpperCase()
      case 'lowercase':
        return String(value).toLowerCase()
      case 'title':
        return this.toTitleCase(String(value))
      default:
        return value
    }
  }

  /**
   * Apply conditional mapping
   */
  protected applyConditionalMapping(value: any, conditions: any[]): any {
    for (const condition of conditions) {
      if (this.evaluateCondition(value, condition.condition)) {
        return condition.value
      }
    }
    
    return conditions.find(c => c.condition === 'default')?.value || value
  }

  /**
   * Apply lookup table mapping
   */
  protected applyLookupMapping(value: any, lookupTable: Record<string, any>): any {
    const key = String(value).toLowerCase()
    return lookupTable[key] || lookupTable['default'] || value
  }

  /**
   * Post-process mapped data
   */
  protected async postprocessData(mappedData: any[]): Promise<any[]> {
    // Default implementation - can be overridden by subclasses
    return mappedData
  }

  /**
   * Apply quality rules to data
   */
  protected async applyQualityRules(data: any[]): Promise<{
    validRecords: any[]
    skippedRecords: any[]
    errors: any[]
    warnings: any[]
  }> {
    const validRecords: any[] = []
    const skippedRecords: any[] = []
    const errors: any[] = []
    const warnings: any[] = []

    const qualityRules = this.template.qualityRules

    for (let i = 0; i < data.length; i++) {
      const record = data[i]
      let isValid = true

      // Check minimum fields requirement
      if (qualityRules?.minimumFields) {
        const nonEmptyFields = Object.values(record).filter(v => 
          v != null && v !== ''
        ).length
        
        if (nonEmptyFields < qualityRules.minimumFields) {
          errors.push({
            recordIndex: i,
            field: 'record',
            error: `Record has only ${nonEmptyFields} fields, minimum ${qualityRules.minimumFields} required`,
            value: record
          })
          isValid = false
        }
      }

      // Check required fields
      for (const requiredField of this.template.requiredFields) {
        if (!record[requiredField] || record[requiredField] === '') {
          errors.push({
            recordIndex: i,
            field: requiredField,
            error: `Required field '${requiredField}' is missing or empty`,
            value: record[requiredField]
          })
          isValid = false
        }
      }

      if (isValid) {
        validRecords.push(record)
      } else {
        skippedRecords.push(record)
      }
    }

    return { validRecords, skippedRecords, errors, warnings }
  }

  /**
   * Platform-specific validation (to be implemented by subclasses)
   */
  protected abstract validatePlatformSpecific(): {
    errors: string[]
    warnings: string[]
    suggestions: string[]
  }

  /**
   * Utility methods
   */
  protected formatPhone(phone: string): string {
    const digits = phone.replace(/\D/g, '')
    if (digits.length === 10) {
      return `(${digits.substr(0, 3)}) ${digits.substr(3, 3)}-${digits.substr(6, 4)}`
    }
    return phone
  }

  protected formatUrl(url: string): string {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return `https://${url}`
    }
    return url
  }

  protected toTitleCase(str: string): string {
    return str.replace(/\w\S*/g, (txt) => 
      txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
    )
  }

  protected evaluateCondition(value: any, condition: string): boolean {
    // Simple condition evaluation - can be extended
    const [operator, operand] = condition.split(':')
    
    switch (operator) {
      case 'equals':
        return value === operand
      case 'contains':
        return String(value).includes(operand)
      case 'exists':
        return value != null && value !== ''
      case 'empty':
        return value == null || value === ''
      default:
        return false
    }
  }
}
