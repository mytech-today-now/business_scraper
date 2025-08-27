/**
 * CRM Transformation Engine
 * Handles data transformation and validation for CRM exports
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMTemplate,
  CRMFieldMapping,
  TransformationResult,
  BatchTransformationResult,
  ValidationError,
  ValidationRule,
  FieldTransformer,
  CRMExportOptions,
} from './types'
import { logger } from '@/utils/logger'

/**
 * Core transformation engine for CRM exports
 */
export class CRMTransformationEngine {
  /**
   * Transform a batch of business records using the specified template
   */
  async transformBatch(
    records: BusinessRecord[],
    template: CRMTemplate,
    options: CRMExportOptions = { template }
  ): Promise<BatchTransformationResult> {
    const startTime = Date.now()
    const validRecords: Record<string, any>[] = []
    const invalidRecords: Array<{
      originalRecord: BusinessRecord
      errors: ValidationError[]
      warnings: string[]
    }> = []

    logger.info(
      'CRMTransformationEngine',
      `Starting batch transformation of ${records.length} records using template: ${template.name}`
    )

    for (const record of records) {
      try {
        const result = await this.transformRecord(record, template, options)

        if (result.isValid || !template.validation.strictMode) {
          validRecords.push(result.data)
        }

        if (!result.isValid) {
          invalidRecords.push({
            originalRecord: record,
            errors: result.errors,
            warnings: result.warnings,
          })
        }
      } catch (error) {
        logger.error('CRMTransformationEngine', `Failed to transform record ${record.id}`, error)
        invalidRecords.push({
          originalRecord: record,
          errors: [
            {
              field: 'general',
              message: `Transformation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
              value: record,
              rule: 'transformation',
            },
          ],
          warnings: [],
        })
      }
    }

    const processingTime = Date.now() - startTime
    const totalWarnings = invalidRecords.reduce((sum, record) => sum + record.warnings.length, 0)

    logger.info(
      'CRMTransformationEngine',
      `Batch transformation completed: ${validRecords.length}/${records.length} valid records in ${processingTime}ms`
    )

    return {
      validRecords,
      invalidRecords,
      summary: {
        total: records.length,
        valid: validRecords.length,
        invalid: invalidRecords.length,
        warnings: totalWarnings,
        processingTime,
      },
    }
  }

  /**
   * Transform a single business record using the specified template
   */
  async transformRecord(
    record: BusinessRecord,
    template: CRMTemplate,
    options: CRMExportOptions = { template }
  ): Promise<TransformationResult> {
    const transformedData: Record<string, any> = {}
    const errors: ValidationError[] = []
    const warnings: string[] = []

    // Process each field mapping
    for (const mapping of template.fieldMappings) {
      try {
        const value = this.extractFieldValue(record, mapping.sourceField)
        let transformedValue = value

        // Apply transformation if specified
        if (mapping.transformer) {
          transformedValue = mapping.transformer(value, record)
        }

        // Apply custom transformers from options
        if (options.customTransformers && options.customTransformers[mapping.targetField]) {
          transformedValue = options.customTransformers[mapping.targetField](
            transformedValue,
            record
          )
        }

        // Use default value if transformed value is empty
        if (
          (transformedValue === null ||
            transformedValue === undefined ||
            transformedValue === '') &&
          mapping.defaultValue !== undefined
        ) {
          transformedValue = mapping.defaultValue
        }

        // Validate the transformed value
        if (mapping.validation) {
          const validationErrors = this.validateField(
            mapping.targetField,
            transformedValue,
            mapping.validation
          )
          errors.push(...validationErrors)
        }

        // Check required fields
        if (
          mapping.required &&
          (transformedValue === null || transformedValue === undefined || transformedValue === '')
        ) {
          errors.push({
            field: mapping.targetField,
            message: `Required field '${mapping.targetField}' is missing or empty`,
            value: transformedValue,
            rule: 'required',
          })
        }

        transformedData[mapping.targetField] = transformedValue
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown transformation error'
        errors.push({
          field: mapping.targetField,
          message: `Transformation failed: ${errorMessage}`,
          value: this.extractFieldValue(record, mapping.sourceField),
          rule: 'transformation',
        })
        warnings.push(
          `Failed to transform field '${mapping.sourceField}' to '${mapping.targetField}': ${errorMessage}`
        )
      }
    }

    return {
      data: transformedData,
      errors,
      warnings,
      isValid: errors.length === 0,
    }
  }

  /**
   * Extract field value from business record using dot notation
   */
  private extractFieldValue(record: BusinessRecord, fieldPath: string): any {
    const parts = fieldPath.split('.')
    let value: any = record

    for (const part of parts) {
      if (value === null || value === undefined) {
        return undefined
      }
      value = value[part]
    }

    return value
  }

  /**
   * Validate a field value against validation rules
   */
  private validateField(fieldName: string, value: any, rules: ValidationRule): ValidationError[] {
    const errors: ValidationError[] = []

    // Required validation
    if (rules.required && (value === null || value === undefined || value === '')) {
      errors.push({
        field: fieldName,
        message: `Field '${fieldName}' is required`,
        value,
        rule: 'required',
      })
      return errors // Don't continue validation if required field is missing
    }

    // Skip other validations if value is empty and not required
    if (value === null || value === undefined || value === '') {
      return errors
    }

    // Type validation
    if (rules.type) {
      const typeError = this.validateType(fieldName, value, rules.type)
      if (typeError) {
        errors.push(typeError)
      }
    }

    // Length validation
    if (rules.maxLength && String(value).length > rules.maxLength) {
      errors.push({
        field: fieldName,
        message: `Field '${fieldName}' exceeds maximum length of ${rules.maxLength}`,
        value,
        rule: 'maxLength',
      })
    }

    if (rules.minLength && String(value).length < rules.minLength) {
      errors.push({
        field: fieldName,
        message: `Field '${fieldName}' is below minimum length of ${rules.minLength}`,
        value,
        rule: 'minLength',
      })
    }

    // Pattern validation
    if (rules.pattern && !rules.pattern.test(String(value))) {
      errors.push({
        field: fieldName,
        message: `Field '${fieldName}' does not match required pattern`,
        value,
        rule: 'pattern',
      })
    }

    // Allowed values validation
    if (rules.allowedValues && !rules.allowedValues.includes(String(value))) {
      errors.push({
        field: fieldName,
        message: `Field '${fieldName}' must be one of: ${rules.allowedValues.join(', ')}`,
        value,
        rule: 'allowedValues',
      })
    }

    // Custom validation
    if (rules.customValidator) {
      const customResult = rules.customValidator(value)
      if (customResult !== true) {
        errors.push({
          field: fieldName,
          message:
            typeof customResult === 'string'
              ? customResult
              : `Field '${fieldName}' failed custom validation`,
          value,
          rule: 'custom',
        })
      }
    }

    return errors
  }

  /**
   * Validate field type
   */
  private validateType(
    fieldName: string,
    value: any,
    expectedType: ValidationRule['type']
  ): ValidationError | null {
    switch (expectedType) {
      case 'string':
        if (typeof value !== 'string') {
          return {
            field: fieldName,
            message: `Field '${fieldName}' must be a string`,
            value,
            rule: 'type',
          }
        }
        break

      case 'number':
        if (typeof value !== 'number' && isNaN(Number(value))) {
          return {
            field: fieldName,
            message: `Field '${fieldName}' must be a number`,
            value,
            rule: 'type',
          }
        }
        break

      case 'boolean':
        if (
          typeof value !== 'boolean' &&
          !['true', 'false', '1', '0'].includes(String(value).toLowerCase())
        ) {
          return {
            field: fieldName,
            message: `Field '${fieldName}' must be a boolean`,
            value,
            rule: 'type',
          }
        }
        break

      case 'date':
        if (isNaN(Date.parse(String(value)))) {
          return {
            field: fieldName,
            message: `Field '${fieldName}' must be a valid date`,
            value,
            rule: 'type',
          }
        }
        break

      case 'email':
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(String(value))) {
          return {
            field: fieldName,
            message: `Field '${fieldName}' must be a valid email address`,
            value,
            rule: 'type',
          }
        }
        break

      case 'phone':
        const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/
        const cleanPhone = String(value).replace(/\D/g, '')
        if (!phoneRegex.test(cleanPhone)) {
          return {
            field: fieldName,
            message: `Field '${fieldName}' must be a valid phone number`,
            value,
            rule: 'type',
          }
        }
        break

      case 'url':
        try {
          new URL(String(value))
        } catch {
          return {
            field: fieldName,
            message: `Field '${fieldName}' must be a valid URL`,
            value,
            rule: 'type',
          }
        }
        break
    }

    return null
  }

  /**
   * Create a summary report of transformation results
   */
  createSummaryReport(result: BatchTransformationResult): string {
    const { summary, invalidRecords } = result

    let report = `CRM Export Transformation Summary\n`
    report += `=====================================\n`
    report += `Total Records: ${summary.total}\n`
    report += `Valid Records: ${summary.valid}\n`
    report += `Invalid Records: ${summary.invalid}\n`
    report += `Warnings: ${summary.warnings}\n`
    report += `Processing Time: ${summary.processingTime}ms\n\n`

    if (invalidRecords.length > 0) {
      report += `Invalid Records Details:\n`
      report += `------------------------\n`

      invalidRecords.slice(0, 10).forEach((record, index) => {
        report += `Record ${index + 1} (ID: ${record.originalRecord.id}):\n`
        record.errors.forEach(error => {
          report += `  - ${error.field}: ${error.message}\n`
        })
        if (record.warnings.length > 0) {
          report += `  Warnings:\n`
          record.warnings.forEach(warning => {
            report += `    - ${warning}\n`
          })
        }
        report += `\n`
      })

      if (invalidRecords.length > 10) {
        report += `... and ${invalidRecords.length - 10} more invalid records\n`
      }
    }

    return report
  }
}
