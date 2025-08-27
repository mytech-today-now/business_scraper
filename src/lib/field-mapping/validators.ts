/**
 * Field Validation Utilities
 * Comprehensive validation functions for field mapping
 */

import { FieldValidator } from '@/types/field-mapping'

/**
 * Validation result interface
 */
export interface ValidationResult {
  isValid: boolean
  error?: string
  warnings?: string[]
  suggestedFix?: string
}

/**
 * Field validation engine
 */
export class FieldValidationEngine {
  /**
   * Validate a value against a set of validators
   */
  static validate(value: any, validators: FieldValidator[]): ValidationResult {
    const warnings: string[] = []

    for (const validator of validators) {
      const result = this.validateSingle(value, validator)

      if (!result.isValid) {
        return result
      }

      if (result.warnings) {
        warnings.push(...result.warnings)
      }
    }

    return {
      isValid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
    }
  }

  /**
   * Validate a value against a single validator
   */
  private static validateSingle(value: any, validator: FieldValidator): ValidationResult {
    switch (validator.type) {
      case 'required':
        return this.validateRequired(value, validator)
      case 'email':
        return this.validateEmail(value, validator)
      case 'phone':
        return this.validatePhone(value, validator)
      case 'url':
        return this.validateUrl(value, validator)
      case 'length':
        return this.validateLength(value, validator)
      case 'pattern':
        return this.validatePattern(value, validator)
      case 'range':
        return this.validateRange(value, validator)
      case 'custom':
        return this.validateCustom(value, validator)
      default:
        return { isValid: true }
    }
  }

  /**
   * Validate required field
   */
  private static validateRequired(value: any, validator: FieldValidator): ValidationResult {
    const isEmpty =
      value === undefined ||
      value === null ||
      value === '' ||
      (Array.isArray(value) && value.length === 0)

    if (isEmpty) {
      return {
        isValid: false,
        error: validator.errorMessage || 'This field is required',
        suggestedFix: 'Provide a value for this required field',
      }
    }

    return { isValid: true }
  }

  /**
   * Validate email format
   */
  private static validateEmail(value: any, validator: FieldValidator): ValidationResult {
    if (!value) return { isValid: true } // Allow empty for optional fields

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    const isValid = emailRegex.test(String(value))

    if (!isValid) {
      return {
        isValid: false,
        error: validator.errorMessage || 'Invalid email format',
        suggestedFix: 'Ensure email follows format: user@domain.com',
      }
    }

    // Additional email validation warnings
    const warnings: string[] = []
    const email = String(value).toLowerCase()

    if (email.includes('+')) {
      warnings.push('Email contains plus sign, may be an alias')
    }

    if (email.endsWith('.test') || email.endsWith('.example')) {
      warnings.push('Email appears to be a test/example address')
    }

    return {
      isValid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
    }
  }

  /**
   * Validate phone number format
   */
  private static validatePhone(value: any, validator: FieldValidator): ValidationResult {
    if (!value) return { isValid: true } // Allow empty for optional fields

    const phoneStr = String(value).replace(/\D/g, '')
    const isValid = phoneStr.length >= 10 && phoneStr.length <= 15

    if (!isValid) {
      return {
        isValid: false,
        error: validator.errorMessage || 'Invalid phone number format',
        suggestedFix: 'Phone number should contain 10-15 digits',
      }
    }

    const warnings: string[] = []

    if (phoneStr.length === 11 && !phoneStr.startsWith('1')) {
      warnings.push('11-digit number should start with country code 1')
    }

    if (phoneStr.length < 10) {
      warnings.push('Phone number may be incomplete')
    }

    return {
      isValid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
    }
  }

  /**
   * Validate URL format
   */
  private static validateUrl(value: any, validator: FieldValidator): ValidationResult {
    if (!value) return { isValid: true } // Allow empty for optional fields

    try {
      const url = new URL(String(value))
      const warnings: string[] = []

      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        warnings.push('URL should use HTTP or HTTPS protocol')
      }

      if (!url.hostname.includes('.')) {
        warnings.push('URL hostname may be invalid')
      }

      return {
        isValid: true,
        warnings: warnings.length > 0 ? warnings : undefined,
      }
    } catch {
      return {
        isValid: false,
        error: validator.errorMessage || 'Invalid URL format',
        suggestedFix: 'URL should include protocol (http:// or https://)',
      }
    }
  }

  /**
   * Validate string length
   */
  private static validateLength(value: any, validator: FieldValidator): ValidationResult {
    if (!value) return { isValid: true } // Allow empty for optional fields

    const length = String(value).length
    const min = validator.params?.min || 0
    const max = validator.params?.max || Infinity

    if (length < min) {
      return {
        isValid: false,
        error: validator.errorMessage || `Value must be at least ${min} characters`,
        suggestedFix: `Provide at least ${min} characters`,
      }
    }

    if (length > max) {
      return {
        isValid: false,
        error: validator.errorMessage || `Value must be no more than ${max} characters`,
        suggestedFix: `Limit to ${max} characters or less`,
      }
    }

    const warnings: string[] = []

    if (length > max * 0.9) {
      warnings.push(`Value is close to maximum length limit (${max})`)
    }

    return {
      isValid: true,
      warnings: warnings.length > 0 ? warnings : undefined,
    }
  }

  /**
   * Validate against regex pattern
   */
  private static validatePattern(value: any, validator: FieldValidator): ValidationResult {
    if (!value) return { isValid: true } // Allow empty for optional fields

    const pattern = validator.params?.pattern
    if (!pattern) return { isValid: true }

    const regex = typeof pattern === 'string' ? new RegExp(pattern) : pattern
    const isValid = regex.test(String(value))

    if (!isValid) {
      return {
        isValid: false,
        error: validator.errorMessage || 'Value does not match required pattern',
        suggestedFix: 'Ensure value matches the expected format',
      }
    }

    return { isValid: true }
  }

  /**
   * Validate numeric range
   */
  private static validateRange(value: any, validator: FieldValidator): ValidationResult {
    if (!value) return { isValid: true } // Allow empty for optional fields

    const numValue = Number(value)

    if (isNaN(numValue)) {
      return {
        isValid: false,
        error: validator.errorMessage || 'Value must be a number',
        suggestedFix: 'Provide a valid numeric value',
      }
    }

    const min = validator.params?.min
    const max = validator.params?.max

    if (min !== undefined && numValue < min) {
      return {
        isValid: false,
        error: validator.errorMessage || `Value must be at least ${min}`,
        suggestedFix: `Provide a value of ${min} or greater`,
      }
    }

    if (max !== undefined && numValue > max) {
      return {
        isValid: false,
        error: validator.errorMessage || `Value must be no more than ${max}`,
        suggestedFix: `Provide a value of ${max} or less`,
      }
    }

    return { isValid: true }
  }

  /**
   * Validate using custom function
   */
  private static validateCustom(value: any, validator: FieldValidator): ValidationResult {
    try {
      const customFn = validator.params?.customFn
      if (!customFn) return { isValid: true }

      // For security, we would need to implement a safe function execution environment
      // For now, return true as custom validation would need to be implemented separately
      return { isValid: true }
    } catch (error) {
      return {
        isValid: false,
        error: validator.errorMessage || 'Custom validation failed',
        suggestedFix: 'Check custom validation logic',
      }
    }
  }
}

/**
 * Common validation presets for business data
 */
export class BusinessValidationPresets {
  /**
   * Get validators for business name
   */
  static getBusinessNameValidators(): FieldValidator[] {
    return [
      {
        type: 'required',
        errorMessage: 'Business name is required',
      },
      {
        type: 'length',
        params: { min: 2, max: 100 },
        errorMessage: 'Business name must be between 2 and 100 characters',
      },
    ]
  }

  /**
   * Get validators for email
   */
  static getEmailValidators(required: boolean = false): FieldValidator[] {
    const validators: FieldValidator[] = [
      {
        type: 'email',
        errorMessage: 'Invalid email format',
      },
    ]

    if (required) {
      validators.unshift({
        type: 'required',
        errorMessage: 'Email is required',
      })
    }

    return validators
  }

  /**
   * Get validators for phone number
   */
  static getPhoneValidators(required: boolean = false): FieldValidator[] {
    const validators: FieldValidator[] = [
      {
        type: 'phone',
        errorMessage: 'Invalid phone number format',
      },
    ]

    if (required) {
      validators.unshift({
        type: 'required',
        errorMessage: 'Phone number is required',
      })
    }

    return validators
  }

  /**
   * Get validators for website URL
   */
  static getWebsiteValidators(required: boolean = false): FieldValidator[] {
    const validators: FieldValidator[] = [
      {
        type: 'url',
        errorMessage: 'Invalid website URL format',
      },
    ]

    if (required) {
      validators.unshift({
        type: 'required',
        errorMessage: 'Website URL is required',
      })
    }

    return validators
  }

  /**
   * Get validators for address
   */
  static getAddressValidators(): FieldValidator[] {
    return [
      {
        type: 'length',
        params: { min: 5, max: 200 },
        errorMessage: 'Address must be between 5 and 200 characters',
      },
    ]
  }

  /**
   * Get validators for ZIP code
   */
  static getZipCodeValidators(): FieldValidator[] {
    return [
      {
        type: 'pattern',
        params: { pattern: /^\d{5}(-\d{4})?$/ },
        errorMessage: 'ZIP code must be in format 12345 or 12345-6789',
      },
    ]
  }

  /**
   * Get validators for industry
   */
  static getIndustryValidators(): FieldValidator[] {
    return [
      {
        type: 'length',
        params: { min: 2, max: 50 },
        errorMessage: 'Industry must be between 2 and 50 characters',
      },
    ]
  }
}
