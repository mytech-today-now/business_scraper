/**
 * Enhanced Input Validation and Sanitization Service
 * Implements comprehensive input validation using DOMPurify and validator
 * 
 * This service provides protection against:
 * - XSS attacks
 * - SQL injection
 * - HTML injection
 * - Script injection
 * - Data validation errors
 */

import DOMPurify from 'isomorphic-dompurify'
import validator from 'validator'
import { logger } from '@/utils/logger'
import { hardenedSecurityConfig } from './hardened-security-config'

export type InputType = 'email' | 'url' | 'text' | 'html' | 'json' | 'number' | 'phone' | 'domain'

export interface ValidationResult {
  isValid: boolean
  sanitizedValue: string
  errors: string[]
  warnings: string[]
  originalValue: string
  detectedThreats: string[]
}

export interface ValidationOptions {
  maxLength?: number
  minLength?: number
  allowEmpty?: boolean
  customPattern?: RegExp
  allowedDomains?: string[]
  strictMode?: boolean
}

/**
 * Enhanced Input Validation and Sanitization Service
 */
export class EnhancedInputValidationService {
  private config = hardenedSecurityConfig.inputValidation

  /**
   * Sanitize and validate input based on type
   */
  sanitizeAndValidateInput(
    input: any,
    type: InputType,
    options: ValidationOptions = {}
  ): ValidationResult {
    const result: ValidationResult = {
      isValid: false,
      sanitizedValue: '',
      errors: [],
      warnings: [],
      originalValue: String(input || ''),
      detectedThreats: []
    }

    try {
      // Type validation
      if (typeof input !== 'string' && input !== null && input !== undefined) {
        result.errors.push('Input must be a string')
        return result
      }

      const inputStr = String(input || '')
      result.originalValue = inputStr

      // Length validation
      if (options.maxLength && inputStr.length > options.maxLength) {
        result.errors.push(`Input exceeds maximum length of ${options.maxLength}`)
        return result
      }

      if (options.minLength && inputStr.length < options.minLength) {
        result.errors.push(`Input is below minimum length of ${options.minLength}`)
        return result
      }

      // Empty value handling
      if (!inputStr.trim()) {
        if (options.allowEmpty) {
          result.isValid = true
          result.sanitizedValue = ''
          return result
        } else {
          result.errors.push('Input cannot be empty')
          return result
        }
      }

      // Threat detection
      this.detectThreats(inputStr, result)

      // Type-specific validation and sanitization
      switch (type) {
        case 'email':
          return this.validateEmail(inputStr, result, options)
        case 'url':
          return this.validateUrl(inputStr, result, options)
        case 'text':
          return this.validateText(inputStr, result, options)
        case 'html':
          return this.validateHtml(inputStr, result, options)
        case 'json':
          return this.validateJson(inputStr, result, options)
        case 'number':
          return this.validateNumber(inputStr, result, options)
        case 'phone':
          return this.validatePhone(inputStr, result, options)
        case 'domain':
          return this.validateDomain(inputStr, result, options)
        default:
          result.errors.push(`Unknown validation type: ${type}`)
          return result
      }
    } catch (error) {
      logger.error('Input Validation Error', { error: error.message, input: input })
      result.errors.push('Validation failed due to internal error')
      return result
    }
  }

  /**
   * Detect potential security threats in input
   */
  private detectThreats(input: string, result: ValidationResult): void {
    // SQL Injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
      /(--|\/\*|\*\/|;|'|")/,
      /(\bOR\b|\bAND\b).*?[=<>]/i,
      /(\bUNION\b.*?\bSELECT\b)/i
    ]

    // XSS patterns
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
      /<embed\b[^>]*>/gi
    ]

    // Command injection patterns
    const commandPatterns = [
      /[;&|`$(){}[\]]/,
      /\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig)\b/i
    ]

    // Check for SQL injection
    if (sqlPatterns.some(pattern => pattern.test(input))) {
      result.detectedThreats.push('SQL_INJECTION')
      result.warnings.push('Potential SQL injection attempt detected')
    }

    // Check for XSS
    if (xssPatterns.some(pattern => pattern.test(input))) {
      result.detectedThreats.push('XSS_ATTEMPT')
      result.warnings.push('Potential XSS attempt detected')
    }

    // Check for command injection
    if (commandPatterns.some(pattern => pattern.test(input))) {
      result.detectedThreats.push('COMMAND_INJECTION')
      result.warnings.push('Potential command injection attempt detected')
    }

    // Check for excessive length (potential DoS)
    if (input.length > this.config.maxInputLength) {
      result.detectedThreats.push('EXCESSIVE_LENGTH')
      result.warnings.push('Input length exceeds security threshold')
    }
  }

  /**
   * Validate email input
   */
  private validateEmail(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    const sanitized = DOMPurify.sanitize(input.trim().toLowerCase())
    
    if (!validator.isEmail(sanitized)) {
      result.errors.push('Invalid email format')
      return result
    }

    // Check domain whitelist if provided
    if (options.allowedDomains) {
      const domain = sanitized.split('@')[1]
      if (!options.allowedDomains.includes(domain)) {
        result.errors.push('Email domain not allowed')
        return result
      }
    }

    result.isValid = true
    result.sanitizedValue = sanitized
    return result
  }

  /**
   * Validate URL input
   */
  private validateUrl(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    const sanitized = DOMPurify.sanitize(input.trim())
    
    if (!validator.isURL(sanitized, { protocols: ['http', 'https'], require_protocol: true })) {
      result.errors.push('Invalid URL format')
      return result
    }

    result.isValid = true
    result.sanitizedValue = sanitized
    return result
  }

  /**
   * Validate text input
   */
  private validateText(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    let sanitized = DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] })
    sanitized = validator.escape(sanitized)

    if (options.customPattern && !options.customPattern.test(sanitized)) {
      result.errors.push('Input does not match required pattern')
      return result
    }

    result.isValid = true
    result.sanitizedValue = sanitized
    return result
  }

  /**
   * Validate HTML input
   */
  private validateHtml(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    const sanitized = DOMPurify.sanitize(input, this.config.sanitizeOptions)

    result.isValid = true
    result.sanitizedValue = sanitized
    return result
  }

  /**
   * Validate JSON input
   */
  private validateJson(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    try {
      const parsed = JSON.parse(input)
      const sanitized = JSON.stringify(parsed)
      
      result.isValid = true
      result.sanitizedValue = sanitized
      return result
    } catch (error) {
      result.errors.push('Invalid JSON format')
      return result
    }
  }

  /**
   * Validate number input
   */
  private validateNumber(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    const sanitized = DOMPurify.sanitize(input.trim())
    
    if (!validator.isNumeric(sanitized)) {
      result.errors.push('Invalid number format')
      return result
    }

    result.isValid = true
    result.sanitizedValue = sanitized
    return result
  }

  /**
   * Validate phone input
   */
  private validatePhone(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    const sanitized = DOMPurify.sanitize(input.trim())
    
    if (!validator.isMobilePhone(sanitized, 'any', { strictMode: options.strictMode || false })) {
      result.errors.push('Invalid phone number format')
      return result
    }

    result.isValid = true
    result.sanitizedValue = sanitized
    return result
  }

  /**
   * Validate domain input
   */
  private validateDomain(input: string, result: ValidationResult, options: ValidationOptions): ValidationResult {
    const sanitized = DOMPurify.sanitize(input.trim().toLowerCase())
    
    if (!validator.isFQDN(sanitized)) {
      result.errors.push('Invalid domain format')
      return result
    }

    result.isValid = true
    result.sanitizedValue = sanitized
    return result
  }

  /**
   * Batch validate multiple inputs
   */
  batchValidate(inputs: Array<{ value: any; type: InputType; options?: ValidationOptions }>): ValidationResult[] {
    return inputs.map(({ value, type, options }) => 
      this.sanitizeAndValidateInput(value, type, options)
    )
  }
}

// Export singleton instance
export const enhancedInputValidationService = new EnhancedInputValidationService()

// Export convenience function
export function sanitizeAndValidateInput(
  input: any,
  type: InputType,
  options: ValidationOptions = {}
): ValidationResult {
  return enhancedInputValidationService.sanitizeAndValidateInput(input, type, options)
}
