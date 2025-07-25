'use strict'

import { z } from 'zod'
import { BusinessRecord, ScrapingConfig, IndustryCategory } from '@/types/business'

/**
 * Email validation regex
 */
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/**
 * Phone number validation regex (US format)
 */
const PHONE_REGEX = /^(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$/

/**
 * ZIP code validation regex (US format)
 */
const ZIP_REGEX = /^\d{5}(-\d{4})?$/

/**
 * URL validation regex
 */
const URL_REGEX = /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/

/**
 * Address schema
 */
const AddressSchema = z.object({
  street: z.string().min(1, 'Street address is required'),
  suite: z.string().optional(),
  city: z.string().min(1, 'City is required'),
  state: z.string().min(2, 'State is required').max(2, 'State must be 2 characters'),
  zipCode: z.string().regex(ZIP_REGEX, 'Invalid ZIP code format'),
})

/**
 * Coordinates schema
 */
const CoordinatesSchema = z.object({
  lat: z.number().min(-90).max(90),
  lng: z.number().min(-180).max(180),
})

/**
 * Business record schema
 */
const BusinessRecordSchema = z.object({
  id: z.string().min(1, 'ID is required'),
  businessName: z.string().min(1, 'Business name is required'),
  email: z.array(z.string().regex(EMAIL_REGEX, 'Invalid email format')),
  phone: z.string().regex(PHONE_REGEX, 'Invalid phone number format').optional(),
  websiteUrl: z.string().regex(URL_REGEX, 'Invalid URL format'),
  address: AddressSchema,
  contactPerson: z.string().optional(),
  coordinates: CoordinatesSchema.optional(),
  industry: z.string().min(1, 'Industry is required'),
  scrapedAt: z.date(),
})

/**
 * Scraping configuration schema
 */
const ScrapingConfigSchema = z.object({
  industries: z.array(z.string()).min(1, 'At least one industry must be selected'),
  zipCode: z.string().regex(ZIP_REGEX, 'Invalid ZIP code format'),
  searchRadius: z.number().min(1, 'Search radius must be at least 1 mile').max(100, 'Search radius cannot exceed 100 miles'),
  searchDepth: z.number().min(1, 'Search depth must be at least 1').max(5, 'Search depth cannot exceed 5'),
  pagesPerSite: z.number().min(1, 'Pages per site must be at least 1').max(20, 'Pages per site cannot exceed 20'),
})

/**
 * Industry category schema
 */
const IndustryCategorySchema = z.object({
  id: z.string().min(1, 'ID is required'),
  name: z.string().min(1, 'Name is required'),
  keywords: z.array(z.string().min(1, 'Keyword cannot be empty')).min(1, 'At least one keyword is required'),
  isCustom: z.boolean(),
})

/**
 * Validation result interface
 */
export interface ValidationResult {
  isValid: boolean
  errors: string[]
  warnings: string[]
}

/**
 * Validation service for data integrity
 */
export class ValidationService {
  /**
   * Validate business record
   * @param business - Business record to validate
   * @returns Validation result
   */
  validateBusinessRecord(business: any): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    try {
      BusinessRecordSchema.parse(business)
    } catch (error) {
      if (error instanceof z.ZodError) {
        result.isValid = false
        result.errors = error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
      }
    }

    // Additional business logic validations
    this.validateBusinessLogic(business, result)

    return result
  }

  /**
   * Validate scraping configuration
   * @param config - Configuration to validate
   * @returns Validation result
   */
  validateScrapingConfig(config: any): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    try {
      ScrapingConfigSchema.parse(config)
    } catch (error) {
      if (error instanceof z.ZodError) {
        result.isValid = false
        result.errors = error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
      }
    }

    // Additional configuration validations
    this.validateConfigLogic(config, result)

    return result
  }

  /**
   * Validate industry category
   * @param industry - Industry category to validate
   * @returns Validation result
   */
  validateIndustryCategory(industry: any): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    try {
      IndustryCategorySchema.parse(industry)
    } catch (error) {
      if (error instanceof z.ZodError) {
        result.isValid = false
        result.errors = error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
      }
    }

    return result
  }

  /**
   * Validate email address
   * @param email - Email to validate
   * @returns Boolean indicating if email is valid
   */
  validateEmail(email: string): boolean {
    return EMAIL_REGEX.test(email)
  }

  /**
   * Validate phone number
   * @param phone - Phone number to validate
   * @returns Boolean indicating if phone is valid
   */
  validatePhoneNumber(phone: string): boolean {
    return PHONE_REGEX.test(phone)
  }

  /**
   * Validate URL
   * @param url - URL to validate
   * @returns Boolean indicating if URL is valid
   */
  validateUrl(url: string): boolean {
    return URL_REGEX.test(url)
  }

  /**
   * Validate ZIP code
   * @param zipCode - ZIP code to validate
   * @returns Boolean indicating if ZIP code is valid
   */
  validateZipCode(zipCode: string): boolean {
    return ZIP_REGEX.test(zipCode)
  }

  /**
   * Sanitize input string
   * @param input - Input string to sanitize
   * @returns Sanitized string
   */
  sanitizeInput(input: string): string {
    let result = input.trim()

    // Remove complete script tags first
    result = result.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')

    // Remove javascript URLs
    result = result.replace(/javascript:/gi, '')

    // Remove event handlers (like onclick=, onload=, etc.)
    result = result.replace(/on\w+\s*=\s*"[^"]*"/gi, '')
    result = result.replace(/on\w+\s*=\s*'[^']*'/gi, '')
    result = result.replace(/on\w+\s*=\s*[^\s"'>]+/gi, '')

    // Remove other HTML tags (but not empty < > pairs)
    result = result.replace(/<[a-zA-Z][^>]*>/g, '')
    result = result.replace(/<\/[a-zA-Z][^>]*>/g, '')

    // Escape dangerous characters that remain
    result = result.replace(/[<>'"&]/g, (char) => {
      const escapeMap: { [key: string]: string } = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;',
      }
      return escapeMap[char] || char
    })

    return result
  }

  /**
   * Validate input against security threats
   * @param input - Input string to validate
   * @returns Validation result with security checks
   */
  validateInputSecurity(input: string): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    // Check for SQL injection patterns
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
      /(--|\/\*|\*\/)/,
      /(\b(OR|AND)\b.*=.*)/i,
      /(\bUNION\b.*\bSELECT\b)/i,
    ]

    for (const pattern of sqlPatterns) {
      if (pattern.test(input)) {
        result.isValid = false
        result.errors.push('Input contains potentially dangerous SQL patterns')
        break
      }
    }

    // Check for XSS patterns
    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
      /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi,
    ]

    for (const pattern of xssPatterns) {
      if (pattern.test(input)) {
        result.isValid = false
        result.errors.push('Input contains potentially dangerous XSS patterns')
        break
      }
    }

    // Check for path traversal
    if (/\.\.\/|\.\.\\/.test(input)) {
      result.isValid = false
      result.errors.push('Input contains path traversal patterns')
    }

    // Check for command injection
    const commandPatterns = [
      /[;&|`$(){}[\]]/,
      /\b(cat|ls|dir|type|echo|curl|wget|nc|netcat)\b/i,
    ]

    for (const pattern of commandPatterns) {
      if (pattern.test(input)) {
        result.warnings.push('Input contains characters or commands that could be dangerous')
        break
      }
    }

    return result
  }

  /**
   * Validate business logic rules
   * @param business - Business record
   * @param result - Validation result to update
   */
  private validateBusinessLogic(business: any, result: ValidationResult): void {
    // Check if business has at least one contact method
    if ((!business.email || business.email.length === 0) && !business.phone) {
      result.warnings.push('Business has no email or phone contact information')
    }

    // Check for suspicious business names
    if (business.businessName) {
      const suspiciousPatterns = [
        /test/i,
        /example/i,
        /placeholder/i,
        /lorem ipsum/i,
      ]
      
      if (suspiciousPatterns.some(pattern => pattern.test(business.businessName))) {
        result.warnings.push('Business name appears to be a placeholder or test value')
      }
    }

    // Check for duplicate emails
    if (business.email && Array.isArray(business.email)) {
      const uniqueEmails = new Set(business.email)
      if (uniqueEmails.size !== business.email.length) {
        result.warnings.push('Business has duplicate email addresses')
      }
    }

    // Validate coordinates if present
    if (business.coordinates) {
      const { lat, lng } = business.coordinates
      
      // Check if coordinates are in a reasonable range for business locations
      if (lat === 0 && lng === 0) {
        result.warnings.push('Coordinates appear to be default values (0, 0)')
      }
      
      // Check if coordinates are in the ocean (very basic check)
      if (Math.abs(lat) < 1 && Math.abs(lng) < 1) {
        result.warnings.push('Coordinates may be inaccurate (too close to 0, 0)')
      }
    }
  }

  /**
   * Validate configuration logic rules
   * @param config - Scraping configuration
   * @param result - Validation result to update
   */
  private validateConfigLogic(config: any, result: ValidationResult): void {
    // Check for reasonable search radius
    if (config.searchRadius > 50) {
      result.warnings.push('Large search radius may result in too many irrelevant results')
    }

    // Check for reasonable search depth
    if (config.searchDepth > 3) {
      result.warnings.push('High search depth may significantly increase scraping time')
    }

    // Check for reasonable pages per site
    if (config.pagesPerSite > 10) {
      result.warnings.push('High pages per site may significantly increase scraping time')
    }

    // Validate industry selection
    if (config.industries && config.industries.length > 10) {
      result.warnings.push('Selecting many industries may result in unfocused results')
    }
  }

  /**
   * Validate array of business records
   * @param businesses - Array of business records
   * @returns Validation summary
   */
  validateBusinessArray(businesses: any[]): {
    totalRecords: number
    validRecords: number
    invalidRecords: number
    errors: Array<{ index: number; errors: string[] }>
    warnings: Array<{ index: number; warnings: string[] }>
  } {
    const summary = {
      totalRecords: businesses.length,
      validRecords: 0,
      invalidRecords: 0,
      errors: [] as Array<{ index: number; errors: string[] }>,
      warnings: [] as Array<{ index: number; warnings: string[] }>,
    }

    businesses.forEach((business, index) => {
      const validation = this.validateBusinessRecord(business)
      
      if (validation.isValid) {
        summary.validRecords++
      } else {
        summary.invalidRecords++
        summary.errors.push({
          index,
          errors: validation.errors,
        })
      }

      if (validation.warnings.length > 0) {
        summary.warnings.push({
          index,
          warnings: validation.warnings,
        })
      }
    })

    return summary
  }

  /**
   * Get validation schemas for external use
   * @returns Object containing all validation schemas
   */
  getSchemas() {
    return {
      BusinessRecordSchema,
      ScrapingConfigSchema,
      IndustryCategorySchema,
      AddressSchema,
      CoordinatesSchema,
    }
  }
}

/**
 * Default validation service instance
 */
export const validationService = new ValidationService()
