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
const URL_REGEX =
  /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/

/**
 * Sanitization options interface
 */
export interface SanitizationOptions {
  maxLength?: number
  allowHtml?: boolean
  allowUrls?: boolean
  preserveNewlines?: boolean
  strictMode?: boolean
}

/**
 * File upload validation options
 */
export interface FileValidationOptions {
  maxSize?: number
  allowedTypes?: string[]
  allowedExtensions?: string[]
  scanForMalware?: boolean
  validateMagicNumbers?: boolean
  allowExecutables?: boolean
  maxFilenameLength?: number
  quarantineDirectory?: string
  virusScanTimeout?: number
}

/**
 * Input length limits configuration
 */
export interface InputLengthLimits {
  username: number
  password: number
  email: number
  businessName: number
  address: number
  phone: number
  url: number
  description: number
  searchQuery: number
  fileName: number
  general: number
}

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
  searchRadius: z
    .number()
    .min(1, 'Search radius must be at least 1 mile')
    .max(100, 'Search radius cannot exceed 100 miles'),
  searchDepth: z
    .number()
    .min(1, 'Search depth must be at least 1')
    .max(5, 'Search depth cannot exceed 5'),
  pagesPerSite: z
    .number()
    .min(1, 'Pages per site must be at least 1')
    .max(20, 'Pages per site cannot exceed 20'),
  // Search configuration (optional fields)
  searchResultPages: z.number().min(1).max(5).optional(),
  // Backward compatibility - deprecated
  duckduckgoSerpPages: z.number().min(1).max(5).optional(),
  maxSearchResults: z.number().min(50).max(10000).optional(),
  bbbAccreditedOnly: z.boolean().optional(),
  zipRadius: z.number().min(5).max(50).optional(),
})

/**
 * Industry category schema
 */
const IndustryCategorySchema = z.object({
  id: z.string().min(1, 'ID is required'),
  name: z.string().min(1, 'Name is required'),
  keywords: z
    .array(z.string().min(1, 'Keyword cannot be empty'))
    .min(1, 'At least one keyword is required'),
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
 * Default input length limits
 */
export const DEFAULT_INPUT_LIMITS: InputLengthLimits = {
  username: 50,
  password: 128,
  email: 254,
  businessName: 200,
  address: 500,
  phone: 20,
  url: 2048,
  description: 2000,
  searchQuery: 200,
  fileName: 255,
  general: 1000,
}

/**
 * Validation service for data integrity
 */
export class ValidationService {
  private inputLimits: InputLengthLimits

  constructor(inputLimits: InputLengthLimits = DEFAULT_INPUT_LIMITS) {
    this.inputLimits = inputLimits
  }
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
   * Sanitize input string with comprehensive security measures
   * @param input - Input string to sanitize
   * @param options - Sanitization options
   * @returns Sanitized string
   */
  sanitizeInput(input: string, options: SanitizationOptions = {}): string {
    if (typeof input !== 'string') {
      return ''
    }

    const {
      maxLength = 10000,
      allowHtml = false,
      allowUrls = true,
      preserveNewlines = false,
      strictMode = false,
    } = options

    let result = input.trim()

    // Enforce length limits
    if (result.length > maxLength) {
      result = result.substring(0, maxLength)
    }

    // Remove null bytes and dangerous control characters
    result = result.replace(/\0/g, '')
    result = result.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

    // Handle newlines based on options
    if (!preserveNewlines) {
      result = result.replace(/[\r\n]/g, ' ')
    }

    // Remove complete script tags first (most dangerous)
    result = result.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    result = result.replace(/<noscript\b[^<]*(?:(?!<\/noscript>)<[^<]*)*<\/noscript>/gi, '')

    // Remove dangerous HTML elements
    const dangerousElements = [
      'iframe',
      'object',
      'embed',
      'applet',
      'form',
      'input',
      'textarea',
      'select',
      'button',
      'link',
      'meta',
      'style',
      'base',
      'frame',
      'frameset',
    ]

    dangerousElements.forEach(element => {
      const regex = new RegExp(
        `<${element}\\b[^<]*(?:(?!<\\/${element}>)<[^<]*)*<\\/${element}>`,
        'gi'
      )
      result = result.replace(regex, '')
      result = result.replace(new RegExp(`<${element}\\b[^>]*>`, 'gi'), '')
    })

    // Remove javascript URLs and protocols
    result = result.replace(/javascript:/gi, '')
    result = result.replace(/vbscript:/gi, '')
    result = result.replace(/data:text\/html/gi, '')
    result = result.replace(/data:application\/javascript/gi, '')

    // Remove event handlers (comprehensive list)
    const eventHandlers = [
      'onabort',
      'onblur',
      'onchange',
      'onclick',
      'ondblclick',
      'onerror',
      'onfocus',
      'onkeydown',
      'onkeypress',
      'onkeyup',
      'onload',
      'onmousedown',
      'onmousemove',
      'onmouseout',
      'onmouseover',
      'onmouseup',
      'onreset',
      'onresize',
      'onselect',
      'onsubmit',
      'onunload',
      'onbeforeunload',
      'oncontextmenu',
      'ondrag',
      'ondrop',
      'onscroll',
      'onwheel',
      'ontouchstart',
      'ontouchend',
      'ontouchmove',
    ]

    eventHandlers.forEach(handler => {
      result = result.replace(new RegExp(`${handler}\\s*=\\s*"[^"]*"`, 'gi'), '')
      result = result.replace(new RegExp(`${handler}\\s*=\\s*'[^']*'`, 'gi'), '')
      result = result.replace(new RegExp(`${handler}\\s*=\\s*[^\\s"'>]+`, 'gi'), '')
    })

    // Remove other HTML tags if not allowed
    if (!allowHtml) {
      result = result.replace(/<[a-zA-Z][^>]*>/g, '')
      result = result.replace(/<\/[a-zA-Z][^>]*>/g, '')
      result = result.replace(/&lt;|&gt;|&amp;|&quot;|&#x27;|&#x2F;/g, match => {
        const entities: Record<string, string> = {
          '&lt;': '<',
          '&gt;': '>',
          '&amp;': '&',
          '&quot;': '"',
          '&#x27;': "'",
          '&#x2F;': '/',
        }
        return entities[match] || match
      })
    }

    // Remove SQL injection patterns (more comprehensive)
    const sqlPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE|REPLACE)\b)/gi,
      /(--|\/\*|\*\/|;|'|"|`)/g,
      /(\b(OR|AND)\b\s*\d*\s*=\s*\d*)/gi,
      /(\bUNION\b.*\bSELECT\b)/gi,
      /(\bINTO\b.*\bOUTFILE\b)/gi,
    ]

    if (strictMode) {
      sqlPatterns.forEach(pattern => {
        result = result.replace(pattern, '')
      })
    }

    // Remove path traversal patterns (comprehensive)
    result = result.replace(/\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f/gi, '')
    result = result.replace(/\.\.%2f|\.\.%5c|%2e%2e\/|%2e%2e\\/gi, '')

    // Remove command injection patterns
    const commandPatterns = [
      /[;&|`$(){}[\]]/g,
      /\b(cat|ls|dir|type|echo|curl|wget|nc|netcat|rm|del|mv|cp|chmod|chown)\b/gi,
    ]

    if (strictMode) {
      commandPatterns.forEach(pattern => {
        result = result.replace(pattern, '')
      })
    }

    // Handle URLs based on options
    if (!allowUrls) {
      result = result.replace(/https?:\/\/[^\s]+/gi, '')
      result = result.replace(/ftp:\/\/[^\s]+/gi, '')
    }

    // Final cleanup - remove excessive whitespace
    result = result.replace(/\s+/g, ' ').trim()

    return result
  }

  /**
   * Enhanced email validation with security checks
   * @param email - Email address to validate
   * @returns Validation result with detailed feedback
   */
  validateEmailEnhanced(email: string): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    if (!email || typeof email !== 'string') {
      result.isValid = false
      result.errors.push('Email is required')
      return result
    }

    const sanitizedEmail = this.sanitizeInput(email, { maxLength: 254, strictMode: true })

    // Basic format validation
    if (!EMAIL_REGEX.test(sanitizedEmail)) {
      result.isValid = false
      result.errors.push('Invalid email format')
      return result
    }

    // Length validation (RFC 5321)
    if (sanitizedEmail.length > 254) {
      result.isValid = false
      result.errors.push('Email address too long (max 254 characters)')
    }

    // Local part validation
    const [localPart, domain] = sanitizedEmail.split('@')
    if (localPart.length > 64) {
      result.isValid = false
      result.errors.push('Email local part too long (max 64 characters)')
    }

    // Domain validation
    if (domain.length > 253) {
      result.isValid = false
      result.errors.push('Email domain too long (max 253 characters)')
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /\+.*\+/, // Multiple plus signs
      /\.{2,}/, // Consecutive dots
      /^\./, // Starting with dot
      /\.$/, // Ending with dot
      /@.*@/, // Multiple @ symbols
    ]

    suspiciousPatterns.forEach(pattern => {
      if (pattern.test(sanitizedEmail)) {
        result.warnings.push('Email contains suspicious patterns')
      }
    })

    return result
  }

  /**
   * Enhanced URL validation with security checks
   * @param url - URL to validate
   * @returns Validation result with detailed feedback
   */
  validateUrlEnhanced(url: string): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    if (!url || typeof url !== 'string') {
      result.isValid = false
      result.errors.push('URL is required')
      return result
    }

    const sanitizedUrl = this.sanitizeInput(url, { maxLength: 2048, allowUrls: true })

    // Basic format validation
    if (!URL_REGEX.test(sanitizedUrl)) {
      result.isValid = false
      result.errors.push('Invalid URL format')
      return result
    }

    try {
      const urlObj = new URL(sanitizedUrl)

      // Protocol validation
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        result.isValid = false
        result.errors.push('Only HTTP and HTTPS protocols are allowed')
      }

      // Length validation
      if (sanitizedUrl.length > 2048) {
        result.isValid = false
        result.errors.push('URL too long (max 2048 characters)')
      }

      // Check for suspicious patterns
      if (
        urlObj.hostname.includes('localhost') ||
        urlObj.hostname.includes('127.0.0.1') ||
        urlObj.hostname.includes('0.0.0.0')
      ) {
        result.warnings.push('URL points to localhost or loopback address')
      }

      // Check for private IP ranges
      const privateIpPatterns = [/^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./]

      privateIpPatterns.forEach(pattern => {
        if (pattern.test(urlObj.hostname)) {
          result.warnings.push('URL points to private IP address')
        }
      })
    } catch (error) {
      result.isValid = false
      result.errors.push('Invalid URL structure')
    }

    return result
  }

  /**
   * Validate file upload with security checks
   * @param file - File object or file info
   * @param options - Validation options
   * @returns Validation result
   */
  validateFileUpload(
    file: File | { name: string; size: number; type: string },
    options: FileValidationOptions = {}
  ): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    const {
      maxSize = 10 * 1024 * 1024, // 10MB default
      allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf'],
      allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.txt', '.pdf'],
      scanForMalware = false,
      validateMagicNumbers = true,
      allowExecutables = false,
      maxFilenameLength = 255,
      virusScanTimeout = 30000,
    } = options

    if (!file) {
      result.isValid = false
      result.errors.push('File is required')
      return result
    }

    // Basic file validation
    if (file.size === 0) {
      result.isValid = false
      result.errors.push('File is empty')
      return result
    }

    // Size validation
    if (file.size > maxSize) {
      result.isValid = false
      result.errors.push(`File size exceeds limit (${Math.round(maxSize / 1024 / 1024)}MB)`)
    }

    // Filename length validation
    if (file.name.length > maxFilenameLength) {
      result.isValid = false
      result.errors.push(`Filename exceeds maximum length (${maxFilenameLength} characters)`)
    }

    // Filename security validation
    const sanitizedFilename = this.sanitizeInput(file.name, {
      maxLength: maxFilenameLength,
      strictMode: true,
    })
    if (sanitizedFilename !== file.name) {
      result.warnings.push('Filename contains potentially dangerous characters')
    }

    // Check for null bytes in filename
    if (file.name.includes('\0')) {
      result.isValid = false
      result.errors.push('Filename contains null bytes')
    }

    // Check for path traversal attempts
    const pathTraversalPattern = /\.\.[\/\\]/
    if (pathTraversalPattern.test(file.name)) {
      result.isValid = false
      result.errors.push('Filename contains path traversal sequences')
    }

    // Extension validation
    const extension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
    if (!allowedExtensions.includes(extension)) {
      result.isValid = false
      result.errors.push(`File extension '${extension}' is not allowed`)
    }

    // Type validation
    if (!allowedTypes.includes(file.type)) {
      result.isValid = false
      result.errors.push(`File type '${file.type}' is not allowed`)
    }

    // Check for double extensions (e.g., .txt.exe)
    const doubleExtensionPattern = /\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+$/
    if (doubleExtensionPattern.test(file.name)) {
      result.warnings.push('File has multiple extensions, which may be suspicious')
    }

    // Check for executable extensions
    const executableExtensions = [
      '.exe',
      '.bat',
      '.cmd',
      '.com',
      '.scr',
      '.pif',
      '.vbs',
      '.js',
      '.jar',
      '.msi',
      '.app',
      '.deb',
      '.rpm',
      '.dmg',
      '.pkg',
      '.run',
      '.bin',
      '.sh',
      '.ps1',
      '.psm1',
      '.psd1',
      '.ps1xml',
      '.psc1',
      '.pssc',
      '.msh',
      '.msh1',
      '.msh2',
      '.mshxml',
      '.msh1xml',
      '.msh2xml',
    ]

    if (
      !allowExecutables &&
      executableExtensions.some(ext => file.name.toLowerCase().endsWith(ext))
    ) {
      result.isValid = false
      result.errors.push('Executable files are not allowed')
    }

    // Check for suspicious file patterns
    const suspiciousPatterns = [
      /autorun\.inf$/i,
      /desktop\.ini$/i,
      /thumbs\.db$/i,
      /\.htaccess$/i,
      /\.htpasswd$/i,
      /web\.config$/i,
      /\.asp$/i,
      /\.aspx$/i,
      /\.php$/i,
      /\.jsp$/i,
      /\.jspx$/i,
    ]

    if (suspiciousPatterns.some(pattern => pattern.test(file.name))) {
      result.isValid = false
      result.errors.push('File type is potentially dangerous')
    }

    // Magic number validation (if file content is available)
    if (validateMagicNumbers && file instanceof File) {
      this.validateFileMagicNumbers(file, extension, result)
    }

    // Additional security warnings
    if (file.size > 50 * 1024 * 1024) {
      // 50MB
      result.warnings.push('Large file size may impact performance')
    }

    if (file.name.length > 100) {
      result.warnings.push('Long filename may cause compatibility issues')
    }

    return result
  }

  /**
   * Validate file magic numbers against expected file type
   * @param file - File object
   * @param extension - File extension
   * @param result - Validation result to update
   */
  private async validateFileMagicNumbers(
    file: File,
    extension: string,
    result: ValidationResult
  ): Promise<void> {
    try {
      // Read first 16 bytes for magic number validation
      const buffer = await file.slice(0, 16).arrayBuffer()
      const bytes = new Uint8Array(buffer)
      const hex = Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')

      // Magic number signatures for common file types
      const magicNumbers: Record<string, string[]> = {
        '.jpg': ['ffd8ff'],
        '.jpeg': ['ffd8ff'],
        '.png': ['89504e47'],
        '.gif': ['474946383761', '474946383961'],
        '.pdf': ['255044462d'],
        '.zip': ['504b0304', '504b0506', '504b0708'],
        '.exe': ['4d5a'],
        '.doc': ['d0cf11e0'],
        '.docx': ['504b0304'],
        '.xls': ['d0cf11e0'],
        '.xlsx': ['504b0304'],
        '.ppt': ['d0cf11e0'],
        '.pptx': ['504b0304'],
      }

      const expectedSignatures = magicNumbers[extension.toLowerCase()]
      if (expectedSignatures) {
        const matches = expectedSignatures.some(signature =>
          hex.toLowerCase().startsWith(signature.toLowerCase())
        )

        if (!matches) {
          result.warnings.push(`File content doesn't match expected type for ${extension}`)
        }
      }

      // Check for embedded executables or suspicious content
      const suspiciousSignatures = [
        '4d5a', // PE executable
        '7f454c46', // ELF executable
        'cafebabe', // Java class file
        'feedface', // Mach-O executable
        'cefaedfe', // Mach-O executable (reverse)
      ]

      if (suspiciousSignatures.some(sig => hex.toLowerCase().includes(sig.toLowerCase()))) {
        result.isValid = false
        result.errors.push('File contains embedded executable content')
      }
    } catch (error) {
      result.warnings.push('Could not validate file magic numbers')
    }
  }

  /**
   * Scan file for malware patterns
   * @param file - File object or file info
   * @param options - Scanning options
   * @returns Promise resolving to scan result
   */
  async scanFileForMalware(
    file: File | { name: string; size: number; type: string },
    options: FileValidationOptions = {}
  ): Promise<ValidationResult> {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    const { virusScanTimeout = 30000 } = options

    try {
      // Basic pattern-based scanning for known malware signatures
      if (file instanceof File) {
        const content = await this.readFileContent(file, virusScanTimeout)

        // Check for suspicious patterns in file content
        const malwarePatterns = [
          /eval\s*\(/gi,
          /document\.write\s*\(/gi,
          /window\.location\s*=/gi,
          /<script[^>]*>[\s\S]*?<\/script>/gi,
          /base64_decode\s*\(/gi,
          /shell_exec\s*\(/gi,
          /system\s*\(/gi,
          /exec\s*\(/gi,
          /passthru\s*\(/gi,
          /file_get_contents\s*\(/gi,
          /curl_exec\s*\(/gi,
        ]

        for (const pattern of malwarePatterns) {
          if (pattern.test(content)) {
            result.warnings.push('File contains potentially suspicious code patterns')
            break
          }
        }

        // Check for excessive obfuscation
        const obfuscationIndicators = [
          /[a-zA-Z0-9+/]{100,}/g, // Long base64-like strings
          /\\x[0-9a-fA-F]{2}/g, // Hex encoded strings
          /\\[0-7]{3}/g, // Octal encoded strings
          /%[0-9a-fA-F]{2}/g, // URL encoded strings
        ]

        let obfuscationScore = 0
        for (const indicator of obfuscationIndicators) {
          const matches = content.match(indicator)
          if (matches && matches.length > 10) {
            obfuscationScore++
          }
        }

        if (obfuscationScore >= 2) {
          result.warnings.push('File appears to be heavily obfuscated')
        }
      }
    } catch (error) {
      result.warnings.push('Could not complete malware scan')
    }

    return result
  }

  /**
   * Read file content with timeout
   * @param file - File object
   * @param timeout - Timeout in milliseconds
   * @returns Promise resolving to file content
   */
  private async readFileContent(file: File, timeout: number): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      const timeoutId = setTimeout(() => {
        reader.abort()
        reject(new Error('File read timeout'))
      }, timeout)

      reader.onload = () => {
        clearTimeout(timeoutId)
        resolve(reader.result as string)
      }

      reader.onerror = () => {
        clearTimeout(timeoutId)
        reject(reader.error)
      }

      // Read as text for pattern matching
      reader.readAsText(file.slice(0, 1024 * 1024)) // Read first 1MB only
    })
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
    const commandPatterns = [/[;&|`$(){}[\]]/, /\b(cat|ls|dir|type|echo|curl|wget|nc|netcat)\b/i]

    for (const pattern of commandPatterns) {
      if (pattern.test(input)) {
        result.warnings.push('Input contains characters or commands that could be dangerous')
        break
      }
    }

    return result
  }

  /**
   * Validate content against Content Security Policy
   * @param content - Content to validate
   * @param cspDirectives - CSP directives to check against
   * @returns Validation result
   */
  validateContentSecurityPolicy(
    content: string,
    cspDirectives: Record<string, string[]> = {}
  ): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    const defaultDirectives = {
      'script-src': ["'self'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'"],
      'font-src': ["'self'"],
      'object-src': ["'none'"],
      'media-src': ["'self'"],
      'frame-src': ["'none'"],
    }

    const directives = { ...defaultDirectives, ...cspDirectives }

    // Check for inline scripts
    if (/<script\b[^>]*>[\s\S]*?<\/script>/gi.test(content)) {
      if (!directives['script-src'].includes("'unsafe-inline'")) {
        result.isValid = false
        result.errors.push('Inline scripts detected but not allowed by CSP')
      }
    }

    // Check for inline styles
    if (/<style\b[^>]*>[\s\S]*?<\/style>/gi.test(content) || /style\s*=/gi.test(content)) {
      if (!directives['style-src'].includes("'unsafe-inline'")) {
        result.warnings.push('Inline styles detected - may violate CSP')
      }
    }

    // Check for external resources
    const resourcePatterns = [
      { directive: 'script-src', pattern: /<script[^>]+src\s*=\s*["']([^"']+)["']/gi },
      { directive: 'img-src', pattern: /<img[^>]+src\s*=\s*["']([^"']+)["']/gi },
      { directive: 'link-src', pattern: /<link[^>]+href\s*=\s*["']([^"']+)["']/gi },
    ]

    resourcePatterns.forEach(({ directive, pattern }) => {
      let match
      while ((match = pattern.exec(content)) !== null) {
        const url = match[1]
        if (url.startsWith('http://') || url.startsWith('https://')) {
          const domain = new URL(url).origin
          if (
            directives[directive] &&
            !directives[directive].includes(domain) &&
            !directives[directive].includes('*')
          ) {
            result.warnings.push(`External resource from ${domain} may violate CSP ${directive}`)
          }
        }
      }
    })

    return result
  }

  /**
   * Advanced input length and complexity validation
   * @param input - Input to validate
   * @param options - Validation options
   * @returns Validation result
   */
  validateInputComplexity(
    input: string,
    options: {
      minLength?: number
      maxLength?: number
      requireSpecialChars?: boolean
      requireNumbers?: boolean
      requireUppercase?: boolean
      requireLowercase?: boolean
      maxRepeatingChars?: number
    } = {}
  ): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    const {
      minLength = 0,
      maxLength = 10000,
      requireSpecialChars = false,
      requireNumbers = false,
      requireUppercase = false,
      requireLowercase = false,
      maxRepeatingChars = 10,
    } = options

    if (input.length < minLength) {
      result.isValid = false
      result.errors.push(`Input too short (minimum ${minLength} characters)`)
    }

    if (input.length > maxLength) {
      result.isValid = false
      result.errors.push(`Input too long (maximum ${maxLength} characters)`)
    }

    if (requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(input)) {
      result.isValid = false
      result.errors.push('Input must contain special characters')
    }

    if (requireNumbers && !/\d/.test(input)) {
      result.isValid = false
      result.errors.push('Input must contain numbers')
    }

    if (requireUppercase && !/[A-Z]/.test(input)) {
      result.isValid = false
      result.errors.push('Input must contain uppercase letters')
    }

    if (requireLowercase && !/[a-z]/.test(input)) {
      result.isValid = false
      result.errors.push('Input must contain lowercase letters')
    }

    // Check for excessive repeating characters
    const repeatingPattern = new RegExp(`(.)\\1{${maxRepeatingChars},}`)
    if (repeatingPattern.test(input)) {
      result.warnings.push(`Input contains more than ${maxRepeatingChars} repeating characters`)
    }

    return result
  }

  /**
   * Validate input length against configured limits
   * @param input - Input string to validate
   * @param type - Type of input for length limit lookup
   * @returns Validation result
   */
  validateInputLength(input: string, type: keyof InputLengthLimits): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    if (typeof input !== 'string') {
      result.isValid = false
      result.errors.push('Input must be a string')
      return result
    }

    const limit = this.inputLimits[type]
    if (input.length > limit) {
      result.isValid = false
      result.errors.push(`Input too long (${input.length} characters, max ${limit})`)
    }

    // Warning for inputs approaching the limit
    if (input.length > limit * 0.9) {
      result.warnings.push(`Input approaching length limit (${input.length}/${limit} characters)`)
    }

    return result
  }

  /**
   * Validate multiple inputs with length limits
   * @param inputs - Object with input values and their types
   * @returns Combined validation result
   */
  validateInputLengths(
    inputs: Record<string, { value: string; type: keyof InputLengthLimits }>
  ): ValidationResult {
    const result: ValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
    }

    for (const [fieldName, { value, type }] of Object.entries(inputs)) {
      const fieldResult = this.validateInputLength(value, type)

      if (!fieldResult.isValid) {
        result.isValid = false
        result.errors.push(...fieldResult.errors.map(error => `${fieldName}: ${error}`))
      }

      result.warnings.push(...fieldResult.warnings.map(warning => `${fieldName}: ${warning}`))
    }

    return result
  }

  /**
   * Get input length limits
   * @returns Current input length limits
   */
  getInputLimits(): InputLengthLimits {
    return { ...this.inputLimits }
  }

  /**
   * Update input length limits
   * @param newLimits - New limits to apply
   */
  updateInputLimits(newLimits: Partial<InputLengthLimits>): void {
    this.inputLimits = { ...this.inputLimits, ...newLimits }
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
      const suspiciousPatterns = [/test/i, /example/i, /placeholder/i, /lorem ipsum/i]

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
  validateBusinessArray(businesses: BusinessRecord[]): {
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
  getSchemas(): {
    BusinessRecordSchema: any
    ScrapingConfigSchema: any
    IndustryCategorySchema: any
    AddressSchema: any
    CoordinatesSchema: any
  } {
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
