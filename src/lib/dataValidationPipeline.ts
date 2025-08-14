/**
 * Advanced Data Validation and Cleaning Pipeline
 * Comprehensive system for validating, cleaning, and enriching business data
 */

import { BusinessRecord, EmailValidationResult, EmailValidationMetadata } from '@/types/business'
import { logger } from '@/utils/logger'
import { EmailValidationService } from './emailValidationService'
import { geocoder } from '@/model/geocoder'

export interface ValidationResult {
  isValid: boolean
  confidence: number
  errors: ValidationError[]
  warnings: ValidationWarning[]
  suggestions: ValidationSuggestion[]
  cleanedData?: Partial<BusinessRecord>
}

export interface ValidationError {
  field: string
  code: string
  message: string
  severity: 'critical' | 'major' | 'minor'
}

export interface ValidationWarning {
  field: string
  code: string
  message: string
  impact: 'high' | 'medium' | 'low'
}

export interface ValidationSuggestion {
  field: string
  originalValue: unknown
  suggestedValue: unknown
  reason: string
  confidence: number
}

export interface DataQualityScore {
  overall: number
  completeness: number
  accuracy: number
  consistency: number
  validity: number
  uniqueness: number
}

// Address validation result interface
export interface AddressValidationResult {
  isValid: boolean
  confidence: number
  normalizedAddress?: {
    street: string
    suite?: string
    city: string
    state: string
    zipCode: string
  }
  coordinates?: {
    lat: number
    lng: number
  }
  errors: string[]
  warnings: string[]
}

export interface EnrichmentResult {
  enriched: boolean
  sources: string[]
  addedFields: string[]
  confidence: number
}

/**
 * Advanced Data Validation and Cleaning Pipeline
 */
export class DataValidationPipeline {
  private emailValidationService: EmailValidationService
  private emailValidationCache = new Map<string, boolean>()


  constructor() {
    this.emailValidationService = EmailValidationService.getInstance()
  }

  /**
   * Validate and clean a business record
   */
  async validateAndClean(business: BusinessRecord): Promise<ValidationResult> {
    logger.debug('DataValidationPipeline', `Validating business: ${business.businessName}`)

    const result: ValidationResult = {
      isValid: true,
      confidence: 1.0,
      errors: [],
      warnings: [],
      suggestions: [],
      cleanedData: { ...business },
    }

    // Validate and clean each field
    await this.validateBusinessName(business, result)
    await this.validateEmails(business, result)
    await this.validatePhone(business, result)
    await this.validateAddress(business, result)
    await this.validateWebsite(business, result)
    await this.validateIndustry(business, result)

    // Calculate overall confidence and validity
    this.calculateOverallScore(result)

    logger.debug('DataValidationPipeline', 
      `Validation complete: ${result.isValid ? 'VALID' : 'INVALID'} (confidence: ${result.confidence.toFixed(2)})`)

    return result
  }

  /**
   * Calculate data quality score
   */
  calculateDataQualityScore(business: BusinessRecord): DataQualityScore {
    const completeness = this.calculateCompleteness(business)
    const accuracy = this.calculateAccuracy(business)
    const consistency = this.calculateConsistency(business)
    const validity = this.calculateValidity(business)
    const uniqueness = this.calculateUniqueness(business)

    const overall = (completeness + accuracy + consistency + validity + uniqueness) / 5

    return {
      overall,
      completeness,
      accuracy,
      consistency,
      validity,
      uniqueness,
    }
  }

  /**
   * Enrich business data from external sources
   */
  async enrichData(business: BusinessRecord): Promise<EnrichmentResult> {
    const result: EnrichmentResult = {
      enriched: false,
      sources: [],
      addedFields: [],
      confidence: 0,
    }

    try {
      // Enrich address with geocoding
      if (business.address && !business.coordinates) {
        const addressString = this.formatAddressString(business.address)
        const geocodingResult = await geocoder.geocodeAddress(addressString)
        
        if (geocodingResult) {
          business.coordinates = {
            lat: geocodingResult.lat,
            lng: geocodingResult.lng,
          }
          result.enriched = true
          result.sources.push('geocoding')
          result.addedFields.push('coordinates')
        }
      }

      // Enrich industry classification
      if (business.businessName && (!business.industry || business.industry === 'Unknown')) {
        const suggestedIndustry = this.classifyIndustry(business.businessName, business.websiteUrl)
        if (suggestedIndustry) {
          business.industry = suggestedIndustry
          result.enriched = true
          result.sources.push('industry_classification')
          result.addedFields.push('industry')
        }
      }

      // Calculate enrichment confidence
      result.confidence = result.addedFields.length > 0 ? 0.8 : 0.0

      logger.info('DataValidationPipeline', 
        `Enrichment ${result.enriched ? 'successful' : 'skipped'}: ${result.addedFields.length} fields added`)

    } catch (error) {
      logger.error('DataValidationPipeline', 'Data enrichment failed', error)
    }

    return result
  }

  /**
   * Validate business name
   */
  private async validateBusinessName(business: BusinessRecord, result: ValidationResult): Promise<void> {
    const name = business.businessName?.trim()

    if (!name) {
      result.errors.push({
        field: 'businessName',
        code: 'MISSING_NAME',
        message: 'Business name is required',
        severity: 'critical',
      })
      result.isValid = false
      return
    }

    // Check for suspicious patterns
    const suspiciousPatterns = [
      /^test/i,
      /^example/i,
      /^placeholder/i,
      /lorem ipsum/i,
      /^untitled/i,
      /^new business/i,
    ]

    if (suspiciousPatterns.some(pattern => pattern.test(name))) {
      result.warnings.push({
        field: 'businessName',
        code: 'SUSPICIOUS_NAME',
        message: 'Business name appears to be a placeholder or test value',
        impact: 'high',
      })
    }

    // Check length
    if (name.length < 2) {
      result.errors.push({
        field: 'businessName',
        code: 'NAME_TOO_SHORT',
        message: 'Business name is too short',
        severity: 'major',
      })
    }

    if (name.length > 100) {
      result.warnings.push({
        field: 'businessName',
        code: 'NAME_TOO_LONG',
        message: 'Business name is unusually long',
        impact: 'medium',
      })
    }

    // Clean and normalize name
    const cleanedName = this.cleanBusinessName(name)
    if (cleanedName !== name) {
      result.suggestions.push({
        field: 'businessName',
        originalValue: name,
        suggestedValue: cleanedName,
        reason: 'Normalized capitalization and removed extra spaces',
        confidence: 0.9,
      })
      if (result.cleanedData) {
        result.cleanedData.businessName = cleanedName
      }
    }
  }

  /**
   * Validate email addresses
   */
  private async validateEmails(business: BusinessRecord, result: ValidationResult): Promise<void> {
    if (!business.email || business.email.length === 0) {
      result.warnings.push({
        field: 'email',
        code: 'NO_EMAIL',
        message: 'No email addresses provided',
        impact: 'medium',
      })
      return
    }

    try {
      // Perform advanced email validation
      const validationResults = await this.emailValidationService.validateEmails(business.email)

      const validEmails: string[] = []
      const invalidEmails: string[] = []
      const disposableEmails: string[] = []
      const roleBasedEmails: string[] = []

      for (const validationResult of validationResults) {
        if (validationResult.isValid) {
          validEmails.push(validationResult.email.toLowerCase().trim())
        } else {
          invalidEmails.push(validationResult.email)
        }

        if (validationResult.isDisposable) {
          disposableEmails.push(validationResult.email)
        }

        if (validationResult.isRoleBased) {
          roleBasedEmails.push(validationResult.email)
        }
      }

      // Report validation issues
      if (invalidEmails.length > 0) {
        result.errors.push({
          field: 'email',
          code: 'INVALID_EMAILS',
          message: `Invalid email addresses: ${invalidEmails.join(', ')}`,
          severity: 'major',
        })
      }

      if (disposableEmails.length > 0) {
        result.warnings.push({
          field: 'email',
          code: 'DISPOSABLE_EMAILS',
          message: `Disposable email addresses detected: ${disposableEmails.join(', ')}`,
          impact: 'high',
        })
      }

      if (roleBasedEmails.length > 0) {
        result.warnings.push({
          field: 'email',
          code: 'ROLE_BASED_EMAILS',
          message: `Role-based email addresses: ${roleBasedEmails.join(', ')}`,
          impact: 'medium',
        })
      }

      // Check for duplicates
      const uniqueEmails = Array.from(new Set(validEmails))
      if (uniqueEmails.length !== validEmails.length) {
        result.warnings.push({
          field: 'email',
          code: 'DUPLICATE_EMAILS',
          message: 'Duplicate email addresses found',
          impact: 'low',
        })
      }

      // Store email validation metadata
      const emailValidation: EmailValidationMetadata = {
        validationResults,
        overallConfidence: this.calculateEmailConfidence(validationResults),
        bestEmail: this.findBestEmail(validationResults),
        validEmailCount: validEmails.length,
        totalEmailCount: business.email.length
      }

      if (result.cleanedData) {
        result.cleanedData.email = uniqueEmails
        result.cleanedData.emailValidation = emailValidation
      }

      logger.debug('DataValidationPipeline', `Email validation completed`, {
        totalEmails: business.email.length,
        validEmails: validEmails.length,
        invalidEmails: invalidEmails.length,
        disposableEmails: disposableEmails.length,
        overallConfidence: emailValidation.overallConfidence
      })

    } catch (error) {
      logger.error('DataValidationPipeline', 'Advanced email validation failed, falling back to basic validation', error)

      // Fallback to basic validation
      const validEmails: string[] = []
      const invalidEmails: string[] = []

      for (const email of business.email) {
        const isValid = await this.validateEmailAddress(email)
        if (isValid) {
          validEmails.push(email.toLowerCase().trim())
        } else {
          invalidEmails.push(email)
        }
      }

      if (invalidEmails.length > 0) {
        result.errors.push({
          field: 'email',
          code: 'INVALID_EMAILS',
          message: `Invalid email addresses: ${invalidEmails.join(', ')}`,
          severity: 'major',
        })
      }

      const uniqueEmails = Array.from(new Set(validEmails))
      if (result.cleanedData) {
        result.cleanedData.email = uniqueEmails
      }
    }
  }

  /**
   * Calculate overall email confidence from validation results
   */
  private calculateEmailConfidence(validationResults: EmailValidationResult[]): number {
    if (validationResults.length === 0) return 0

    const validResults = validationResults.filter(result => result.isValid)
    if (validResults.length === 0) return 0

    const avgConfidence = validResults.reduce((sum, result) => sum + result.confidence, 0) / validResults.length
    const countBonus = Math.min(validResults.length * 5, 20)

    return Math.min(100, Math.round(avgConfidence + countBonus))
  }

  /**
   * Find the best email from validation results
   */
  private findBestEmail(validationResults: EmailValidationResult[]): string | undefined {
    const validEmails = validationResults.filter(result =>
      result.isValid && !result.isDisposable
    )

    if (validEmails.length === 0) return undefined

    const sortedEmails = validEmails.sort((a, b) => {
      if (!a.isRoleBased && b.isRoleBased) return -1
      if (a.isRoleBased && !b.isRoleBased) return 1
      return b.confidence - a.confidence
    })

    return sortedEmails[0].email
  }

  /**
   * Validate phone number
   */
  private async validatePhone(business: BusinessRecord, result: ValidationResult): Promise<void> {
    if (!business.phone) {
      result.warnings.push({
        field: 'phone',
        code: 'NO_PHONE',
        message: 'No phone number provided',
        impact: 'medium',
      })
      return
    }

    const formattedPhone = this.formatPhoneNumber(business.phone)
    if (!formattedPhone) {
      result.errors.push({
        field: 'phone',
        code: 'INVALID_PHONE',
        message: 'Invalid phone number format',
        severity: 'major',
      })
    } else if (formattedPhone !== business.phone) {
      result.suggestions.push({
        field: 'phone',
        originalValue: business.phone,
        suggestedValue: formattedPhone,
        reason: 'Standardized phone number format',
        confidence: 0.95,
      })
      if (result.cleanedData) {
        result.cleanedData.phone = formattedPhone
      }
    }
  }

  /**
   * Validate address
   */
  private async validateAddress(business: BusinessRecord, result: ValidationResult): Promise<void> {
    if (!business.address) {
      result.warnings.push({
        field: 'address',
        code: 'NO_ADDRESS',
        message: 'No address provided',
        impact: 'high',
      })
      return
    }

    const { street, city, state, zipCode } = business.address

    // Validate required fields
    if (!street) {
      result.errors.push({
        field: 'address.street',
        code: 'MISSING_STREET',
        message: 'Street address is required',
        severity: 'major',
      })
    }

    if (!city) {
      result.errors.push({
        field: 'address.city',
        code: 'MISSING_CITY',
        message: 'City is required',
        severity: 'major',
      })
    }

    if (!state) {
      result.errors.push({
        field: 'address.state',
        code: 'MISSING_STATE',
        message: 'State is required',
        severity: 'major',
      })
    }

    // Validate ZIP code
    if (zipCode) {
      // ReDoS safe ZIP code pattern
      const zipPattern = /^[0-9]{5}(?:-[0-9]{4})?$/
      if (!zipPattern.test(zipCode)) {
        result.errors.push({
          field: 'address.zipCode',
          code: 'INVALID_ZIP',
          message: 'Invalid ZIP code format',
          severity: 'major',
        })
      }
    }

    // Clean and standardize address
    const cleanedAddress = this.cleanAddress(business.address)
    if (JSON.stringify(cleanedAddress) !== JSON.stringify(business.address)) {
      result.suggestions.push({
        field: 'address',
        originalValue: business.address,
        suggestedValue: cleanedAddress,
        reason: 'Standardized address format',
        confidence: 0.85,
      })
      if (result.cleanedData) {
        result.cleanedData.address = cleanedAddress
      }
    }
  }

  /**
   * Validate website URL
   */
  private async validateWebsite(business: BusinessRecord, result: ValidationResult): Promise<void> {
    if (!business.websiteUrl) {
      result.warnings.push({
        field: 'websiteUrl',
        code: 'NO_WEBSITE',
        message: 'No website URL provided',
        impact: 'medium',
      })
      return
    }

    try {
      const url = new URL(business.websiteUrl)

      // Ensure HTTPS
      if (url.protocol === 'http:') {
        result.suggestions.push({
          field: 'websiteUrl',
          originalValue: business.websiteUrl,
          suggestedValue: business.websiteUrl.replace('http:', 'https:'),
          reason: 'Upgrade to HTTPS for security',
          confidence: 0.7,
        })
      }

      // Clean URL
      const cleanedUrl = this.cleanWebsiteUrl(business.websiteUrl)
      if (cleanedUrl !== business.websiteUrl) {
        result.suggestions.push({
          field: 'websiteUrl',
          originalValue: business.websiteUrl,
          suggestedValue: cleanedUrl,
          reason: 'Cleaned and normalized URL',
          confidence: 0.9,
        })
        if (result.cleanedData) {
          result.cleanedData.websiteUrl = cleanedUrl
        }
      }

    } catch (error) {
      result.errors.push({
        field: 'website',
        code: 'INVALID_URL',
        message: 'Invalid website URL format',
        severity: 'major',
      })
    }
  }

  /**
   * Validate industry classification
   */
  private async validateIndustry(business: BusinessRecord, result: ValidationResult): Promise<void> {
    if (!business.industry || business.industry === 'Unknown') {
      result.warnings.push({
        field: 'industry',
        code: 'MISSING_INDUSTRY',
        message: 'Industry classification missing or unknown',
        impact: 'medium',
      })

      // Suggest industry based on business name
      const suggestedIndustry = this.classifyIndustry(business.businessName, business.websiteUrl)
      if (suggestedIndustry) {
        result.suggestions.push({
          field: 'industry',
          originalValue: business.industry,
          suggestedValue: suggestedIndustry,
          reason: 'Classified based on business name and website',
          confidence: 0.7,
        })
      }
    }
  }

  /**
   * Calculate overall validation score
   */
  private calculateOverallScore(result: ValidationResult): void {
    let score = 1.0

    // Deduct for errors
    result.errors.forEach(error => {
      switch (error.severity) {
        case 'critical':
          score -= 0.3
          result.isValid = false
          break
        case 'major':
          score -= 0.2
          break
        case 'minor':
          score -= 0.1
          break
      }
    })

    // Deduct for warnings
    result.warnings.forEach(warning => {
      switch (warning.impact) {
        case 'high':
          score -= 0.1
          break
        case 'medium':
          score -= 0.05
          break
        case 'low':
          score -= 0.02
          break
      }
    })

    result.confidence = Math.max(0, score)
  }

  /**
   * Calculate data completeness score
   */
  private calculateCompleteness(business: BusinessRecord): number {
    const fields = [
      'businessName',
      'email',
      'phone',
      'website',
      'address',
      'industry',
      'coordinates',
    ]

    let completedFields = 0
    
    fields.forEach(field => {
      const value = business[field as keyof BusinessRecord]
      if (value !== undefined && value !== null && value !== '' &&
          !(Array.isArray(value) && value.length === 0)) {
        completedFields++
      }
    })

    return completedFields / fields.length
  }

  /**
   * Calculate data accuracy score (simplified)
   */
  private calculateAccuracy(business: BusinessRecord): number {
    let score = 1.0

    // Check email format
    if (business.email) {
      const invalidEmails = business.email.filter(email => !this.isValidEmailFormat(email))
      score -= (invalidEmails.length / business.email.length) * 0.2
    }

    // Check phone format
    if (business.phone && !this.isValidPhoneFormat(business.phone)) {
      score -= 0.2
    }

    // Check URL format
    if (business.websiteUrl) {
      try {
        new URL(business.websiteUrl)
      } catch {
        score -= 0.2
      }
    }

    return Math.max(0, score)
  }

  /**
   * Calculate data consistency score
   */
  private calculateConsistency(_business: BusinessRecord): number {
    // This would check consistency across related fields
    // For now, return a default score
    return 0.8
  }

  /**
   * Calculate data validity score
   */
  private calculateValidity(_business: BusinessRecord): number {
    // This would check business rules and constraints
    // For now, return a default score
    return 0.9
  }

  /**
   * Calculate data uniqueness score
   */
  private calculateUniqueness(_business: BusinessRecord): number {
    // This would check for duplicates in the dataset
    // For now, return a default score
    return 0.95
  }

  /**
   * Helper methods for data cleaning and validation
   */
  private async validateEmailAddress(email: string): Promise<boolean> {
    if (this.emailValidationCache.has(email)) {
      return this.emailValidationCache.get(email)!
    }

    const isValid = this.isValidEmailFormat(email)
    this.emailValidationCache.set(email, isValid)
    return isValid
  }

  private isValidEmailFormat(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }

  private isValidPhoneFormat(phone: string): boolean {
    const phoneRegex = /^\+?[\d\s\-\(\)\.]{10,}$/
    return phoneRegex.test(phone)
  }

  private formatPhoneNumber(phone: string): string | null {
    const cleaned = phone.replace(/[^\d]/g, '')
    
    if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 3)}) ${cleaned.slice(3, 6)}-${cleaned.slice(6)}`
    } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
      return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7)}`
    }
    
    return null
  }

  private cleanBusinessName(name: string): string {
    return name
      .trim()
      .replace(/\s+/g, ' ')
      .replace(/\b\w/g, l => l.toUpperCase())
  }

  private cleanAddress(address: BusinessRecord['address']): BusinessRecord['address'] {
    return {
      street: address.street?.trim().replace(/\s+/g, ' ') || '',
      city: address.city?.trim().replace(/\s+/g, ' ') || '',
      state: address.state?.trim().toUpperCase() || '',
      zipCode: address.zipCode?.trim() || '',
    }
  }

  private cleanWebsiteUrl(url: string): string {
    try {
      const urlObj = new URL(url)
      return urlObj.href
    } catch {
      return url
    }
  }

  private formatAddressString(address: BusinessRecord['address']): string {
    const parts = [address.street, address.city, address.state, address.zipCode]
    return parts.filter(Boolean).join(', ')
  }

  private classifyIndustry(businessName: string, website?: string): string | null {
    const industryKeywords = {
      'Restaurant': ['restaurant', 'cafe', 'diner', 'bistro', 'eatery', 'food'],
      'Healthcare': ['medical', 'doctor', 'clinic', 'hospital', 'health'],
      'Retail': ['store', 'shop', 'retail', 'boutique', 'market'],
      'Technology': ['tech', 'software', 'IT', 'computer', 'digital'],
      'Professional Services': ['law', 'accounting', 'consulting', 'legal'],
    }

    const text = `${businessName} ${website || ''}`.toLowerCase()

    for (const [industry, keywords] of Object.entries(industryKeywords)) {
      if (keywords.some(keyword => text.includes(keyword))) {
        return industry
      }
    }

    return null
  }
}

/**
 * Default data validation pipeline instance
 */
export const dataValidationPipeline = new DataValidationPipeline()
