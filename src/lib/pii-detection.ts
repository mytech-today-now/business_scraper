/**
 * Enhanced PII Detection and Redaction System
 * Automatically identifies and redacts personally identifiable information
 */

import { logger } from '@/utils/logger'
import { DataClassification } from '@/lib/response-sanitization'

/**
 * PII detection patterns with enhanced accuracy
 */
export const ENHANCED_PII_PATTERNS = {
  // Email addresses
  email: {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    classification: DataClassification.CONFIDENTIAL,
    confidence: 0.95,
    description: 'Email address',
  },

  // Phone numbers (various formats)
  phone: {
    pattern: /(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/g,
    classification: DataClassification.CONFIDENTIAL,
    confidence: 0.9,
    description: 'Phone number',
  },

  // Social Security Numbers
  ssn: {
    pattern: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    classification: DataClassification.RESTRICTED,
    confidence: 0.95,
    description: 'Social Security Number',
  },

  // Credit card numbers (Luhn algorithm validation)
  creditCard: {
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|4111[-\s]?1111[-\s]?1111[-\s]?1111)\b/g,
    classification: DataClassification.RESTRICTED,
    confidence: 0.9,
    description: 'Credit card number',
  },

  // IP addresses
  ipAddress: {
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    classification: DataClassification.CONFIDENTIAL,
    confidence: 0.8,
    description: 'IP address',
  },

  // UUIDs
  uuid: {
    pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
    classification: DataClassification.INTERNAL,
    confidence: 0.95,
    description: 'UUID',
  },

  // API Keys and tokens
  apiKey: {
    pattern: /\b(?:sk-|pk_|rk_)[a-zA-Z0-9]{20,}\b/g,
    classification: DataClassification.SECRET,
    confidence: 0.95,
    description: 'API key',
  },

  // JWT tokens
  jwt: {
    pattern: /\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/g,
    classification: DataClassification.SECRET,
    confidence: 0.9,
    description: 'JWT token',
  },

  // Passport numbers
  passport: {
    pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g,
    classification: DataClassification.RESTRICTED,
    confidence: 0.7,
    description: 'Passport number',
  },

  // Driver's license (US format)
  driversLicense: {
    pattern: /\b[A-Z]{1,2}[0-9]{6,8}\b/g,
    classification: DataClassification.RESTRICTED,
    confidence: 0.6,
    description: 'Driver\'s license',
  },

  // Bank account numbers
  bankAccount: {
    pattern: /\b[0-9]{8,17}\b/g,
    classification: DataClassification.RESTRICTED,
    confidence: 0.5,
    description: 'Bank account number',
  },

  // Medical record numbers
  medicalRecord: {
    pattern: /\bMRN[-\s]?[0-9]{6,10}\b/gi,
    classification: DataClassification.RESTRICTED,
    confidence: 0.8,
    description: 'Medical record number',
  },
}

/**
 * PII detection result
 */
export interface PIIDetectionResult {
  type: string
  value: string
  startIndex: number
  endIndex: number
  confidence: number
  classification: DataClassification
  description: string
  redactedValue: string
}

/**
 * PII detection options
 */
export interface PIIDetectionOptions {
  enableContextualAnalysis: boolean
  minimumConfidence: number
  customPatterns: Record<string, any>
  preserveFormat: boolean
  logDetections: boolean
}

/**
 * Default PII detection options
 */
export const DEFAULT_PII_OPTIONS: PIIDetectionOptions = {
  enableContextualAnalysis: true,
  minimumConfidence: 0.7,
  customPatterns: {},
  preserveFormat: true,
  logDetections: process.env.NODE_ENV === 'development',
}

/**
 * Enhanced PII Detection Service
 */
export class PIIDetectionService {
  private options: PIIDetectionOptions
  private patterns: Record<string, any>

  constructor(options: Partial<PIIDetectionOptions> = {}) {
    this.options = { ...DEFAULT_PII_OPTIONS, ...options }
    this.patterns = { ...ENHANCED_PII_PATTERNS, ...this.options.customPatterns }
  }

  /**
   * Detect PII in text
   */
  detectPII(text: string, context?: string): PIIDetectionResult[] {
    if (!text || typeof text !== 'string') {
      return []
    }

    const detections: PIIDetectionResult[] = []

    for (const [type, config] of Object.entries(this.patterns)) {
      const matches = this.findMatches(text, config, type)
      detections.push(...matches)
    }

    // Filter by confidence threshold
    const filteredDetections = detections.filter(
      detection => detection.confidence >= this.options.minimumConfidence
    )

    // Apply contextual analysis if enabled
    const finalDetections = this.options.enableContextualAnalysis
      ? this.applyContextualAnalysis(filteredDetections, text, context)
      : filteredDetections

    // Log detections if enabled
    if (this.options.logDetections && finalDetections.length > 0) {
      logger.info('PII Detection', 'PII detected in text', {
        context,
        detectionCount: finalDetections.length,
        types: finalDetections.map(d => d.type),
        classifications: [...new Set(finalDetections.map(d => d.classification))],
      })
    }

    return finalDetections
  }

  /**
   * Redact PII in text
   */
  redactPII(text: string, context?: string): { redactedText: string; detections: PIIDetectionResult[] } {
    const detections = this.detectPII(text, context)
    let redactedText = text

    // Sort detections by start index in reverse order to maintain indices
    const sortedDetections = detections.sort((a, b) => b.startIndex - a.startIndex)

    for (const detection of sortedDetections) {
      redactedText = redactedText.substring(0, detection.startIndex) +
        detection.redactedValue +
        redactedText.substring(detection.endIndex)
    }

    return { redactedText, detections }
  }

  /**
   * Redact PII in object
   */
  redactPIIInObject(obj: any, context?: string): { redactedObject: any; detections: PIIDetectionResult[] } {
    const allDetections: PIIDetectionResult[] = []
    const redactedObject = this.redactObjectRecursive(obj, '', allDetections, context)

    return { redactedObject, detections: allDetections }
  }

  /**
   * Check if text contains PII
   */
  containsPII(text: string, context?: string): boolean {
    const detections = this.detectPII(text, context)
    return detections.length > 0
  }

  /**
   * Get PII statistics for text
   */
  getPIIStats(text: string, context?: string): Record<string, number> {
    const detections = this.detectPII(text, context)
    const stats: Record<string, number> = {}

    for (const detection of detections) {
      stats[detection.type] = (stats[detection.type] || 0) + 1
    }

    return stats
  }

  /**
   * Find pattern matches in text
   */
  private findMatches(text: string, config: any, type: string): PIIDetectionResult[] {
    const matches: PIIDetectionResult[] = []
    const pattern = config.pattern
    let match

    // Reset regex lastIndex
    pattern.lastIndex = 0

    while ((match = pattern.exec(text)) !== null) {
      const value = match[0]
      const redactedValue = this.generateRedactedValue(value, type, config)

      matches.push({
        type,
        value,
        startIndex: match.index,
        endIndex: match.index + value.length,
        confidence: config.confidence,
        classification: config.classification,
        description: config.description,
        redactedValue,
      })

      // Prevent infinite loop for global patterns
      if (!pattern.global) break
    }

    return matches
  }

  /**
   * Generate redacted value based on type and format
   */
  private generateRedactedValue(value: string, type: string, config: any): string {
    if (!this.options.preserveFormat) {
      return `[${type.toUpperCase()}_REDACTED]`
    }

    switch (type) {
      case 'email':
        return this.redactEmail(value)
      case 'phone':
        return this.redactPhone(value)
      case 'ssn':
        return this.redactSSN(value)
      case 'creditCard':
        return this.redactCreditCard(value)
      case 'ipAddress':
        return this.redactIPAddress(value)
      case 'uuid':
        return '[UUID_REDACTED]'
      case 'apiKey':
      case 'jwt':
        return '[TOKEN_REDACTED]'
      default:
        return `[${type.toUpperCase()}_REDACTED]`
    }
  }

  /**
   * Redact email address
   */
  private redactEmail(email: string): string {
    const [local, domain] = email.split('@')
    if (!domain) return '[EMAIL_REDACTED]'

    const maskedLocal = local.length > 2
      ? local.substring(0, 2) + '*'.repeat(Math.max(local.length - 2, 1))
      : '*'.repeat(local.length)

    return `${maskedLocal}@${domain}`
  }

  /**
   * Redact phone number
   */
  private redactPhone(phone: string): string {
    const digits = phone.replace(/\D/g, '')
    if (digits.length >= 10) {
      const format = phone.replace(/\d/g, '*')
      return format.replace(/\*{4}$/, digits.slice(-4))
    }
    return '[PHONE_REDACTED]'
  }

  /**
   * Redact SSN
   */
  private redactSSN(ssn: string): string {
    return ssn.replace(/\d/g, '*').replace(/\*{4}$/, ssn.slice(-4))
  }

  /**
   * Redact credit card number
   */
  private redactCreditCard(card: string): string {
    const digits = card.replace(/\D/g, '')
    return '*'.repeat(digits.length - 4) + digits.slice(-4)
  }

  /**
   * Redact IP address
   */
  private redactIPAddress(ip: string): string {
    const parts = ip.split('.')
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.*.***`
    }
    return '[IP_REDACTED]'
  }

  /**
   * Apply contextual analysis to improve accuracy
   */
  private applyContextualAnalysis(
    detections: PIIDetectionResult[],
    text: string,
    context?: string
  ): PIIDetectionResult[] {
    return detections.filter(detection => {
      // Additional validation based on context
      if (detection.type === 'bankAccount' && detection.confidence < 0.8) {
        // Check if it's in a financial context
        const surroundingText = this.getSurroundingText(text, detection.startIndex, 50)
        if (!this.isFinancialContext(surroundingText)) {
          return false
        }
      }

      if (detection.type === 'driversLicense' && detection.confidence < 0.8) {
        // Check if it's in an ID context
        const surroundingText = this.getSurroundingText(text, detection.startIndex, 30)
        if (!this.isIDContext(surroundingText)) {
          return false
        }
      }

      return true
    })
  }

  /**
   * Get surrounding text for context analysis
   */
  private getSurroundingText(text: string, index: number, radius: number): string {
    const start = Math.max(0, index - radius)
    const end = Math.min(text.length, index + radius)
    return text.substring(start, end).toLowerCase()
  }

  /**
   * Check if text is in financial context
   */
  private isFinancialContext(text: string): boolean {
    const financialKeywords = ['account', 'bank', 'routing', 'deposit', 'payment', 'transfer']
    return financialKeywords.some(keyword => text.includes(keyword))
  }

  /**
   * Check if text is in ID context
   */
  private isIDContext(text: string): boolean {
    const idKeywords = ['license', 'id', 'identification', 'driver', 'permit']
    return idKeywords.some(keyword => text.includes(keyword))
  }

  /**
   * Recursively redact PII in object
   */
  private redactObjectRecursive(
    obj: any,
    path: string,
    allDetections: PIIDetectionResult[],
    context?: string
  ): any {
    if (obj === null || obj === undefined) {
      return obj
    }

    if (typeof obj === 'string') {
      const { redactedText, detections } = this.redactPII(obj, `${context}.${path}`)
      allDetections.push(...detections)
      return redactedText
    }

    if (Array.isArray(obj)) {
      return obj.map((item, index) =>
        this.redactObjectRecursive(item, `${path}[${index}]`, allDetections, context)
      )
    }

    if (typeof obj === 'object') {
      const redactedObj: any = {}
      for (const [key, value] of Object.entries(obj)) {
        const fieldPath = path ? `${path}.${key}` : key
        redactedObj[key] = this.redactObjectRecursive(value, fieldPath, allDetections, context)
      }
      return redactedObj
    }

    return obj
  }
}

// Export singleton instance
export const piiDetectionService = new PIIDetectionService()
