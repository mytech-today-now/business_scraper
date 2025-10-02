/**
 * Data Classification System
 * Categorizes data fields by sensitivity level and applies appropriate protection controls
 */

import { logger } from '@/utils/logger'
import { DataClassification } from '@/lib/response-sanitization'

/**
 * Field classification rules
 */
export interface FieldClassificationRule {
  pattern: string | RegExp
  classification: DataClassification
  description: string
  autoMask?: boolean
  autoRemove?: boolean
  encryptAtRest?: boolean
  auditAccess?: boolean
}

/**
 * Data protection policy
 */
export interface DataProtectionPolicy {
  classification: DataClassification
  allowInLogs: boolean
  allowInResponses: boolean
  requireEncryption: boolean
  requireAudit: boolean
  maskInProduction: boolean
  retentionDays?: number
}

/**
 * Classification result
 */
export interface ClassificationResult {
  field: string
  classification: DataClassification
  rule: FieldClassificationRule
  protectionPolicy: DataProtectionPolicy
  recommendations: string[]
}

/**
 * Default field classification rules
 */
export const DEFAULT_CLASSIFICATION_RULES: FieldClassificationRule[] = [
  // Authentication & Security (SECRET)
  {
    pattern: /^(password|pwd|secret|private_key|api_key|access_token|refresh_token)$/i,
    classification: DataClassification.SECRET,
    description: 'Authentication credentials and secrets',
    autoRemove: true,
    encryptAtRest: true,
    auditAccess: true,
  },
  {
    pattern: /^(password_hash|password_salt|hash|salt)$/i,
    classification: DataClassification.SECRET,
    description: 'Password hashes and salts',
    autoRemove: true,
    encryptAtRest: true,
    auditAccess: true,
  },

  // Personal Identifiable Information (RESTRICTED)
  {
    pattern: /^(ssn|social_security_number|tax_id|passport|drivers_license|national_id)$/i,
    classification: DataClassification.RESTRICTED,
    description: 'Government-issued identification numbers',
    autoMask: true,
    encryptAtRest: true,
    auditAccess: true,
  },
  {
    pattern: /^(credit_card|card_number|cvv|cvc|bank_account|routing_number|account_number)$/i,
    classification: DataClassification.RESTRICTED,
    description: 'Financial account information',
    autoMask: true,
    encryptAtRest: true,
    auditAccess: true,
  },

  // Personal Information (CONFIDENTIAL)
  {
    pattern: /^(email|email_address|personal_email)$/i,
    classification: DataClassification.CONFIDENTIAL,
    description: 'Email addresses',
    autoMask: true,
    encryptAtRest: false,
    auditAccess: true,
  },
  {
    pattern: /^(phone|phone_number|mobile|telephone)$/i,
    classification: DataClassification.CONFIDENTIAL,
    description: 'Phone numbers',
    autoMask: true,
    encryptAtRest: false,
    auditAccess: true,
  },
  {
    pattern: /^(address|street|home_address|billing_address|shipping_address)$/i,
    classification: DataClassification.CONFIDENTIAL,
    description: 'Physical addresses',
    autoMask: true,
    encryptAtRest: false,
    auditAccess: true,
  },
  {
    pattern: /^(ip_address|client_ip|remote_addr)$/i,
    classification: DataClassification.CONFIDENTIAL,
    description: 'IP addresses',
    autoMask: true,
    encryptAtRest: false,
    auditAccess: true,
  },

  // Session & System Information (INTERNAL)
  {
    pattern: /^(session_id|csrf_token|nonce|request_id)$/i,
    classification: DataClassification.INTERNAL,
    description: 'Session and request identifiers',
    autoRemove: false,
    encryptAtRest: false,
    auditAccess: false,
  },
  {
    pattern: /^(database_url|connection_string|config|internal_id|system_path)$/i,
    classification: DataClassification.INTERNAL,
    description: 'Internal system configuration',
    autoRemove: true,
    encryptAtRest: false,
    auditAccess: true,
  },
  {
    pattern: /^(debug|stack_trace|error_details|internal_error)$/i,
    classification: DataClassification.INTERNAL,
    description: 'Debug and error information',
    autoRemove: true,
    encryptAtRest: false,
    auditAccess: false,
  },

  // Business Information (PUBLIC/INTERNAL)
  {
    pattern: /^(business_name|company|organization|title|description)$/i,
    classification: DataClassification.PUBLIC,
    description: 'Public business information',
    autoRemove: false,
    encryptAtRest: false,
    auditAccess: false,
  },
  {
    pattern: /^(id|uuid|created_at|updated_at|timestamp)$/i,
    classification: DataClassification.PUBLIC,
    description: 'Standard identifiers and timestamps',
    autoRemove: false,
    encryptAtRest: false,
    auditAccess: false,
  },
]

/**
 * Data protection policies by classification level
 */
export const DATA_PROTECTION_POLICIES: Record<DataClassification, DataProtectionPolicy> = {
  [DataClassification.PUBLIC]: {
    classification: DataClassification.PUBLIC,
    allowInLogs: true,
    allowInResponses: true,
    requireEncryption: false,
    requireAudit: false,
    maskInProduction: false,
  },
  [DataClassification.INTERNAL]: {
    classification: DataClassification.INTERNAL,
    allowInLogs: true,
    allowInResponses: false,
    requireEncryption: false,
    requireAudit: true,
    maskInProduction: true,
    retentionDays: 90,
  },
  [DataClassification.CONFIDENTIAL]: {
    classification: DataClassification.CONFIDENTIAL,
    allowInLogs: false,
    allowInResponses: false,
    requireEncryption: true,
    requireAudit: true,
    maskInProduction: true,
    retentionDays: 365,
  },
  [DataClassification.RESTRICTED]: {
    classification: DataClassification.RESTRICTED,
    allowInLogs: false,
    allowInResponses: false,
    requireEncryption: true,
    requireAudit: true,
    maskInProduction: true,
    retentionDays: 2555, // 7 years for financial data
  },
  [DataClassification.SECRET]: {
    classification: DataClassification.SECRET,
    allowInLogs: false,
    allowInResponses: false,
    requireEncryption: true,
    requireAudit: true,
    maskInProduction: true,
    retentionDays: 30, // Minimal retention for secrets
  },
}

/**
 * Data Classification Service
 */
export class DataClassificationService {
  private rules: FieldClassificationRule[]
  private customRules: FieldClassificationRule[] = []

  constructor(customRules: FieldClassificationRule[] = []) {
    this.rules = [...DEFAULT_CLASSIFICATION_RULES, ...customRules]
    this.customRules = customRules
  }

  /**
   * Classify a field name
   */
  classifyField(fieldName: string): ClassificationResult {
    const normalizedField = fieldName.toLowerCase().trim()

    // Find matching rule
    for (const rule of this.rules) {
      if (this.matchesPattern(normalizedField, rule.pattern)) {
        const protectionPolicy = DATA_PROTECTION_POLICIES[rule.classification]
        const recommendations = this.generateRecommendations(rule, protectionPolicy)

        return {
          field: fieldName,
          classification: rule.classification,
          rule,
          protectionPolicy,
          recommendations,
        }
      }
    }

    // Default to PUBLIC if no rule matches
    const defaultRule: FieldClassificationRule = {
      pattern: '.*',
      classification: DataClassification.PUBLIC,
      description: 'Unclassified field - defaulting to public',
      autoMask: false,
      autoRemove: false,
      encryptAtRest: false,
      auditAccess: false,
    }

    return {
      field: fieldName,
      classification: DataClassification.PUBLIC,
      rule: defaultRule,
      protectionPolicy: DATA_PROTECTION_POLICIES[DataClassification.PUBLIC],
      recommendations: ['Consider adding explicit classification rule for this field'],
    }
  }

  /**
   * Classify multiple fields
   */
  classifyFields(fieldNames: string[]): ClassificationResult[] {
    return fieldNames.map(field => this.classifyField(field))
  }

  /**
   * Classify an entire object structure
   */
  classifyObject(obj: any, path: string = ''): Map<string, ClassificationResult> {
    const results = new Map<string, ClassificationResult>()

    if (obj === null || obj === undefined) {
      return results
    }

    if (typeof obj === 'object' && !Array.isArray(obj)) {
      for (const [key, value] of Object.entries(obj)) {
        const fieldPath = path ? `${path}.${key}` : key
        const classification = this.classifyField(key)
        results.set(fieldPath, classification)

        // Recursively classify nested objects
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          const nestedResults = this.classifyObject(value, fieldPath)
          nestedResults.forEach((result, nestedPath) => {
            results.set(nestedPath, result)
          })
        }
      }
    }

    return results
  }

  /**
   * Add custom classification rule
   */
  addCustomRule(rule: FieldClassificationRule): void {
    this.customRules.push(rule)
    this.rules = [...DEFAULT_CLASSIFICATION_RULES, ...this.customRules]
    
    logger.info('Data Classification', 'Added custom classification rule', {
      pattern: rule.pattern.toString(),
      classification: rule.classification,
      description: rule.description,
    })
  }

  /**
   * Get classification statistics
   */
  getClassificationStats(obj: any): Record<DataClassification, number> {
    const classifications = this.classifyObject(obj)
    const stats: Record<DataClassification, number> = {
      [DataClassification.PUBLIC]: 0,
      [DataClassification.INTERNAL]: 0,
      [DataClassification.CONFIDENTIAL]: 0,
      [DataClassification.RESTRICTED]: 0,
      [DataClassification.SECRET]: 0,
    }

    classifications.forEach(result => {
      stats[result.classification]++
    })

    return stats
  }

  /**
   * Check if pattern matches field name
   */
  private matchesPattern(fieldName: string, pattern: string | RegExp): boolean {
    if (pattern instanceof RegExp) {
      return pattern.test(fieldName)
    }
    return fieldName.includes(pattern.toLowerCase())
  }

  /**
   * Generate recommendations based on classification
   */
  private generateRecommendations(rule: FieldClassificationRule, policy: DataProtectionPolicy): string[] {
    const recommendations: string[] = []

    if (policy.requireEncryption) {
      recommendations.push('Encrypt this field at rest')
    }

    if (policy.requireAudit) {
      recommendations.push('Log access to this field for audit purposes')
    }

    if (policy.maskInProduction) {
      recommendations.push('Mask this field in production responses')
    }

    if (!policy.allowInLogs) {
      recommendations.push('Exclude this field from application logs')
    }

    if (!policy.allowInResponses) {
      recommendations.push('Remove this field from API responses')
    }

    if (policy.retentionDays) {
      recommendations.push(`Implement data retention policy: ${policy.retentionDays} days`)
    }

    return recommendations
  }
}

// Export singleton instance
export const dataClassificationService = new DataClassificationService()
