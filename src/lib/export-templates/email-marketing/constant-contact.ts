/**
 * Constant Contact Export Template
 * Specialized template for Constant Contact email marketing platform
 */

import { ExportTemplate, FieldTransformation } from '@/types/export-templates'
import { BaseExportTemplate } from '../base-template'
import { BusinessRecord } from '@/types/business'

/**
 * Constant Contact email marketing export template
 */
export class ConstantContactExportTemplate extends BaseExportTemplate {
  constructor() {
    super(ConstantContactExportTemplate.createTemplate())
  }

  /**
   * Create Constant Contact template configuration
   */
  static createTemplate(): ExportTemplate {
    return {
      id: 'constant-contact-contacts',
      name: 'Constant Contact Contacts',
      platform: 'constant-contact',
      description: 'Export business data as Constant Contact contact list',
      version: '1.0.0',

      fieldMappings: [
        {
          type: 'format',
          sourceFields: ['email.0'],
          targetField: 'Email',
          options: {
            format: 'email',
          },
          validation: [
            {
              type: 'required',
              message: 'Email address is required for Constant Contact',
            },
            {
              type: 'email',
              message: 'Invalid email format',
            },
          ],
        },
        {
          type: 'calculate',
          sourceFields: ['businessName'],
          targetField: 'First Name',
          options: {
            calculation: 'extractFirstName',
          },
          validation: [],
        },
        {
          type: 'calculate',
          sourceFields: ['businessName'],
          targetField: 'Last Name',
          options: {
            calculation: 'extractLastName',
          },
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['businessName'],
          targetField: 'Company Name',
          options: {},
          validation: [],
        },
        {
          type: 'format',
          sourceFields: ['phone.0'],
          targetField: 'Work Phone',
          options: {
            format: 'phone',
          },
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.street'],
          targetField: 'Home Street Address',
          options: {},
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.city'],
          targetField: 'Home City',
          options: {},
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.state'],
          targetField: 'Home State',
          options: {},
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.zipCode'],
          targetField: 'Home Zip',
          options: {},
          validation: [],
        },
        {
          type: 'conditional',
          sourceFields: ['address.country'],
          targetField: 'Home Country',
          options: {
            conditions: [
              { condition: 'empty', value: 'United States' },
              { condition: 'default', value: 'address.country' },
            ],
          },
          validation: [],
        },
        {
          type: 'format',
          sourceFields: ['website'],
          targetField: 'Website',
          options: {
            format: 'url',
          },
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['industry'],
          targetField: 'Custom Field 1',
          options: {},
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['description'],
          targetField: 'Custom Field 2',
          options: {},
          validation: [],
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Opt-in Source',
          options: {
            conditions: [{ condition: 'exists', value: 'Web Scraping' }],
          },
          validation: [],
        },
        {
          type: 'conditional',
          sourceFields: ['email'],
          targetField: 'Permission to Email',
          options: {
            conditions: [{ condition: 'exists', value: 'No' }],
          },
          validation: [],
        },
        {
          type: 'calculate',
          sourceFields: ['email', 'phone', 'website', 'address'],
          targetField: 'Custom Field 3',
          options: {
            calculation: 'calculateLeadScore',
          },
          validation: [],
        },
        {
          type: 'calculate',
          sourceFields: ['businessName'],
          targetField: 'Date Added',
          options: {
            calculation: 'currentDate',
          },
          validation: [],
        },
      ],

      requiredFields: ['Email'],
      optionalFields: [
        'First Name',
        'Last Name',
        'Company Name',
        'Work Phone',
        'Home Street Address',
        'Home City',
        'Home State',
        'Home Zip',
        'Home Country',
        'Website',
        'Custom Field 1',
        'Custom Field 2',
        'Custom Field 3',
        'Opt-in Source',
        'Permission to Email',
        'Date Added',
      ],

      platformConfig: {
        fileFormat: 'csv',
        headers: {
          Email: 'Email',
          'First Name': 'First Name',
          'Last Name': 'Last Name',
          'Company Name': 'Company Name',
          'Work Phone': 'Work Phone',
          'Home Street Address': 'Home Street Address',
          'Home City': 'Home City',
          'Home State': 'Home State',
          'Home Zip': 'Home Zip',
          'Home Country': 'Home Country',
          Website: 'Website',
          'Custom Field 1': 'Custom Field 1',
          'Custom Field 2': 'Custom Field 2',
          'Custom Field 3': 'Custom Field 3',
          'Opt-in Source': 'Opt-in Source',
          'Permission to Email': 'Permission to Email',
          'Date Added': 'Date Added',
        },
        delimiter: ',',
        encoding: 'utf-8',
        dateFormat: 'MM/DD/YYYY',
        booleanFormat: { true: 'Yes', false: 'No' },
        nullValue: '',
      },

      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: 'system',
        tags: ['email-marketing', 'constant-contact', 'contacts'],
        category: 'email-marketing',
      },

      qualityRules: {
        minimumFields: 1,
        duplicateHandling: 'skip',
        dataValidation: [
          {
            type: 'required',
            message: 'Email address is required',
          },
          {
            type: 'email',
            message: 'Valid email address required',
          },
        ],
      },
    }
  }

  /**
   * Constant Contact-specific data preprocessing
   */
  protected async preprocessData(businesses: BusinessRecord[]): Promise<BusinessRecord[]> {
    const baseProcessed = await super.preprocessData(businesses)

    // Filter for businesses with valid email addresses
    return baseProcessed
      .filter(business => {
        return (
          business.email &&
          business.email.length > 0 &&
          business.email[0] &&
          this.isValidEmail(business.email[0])
        )
      })
      .map(business => {
        return {
          ...business,
          email: business.email?.map(email => email.toLowerCase().trim()),
          businessName: this.normalizeBusinessName(business.businessName),
          description: this.normalizeDescription(business.description),
        }
      })
  }

  /**
   * Constant Contact-specific field mapping for calculated fields
   */
  protected async applyFieldMapping(
    business: BusinessRecord,
    mapping: FieldTransformation
  ): Promise<any> {
    if (mapping.type === 'calculate') {
      switch (mapping.options?.calculation) {
        case 'extractFirstName':
          return this.extractFirstName(business.businessName)
        case 'extractLastName':
          return this.extractLastName(business.businessName)
        case 'calculateLeadScore':
          return this.calculateLeadScore(business)
        case 'currentDate':
          return new Date().toLocaleDateString('en-US')
        default:
          return super.applyFieldMapping(business, mapping)
      }
    }

    return super.applyFieldMapping(business, mapping)
  }

  /**
   * Platform-specific validation
   */
  protected validatePlatformSpecific(): {
    errors: string[]
    warnings: string[]
    suggestions: string[]
  } {
    const errors: string[] = []
    const warnings: string[] = []
    const suggestions: string[] = []

    // Check for Constant Contact-specific requirements
    const emailMapping = this.template.fieldMappings.find(m => m.targetField === 'Email')
    if (!emailMapping) {
      errors.push('Constant Contact template must include Email field mapping')
    }

    // Permission compliance check
    const permissionMapping = this.template.fieldMappings.find(
      m => m.targetField === 'Permission to Email'
    )
    if (!permissionMapping) {
      warnings.push('Consider adding Permission to Email field for compliance')
    }

    // Constant Contact optimization suggestions
    suggestions.push('Use custom fields for industry-specific segmentation')
    suggestions.push('Add birthday field for personalized campaigns')
    suggestions.push('Include list membership for better organization')

    return { errors, warnings, suggestions }
  }

  /**
   * Validate email format
   */
  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }

  /**
   * Normalize business name
   */
  private normalizeBusinessName(name: string): string {
    if (!name) return ''

    return name.trim().replace(/\s+/g, ' ').substring(0, 100)
  }

  /**
   * Normalize description for custom field
   */
  private normalizeDescription(description: string): string {
    if (!description) return ''

    // Constant Contact custom fields have character limits
    return description.trim().substring(0, 250) // Reasonable limit for custom fields
  }

  /**
   * Extract first name from business name
   */
  private extractFirstName(businessName: string): string {
    if (!businessName) return ''

    const words = businessName.trim().split(/\s+/)
    return words[0] || ''
  }

  /**
   * Extract last name from business name
   */
  private extractLastName(businessName: string): string {
    if (!businessName) return ''

    const words = businessName.trim().split(/\s+/)
    return words.slice(1).join(' ') || ''
  }

  /**
   * Calculate lead score for Constant Contact
   */
  private calculateLeadScore(business: BusinessRecord): string {
    let score = 0

    // Email quality
    if (business.email?.length) {
      score += 20
      const email = business.email[0]
      const domain = email.split('@')[1]?.toLowerCase()
      if (domain && !['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'].includes(domain)) {
        score += 10 // Business email bonus
      }
    }

    // Contact information completeness
    if (business.phone?.length) score += 15
    if (business.website) score += 15
    if (business.address?.street && business.address?.city && business.address?.state) score += 20

    // Business information
    if (business.industry) score += 10
    if (business.description && business.description.length > 50) score += 10

    // Return descriptive score
    if (score >= 80) return 'Excellent Lead'
    if (score >= 60) return 'Good Lead'
    if (score >= 40) return 'Fair Lead'
    if (score >= 20) return 'Basic Lead'

    return 'Minimal Lead'
  }

  /**
   * Post-process data for Constant Contact-specific requirements
   */
  protected async postprocessData(mappedData: any[]): Promise<any[]> {
    return mappedData.map(record => {
      // Ensure compliance fields are set
      return {
        ...record,
        'Permission to Email': record['Permission to Email'] || 'No',
        'Opt-in Source': record['Opt-in Source'] || 'Web Scraping',
        'Custom Field 1': record['Custom Field 1'] || 'Unknown Industry',
        'Custom Field 2': record['Custom Field 2'] || 'Web scraped business contact',
      }
    })
  }

  /**
   * Apply quality rules with email-specific validation
   */
  protected async applyQualityRules(data: any[]): Promise<{
    validRecords: any[]
    skippedRecords: any[]
    errors: any[]
    warnings: any[]
  }> {
    const baseResult = await super.applyQualityRules(data)

    // Additional email-specific validation
    const emailValidatedRecords: any[] = []
    const emailSkippedRecords: any[] = []
    const emailErrors: any[] = []
    const emailWarnings: any[] = []

    for (let i = 0; i < baseResult.validRecords.length; i++) {
      const record = baseResult.validRecords[i]
      const email = record['Email']

      if (!email || !this.isValidEmail(email)) {
        emailErrors.push({
          recordIndex: i,
          field: 'Email',
          error: 'Invalid or missing email address',
          value: email,
        })
        emailSkippedRecords.push(record)
      } else {
        // Check for potential issues
        if (email.includes('+')) {
          emailWarnings.push({
            recordIndex: i,
            field: 'Email',
            warning: 'Email contains plus sign, may be an alias',
            value: email,
          })
        }

        emailValidatedRecords.push(record)
      }
    }

    return {
      validRecords: emailValidatedRecords,
      skippedRecords: [...baseResult.skippedRecords, ...emailSkippedRecords],
      errors: [...baseResult.errors, ...emailErrors],
      warnings: [...baseResult.warnings, ...emailWarnings],
    }
  }
}

// Export factory function
export function createConstantContactTemplate(): ConstantContactExportTemplate {
  return new ConstantContactExportTemplate()
}
