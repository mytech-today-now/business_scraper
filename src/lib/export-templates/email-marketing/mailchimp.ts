/**
 * Mailchimp Export Template
 * Specialized template for Mailchimp email marketing platform
 */

import { ExportTemplate, FieldTransformation } from '@/types/export-templates'
import { BaseExportTemplate } from '../base-template'
import { BusinessRecord } from '@/types/business'

/**
 * Mailchimp email marketing export template
 */
export class MailchimpExportTemplate extends BaseExportTemplate {
  constructor() {
    super(MailchimpExportTemplate.createTemplate())
  }

  /**
   * Create Mailchimp template configuration
   */
  static createTemplate(): ExportTemplate {
    return {
      id: 'mailchimp-contacts',
      name: 'Mailchimp Contacts',
      platform: 'mailchimp',
      description: 'Export business data as Mailchimp contact list',
      version: '1.0.0',

      fieldMappings: [
        {
          type: 'format',
          sourceFields: ['email.0'],
          targetField: 'Email Address',
          options: {
            format: 'email',
          },
          validation: [
            {
              type: 'required',
              message: 'Email address is required for Mailchimp contacts',
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
          targetField: 'Company',
          options: {},
          validation: [],
        },
        {
          type: 'format',
          sourceFields: ['phone.0'],
          targetField: 'Phone',
          options: {
            format: 'phone',
          },
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.street'],
          targetField: 'Address',
          options: {},
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.city'],
          targetField: 'City',
          options: {},
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.state'],
          targetField: 'State',
          options: {},
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['address.zipCode'],
          targetField: 'Zip',
          options: {},
          validation: [],
        },
        {
          type: 'conditional',
          sourceFields: ['address.country'],
          targetField: 'Country',
          options: {
            conditions: [
              { condition: 'empty', value: 'US' },
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
          targetField: 'Industry',
          options: {},
          validation: [],
        },
        {
          type: 'calculate',
          sourceFields: ['industry', 'address.state', 'website', 'email', 'phone'],
          targetField: 'Tags',
          options: {
            calculation: 'generateTags',
          },
          validation: [],
        },
        {
          type: 'conditional',
          sourceFields: ['email'],
          targetField: 'GDPR Permission',
          options: {
            conditions: [{ condition: 'exists', value: 'No' }],
          },
          validation: [],
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Source',
          options: {
            conditions: [{ condition: 'exists', value: 'Web Scraping' }],
          },
          validation: [],
        },
        {
          type: 'conditional',
          sourceFields: ['email'],
          targetField: 'Opt-in Status',
          options: {
            conditions: [{ condition: 'exists', value: 'pending' }],
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

      requiredFields: ['Email Address'],
      optionalFields: [
        'First Name',
        'Last Name',
        'Company',
        'Phone',
        'Address',
        'City',
        'State',
        'Zip',
        'Country',
        'Website',
        'Industry',
        'Tags',
        'GDPR Permission',
        'Source',
        'Opt-in Status',
        'Date Added',
      ],

      platformConfig: {
        fileFormat: 'csv',
        headers: {
          'Email Address': 'Email Address',
          'First Name': 'First Name',
          'Last Name': 'Last Name',
          Company: 'Company',
          Phone: 'Phone',
          Address: 'Address',
          City: 'City',
          State: 'State',
          Zip: 'Zip',
          Country: 'Country',
          Website: 'Website',
          Industry: 'Industry',
          Tags: 'Tags',
          'GDPR Permission': 'GDPR Permission',
          Source: 'Source',
          'Opt-in Status': 'Opt-in Status',
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
        tags: ['email-marketing', 'mailchimp', 'contacts'],
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
   * Mailchimp-specific data preprocessing
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
        }
      })
  }

  /**
   * Mailchimp-specific field mapping for calculated fields
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
        case 'generateTags':
          return this.generateTags(business)
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

    // Check for Mailchimp-specific requirements
    const emailMapping = this.template.fieldMappings.find(m => m.targetField === 'Email Address')
    if (!emailMapping) {
      errors.push('Mailchimp template must include Email Address field mapping')
    }

    // GDPR compliance check
    const gdprMapping = this.template.fieldMappings.find(m => m.targetField === 'GDPR Permission')
    if (!gdprMapping) {
      warnings.push('Consider adding GDPR Permission field for compliance')
    }

    // Mailchimp optimization suggestions
    suggestions.push('Add merge tags for personalized email campaigns')
    suggestions.push('Include interest groups for better segmentation')
    suggestions.push('Add custom fields for industry-specific data')

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

    return name.trim().replace(/\s+/g, ' ').substring(0, 100) // Reasonable limit for company names
  }

  /**
   * Extract first name from business name
   */
  private extractFirstName(businessName: string): string {
    if (!businessName) return ''

    // For business names, use the first word as "first name"
    const words = businessName.trim().split(/\s+/)
    return words[0] || ''
  }

  /**
   * Extract last name from business name
   */
  private extractLastName(businessName: string): string {
    if (!businessName) return ''

    // For business names, use remaining words as "last name"
    const words = businessName.trim().split(/\s+/)
    return words.slice(1).join(' ') || ''
  }

  /**
   * Generate tags for Mailchimp segmentation
   */
  private generateTags(business: BusinessRecord): string {
    const tags: string[] = ['web-scraped']

    // Industry tag
    if (business.industry) {
      tags.push(business.industry.toLowerCase().replace(/\s+/g, '-'))
    }

    // Location tag
    if (business.address?.state) {
      tags.push(business.address.state.toLowerCase().replace(/\s+/g, '-'))
    }

    // Data quality tags
    if (business.website) {
      tags.push('has-website')
    }

    if (business.phone?.length) {
      tags.push('has-phone')
    }

    if (business.address?.street) {
      tags.push('has-address')
    }

    // Business type tags based on email domain
    if (business.email?.[0]) {
      const domain = business.email[0].split('@')[1]?.toLowerCase()
      if (domain) {
        if (['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'].includes(domain)) {
          tags.push('personal-email')
        } else {
          tags.push('business-email')
        }
      }
    }

    // Lead quality tag
    const qualityScore = this.calculateQualityScore(business)
    if (qualityScore >= 7) {
      tags.push('high-quality')
    } else if (qualityScore >= 4) {
      tags.push('medium-quality')
    } else {
      tags.push('low-quality')
    }

    return tags.join(',')
  }

  /**
   * Calculate lead quality score
   */
  private calculateQualityScore(business: BusinessRecord): number {
    let score = 0

    if (business.email?.length) score += 2
    if (business.phone?.length) score += 2
    if (business.website) score += 2
    if (business.address?.street) score += 1
    if (business.address?.city && business.address?.state) score += 1
    if (business.industry) score += 1
    if (business.description && business.description.length > 50) score += 1

    return score
  }

  /**
   * Post-process data for Mailchimp-specific requirements
   */
  protected async postprocessData(mappedData: any[]): Promise<any[]> {
    return mappedData.map(record => {
      // Ensure GDPR compliance fields are set
      return {
        ...record,
        'GDPR Permission': record['GDPR Permission'] || 'No',
        'Opt-in Status': record['Opt-in Status'] || 'pending',
        Source: record['Source'] || 'Web Scraping',
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

    for (let i = 0; i < baseResult.validRecords.length; i++) {
      const record = baseResult.validRecords[i]
      const email = record['Email Address']

      if (!email || !this.isValidEmail(email)) {
        emailErrors.push({
          recordIndex: i,
          field: 'Email Address',
          error: 'Invalid or missing email address',
          value: email,
        })
        emailSkippedRecords.push(record)
      } else {
        emailValidatedRecords.push(record)
      }
    }

    return {
      validRecords: emailValidatedRecords,
      skippedRecords: [...baseResult.skippedRecords, ...emailSkippedRecords],
      errors: [...baseResult.errors, ...emailErrors],
      warnings: baseResult.warnings,
    }
  }
}

// Export factory function
export function createMailchimpTemplate(): MailchimpExportTemplate {
  return new MailchimpExportTemplate()
}
