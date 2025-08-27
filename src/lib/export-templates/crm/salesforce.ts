/**
 * Salesforce Export Template
 * Specialized template for Salesforce CRM integration
 */

import { ExportTemplate, FieldTransformation } from '@/types/export-templates'
import { BaseExportTemplate } from '../base-template'
import { BusinessRecord } from '@/types/business'

/**
 * Salesforce CRM export template
 */
export class SalesforceExportTemplate extends BaseExportTemplate {
  constructor() {
    super(SalesforceExportTemplate.createTemplate())
  }

  /**
   * Create Salesforce template configuration
   */
  static createTemplate(): ExportTemplate {
    return {
      id: 'salesforce-leads',
      name: 'Salesforce Leads',
      platform: 'salesforce',
      description: 'Export business data as Salesforce Lead records',
      version: '1.0.0',

      fieldMappings: [
        {
          type: 'direct',
          sourceFields: ['businessName'],
          targetField: 'Company',
          options: {},
          validation: [
            {
              type: 'required',
              message: 'Company name is required for Salesforce leads',
            },
            {
              type: 'length',
              value: 255,
              message: 'Company name must be 255 characters or less',
            },
          ],
        },
        {
          type: 'format',
          sourceFields: ['phone.0'],
          targetField: 'Phone',
          options: {
            format: 'phone',
          },
          validation: [
            {
              type: 'phone',
              message: 'Invalid phone number format',
            },
          ],
        },
        {
          type: 'format',
          sourceFields: ['email.0'],
          targetField: 'Email',
          options: {
            format: 'email',
          },
          validation: [
            {
              type: 'email',
              message: 'Invalid email format',
            },
          ],
        },
        {
          type: 'format',
          sourceFields: ['website'],
          targetField: 'Website',
          options: {
            format: 'url',
          },
          validation: [
            {
              type: 'url',
              message: 'Invalid website URL',
            },
          ],
        },
        {
          type: 'direct',
          sourceFields: ['address.street'],
          targetField: 'Street',
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
          targetField: 'PostalCode',
          options: {},
          validation: [
            {
              type: 'pattern',
              value: /^\d{5}(-\d{4})?$/,
              message: 'Invalid ZIP code format',
            },
          ],
        },
        {
          type: 'conditional',
          sourceFields: ['address.country'],
          targetField: 'Country',
          options: {
            conditions: [
              { condition: 'empty', value: 'United States' },
              { condition: 'default', value: 'address.country' },
            ],
          },
          validation: [],
        },
        {
          type: 'lookup',
          sourceFields: ['industry'],
          targetField: 'Industry',
          options: {
            lookupTable: {
              technology: 'Technology',
              healthcare: 'Healthcare',
              finance: 'Financial Services',
              retail: 'Retail',
              manufacturing: 'Manufacturing',
              education: 'Education',
              'real estate': 'Real Estate',
              construction: 'Construction',
              automotive: 'Automotive',
              'food service': 'Food & Beverage',
              default: 'Other',
            },
          },
          validation: [],
        },
        {
          type: 'direct',
          sourceFields: ['description'],
          targetField: 'Description',
          options: {},
          validation: [
            {
              type: 'length',
              value: 32000,
              message: 'Description must be 32,000 characters or less',
            },
          ],
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'LeadSource',
          options: {
            conditions: [{ condition: 'exists', value: 'Web Scraping' }],
          },
          validation: [],
        },
        {
          type: 'calculate',
          sourceFields: ['email', 'phone', 'website', 'address'],
          targetField: 'Rating',
          options: {
            calculation: 'calculateLeadRating',
          },
          validation: [],
        },
        {
          type: 'calculate',
          sourceFields: ['website', 'email', 'address'],
          targetField: 'AnnualRevenue',
          options: {
            calculation: 'estimateRevenue',
          },
          validation: [],
        },
        {
          type: 'calculate',
          sourceFields: ['email', 'phone', 'website'],
          targetField: 'NumberOfEmployees',
          options: {
            calculation: 'estimateEmployees',
          },
          validation: [],
        },
      ],

      requiredFields: ['Company'],
      optionalFields: [
        'Phone',
        'Email',
        'Website',
        'Street',
        'City',
        'State',
        'PostalCode',
        'Country',
        'Industry',
        'Description',
        'LeadSource',
        'Rating',
        'AnnualRevenue',
        'NumberOfEmployees',
      ],

      platformConfig: {
        fileFormat: 'csv',
        headers: {
          Company: 'Company',
          Phone: 'Phone',
          Email: 'Email',
          Website: 'Website',
          Street: 'Street',
          City: 'City',
          State: 'State/Province',
          PostalCode: 'Zip/Postal Code',
          Country: 'Country',
          Industry: 'Industry',
          Description: 'Description',
          LeadSource: 'Lead Source',
          Rating: 'Rating',
          AnnualRevenue: 'Annual Revenue',
          NumberOfEmployees: 'No. of Employees',
        },
        delimiter: ',',
        encoding: 'utf-8',
        dateFormat: 'YYYY-MM-DD',
        booleanFormat: { true: 'true', false: 'false' },
        nullValue: '',
      },

      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: 'system',
        tags: ['crm', 'salesforce', 'leads'],
        category: 'crm',
      },

      qualityRules: {
        minimumFields: 2,
        duplicateHandling: 'skip',
        dataValidation: [
          {
            type: 'required',
            message: 'Company name is required',
          },
        ],
      },
    }
  }

  /**
   * Salesforce-specific data preprocessing
   */
  protected async preprocessData(businesses: BusinessRecord[]): Promise<BusinessRecord[]> {
    // Call parent preprocessing first
    const baseProcessed = await super.preprocessData(businesses)

    // Salesforce-specific filtering and preprocessing
    return baseProcessed
      .filter(business => {
        // Ensure we have at least company name and one contact method
        const hasCompany = business.businessName && business.businessName.trim().length > 0
        const hasContact =
          (business.email && business.email.length > 0) ||
          (business.phone && business.phone.length > 0) ||
          business.website

        return hasCompany && hasContact
      })
      .map(business => {
        // Normalize data for Salesforce
        return {
          ...business,
          businessName: this.normalizeCompanyName(business.businessName),
          industry: this.normalizeIndustry(business.industry),
          email: business.email?.map(email => email.toLowerCase().trim()),
          phone: business.phone?.map(phone => this.normalizePhone(phone)),
        }
      })
  }

  /**
   * Salesforce-specific field mapping for calculated fields
   */
  protected async applyFieldMapping(
    business: BusinessRecord,
    mapping: FieldTransformation
  ): Promise<any> {
    if (mapping.type === 'calculate') {
      switch (mapping.options?.calculation) {
        case 'calculateLeadRating':
          return this.calculateLeadRating(business)
        case 'estimateRevenue':
          return this.estimateRevenue(business)
        case 'estimateEmployees':
          return this.estimateEmployees(business)
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

    // Check for Salesforce-specific requirements
    const companyMapping = this.template.fieldMappings.find(m => m.targetField === 'Company')
    if (!companyMapping) {
      errors.push('Salesforce template must include Company field mapping')
    }

    // Check field length limits
    const fieldLimits = {
      Company: 255,
      Phone: 40,
      Email: 80,
      Website: 255,
      Street: 255,
      City: 40,
      State: 80,
      PostalCode: 20,
      Country: 80,
      Industry: 40,
      Description: 32000,
    }

    for (const [field, limit] of Object.entries(fieldLimits)) {
      const mapping = this.template.fieldMappings.find(m => m.targetField === field)
      if (mapping && !mapping.validation?.some(v => v.type === 'length')) {
        warnings.push(`Consider adding length validation for ${field} (max ${limit} characters)`)
      }
    }

    // Suggestions for optimization
    suggestions.push('Consider adding Lead Status field for better lead management')
    suggestions.push('Add Lead Owner assignment for automatic lead distribution')
    suggestions.push('Include Campaign field to track lead source campaigns')

    return { errors, warnings, suggestions }
  }

  /**
   * Normalize company name for Salesforce
   */
  private normalizeCompanyName(name: string): string {
    if (!name) return ''

    return name
      .trim()
      .replace(/\s+/g, ' ')
      .replace(/[^\w\s&.-]/g, '') // Remove special characters except common business ones
      .substring(0, 255) // Salesforce limit
  }

  /**
   * Normalize industry for Salesforce picklist values
   */
  private normalizeIndustry(industry: string): string {
    if (!industry) return ''

    const industryMap: Record<string, string> = {
      tech: 'Technology',
      it: 'Technology',
      software: 'Technology',
      healthcare: 'Healthcare',
      medical: 'Healthcare',
      finance: 'Financial Services',
      banking: 'Financial Services',
      retail: 'Retail',
      ecommerce: 'Retail',
      manufacturing: 'Manufacturing',
      education: 'Education',
      realestate: 'Real Estate',
      construction: 'Construction',
      automotive: 'Automotive',
      food: 'Food & Beverage',
      restaurant: 'Food & Beverage',
    }

    const normalized = industry.toLowerCase().replace(/\s+/g, '')
    return industryMap[normalized] || industry
  }

  /**
   * Normalize phone number
   */
  private normalizePhone(phone: string): string {
    if (!phone) return ''

    const digits = phone.replace(/\D/g, '')
    if (digits.length === 10) {
      return `(${digits.substr(0, 3)}) ${digits.substr(3, 3)}-${digits.substr(6, 4)}`
    } else if (digits.length === 11 && digits.startsWith('1')) {
      return `+1 (${digits.substr(1, 3)}) ${digits.substr(4, 3)}-${digits.substr(7, 4)}`
    }

    return phone
  }

  /**
   * Calculate lead rating based on data completeness and quality
   */
  private calculateLeadRating(business: BusinessRecord): string {
    let score = 0

    // Email presence and quality
    if (business.email?.length) {
      score += 2
      if (business.email.some(email => !email.includes('gmail') && !email.includes('yahoo'))) {
        score += 1 // Business email
      }
    }

    // Phone presence
    if (business.phone?.length) score += 2

    // Website presence
    if (business.website) {
      score += 2
      if (!business.website.includes('facebook') && !business.website.includes('linkedin')) {
        score += 1 // Own website
      }
    }

    // Address completeness
    if (business.address?.street && business.address?.city && business.address?.state) {
      score += 2
    }

    // Industry and description
    if (business.industry) score += 1
    if (business.description && business.description.length > 50) score += 1

    if (score >= 8) return 'Hot'
    if (score >= 6) return 'Warm'
    if (score >= 4) return 'Cold'
    return 'Unqualified'
  }

  /**
   * Estimate annual revenue
   */
  private estimateRevenue(business: BusinessRecord): number | null {
    let score = 0

    if (business.website) score += 2
    if (business.email?.some(email => !email.includes('gmail') && !email.includes('yahoo')))
      score += 2
    if (business.address?.street) score += 1
    if (business.phone?.length && business.phone.length > 1) score += 1
    if (business.description && business.description.length > 100) score += 1

    if (score >= 6) return 2500000 // $2.5M
    if (score >= 4) return 750000 // $750K
    if (score >= 2) return 250000 // $250K

    return null
  }

  /**
   * Estimate number of employees
   */
  private estimateEmployees(business: BusinessRecord): number | null {
    let score = 0

    if (business.email?.length && business.email.length > 1) score += 2
    if (business.phone?.length && business.phone.length > 1) score += 2
    if (business.website) score += 1
    if (business.address?.street) score += 1

    if (score >= 5) return 25 // 11-50 range
    if (score >= 3) return 5 // 2-10 range

    return 1 // 1 employee
  }
}

// Export factory function
export function createSalesforceTemplate(): SalesforceExportTemplate {
  return new SalesforceExportTemplate()
}
