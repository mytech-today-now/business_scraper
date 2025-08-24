/**
 * HubSpot Export Template
 * Specialized template for HubSpot CRM integration
 */

import { ExportTemplate, FieldTransformation } from '@/types/export-templates'
import { BaseExportTemplate } from '../base-template'
import { BusinessRecord } from '@/types/business'

/**
 * HubSpot CRM export template
 */
export class HubSpotExportTemplate extends BaseExportTemplate {
  
  constructor() {
    super(HubSpotExportTemplate.createTemplate())
  }

  /**
   * Create HubSpot template configuration
   */
  static createTemplate(): ExportTemplate {
    return {
      id: 'hubspot-companies',
      name: 'HubSpot Companies',
      platform: 'hubspot',
      description: 'Export business data as HubSpot Company records',
      version: '1.0.0',
      
      fieldMappings: [
        {
          type: 'direct',
          sourceFields: ['businessName'],
          targetField: 'Name',
          options: {},
          validation: [
            {
              type: 'required',
              message: 'Company name is required for HubSpot companies'
            }
          ]
        },
        {
          type: 'format',
          sourceFields: ['website'],
          targetField: 'Domain',
          options: {
            format: 'domain'
          },
          validation: []
        },
        {
          type: 'format',
          sourceFields: ['website'],
          targetField: 'Website URL',
          options: {
            format: 'url'
          },
          validation: []
        },
        {
          type: 'format',
          sourceFields: ['phone.0'],
          targetField: 'Phone Number',
          options: {
            format: 'phone'
          },
          validation: []
        },
        {
          type: 'concatenate',
          sourceFields: ['address.street', 'address.city', 'address.state', 'address.zipCode'],
          targetField: 'Address',
          options: {
            separator: ', '
          },
          validation: []
        },
        {
          type: 'direct',
          sourceFields: ['address.city'],
          targetField: 'City',
          options: {},
          validation: []
        },
        {
          type: 'direct',
          sourceFields: ['address.state'],
          targetField: 'State/Region',
          options: {},
          validation: []
        },
        {
          type: 'direct',
          sourceFields: ['address.zipCode'],
          targetField: 'Postal Code',
          options: {},
          validation: []
        },
        {
          type: 'conditional',
          sourceFields: ['address.country'],
          targetField: 'Country',
          options: {
            conditions: [
              { condition: 'empty', value: 'United States' },
              { condition: 'default', value: 'address.country' }
            ]
          },
          validation: []
        },
        {
          type: 'lookup',
          sourceFields: ['industry'],
          targetField: 'Industry',
          options: {
            lookupTable: {
              'technology': 'COMPUTER_SOFTWARE',
              'software': 'COMPUTER_SOFTWARE',
              'healthcare': 'HOSPITAL_HEALTH_CARE',
              'finance': 'FINANCIAL_SERVICES',
              'retail': 'RETAIL',
              'manufacturing': 'MANUFACTURING',
              'education': 'EDUCATION_MANAGEMENT',
              'real estate': 'REAL_ESTATE',
              'construction': 'CONSTRUCTION',
              'automotive': 'AUTOMOTIVE',
              'food service': 'RESTAURANTS',
              'default': 'OTHER'
            }
          },
          validation: []
        },
        {
          type: 'direct',
          sourceFields: ['description'],
          targetField: 'Description',
          options: {},
          validation: []
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Lead Status',
          options: {
            conditions: [
              { condition: 'exists', value: 'NEW' }
            ]
          },
          validation: []
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Lifecycle Stage',
          options: {
            conditions: [
              { condition: 'exists', value: 'lead' }
            ]
          },
          validation: []
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Original Source',
          options: {
            conditions: [
              { condition: 'exists', value: 'WEB_SCRAPING' }
            ]
          },
          validation: []
        },
        {
          type: 'calculate',
          sourceFields: ['website', 'email', 'phone', 'address'],
          targetField: 'Company size',
          options: {
            calculation: 'estimateCompanySize'
          },
          validation: []
        },
        {
          type: 'calculate',
          sourceFields: ['website', 'email', 'address'],
          targetField: 'Annual revenue',
          options: {
            calculation: 'estimateAnnualRevenue'
          },
          validation: []
        },
        {
          type: 'calculate',
          sourceFields: ['businessName'],
          targetField: 'Create date',
          options: {
            calculation: 'currentTimestamp'
          },
          validation: []
        }
      ],
      
      requiredFields: ['Name'],
      optionalFields: [
        'Domain', 'Website URL', 'Phone Number', 'Address', 'City', 
        'State/Region', 'Postal Code', 'Country', 'Industry', 'Description',
        'Lead Status', 'Lifecycle Stage', 'Original Source', 'Company size',
        'Annual revenue', 'Create date'
      ],
      
      platformConfig: {
        fileFormat: 'csv',
        headers: {
          'Name': 'Name',
          'Domain': 'Domain',
          'Website URL': 'Website URL',
          'Phone Number': 'Phone Number',
          'Address': 'Address',
          'City': 'City',
          'State/Region': 'State/Region',
          'Postal Code': 'Postal Code',
          'Country': 'Country',
          'Industry': 'Industry',
          'Description': 'Description',
          'Lead Status': 'Lead Status',
          'Lifecycle Stage': 'Lifecycle Stage',
          'Original Source': 'Original Source',
          'Company size': 'Company size',
          'Annual revenue': 'Annual revenue',
          'Create date': 'Create date'
        },
        delimiter: ',',
        encoding: 'utf-8',
        dateFormat: 'MM/DD/YYYY',
        booleanFormat: { true: 'true', false: 'false' },
        nullValue: ''
      },
      
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: 'system',
        tags: ['crm', 'hubspot', 'companies'],
        category: 'crm'
      },
      
      qualityRules: {
        minimumFields: 2,
        duplicateHandling: 'merge',
        dataValidation: [
          {
            type: 'required',
            message: 'Company name is required'
          }
        ]
      }
    }
  }

  /**
   * HubSpot-specific data preprocessing
   */
  protected async preprocessData(businesses: BusinessRecord[]): Promise<BusinessRecord[]> {
    const baseProcessed = await super.preprocessData(businesses)
    
    return baseProcessed.map(business => {
      return {
        ...business,
        businessName: this.normalizeCompanyName(business.businessName),
        website: this.normalizeWebsite(business.website),
        industry: this.normalizeIndustry(business.industry)
      }
    })
  }

  /**
   * HubSpot-specific field mapping for calculated fields
   */
  protected async applyFieldMapping(business: BusinessRecord, mapping: FieldTransformation): Promise<any> {
    if (mapping.type === 'calculate') {
      switch (mapping.options?.calculation) {
        case 'estimateCompanySize':
          return this.estimateCompanySize(business)
        case 'estimateAnnualRevenue':
          return this.estimateAnnualRevenue(business)
        case 'currentTimestamp':
          return new Date().toLocaleDateString('en-US')
        default:
          return super.applyFieldMapping(business, mapping)
      }
    }
    
    if (mapping.type === 'format' && mapping.options?.format === 'domain') {
      return this.extractDomain(this.extractFieldValue(business, mapping.sourceFields[0]))
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

    // Check for HubSpot-specific requirements
    const nameMapping = this.template.fieldMappings.find(m => m.targetField === 'Name')
    if (!nameMapping) {
      errors.push('HubSpot template must include Name field mapping')
    }

    // Check for domain field which is important for HubSpot deduplication
    const domainMapping = this.template.fieldMappings.find(m => m.targetField === 'Domain')
    if (!domainMapping) {
      warnings.push('Consider adding Domain field for better HubSpot deduplication')
    }

    // Suggestions for HubSpot optimization
    suggestions.push('Add HubSpot Owner field for automatic assignment')
    suggestions.push('Include Lead Score field for better lead qualification')
    suggestions.push('Add custom properties for industry-specific data')

    return { errors, warnings, suggestions }
  }

  /**
   * Normalize company name for HubSpot
   */
  private normalizeCompanyName(name: string): string {
    if (!name) return ''
    
    return name
      .trim()
      .replace(/\s+/g, ' ')
      .replace(/\b(inc|llc|corp|ltd|co)\b\.?/gi, (match) => match.toUpperCase())
  }

  /**
   * Normalize website URL
   */
  private normalizeWebsite(website: string): string {
    if (!website) return ''
    
    let normalized = website.trim().toLowerCase()
    
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'https://' + normalized
    }
    
    return normalized
  }

  /**
   * Extract domain from website URL
   */
  private extractDomain(website: string): string {
    if (!website) return ''
    
    try {
      const url = new URL(website.startsWith('http') ? website : `https://${website}`)
      return url.hostname.replace('www.', '')
    } catch {
      return website.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0]
    }
  }

  /**
   * Normalize industry for HubSpot
   */
  private normalizeIndustry(industry: string): string {
    if (!industry) return ''
    
    // HubSpot uses specific industry codes
    const industryMap: Record<string, string> = {
      'technology': 'COMPUTER_SOFTWARE',
      'tech': 'COMPUTER_SOFTWARE',
      'software': 'COMPUTER_SOFTWARE',
      'it': 'COMPUTER_SOFTWARE',
      'healthcare': 'HOSPITAL_HEALTH_CARE',
      'medical': 'HOSPITAL_HEALTH_CARE',
      'finance': 'FINANCIAL_SERVICES',
      'banking': 'FINANCIAL_SERVICES',
      'retail': 'RETAIL',
      'ecommerce': 'RETAIL',
      'manufacturing': 'MANUFACTURING',
      'education': 'EDUCATION_MANAGEMENT',
      'realestate': 'REAL_ESTATE',
      'construction': 'CONSTRUCTION',
      'automotive': 'AUTOMOTIVE',
      'food': 'RESTAURANTS',
      'restaurant': 'RESTAURANTS'
    }
    
    const normalized = industry.toLowerCase().replace(/\s+/g, '')
    return industryMap[normalized] || 'OTHER'
  }

  /**
   * Estimate company size for HubSpot
   */
  private estimateCompanySize(business: BusinessRecord): string {
    let score = 0
    
    if (business.website) score += 2
    if (business.email?.length && business.email.length > 1) score += 2
    if (business.phone?.length && business.phone.length > 1) score += 1
    if (business.address?.street) score += 1
    if (business.description && business.description.length > 100) score += 1
    
    if (score >= 6) return '51-200'
    if (score >= 4) return '11-50'
    if (score >= 2) return '2-10'
    
    return '1'
  }

  /**
   * Estimate annual revenue for HubSpot
   */
  private estimateAnnualRevenue(business: BusinessRecord): string {
    let score = 0
    
    if (business.website) score += 2
    if (business.email?.some(email => !email.includes('gmail') && !email.includes('yahoo'))) score += 2
    if (business.address?.street && business.address?.city && business.address?.state) score += 2
    if (business.phone?.length && business.phone.length > 1) score += 1
    if (business.description && business.description.length > 100) score += 1
    
    if (score >= 7) return '$5M-$10M'
    if (score >= 5) return '$1M-$5M'
    if (score >= 3) return '$500K-$1M'
    if (score >= 1) return '$100K-$500K'
    
    return 'Less than $100K'
  }
}

// Export factory function
export function createHubSpotTemplate(): HubSpotExportTemplate {
  return new HubSpotExportTemplate()
}
