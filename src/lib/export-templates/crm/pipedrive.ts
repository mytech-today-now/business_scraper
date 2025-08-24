/**
 * Pipedrive Export Template
 * Specialized template for Pipedrive CRM integration
 */

import { ExportTemplate, FieldTransformation } from '@/types/export-templates'
import { BaseExportTemplate } from '../base-template'
import { BusinessRecord } from '@/types/business'

/**
 * Pipedrive CRM export template
 */
export class PipedriveExportTemplate extends BaseExportTemplate {
  
  constructor() {
    super(PipedriveExportTemplate.createTemplate())
  }

  /**
   * Create Pipedrive template configuration
   */
  static createTemplate(): ExportTemplate {
    return {
      id: 'pipedrive-organizations',
      name: 'Pipedrive Organizations',
      platform: 'pipedrive',
      description: 'Export business data as Pipedrive Organization records',
      version: '1.0.0',
      
      fieldMappings: [
        {
          type: 'direct',
          sourceFields: ['businessName'],
          targetField: 'Organization name',
          options: {},
          validation: [
            {
              type: 'required',
              message: 'Organization name is required for Pipedrive'
            }
          ]
        },
        {
          type: 'format',
          sourceFields: ['phone.0'],
          targetField: 'Phone',
          options: {
            format: 'phone'
          },
          validation: []
        },
        {
          type: 'format',
          sourceFields: ['email.0'],
          targetField: 'Email',
          options: {
            format: 'email'
          },
          validation: []
        },
        {
          type: 'format',
          sourceFields: ['website'],
          targetField: 'Website',
          options: {
            format: 'url'
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
          sourceFields: ['industry'],
          targetField: 'Industry',
          options: {},
          validation: []
        },
        {
          type: 'direct',
          sourceFields: ['description'],
          targetField: 'Notes',
          options: {},
          validation: []
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Label',
          options: {
            conditions: [
              { condition: 'exists', value: 'Web Scraped Lead' }
            ]
          },
          validation: []
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Owner',
          options: {
            conditions: [
              { condition: 'exists', value: 'Admin' }
            ]
          },
          validation: []
        },
        {
          type: 'conditional',
          sourceFields: ['businessName'],
          targetField: 'Visible to',
          options: {
            conditions: [
              { condition: 'exists', value: 'Everyone' }
            ]
          },
          validation: []
        },
        {
          type: 'calculate',
          sourceFields: ['email', 'phone', 'website', 'address'],
          targetField: 'Lead Score',
          options: {
            calculation: 'calculateLeadScore'
          },
          validation: []
        },
        {
          type: 'calculate',
          sourceFields: ['website', 'email', 'address'],
          targetField: 'Company Size',
          options: {
            calculation: 'estimateCompanySize'
          },
          validation: []
        },
        {
          type: 'calculate',
          sourceFields: ['businessName'],
          targetField: 'Add time',
          options: {
            calculation: 'currentTimestamp'
          },
          validation: []
        }
      ],
      
      requiredFields: ['Organization name'],
      optionalFields: [
        'Phone', 'Email', 'Website', 'Address', 'Industry', 'Notes',
        'Label', 'Owner', 'Visible to', 'Lead Score', 'Company Size', 'Add time'
      ],
      
      platformConfig: {
        fileFormat: 'csv',
        headers: {
          'Organization name': 'Organization name',
          'Phone': 'Phone',
          'Email': 'Email',
          'Website': 'Website',
          'Address': 'Address',
          'Industry': 'Industry',
          'Notes': 'Notes',
          'Label': 'Label',
          'Owner': 'Owner',
          'Visible to': 'Visible to',
          'Lead Score': 'Lead Score',
          'Company Size': 'Company Size',
          'Add time': 'Add time'
        },
        delimiter: ',',
        encoding: 'utf-8',
        dateFormat: 'YYYY-MM-DD HH:mm:ss',
        booleanFormat: { true: '1', false: '0' },
        nullValue: ''
      },
      
      metadata: {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: 'system',
        tags: ['crm', 'pipedrive', 'organizations'],
        category: 'crm'
      },
      
      qualityRules: {
        minimumFields: 1,
        duplicateHandling: 'include',
        dataValidation: [
          {
            type: 'required',
            message: 'Organization name is required'
          }
        ]
      }
    }
  }

  /**
   * Pipedrive-specific data preprocessing
   */
  protected async preprocessData(businesses: BusinessRecord[]): Promise<BusinessRecord[]> {
    const baseProcessed = await super.preprocessData(businesses)
    
    return baseProcessed.map(business => {
      return {
        ...business,
        businessName: this.normalizeOrganizationName(business.businessName),
        industry: this.normalizeIndustry(business.industry),
        description: this.normalizeNotes(business.description)
      }
    })
  }

  /**
   * Pipedrive-specific field mapping for calculated fields
   */
  protected async applyFieldMapping(business: BusinessRecord, mapping: FieldTransformation): Promise<any> {
    if (mapping.type === 'calculate') {
      switch (mapping.options?.calculation) {
        case 'calculateLeadScore':
          return this.calculateLeadScore(business)
        case 'estimateCompanySize':
          return this.estimateCompanySize(business)
        case 'currentTimestamp':
          return new Date().toISOString().replace('T', ' ').substring(0, 19)
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

    // Check for Pipedrive-specific requirements
    const orgNameMapping = this.template.fieldMappings.find(m => m.targetField === 'Organization name')
    if (!orgNameMapping) {
      errors.push('Pipedrive template must include Organization name field mapping')
    }

    // Pipedrive recommendations
    suggestions.push('Add custom fields for industry-specific data')
    suggestions.push('Include Pipeline and Stage fields for deal tracking')
    suggestions.push('Add Person records for individual contacts within organizations')

    return { errors, warnings, suggestions }
  }

  /**
   * Normalize organization name for Pipedrive
   */
  private normalizeOrganizationName(name: string): string {
    if (!name) return ''
    
    return name
      .trim()
      .replace(/\s+/g, ' ')
      .substring(0, 255) // Reasonable limit for organization names
  }

  /**
   * Normalize industry for Pipedrive
   */
  private normalizeIndustry(industry: string): string {
    if (!industry) return ''
    
    // Pipedrive allows free-form industry text
    return industry
      .trim()
      .replace(/\s+/g, ' ')
      .substring(0, 100)
  }

  /**
   * Normalize notes/description for Pipedrive
   */
  private normalizeNotes(description: string): string {
    if (!description) return ''
    
    // Add context to the notes
    const timestamp = new Date().toLocaleDateString()
    const prefix = `[Web Scraped ${timestamp}] `
    
    return prefix + description.trim().substring(0, 3000 - prefix.length)
  }

  /**
   * Calculate lead score for Pipedrive
   */
  private calculateLeadScore(business: BusinessRecord): number {
    let score = 0
    
    // Email scoring
    if (business.email?.length) {
      score += 20
      if (business.email.some(email => !email.includes('gmail') && !email.includes('yahoo'))) {
        score += 10 // Business email bonus
      }
    }
    
    // Phone scoring
    if (business.phone?.length) {
      score += 15
      if (business.phone.length > 1) {
        score += 5 // Multiple phones bonus
      }
    }
    
    // Website scoring
    if (business.website) {
      score += 20
      if (!business.website.includes('facebook') && !business.website.includes('linkedin')) {
        score += 10 // Own website bonus
      }
    }
    
    // Address scoring
    if (business.address?.street && business.address?.city && business.address?.state) {
      score += 15
    }
    
    // Industry and description scoring
    if (business.industry) score += 5
    if (business.description && business.description.length > 50) score += 10
    if (business.description && business.description.length > 200) score += 5
    
    return Math.min(score, 100) // Cap at 100
  }

  /**
   * Estimate company size for Pipedrive
   */
  private estimateCompanySize(business: BusinessRecord): string {
    let indicators = 0
    
    if (business.website) indicators++
    if (business.email?.length && business.email.length > 1) indicators++
    if (business.phone?.length && business.phone.length > 1) indicators++
    if (business.address?.street) indicators++
    if (business.description && business.description.length > 100) indicators++
    
    if (indicators >= 4) return 'Large (50+ employees)'
    if (indicators >= 3) return 'Medium (11-50 employees)'
    if (indicators >= 2) return 'Small (2-10 employees)'
    
    return 'Micro (1 employee)'
  }

  /**
   * Post-process data for Pipedrive-specific formatting
   */
  protected async postprocessData(mappedData: any[]): Promise<any[]> {
    return mappedData.map(record => {
      // Ensure all required Pipedrive fields are present
      return {
        ...record,
        'Organization name': record['Organization name'] || 'Unknown Company',
        'Visible to': record['Visible to'] || 'Everyone',
        'Owner': record['Owner'] || 'Admin'
      }
    })
  }
}

// Export factory function
export function createPipedriveTemplate(): PipedriveExportTemplate {
  return new PipedriveExportTemplate()
}
