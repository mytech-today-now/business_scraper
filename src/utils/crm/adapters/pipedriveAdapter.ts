/**
 * Pipedrive CRM Adapter
 * Handles Pipedrive-specific export templates and transformations
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMAdapter,
  CRMTemplate,
  CRMFieldMapping,
  BatchTransformationResult,
  ValidationError,
  CRMExportOptions,
  CommonTransformers
} from '../types'
import { CRMTransformationEngine } from '../transformationEngine'
import { logger } from '@/utils/logger'

/**
 * Pipedrive CRM Adapter
 */
export class PipedriveAdapter implements CRMAdapter {
  platform = 'pipedrive' as const
  displayName = 'Pipedrive'
  private transformationEngine = new CRMTransformationEngine()

  /**
   * Pipedrive-specific field transformers
   */
  private pipedriveTransformers = {
    /** Format Pipedrive currency */
    formatPipedriveCurrency: (value: any): string => {
      const num = CommonTransformers.formatCurrency(value)
      return num.toFixed(2) // Pipedrive expects string format for currency
    },

    /** Format Pipedrive deal stage */
    formatDealStage: (value: any): string => {
      const stages = ['Lead In', 'Contact Made', 'Demo Scheduled', 'Proposal Made', 'Negotiations Started', 'Won', 'Lost']
      const stage = String(value || '').trim()
      return stages.includes(stage) ? stage : 'Lead In'
    },

    /** Format organization name */
    formatOrganizationName: (value: any, record: BusinessRecord): string => {
      return value || record.businessName || 'Unknown Organization'
    },

    /** Format person name from business name */
    formatPersonName: (value: any): string => {
      const name = String(value || '').trim()
      return name ? `${name} Contact` : 'Contact'
    },

    /** Format Pipedrive owner ID */
    formatOwnerId: (value: any): string => {
      // In real implementation, this would map to actual Pipedrive user IDs
      return value || '1' // Default to first user
    },

    /** Format Pipedrive visibility */
    formatVisibility: (value: any): string => {
      const visibilities = ['1', '3'] // 1 = Owner & followers, 3 = Entire company
      return visibilities.includes(String(value)) ? String(value) : '3'
    },

    /** Generate deal title */
    generateDealTitle: (value: any, record: BusinessRecord): string => {
      const company = record.businessName || 'Unknown Company'
      const industry = record.industry || 'Business'
      return `${company} - ${industry} Opportunity`
    },

    /** Format Pipedrive label */
    formatLabel: (value: any): string => {
      const labels = ['hot', 'warm', 'cold']
      const label = String(value || '').toLowerCase()
      return labels.includes(label) ? label : 'warm'
    },

    /** Estimate deal value based on industry */
    estimateDealValue: (value: any, record: BusinessRecord): string => {
      if (value && !isNaN(parseFloat(value))) {
        return this.pipedriveTransformers.formatPipedriveCurrency(value)
      }

      // Estimate based on industry
      const industryValues: Record<string, number> = {
        'technology': 50000,
        'finance': 75000,
        'healthcare': 40000,
        'manufacturing': 60000,
        'retail': 25000,
        'restaurants': 15000,
        'real estate': 100000,
        'construction': 80000,
        'automotive': 45000,
        'education': 30000
      }

      const industry = String(record.industry || '').toLowerCase()
      const estimatedValue = industryValues[industry] || 25000
      return this.pipedriveTransformers.formatPipedriveCurrency(estimatedValue)
    },

    /** Format Pipedrive phone */
    formatPipedrivePhone: (value: any): string => {
      if (!value) return ''
      const phone = String(value).replace(/\D/g, '')
      return phone.length >= 10 ? phone : ''
    }
  }

  /**
   * Available Pipedrive templates
   */
  templates: CRMTemplate[] = [
    {
      id: 'pipedrive-organization-person',
      name: 'Pipedrive Organization & Person',
      platform: 'pipedrive',
      description: 'Pipedrive Organization and Person import template',
      exportFormat: 'csv',
      fieldMappings: [
        // Organization fields
        {
          sourceField: 'businessName',
          targetField: 'Organization Name',
          transformer: this.pipedriveTransformers.formatOrganizationName,
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Organization name'
        },
        {
          sourceField: 'websiteUrl',
          targetField: 'Organization Website',
          validation: { required: false, type: 'url' },
          description: 'Organization website'
        },
        {
          sourceField: 'phone',
          targetField: 'Organization Phone',
          transformer: this.pipedriveTransformers.formatPipedrivePhone,
          validation: { required: false, type: 'phone' },
          description: 'Organization phone'
        },
        {
          sourceField: 'address.street',
          targetField: 'Organization Address',
          validation: { required: false, type: 'string', maxLength: 255 },
          description: 'Organization address'
        },
        {
          sourceField: 'confidence',
          targetField: 'Organization Label',
          transformer: (value: any) => {
            const confidence = parseFloat(value || '0')
            if (confidence > 0.8) return 'hot'
            if (confidence > 0.5) return 'warm'
            return 'cold'
          },
          defaultValue: 'warm',
          validation: { required: false, type: 'string' },
          description: 'Organization label (hot/warm/cold)'
        },
        // Person fields
        {
          sourceField: 'businessName',
          targetField: 'Person Name',
          transformer: this.pipedriveTransformers.formatPersonName,
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Person name'
        },
        {
          sourceField: 'email',
          targetField: 'Person Email',
          transformer: CommonTransformers.formatEmail,
          validation: { required: false, type: 'email' },
          description: 'Person email'
        },
        {
          sourceField: 'phone',
          targetField: 'Person Phone',
          transformer: this.pipedriveTransformers.formatPipedrivePhone,
          validation: { required: false, type: 'phone' },
          description: 'Person phone'
        },
        {
          sourceField: 'confidence',
          targetField: 'Person Label',
          transformer: this.pipedriveTransformers.formatLabel,
          defaultValue: 'warm',
          validation: { required: false, type: 'string' },
          description: 'Person label'
        }
      ],
      customHeaders: {
        'Organization Name': 'Organization Name',
        'Organization Website': 'Website',
        'Organization Phone': 'Phone',
        'Organization Address': 'Address',
        'Organization Label': 'Label',
        'Person Name': 'Person Name',
        'Person Email': 'Email',
        'Person Phone': 'Phone',
        'Person Label': 'Label'
      },
      metadata: {
        version: '1.0.0',
        author: 'Business Scraper',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['pipedrive', 'organization', 'person']
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100
      }
    },
    {
      id: 'pipedrive-deals-complete',
      name: 'Pipedrive Deals (Complete)',
      platform: 'pipedrive',
      description: 'Complete Pipedrive Deals import with Organizations and Persons',
      exportFormat: 'csv',
      fieldMappings: [
        // Deal fields
        {
          sourceField: 'businessName',
          targetField: 'Deal Title',
          transformer: this.pipedriveTransformers.generateDealTitle,
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Deal title'
        },
        {
          sourceField: 'confidence',
          targetField: 'Deal Value',
          transformer: this.pipedriveTransformers.estimateDealValue,
          defaultValue: '25000.00',
          validation: { required: false, type: 'string' },
          description: 'Deal value in currency'
        },
        {
          sourceField: 'industry',
          targetField: 'Deal Currency',
          transformer: () => 'USD',
          defaultValue: 'USD',
          validation: { required: false, type: 'string' },
          description: 'Deal currency'
        },
        {
          sourceField: 'confidence',
          targetField: 'Deal Stage',
          transformer: (value: any) => {
            const confidence = parseFloat(value || '0')
            if (confidence > 0.9) return 'Negotiations Started'
            if (confidence > 0.7) return 'Proposal Made'
            if (confidence > 0.5) return 'Demo Scheduled'
            if (confidence > 0.3) return 'Contact Made'
            return 'Lead In'
          },
          defaultValue: 'Lead In',
          validation: { required: false, type: 'string' },
          description: 'Deal stage'
        },
        {
          sourceField: 'scrapedAt',
          targetField: 'Deal Expected Close Date',
          transformer: (value: any) => {
            const date = new Date(value || Date.now())
            date.setMonth(date.getMonth() + 3) // 3 months from now
            return date.toISOString().split('T')[0] // YYYY-MM-DD format
          },
          validation: { required: false, type: 'date' },
          description: 'Expected close date'
        },
        // Organization fields for the deal
        {
          sourceField: 'businessName',
          targetField: 'Organization Name',
          transformer: this.pipedriveTransformers.formatOrganizationName,
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Organization name'
        },
        {
          sourceField: 'websiteUrl',
          targetField: 'Organization Website',
          validation: { required: false, type: 'url' },
          description: 'Organization website'
        },
        {
          sourceField: 'phone',
          targetField: 'Organization Phone',
          transformer: this.pipedriveTransformers.formatPipedrivePhone,
          validation: { required: false, type: 'phone' },
          description: 'Organization phone'
        },
        // Person fields for the deal
        {
          sourceField: 'businessName',
          targetField: 'Person Name',
          transformer: this.pipedriveTransformers.formatPersonName,
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Person name'
        },
        {
          sourceField: 'email',
          targetField: 'Person Email',
          transformer: CommonTransformers.formatEmail,
          validation: { required: false, type: 'email' },
          description: 'Person email'
        },
        {
          sourceField: 'phone',
          targetField: 'Person Phone',
          transformer: this.pipedriveTransformers.formatPipedrivePhone,
          validation: { required: false, type: 'phone' },
          description: 'Person phone'
        }
      ],
      customHeaders: {
        'Deal Title': 'Title',
        'Deal Value': 'Value',
        'Deal Currency': 'Currency',
        'Deal Stage': 'Stage',
        'Deal Expected Close Date': 'Expected Close Date',
        'Organization Name': 'Organization Name',
        'Organization Website': 'Organization Website',
        'Organization Phone': 'Organization Phone',
        'Person Name': 'Person Name',
        'Person Email': 'Person Email',
        'Person Phone': 'Person Phone'
      },
      metadata: {
        version: '1.0.0',
        author: 'Business Scraper',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['pipedrive', 'deals', 'complete', 'organization', 'person']
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100
      }
    }
  ]

  /**
   * Transform business records for Pipedrive
   */
  async transformRecords(
    records: BusinessRecord[],
    template: CRMTemplate,
    options?: CRMExportOptions
  ): Promise<BatchTransformationResult> {
    logger.info('PipedriveAdapter', `Transforming ${records.length} records using template: ${template.name}`)
    
    const mergedOptions: CRMExportOptions = {
      ...options,
      template,
      customTransformers: {
        ...this.pipedriveTransformers,
        ...options?.customTransformers
      }
    }

    return await this.transformationEngine.transformBatch(records, template, mergedOptions)
  }

  /**
   * Validate a single record against Pipedrive requirements
   */
  validateRecord(record: BusinessRecord, template: CRMTemplate): ValidationError[] {
    const errors: ValidationError[] = []

    // Pipedrive-specific validations
    if (template.id.includes('organization') && !record.businessName) {
      errors.push({
        field: 'Organization Name',
        message: 'Organization name is required for Pipedrive',
        value: record.businessName,
        rule: 'pipedrive-organization-required'
      })
    }

    if (template.id.includes('deals') && !record.businessName) {
      errors.push({
        field: 'Deal Title',
        message: 'Deal title is required for Pipedrive deals',
        value: record.businessName,
        rule: 'pipedrive-deal-required'
      })
    }

    return errors
  }

  /**
   * Get default Pipedrive template
   */
  getDefaultTemplate(): CRMTemplate {
    return this.templates[0] // Return organization & person template as default
  }

  /**
   * Create custom Pipedrive template
   */
  createCustomTemplate(
    name: string,
    fieldMappings: CRMFieldMapping[],
    options?: Partial<CRMTemplate>
  ): CRMTemplate {
    return {
      id: `pipedrive-custom-${Date.now()}`,
      name,
      platform: 'pipedrive',
      description: options?.description || 'Custom Pipedrive template',
      exportFormat: options?.exportFormat || 'csv',
      fieldMappings,
      customHeaders: options?.customHeaders || {},
      metadata: {
        version: '1.0.0',
        author: 'User',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['pipedrive', 'custom']
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100,
        ...options?.validation
      }
    }
  }
}
