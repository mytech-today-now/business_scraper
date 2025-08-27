/**
 * HubSpot CRM Adapter
 * Handles HubSpot-specific export templates and transformations
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMAdapter,
  CRMTemplate,
  CRMFieldMapping,
  BatchTransformationResult,
  ValidationError,
  CRMExportOptions,
  CommonTransformers,
} from '../types'
import { CRMTransformationEngine } from '../transformationEngine'
import { logger } from '@/utils/logger'

/**
 * HubSpot CRM Adapter
 */
export class HubSpotAdapter implements CRMAdapter {
  platform = 'hubspot' as const
  displayName = 'HubSpot'
  private transformationEngine = new CRMTransformationEngine()

  /**
   * HubSpot-specific field transformers
   */
  private hubspotTransformers = {
    /** Format HubSpot lifecycle stage */
    formatLifecycleStage: (value: any): string => {
      const stages = [
        'subscriber',
        'lead',
        'marketingqualifiedlead',
        'salesqualifiedlead',
        'opportunity',
        'customer',
        'evangelist',
        'other',
      ]
      const stage = String(value || '').toLowerCase()
      return stages.includes(stage) ? stage : 'lead'
    },

    /** Format HubSpot lead status */
    formatLeadStatus: (value: any): string => {
      const statuses = [
        'NEW',
        'OPEN',
        'IN_PROGRESS',
        'OPEN_DEAL',
        'UNQUALIFIED',
        'ATTEMPTED_TO_CONTACT',
        'CONNECTED',
        'BAD_TIMING',
      ]
      const status = String(value || '').toUpperCase()
      return statuses.includes(status) ? status : 'NEW'
    },

    /** Format company name for HubSpot */
    formatCompanyName: (value: any, record: BusinessRecord): string => {
      return value || record.businessName || 'Unknown Company'
    },

    /** Format HubSpot industry */
    formatHubSpotIndustry: (value: any): string => {
      const industryMap: Record<string, string> = {
        restaurants: 'RESTAURANT',
        retail: 'RETAIL',
        healthcare: 'HEALTH_CARE',
        technology: 'COMPUTER_SOFTWARE',
        finance: 'FINANCIAL_SERVICES',
        'real estate': 'REAL_ESTATE',
        education: 'EDUCATION_MANAGEMENT',
        manufacturing: 'MANUFACTURING',
        construction: 'CONSTRUCTION',
        automotive: 'AUTOMOTIVE',
        hospitality: 'HOSPITALITY',
        legal: 'LEGAL_SERVICES',
        consulting: 'MANAGEMENT_CONSULTING',
        nonprofit: 'NONPROFIT_ORGANIZATION_MANAGEMENT',
      }

      const industry = String(value || '').toLowerCase()
      return industryMap[industry] || 'OTHER'
    },

    /** Format HubSpot owner ID */
    formatOwnerId: (value: any): string => {
      // In real implementation, this would map to actual HubSpot user IDs
      return value || '' // Leave empty for auto-assignment
    },

    /** Format HubSpot contact source */
    formatContactSource: (value: any): string => {
      const sources = [
        'ORGANIC_SEARCH',
        'PAID_SEARCH',
        'EMAIL_MARKETING',
        'SOCIAL_MEDIA',
        'REFERRALS',
        'OTHER_CAMPAIGNS',
        'DIRECT_TRAFFIC',
        'OFFLINE_SOURCES',
      ]
      return sources.includes(value) ? value : 'DIRECT_TRAFFIC'
    },

    /** Split business name into first and last name */
    splitBusinessNameToContact: (businessName: string) => {
      const name = String(businessName || '').trim()
      if (!name) return { firstName: '', lastName: 'Contact' }

      const parts = name.split(' ')
      if (parts.length === 1) {
        return { firstName: parts[0], lastName: 'Contact' }
      }

      return {
        firstName: parts.slice(0, -1).join(' '),
        lastName: parts[parts.length - 1],
      }
    },

    /** Format HubSpot boolean */
    formatHubSpotBoolean: (value: any): string => {
      return CommonTransformers.toBoolean(value) ? 'true' : 'false'
    },
  }

  /**
   * Available HubSpot templates
   */
  templates: CRMTemplate[] = [
    {
      id: 'hubspot-contact-basic',
      name: 'HubSpot Contact (Basic)',
      platform: 'hubspot',
      description: 'Basic HubSpot Contact import template with essential fields',
      exportFormat: 'csv',
      fieldMappings: [
        {
          sourceField: 'email',
          targetField: 'Email',
          transformer: CommonTransformers.formatEmail,
          required: true,
          validation: { required: true, type: 'email' },
          description: 'Contact email address (required for HubSpot)',
        },
        {
          sourceField: 'businessName',
          targetField: 'First Name',
          transformer: (value: any) =>
            this.hubspotTransformers.splitBusinessNameToContact(value).firstName,
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'Contact first name',
        },
        {
          sourceField: 'businessName',
          targetField: 'Last Name',
          transformer: (value: any) =>
            this.hubspotTransformers.splitBusinessNameToContact(value).lastName,
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'Contact last name',
        },
        {
          sourceField: 'businessName',
          targetField: 'Company name',
          transformer: this.hubspotTransformers.formatCompanyName,
          validation: { required: false, type: 'string', maxLength: 255 },
          description: 'Company name',
        },
        {
          sourceField: 'phone',
          targetField: 'Phone Number',
          transformer: CommonTransformers.formatPhone,
          validation: { required: false, type: 'phone' },
          description: 'Primary phone number',
        },
        {
          sourceField: 'websiteUrl',
          targetField: 'Website URL',
          validation: { required: false, type: 'url' },
          description: 'Company website URL',
        },
        {
          sourceField: 'address.street',
          targetField: 'Street Address',
          validation: { required: false, type: 'string', maxLength: 255 },
          description: 'Street address',
        },
        {
          sourceField: 'address.city',
          targetField: 'City',
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'City',
        },
        {
          sourceField: 'address.state',
          targetField: 'State/Region',
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'State or region',
        },
        {
          sourceField: 'address.zipCode',
          targetField: 'Postal Code',
          validation: { required: false, type: 'string', maxLength: 20 },
          description: 'Postal or ZIP code',
        },
        {
          sourceField: 'industry',
          targetField: 'Industry',
          transformer: this.hubspotTransformers.formatHubSpotIndustry,
          validation: { required: false, type: 'string' },
          description: 'Industry classification',
        },
        {
          sourceField: 'source',
          targetField: 'Lead Source',
          transformer: this.hubspotTransformers.formatContactSource,
          defaultValue: 'DIRECT_TRAFFIC',
          validation: { required: false, type: 'string' },
          description: 'Original source of contact',
        },
        {
          sourceField: 'confidence',
          targetField: 'Lifecycle Stage',
          transformer: (value: any) => {
            const confidence = parseFloat(value || '0')
            if (confidence > 0.8) return 'salesqualifiedlead'
            if (confidence > 0.6) return 'marketingqualifiedlead'
            return 'lead'
          },
          defaultValue: 'lead',
          validation: { required: false, type: 'string' },
          description: 'Contact lifecycle stage',
        },
      ],
      customHeaders: {
        Email: 'Email',
        'First Name': 'First Name',
        'Last Name': 'Last Name',
        'Company name': 'Company name',
        'Phone Number': 'Phone Number',
        'Website URL': 'Website URL',
        'Street Address': 'Street Address',
        City: 'City',
        'State/Region': 'State/Region',
        'Postal Code': 'Postal Code',
        Industry: 'Industry',
        'Lead Source': 'Lead Source',
        'Lifecycle Stage': 'Lifecycle Stage',
      },
      metadata: {
        version: '1.0.0',
        author: 'Business Scraper',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['hubspot', 'contact', 'basic'],
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100,
      },
    },
    {
      id: 'hubspot-company-contact',
      name: 'HubSpot Company & Contact',
      platform: 'hubspot',
      description: 'HubSpot Company and Contact import template for B2B data',
      exportFormat: 'json',
      fieldMappings: [
        // Company fields
        {
          sourceField: 'businessName',
          targetField: 'company.name',
          transformer: this.hubspotTransformers.formatCompanyName,
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Company name',
        },
        {
          sourceField: 'websiteUrl',
          targetField: 'company.domain',
          transformer: (value: any) => {
            if (!value) return ''
            try {
              const url = new URL(value)
              return url.hostname.replace('www.', '')
            } catch {
              return value
            }
          },
          validation: { required: false, type: 'string' },
          description: 'Company domain',
        },
        {
          sourceField: 'phone',
          targetField: 'company.phone',
          transformer: CommonTransformers.formatPhone,
          validation: { required: false, type: 'phone' },
          description: 'Company phone',
        },
        {
          sourceField: 'industry',
          targetField: 'company.industry',
          transformer: this.hubspotTransformers.formatHubSpotIndustry,
          validation: { required: false, type: 'string' },
          description: 'Company industry',
        },
        {
          sourceField: 'address.street',
          targetField: 'company.address',
          validation: { required: false, type: 'string', maxLength: 255 },
          description: 'Company address',
        },
        {
          sourceField: 'address.city',
          targetField: 'company.city',
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'Company city',
        },
        {
          sourceField: 'address.state',
          targetField: 'company.state',
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'Company state',
        },
        {
          sourceField: 'address.zipCode',
          targetField: 'company.zip',
          validation: { required: false, type: 'string', maxLength: 20 },
          description: 'Company ZIP code',
        },
        // Contact fields
        {
          sourceField: 'email',
          targetField: 'contact.email',
          transformer: CommonTransformers.formatEmail,
          required: true,
          validation: { required: true, type: 'email' },
          description: 'Contact email',
        },
        {
          sourceField: 'businessName',
          targetField: 'contact.firstname',
          transformer: (value: any) =>
            this.hubspotTransformers.splitBusinessNameToContact(value).firstName,
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'Contact first name',
        },
        {
          sourceField: 'businessName',
          targetField: 'contact.lastname',
          transformer: (value: any) =>
            this.hubspotTransformers.splitBusinessNameToContact(value).lastName,
          validation: { required: false, type: 'string', maxLength: 100 },
          description: 'Contact last name',
        },
        {
          sourceField: 'phone',
          targetField: 'contact.phone',
          transformer: CommonTransformers.formatPhone,
          validation: { required: false, type: 'phone' },
          description: 'Contact phone',
        },
        {
          sourceField: 'confidence',
          targetField: 'contact.lifecyclestage',
          transformer: this.hubspotTransformers.formatLifecycleStage,
          defaultValue: 'lead',
          validation: { required: false, type: 'string' },
          description: 'Contact lifecycle stage',
        },
      ],
      customHeaders: {},
      metadata: {
        version: '1.0.0',
        author: 'Business Scraper',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['hubspot', 'company', 'contact', 'json'],
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100,
      },
    },
  ]

  /**
   * Transform business records for HubSpot
   */
  async transformRecords(
    records: BusinessRecord[],
    template: CRMTemplate,
    options?: CRMExportOptions
  ): Promise<BatchTransformationResult> {
    logger.info(
      'HubSpotAdapter',
      `Transforming ${records.length} records using template: ${template.name}`
    )

    const mergedOptions: CRMExportOptions = {
      ...options,
      template,
      customTransformers: {
        ...this.hubspotTransformers,
        ...options?.customTransformers,
      },
    }

    return await this.transformationEngine.transformBatch(records, template, mergedOptions)
  }

  /**
   * Validate a single record against HubSpot requirements
   */
  validateRecord(record: BusinessRecord, template: CRMTemplate): ValidationError[] {
    const errors: ValidationError[] = []

    // HubSpot-specific validations
    if (!record.email || !CommonTransformers.formatEmail(record.email)) {
      errors.push({
        field: 'Email',
        message: 'Valid email address is required for HubSpot contacts',
        value: record.email,
        rule: 'hubspot-email-required',
      })
    }

    return errors
  }

  /**
   * Get default HubSpot template
   */
  getDefaultTemplate(): CRMTemplate {
    return this.templates[0] // Return basic contact template as default
  }

  /**
   * Create custom HubSpot template
   */
  createCustomTemplate(
    name: string,
    fieldMappings: CRMFieldMapping[],
    options?: Partial<CRMTemplate>
  ): CRMTemplate {
    return {
      id: `hubspot-custom-${Date.now()}`,
      name,
      platform: 'hubspot',
      description: options?.description || 'Custom HubSpot template',
      exportFormat: options?.exportFormat || 'csv',
      fieldMappings,
      customHeaders: options?.customHeaders || {},
      metadata: {
        version: '1.0.0',
        author: 'User',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['hubspot', 'custom'],
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100,
        ...options?.validation,
      },
    }
  }
}
