/**
 * Salesforce CRM Adapter
 * Handles Salesforce-specific export templates and transformations
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
 * Salesforce CRM Adapter
 */
export class SalesforceAdapter implements CRMAdapter {
  platform = 'salesforce' as const
  displayName = 'Salesforce'
  private transformationEngine = new CRMTransformationEngine()

  /**
   * Salesforce-specific field transformers
   */
  private salesforceTransformers = {
    /** Format Salesforce Owner ID */
    formatOwnerId: (value: any): string => {
      // Default to a placeholder - in real implementation, this would map to actual user IDs
      return value || '005000000000000AAA' // Default Salesforce user ID format
    },

    /** Format Salesforce Record Type ID */
    formatRecordTypeId: (value: any): string => {
      // Default to standard record type - in real implementation, this would map to actual record types
      return value || '012000000000000AAA' // Default Salesforce record type ID format
    },

    /** Format Salesforce picklist values */
    formatPicklist: (allowedValues: string[]) => (value: any): string => {
      const stringValue = String(value || '').trim()
      return allowedValues.includes(stringValue) ? stringValue : allowedValues[0] || ''
    },

    /** Format Salesforce currency */
    formatSalesforceCurrency: (value: any): number => {
      const num = CommonTransformers.formatCurrency(value)
      return Math.round(num * 100) / 100 // Round to 2 decimal places
    },

    /** Format company name for Account */
    formatAccountName: (value: any, record: BusinessRecord): string => {
      return value || record.businessName || 'Unknown Company'
    },

    /** Format lead source */
    formatLeadSource: (value: any): string => {
      const leadSources = ['Web', 'Phone Inquiry', 'Partner Referral', 'Purchased List', 'Other']
      return leadSources.includes(value) ? value : 'Web'
    },

    /** Format industry for Salesforce */
    formatSalesforceIndustry: (value: any): string => {
      const industryMap: Record<string, string> = {
        'restaurants': 'Food & Beverage',
        'retail': 'Retail',
        'healthcare': 'Healthcare',
        'technology': 'Technology',
        'finance': 'Financial Services',
        'real estate': 'Real Estate',
        'education': 'Education',
        'manufacturing': 'Manufacturing',
        'construction': 'Construction',
        'automotive': 'Automotive',
        'hospitality': 'Hospitality',
        'legal': 'Legal',
        'consulting': 'Consulting',
        'nonprofit': 'Nonprofit'
      }
      
      const industry = String(value || '').toLowerCase()
      return industryMap[industry] || 'Other'
    }
  }

  /**
   * Available Salesforce templates
   */
  templates: CRMTemplate[] = [
    {
      id: 'salesforce-lead-basic',
      name: 'Salesforce Lead (Basic)',
      platform: 'salesforce',
      description: 'Basic Salesforce Lead import template with essential fields',
      exportFormat: 'csv',
      fieldMappings: [
        {
          sourceField: 'businessName',
          targetField: 'Company',
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Company name for the lead'
        },
        {
          sourceField: 'email',
          targetField: 'Email',
          transformer: CommonTransformers.formatEmail,
          validation: { required: false, type: 'email' },
          description: 'Primary email address'
        },
        {
          sourceField: 'phone',
          targetField: 'Phone',
          transformer: CommonTransformers.formatPhone,
          validation: { required: false, type: 'phone' },
          description: 'Primary phone number'
        },
        {
          sourceField: 'websiteUrl',
          targetField: 'Website',
          validation: { required: false, type: 'url' },
          description: 'Company website URL'
        },
        {
          sourceField: 'address.street',
          targetField: 'Street',
          validation: { required: false, type: 'string', maxLength: 255 },
          description: 'Street address'
        },
        {
          sourceField: 'address.city',
          targetField: 'City',
          validation: { required: false, type: 'string', maxLength: 40 },
          description: 'City'
        },
        {
          sourceField: 'address.state',
          targetField: 'State',
          validation: { required: false, type: 'string', maxLength: 80 },
          description: 'State or province'
        },
        {
          sourceField: 'address.zipCode',
          targetField: 'PostalCode',
          validation: { required: false, type: 'string', maxLength: 20 },
          description: 'Postal or ZIP code'
        },
        {
          sourceField: 'industry',
          targetField: 'Industry',
          transformer: this.salesforceTransformers.formatSalesforceIndustry,
          validation: { required: false, type: 'string' },
          description: 'Industry classification'
        },
        {
          sourceField: 'businessName',
          targetField: 'LastName',
          transformer: (value: any) => `${value} Contact`,
          required: true,
          validation: { required: true, type: 'string', maxLength: 80 },
          description: 'Contact last name (derived from business name)'
        },
        {
          sourceField: 'source',
          targetField: 'LeadSource',
          transformer: this.salesforceTransformers.formatLeadSource,
          defaultValue: 'Web',
          validation: { required: false, type: 'string' },
          description: 'Source of the lead'
        }
      ],
      customHeaders: {
        'Company': 'Company',
        'Email': 'Email',
        'Phone': 'Phone',
        'Website': 'Website',
        'Street': 'Street',
        'City': 'City',
        'State': 'State/Province',
        'PostalCode': 'Zip/Postal Code',
        'Industry': 'Industry',
        'LastName': 'Last Name',
        'LeadSource': 'Lead Source'
      },
      metadata: {
        version: '1.0.0',
        author: 'Business Scraper',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['salesforce', 'lead', 'basic']
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100
      }
    },
    {
      id: 'salesforce-account-contact',
      name: 'Salesforce Account & Contact',
      platform: 'salesforce',
      description: 'Salesforce Account and Contact import template for B2B data',
      exportFormat: 'csv',
      fieldMappings: [
        // Account fields
        {
          sourceField: 'businessName',
          targetField: 'Account Name',
          transformer: this.salesforceTransformers.formatAccountName,
          required: true,
          validation: { required: true, type: 'string', maxLength: 255 },
          description: 'Account name'
        },
        {
          sourceField: 'websiteUrl',
          targetField: 'Account Website',
          validation: { required: false, type: 'url' },
          description: 'Account website'
        },
        {
          sourceField: 'phone',
          targetField: 'Account Phone',
          transformer: CommonTransformers.formatPhone,
          validation: { required: false, type: 'phone' },
          description: 'Account main phone'
        },
        {
          sourceField: 'industry',
          targetField: 'Account Industry',
          transformer: this.salesforceTransformers.formatSalesforceIndustry,
          validation: { required: false, type: 'string' },
          description: 'Account industry'
        },
        {
          sourceField: 'address.street',
          targetField: 'Account Billing Street',
          validation: { required: false, type: 'string', maxLength: 255 },
          description: 'Account billing street'
        },
        {
          sourceField: 'address.city',
          targetField: 'Account Billing City',
          validation: { required: false, type: 'string', maxLength: 40 },
          description: 'Account billing city'
        },
        {
          sourceField: 'address.state',
          targetField: 'Account Billing State',
          validation: { required: false, type: 'string', maxLength: 80 },
          description: 'Account billing state'
        },
        {
          sourceField: 'address.zipCode',
          targetField: 'Account Billing Postal Code',
          validation: { required: false, type: 'string', maxLength: 20 },
          description: 'Account billing postal code'
        },
        // Contact fields
        {
          sourceField: 'businessName',
          targetField: 'Contact Last Name',
          transformer: (value: any) => `${value} Contact`,
          required: true,
          validation: { required: true, type: 'string', maxLength: 80 },
          description: 'Contact last name'
        },
        {
          sourceField: 'email',
          targetField: 'Contact Email',
          transformer: CommonTransformers.formatEmail,
          validation: { required: false, type: 'email' },
          description: 'Contact email'
        },
        {
          sourceField: 'phone',
          targetField: 'Contact Phone',
          transformer: CommonTransformers.formatPhone,
          validation: { required: false, type: 'phone' },
          description: 'Contact phone'
        }
      ],
      customHeaders: {
        'Account Name': 'Account Name',
        'Account Website': 'Website',
        'Account Phone': 'Phone',
        'Account Industry': 'Industry',
        'Account Billing Street': 'Billing Street',
        'Account Billing City': 'Billing City',
        'Account Billing State': 'Billing State/Province',
        'Account Billing Postal Code': 'Billing Zip/Postal Code',
        'Contact Last Name': 'Contact Last Name',
        'Contact Email': 'Contact Email',
        'Contact Phone': 'Contact Phone'
      },
      metadata: {
        version: '1.0.0',
        author: 'Business Scraper',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['salesforce', 'account', 'contact', 'b2b']
      },
      validation: {
        strictMode: false,
        skipInvalidRecords: true,
        maxErrors: 100
      }
    }
  ]

  /**
   * Transform business records for Salesforce
   */
  async transformRecords(
    records: BusinessRecord[],
    template: CRMTemplate,
    options?: CRMExportOptions
  ): Promise<BatchTransformationResult> {
    logger.info('SalesforceAdapter', `Transforming ${records.length} records using template: ${template.name}`)
    
    const mergedOptions: CRMExportOptions = {
      ...options,
      template,
      customTransformers: {
        ...this.salesforceTransformers,
        ...options?.customTransformers
      }
    }

    return await this.transformationEngine.transformBatch(records, template, mergedOptions)
  }

  /**
   * Validate a single record against Salesforce requirements
   */
  validateRecord(record: BusinessRecord, template: CRMTemplate): ValidationError[] {
    const errors: ValidationError[] = []

    // Salesforce-specific validations
    if (template.id.includes('lead') && !record.businessName) {
      errors.push({
        field: 'Company',
        message: 'Company name is required for Salesforce Leads',
        value: record.businessName,
        rule: 'salesforce-lead-required'
      })
    }

    if (template.id.includes('account') && !record.businessName) {
      errors.push({
        field: 'Account Name',
        message: 'Account name is required for Salesforce Accounts',
        value: record.businessName,
        rule: 'salesforce-account-required'
      })
    }

    return errors
  }

  /**
   * Get default Salesforce template
   */
  getDefaultTemplate(): CRMTemplate {
    return this.templates[0] // Return basic lead template as default
  }

  /**
   * Create custom Salesforce template
   */
  createCustomTemplate(
    name: string,
    fieldMappings: CRMFieldMapping[],
    options?: Partial<CRMTemplate>
  ): CRMTemplate {
    return {
      id: `salesforce-custom-${Date.now()}`,
      name,
      platform: 'salesforce',
      description: options?.description || 'Custom Salesforce template',
      exportFormat: options?.exportFormat || 'csv',
      fieldMappings,
      customHeaders: options?.customHeaders || {},
      metadata: {
        version: '1.0.0',
        author: 'User',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['salesforce', 'custom']
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
