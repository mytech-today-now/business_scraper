/**
 * CRM Template Manager
 * Central management for CRM export templates and adapters
 */

import {
  CRMTemplateManager,
  CRMTemplate,
  CRMAdapter,
  CRMPlatform,
  ValidationError,
  CRMFieldMapping,
} from './types'
import { SalesforceAdapter } from './adapters/salesforceAdapter'
import { HubSpotAdapter } from './adapters/hubspotAdapter'
import { PipedriveAdapter } from './adapters/pipedriveAdapter'
import { logger } from '@/utils/logger'

/**
 * Central CRM Template Manager
 */
export class CRMTemplateManagerImpl implements CRMTemplateManager {
  private adapters: Map<CRMPlatform, CRMAdapter> = new Map()
  private customTemplates: CRMTemplate[] = []
  private readonly STORAGE_KEY = 'crm-custom-templates'

  constructor() {
    this.initializeAdapters()
    this.loadCustomTemplates()
  }

  /**
   * Initialize CRM adapters
   */
  private initializeAdapters(): void {
    const salesforceAdapter = new SalesforceAdapter()
    const hubspotAdapter = new HubSpotAdapter()
    const pipedriveAdapter = new PipedriveAdapter()

    this.adapters.set('salesforce', salesforceAdapter)
    this.adapters.set('hubspot', hubspotAdapter)
    this.adapters.set('pipedrive', pipedriveAdapter)

    logger.info('CRMTemplateManager', 'Initialized CRM adapters', {
      platforms: Array.from(this.adapters.keys()),
    })
  }

  /**
   * Load custom templates from localStorage
   */
  private loadCustomTemplates(): void {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY)
      if (stored) {
        this.customTemplates = JSON.parse(stored)
        logger.info('CRMTemplateManager', `Loaded ${this.customTemplates.length} custom templates`)
      }
    } catch (error) {
      logger.error('CRMTemplateManager', 'Failed to load custom templates', error)
      this.customTemplates = []
    }
  }

  /**
   * Save custom templates to localStorage
   */
  private saveCustomTemplates(): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.customTemplates))
      logger.info('CRMTemplateManager', `Saved ${this.customTemplates.length} custom templates`)
    } catch (error) {
      logger.error('CRMTemplateManager', 'Failed to save custom templates', error)
      throw new Error('Failed to save custom templates')
    }
  }

  /**
   * Get all available templates (built-in + custom)
   */
  getAllTemplates(): CRMTemplate[] {
    const builtInTemplates: CRMTemplate[] = []

    for (const adapter of this.adapters.values()) {
      builtInTemplates.push(...adapter.templates)
    }

    return [...builtInTemplates, ...this.customTemplates]
  }

  /**
   * Get templates for specific platform
   */
  getTemplatesByPlatform(platform: CRMPlatform): CRMTemplate[] {
    const adapter = this.adapters.get(platform)
    const builtInTemplates = adapter ? adapter.templates : []
    const customTemplatesForPlatform = this.customTemplates.filter(t => t.platform === platform)

    return [...builtInTemplates, ...customTemplatesForPlatform]
  }

  /**
   * Get template by ID
   */
  getTemplate(id: string): CRMTemplate | null {
    // Check built-in templates first
    for (const adapter of this.adapters.values()) {
      const template = adapter.templates.find(t => t.id === id)
      if (template) return template
    }

    // Check custom templates
    const customTemplate = this.customTemplates.find(t => t.id === id)
    return customTemplate || null
  }

  /**
   * Get CRM adapter for platform
   */
  getAdapter(platform: CRMPlatform): CRMAdapter | null {
    return this.adapters.get(platform) || null
  }

  /**
   * Get all available platforms
   */
  getAvailablePlatforms(): Array<{
    platform: CRMPlatform
    displayName: string
    templateCount: number
  }> {
    return Array.from(this.adapters.entries()).map(([platform, adapter]) => ({
      platform,
      displayName: adapter.displayName,
      templateCount: this.getTemplatesByPlatform(platform).length,
    }))
  }

  /**
   * Save custom template
   */
  async saveTemplate(template: CRMTemplate): Promise<void> {
    // Validate template
    const errors = this.validateTemplate(template)
    if (errors.length > 0) {
      throw new Error(`Template validation failed: ${errors.map(e => e.message).join(', ')}`)
    }

    // Check if template already exists
    const existingIndex = this.customTemplates.findIndex(t => t.id === template.id)

    if (existingIndex >= 0) {
      // Update existing template
      this.customTemplates[existingIndex] = {
        ...template,
        metadata: {
          ...template.metadata,
          updatedAt: new Date().toISOString(),
        },
      }
      logger.info('CRMTemplateManager', `Updated custom template: ${template.name}`)
    } else {
      // Add new template
      this.customTemplates.push({
        ...template,
        metadata: {
          ...template.metadata,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      })
      logger.info('CRMTemplateManager', `Added new custom template: ${template.name}`)
    }

    this.saveCustomTemplates()
  }

  /**
   * Delete custom template
   */
  async deleteTemplate(id: string): Promise<void> {
    const index = this.customTemplates.findIndex(t => t.id === id)

    if (index === -1) {
      throw new Error(`Template with ID ${id} not found`)
    }

    const template = this.customTemplates[index]
    this.customTemplates.splice(index, 1)
    this.saveCustomTemplates()

    logger.info('CRMTemplateManager', `Deleted custom template: ${template.name}`)
  }

  /**
   * Clone existing template
   */
  cloneTemplate(id: string, newName: string): CRMTemplate {
    const originalTemplate = this.getTemplate(id)

    if (!originalTemplate) {
      throw new Error(`Template with ID ${id} not found`)
    }

    const clonedTemplate: CRMTemplate = {
      ...originalTemplate,
      id: `${originalTemplate.platform}-custom-${Date.now()}`,
      name: newName,
      metadata: {
        ...originalTemplate.metadata,
        author: 'User',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: [...originalTemplate.metadata.tags, 'cloned'],
      },
    }

    logger.info('CRMTemplateManager', `Cloned template ${originalTemplate.name} as ${newName}`)
    return clonedTemplate
  }

  /**
   * Validate template configuration
   */
  validateTemplate(template: CRMTemplate): ValidationError[] {
    const errors: ValidationError[] = []

    // Basic validation
    if (!template.id) {
      errors.push({
        field: 'id',
        message: 'Template ID is required',
        value: template.id,
        rule: 'required',
      })
    }

    if (!template.name) {
      errors.push({
        field: 'name',
        message: 'Template name is required',
        value: template.name,
        rule: 'required',
      })
    }

    if (!template.platform) {
      errors.push({
        field: 'platform',
        message: 'Template platform is required',
        value: template.platform,
        rule: 'required',
      })
    }

    if (!this.adapters.has(template.platform)) {
      errors.push({
        field: 'platform',
        message: `Unsupported platform: ${template.platform}`,
        value: template.platform,
        rule: 'invalid',
      })
    }

    if (!template.fieldMappings || template.fieldMappings.length === 0) {
      errors.push({
        field: 'fieldMappings',
        message: 'At least one field mapping is required',
        value: template.fieldMappings,
        rule: 'required',
      })
    }

    // Validate field mappings
    if (template.fieldMappings) {
      template.fieldMappings.forEach((mapping, index) => {
        if (!mapping.sourceField) {
          errors.push({
            field: `fieldMappings[${index}].sourceField`,
            message: 'Source field is required',
            value: mapping.sourceField,
            rule: 'required',
          })
        }

        if (!mapping.targetField) {
          errors.push({
            field: `fieldMappings[${index}].targetField`,
            message: 'Target field is required',
            value: mapping.targetField,
            rule: 'required',
          })
        }
      })

      // Check for duplicate target fields
      const targetFields = template.fieldMappings.map(m => m.targetField)
      const duplicates = targetFields.filter(
        (field, index) => targetFields.indexOf(field) !== index
      )

      if (duplicates.length > 0) {
        errors.push({
          field: 'fieldMappings',
          message: `Duplicate target fields: ${duplicates.join(', ')}`,
          value: duplicates,
          rule: 'unique',
        })
      }
    }

    return errors
  }

  /**
   * Create template from field mappings
   */
  createTemplateFromMappings(
    platform: CRMPlatform,
    name: string,
    fieldMappings: CRMFieldMapping[],
    options?: {
      description?: string
      exportFormat?: 'csv' | 'json' | 'xml'
      customHeaders?: Record<string, string>
    }
  ): CRMTemplate {
    const adapter = this.getAdapter(platform)

    if (!adapter) {
      throw new Error(`No adapter found for platform: ${platform}`)
    }

    return adapter.createCustomTemplate(name, fieldMappings, options)
  }

  /**
   * Get template suggestions based on business record fields
   */
  getTemplateSuggestions(availableFields: string[]): Array<{
    platform: CRMPlatform
    template: CRMTemplate
    matchScore: number
    missingFields: string[]
  }> {
    const suggestions: Array<{
      platform: CRMPlatform
      template: CRMTemplate
      matchScore: number
      missingFields: string[]
    }> = []

    for (const template of this.getAllTemplates()) {
      const requiredFields = template.fieldMappings.filter(m => m.required).map(m => m.sourceField)

      const availableRequiredFields = requiredFields.filter(field =>
        availableFields.includes(field)
      )

      const matchScore =
        requiredFields.length > 0 ? availableRequiredFields.length / requiredFields.length : 1

      const missingFields = requiredFields.filter(field => !availableFields.includes(field))

      suggestions.push({
        platform: template.platform,
        template,
        matchScore,
        missingFields,
      })
    }

    // Sort by match score (highest first)
    return suggestions.sort((a, b) => b.matchScore - a.matchScore)
  }

  /**
   * Export template configuration
   */
  exportTemplateConfig(templateId: string): string {
    const template = this.getTemplate(templateId)

    if (!template) {
      throw new Error(`Template with ID ${templateId} not found`)
    }

    return JSON.stringify(template, null, 2)
  }

  /**
   * Import template configuration
   */
  async importTemplateConfig(configJson: string): Promise<CRMTemplate> {
    try {
      const template: CRMTemplate = JSON.parse(configJson)

      // Validate imported template
      const errors = this.validateTemplate(template)
      if (errors.length > 0) {
        throw new Error(`Invalid template configuration: ${errors.map(e => e.message).join(', ')}`)
      }

      // Generate new ID to avoid conflicts
      template.id = `${template.platform}-imported-${Date.now()}`
      template.metadata.createdAt = new Date().toISOString()
      template.metadata.updatedAt = new Date().toISOString()

      await this.saveTemplate(template)
      return template
    } catch (error) {
      logger.error('CRMTemplateManager', 'Failed to import template', error)
      throw new Error(
        `Failed to import template: ${error instanceof Error ? error.message : 'Unknown error'}`
      )
    }
  }
}

// Export singleton instance
export const crmTemplateManager = new CRMTemplateManagerImpl()
