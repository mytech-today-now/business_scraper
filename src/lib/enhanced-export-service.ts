/**
 * Enhanced Export Service
 * Advanced export service with template support and CRM/email marketing integrations
 */

import { BusinessRecord } from '@/types/business'
import {
  ExportTemplate,
  ExportTemplateResult,
  ExportPlatform,
  ExportTemplateRegistry,
} from '@/types/export-templates'
import { logger } from '@/utils/logger'

// Import template classes
import { createSalesforceTemplate } from './export-templates/crm/salesforce'
import { createHubSpotTemplate } from './export-templates/crm/hubspot'
import { createPipedriveTemplate } from './export-templates/crm/pipedrive'
import { createMailchimpTemplate } from './export-templates/email-marketing/mailchimp'
import { createConstantContactTemplate } from './export-templates/email-marketing/constant-contact'
import { BaseExportTemplate } from './export-templates/base-template'

/**
 * Enhanced export service with template support
 */
export class EnhancedExportService implements ExportTemplateRegistry {
  private templates: Map<string, BaseExportTemplate> = new Map()

  constructor() {
    this.initializeBuiltInTemplates()
  }

  /**
   * Initialize built-in export templates
   */
  private initializeBuiltInTemplates(): void {
    try {
      // CRM templates
      this.registerTemplateInstance('salesforce-leads', createSalesforceTemplate())
      this.registerTemplateInstance('hubspot-companies', createHubSpotTemplate())
      this.registerTemplateInstance('pipedrive-organizations', createPipedriveTemplate())

      // Email marketing templates
      this.registerTemplateInstance('mailchimp-contacts', createMailchimpTemplate())
      this.registerTemplateInstance('constant-contact-contacts', createConstantContactTemplate())

      logger.info('EnhancedExportService', `Initialized ${this.templates.size} built-in templates`)
    } catch (error) {
      logger.error('EnhancedExportService', 'Failed to initialize built-in templates', error)
    }
  }

  /**
   * Register a template instance
   */
  private registerTemplateInstance(id: string, templateInstance: BaseExportTemplate): void {
    this.templates.set(id, templateInstance)
    logger.debug('EnhancedExportService', `Registered template: ${id}`)
  }

  /**
   * Get template by ID
   */
  getTemplate(id: string): ExportTemplate | null {
    const templateInstance = this.templates.get(id)
    return templateInstance ? templateInstance.getTemplate() : null
  }

  /**
   * Register a new template
   */
  registerTemplate(template: ExportTemplate): void {
    // For now, we only support built-in templates
    // Custom template registration would require creating template instances
    logger.warn('EnhancedExportService', 'Custom template registration not yet implemented')
  }

  /**
   * Validate a template
   */
  validateTemplate(template: ExportTemplate): any {
    const templateInstance = this.templates.get(template.id)
    if (!templateInstance) {
      return {
        isValid: false,
        errors: ['Template not found'],
        warnings: [],
        suggestions: [],
        compatibility: {
          platform: template.platform,
          version: template.version,
          supported: false,
          limitations: ['Template not registered'],
        },
      }
    }

    return templateInstance.validate()
  }

  /**
   * List available templates
   */
  listTemplates(platform?: ExportPlatform): ExportTemplate[] {
    const allTemplates = Array.from(this.templates.values()).map(instance => instance.getTemplate())

    if (platform) {
      return allTemplates.filter(template => template.platform === platform)
    }

    return allTemplates
  }

  /**
   * Search templates by query
   */
  searchTemplates(query: string): ExportTemplate[] {
    const searchTerm = query.toLowerCase()

    return this.listTemplates().filter(
      template =>
        template.name.toLowerCase().includes(searchTerm) ||
        template.description.toLowerCase().includes(searchTerm) ||
        template.platform.toLowerCase().includes(searchTerm) ||
        template.metadata.tags.some(tag => tag.toLowerCase().includes(searchTerm))
    )
  }

  /**
   * Export businesses using a specific template
   */
  async exportWithTemplate(
    templateId: string,
    businesses: BusinessRecord[],
    options: {
      validateData?: boolean
      skipErrors?: boolean
      includeMetadata?: boolean
    } = {}
  ): Promise<ExportTemplateResult> {
    const templateInstance = this.templates.get(templateId)

    if (!templateInstance) {
      throw new Error(`Template not found: ${templateId}`)
    }

    logger.info('EnhancedExportService', `Starting export with template: ${templateId}`, {
      templateId,
      businessCount: businesses.length,
      options,
    })

    try {
      const result = await templateInstance.execute(businesses)

      logger.info('EnhancedExportService', `Export completed: ${templateId}`, {
        templateId,
        success: result.success,
        recordsProcessed: result.recordsProcessed,
        recordsExported: result.recordsExported,
        recordsSkipped: result.recordsSkipped,
        errorCount: result.errors.length,
        warningCount: result.warnings.length,
      })

      return result
    } catch (error) {
      logger.error('EnhancedExportService', `Export failed: ${templateId}`, error)
      throw error
    }
  }

  /**
   * Export to multiple platforms simultaneously
   */
  async exportToMultiplePlatforms(
    templateIds: string[],
    businesses: BusinessRecord[],
    options: {
      continueOnError?: boolean
      includeMetadata?: boolean
    } = {}
  ): Promise<{
    results: Array<{
      templateId: string
      result: ExportTemplateResult | null
      error?: string
    }>
    summary: {
      totalTemplates: number
      successfulExports: number
      failedExports: number
      totalRecordsProcessed: number
      totalRecordsExported: number
    }
  }> {
    const results: Array<{
      templateId: string
      result: ExportTemplateResult | null
      error?: string
    }> = []

    let successfulExports = 0
    let failedExports = 0
    let totalRecordsExported = 0

    logger.info('EnhancedExportService', `Starting multi-platform export`, {
      templateIds,
      businessCount: businesses.length,
      options,
    })

    for (const templateId of templateIds) {
      try {
        const result = await this.exportWithTemplate(templateId, businesses, options)

        results.push({
          templateId,
          result,
        })

        if (result.success) {
          successfulExports++
          totalRecordsExported += result.recordsExported
        } else {
          failedExports++
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error'

        results.push({
          templateId,
          result: null,
          error: errorMessage,
        })

        failedExports++

        if (!options.continueOnError) {
          logger.error(
            'EnhancedExportService',
            `Multi-platform export stopped due to error in ${templateId}`,
            error
          )
          break
        }
      }
    }

    const summary = {
      totalTemplates: templateIds.length,
      successfulExports,
      failedExports,
      totalRecordsProcessed: businesses.length,
      totalRecordsExported,
    }

    logger.info('EnhancedExportService', `Multi-platform export completed`, summary)

    return { results, summary }
  }

  /**
   * Get export statistics
   */
  getExportStatistics(): {
    availableTemplates: number
    templatesByPlatform: Record<ExportPlatform, number>
    templatesByCategory: Record<string, number>
  } {
    const templates = this.listTemplates()

    const templatesByPlatform: Record<string, number> = {}
    const templatesByCategory: Record<string, number> = {}

    for (const template of templates) {
      // Count by platform
      templatesByPlatform[template.platform] = (templatesByPlatform[template.platform] || 0) + 1

      // Count by category
      const category = template.metadata.category
      templatesByCategory[category] = (templatesByCategory[category] || 0) + 1
    }

    return {
      availableTemplates: templates.length,
      templatesByPlatform: templatesByPlatform as Record<ExportPlatform, number>,
      templatesByCategory,
    }
  }

  /**
   * Generate export preview
   */
  async generateExportPreview(
    templateId: string,
    businesses: BusinessRecord[],
    sampleSize: number = 5
  ): Promise<{
    templateInfo: ExportTemplate
    sampleData: any[]
    fieldMappings: Array<{
      sourceField: string
      targetField: string
      sampleValue: any
      transformationType: string
    }>
    validation: any
  }> {
    const templateInstance = this.templates.get(templateId)

    if (!templateInstance) {
      throw new Error(`Template not found: ${templateId}`)
    }

    const template = templateInstance.getTemplate()
    const sampleBusinesses = businesses.slice(0, sampleSize)

    // Generate sample export
    const result = await templateInstance.execute(sampleBusinesses)

    // Generate field mapping preview
    const fieldMappings = template.fieldMappings.map(mapping => ({
      sourceField: mapping.sourceFields.join(', '),
      targetField: mapping.targetField,
      sampleValue: result.exportData[0]?.[mapping.targetField] || null,
      transformationType: mapping.type,
    }))

    return {
      templateInfo: template,
      sampleData: result.exportData,
      fieldMappings,
      validation: templateInstance.validate(),
    }
  }

  /**
   * Convert export result to downloadable format
   */
  async convertToDownloadableFormat(
    result: ExportTemplateResult,
    format: 'csv' | 'json' | 'xlsx' = 'csv'
  ): Promise<{
    blob: Blob
    filename: string
    mimeType: string
  }> {
    const template = this.getTemplate(result.templateId)
    if (!template) {
      throw new Error(`Template not found: ${result.templateId}`)
    }

    const timestamp = new Date().toISOString().split('T')[0]
    const baseFilename = `${template.platform}-export-${timestamp}`

    switch (format) {
      case 'csv':
        return this.convertToCSV(result, baseFilename)
      case 'json':
        return this.convertToJSON(result, baseFilename)
      case 'xlsx':
        // For now, return CSV with xlsx extension (as per existing security practice)
        const csvResult = await this.convertToCSV(result, baseFilename)
        return {
          ...csvResult,
          filename: csvResult.filename.replace('.csv', '.xlsx'),
        }
      default:
        throw new Error(`Unsupported format: ${format}`)
    }
  }

  /**
   * Convert to CSV format
   */
  private async convertToCSV(
    result: ExportTemplateResult,
    baseFilename: string
  ): Promise<{
    blob: Blob
    filename: string
    mimeType: string
  }> {
    const template = this.getTemplate(result.templateId)
    if (!template || !result.exportData.length) {
      throw new Error('No data to export')
    }

    const headers = Object.keys(template.platformConfig.headers)
    const csvHeaders = headers.map(header => template.platformConfig.headers[header])

    let csvContent = csvHeaders.join(',') + '\n'

    for (const record of result.exportData) {
      const row = headers.map(header => {
        const value = record[header] || ''
        // Escape CSV values
        if (
          typeof value === 'string' &&
          (value.includes(',') || value.includes('"') || value.includes('\n'))
        ) {
          return `"${value.replace(/"/g, '""')}"`
        }
        return value
      })
      csvContent += row.join(',') + '\n'
    }

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8' })

    return {
      blob,
      filename: `${baseFilename}.csv`,
      mimeType: 'text/csv',
    }
  }

  /**
   * Convert to JSON format
   */
  private async convertToJSON(
    result: ExportTemplateResult,
    baseFilename: string
  ): Promise<{
    blob: Blob
    filename: string
    mimeType: string
  }> {
    const exportData = {
      metadata: result.metadata,
      statistics: {
        recordsProcessed: result.recordsProcessed,
        recordsExported: result.recordsExported,
        recordsSkipped: result.recordsSkipped,
      },
      data: result.exportData,
      errors: result.errors,
      warnings: result.warnings,
    }

    const jsonContent = JSON.stringify(exportData, null, 2)
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8' })

    return {
      blob,
      filename: `${baseFilename}.json`,
      mimeType: 'application/json',
    }
  }
}

// Export singleton instance
export const enhancedExportService = new EnhancedExportService()
