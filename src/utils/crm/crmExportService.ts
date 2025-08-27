/**
 * CRM Export Service
 * Enhanced export service with CRM-specific functionality
 */

import { BusinessRecord } from '@/types/business'
import {
  CRMTemplate,
  CRMExportOptions,
  CRMExportResult,
  CRMExportProgress,
  BatchTransformationResult,
  CRMPlatform,
} from './types'
import { crmTemplateManager } from './crmTemplateManager'
import { logger } from '@/utils/logger'

/**
 * Enhanced CRM Export Service
 */
export class CRMExportService {
  /**
   * Export business records using CRM template
   */
  async exportWithCRMTemplate(
    records: BusinessRecord[],
    template: CRMTemplate,
    options: CRMExportOptions = { template },
    onProgress?: (progress: CRMExportProgress) => void
  ): Promise<CRMExportResult> {
    const startTime = Date.now()

    logger.info('CRMExportService', `Starting CRM export with template: ${template.name}`, {
      recordCount: records.length,
      platform: template.platform,
      format: template.exportFormat,
    })

    // Get appropriate adapter
    const adapter = crmTemplateManager.getAdapter(template.platform)
    if (!adapter) {
      throw new Error(`No adapter found for platform: ${template.platform}`)
    }

    try {
      // Step 1: Validation
      if (onProgress) {
        onProgress({
          step: 'validating',
          processed: 0,
          total: records.length,
          percentage: 0,
          currentOperation: 'Validating records...',
          estimatedTimeRemaining: 0,
          errors: [],
          warnings: [],
        })
      }

      // Step 2: Transformation
      if (onProgress) {
        onProgress({
          step: 'transforming',
          processed: 0,
          total: records.length,
          percentage: 10,
          currentOperation: 'Transforming records...',
          estimatedTimeRemaining: 0,
          errors: [],
          warnings: [],
        })
      }

      const transformationResult = await adapter.transformRecords(records, template, options)

      // Step 3: Export
      if (onProgress) {
        onProgress({
          step: 'exporting',
          processed: transformationResult.validRecords.length,
          total: records.length,
          percentage: 80,
          currentOperation: 'Generating export file...',
          estimatedTimeRemaining: 0,
          errors: transformationResult.invalidRecords.flatMap(r => r.errors),
          warnings: transformationResult.invalidRecords.flatMap(r => r.warnings),
        })
      }

      const exportBlob = await this.generateExportFile(transformationResult, template, options)
      const filename = this.generateFilename(template, options)

      const processingTime = Date.now() - startTime

      // Step 4: Complete
      if (onProgress) {
        onProgress({
          step: 'complete',
          processed: transformationResult.validRecords.length,
          total: records.length,
          percentage: 100,
          currentOperation: 'Export complete',
          estimatedTimeRemaining: 0,
          errors: transformationResult.invalidRecords.flatMap(r => r.errors),
          warnings: transformationResult.invalidRecords.flatMap(r => r.warnings),
        })
      }

      const result: CRMExportResult = {
        blob: exportBlob,
        filename,
        statistics: {
          totalRecords: records.length,
          exportedRecords: transformationResult.validRecords.length,
          skippedRecords: transformationResult.invalidRecords.length,
          errors: transformationResult.invalidRecords.flatMap(r => r.errors),
          warnings: transformationResult.invalidRecords.flatMap(r => r.warnings),
          processingTime,
        },
        template,
        metadata: {
          exportDate: new Date().toISOString(),
          platform: template.platform,
          format: template.exportFormat,
          version: '1.0.0',
        },
      }

      logger.info('CRMExportService', 'CRM export completed successfully', {
        totalRecords: result.statistics.totalRecords,
        exportedRecords: result.statistics.exportedRecords,
        skippedRecords: result.statistics.skippedRecords,
        processingTime: result.statistics.processingTime,
      })

      return result
    } catch (error) {
      logger.error('CRMExportService', 'CRM export failed', error)
      throw new Error(
        `CRM export failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      )
    }
  }

  /**
   * Generate export file based on format
   */
  private async generateExportFile(
    transformationResult: BatchTransformationResult,
    template: CRMTemplate,
    options: CRMExportOptions
  ): Promise<Blob> {
    const { validRecords } = transformationResult

    switch (template.exportFormat) {
      case 'csv':
        return this.generateCSVBlob(validRecords, template, options)

      case 'json':
        return this.generateJSONBlob(validRecords, template, options)

      case 'xml':
        return this.generateXMLBlob(validRecords, template, options)

      default:
        throw new Error(`Unsupported export format: ${template.exportFormat}`)
    }
  }

  /**
   * Generate CSV blob
   */
  private generateCSVBlob(
    records: Record<string, any>[],
    template: CRMTemplate,
    options: CRMExportOptions
  ): Blob {
    if (records.length === 0) {
      return new Blob([''], { type: 'text/csv' })
    }

    const headers = Object.keys(records[0])
    const customHeaders = template.customHeaders || {}

    // Use custom headers if available
    const csvHeaders = headers.map(header => customHeaders[header] || header)

    let csvContent = ''

    // Add headers
    if (options.includeHeaders !== false) {
      csvContent += csvHeaders.map(header => this.escapeCsvValue(header)).join(',') + '\n'
    }

    // Add data rows
    for (const record of records) {
      const row = headers.map(header => {
        const value = record[header]
        return this.escapeCsvValue(value)
      })
      csvContent += row.join(',') + '\n'
    }

    return new Blob([csvContent], { type: 'text/csv' })
  }

  /**
   * Generate JSON blob
   */
  private generateJSONBlob(
    records: Record<string, any>[],
    template: CRMTemplate,
    options: CRMExportOptions
  ): Blob {
    const exportData = {
      metadata: {
        exportDate: new Date().toISOString(),
        platform: template.platform,
        template: template.name,
        totalRecords: records.length,
        version: '1.0.0',
      },
      records,
    }

    const jsonContent = JSON.stringify(exportData, null, 2)
    return new Blob([jsonContent], { type: 'application/json' })
  }

  /**
   * Generate XML blob
   */
  private generateXMLBlob(
    records: Record<string, any>[],
    template: CRMTemplate,
    options: CRMExportOptions
  ): Blob {
    let xmlContent = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xmlContent += `<export platform="${template.platform}" template="${template.name}" date="${new Date().toISOString()}">\n`

    for (const record of records) {
      xmlContent += '  <record>\n'
      for (const [key, value] of Object.entries(record)) {
        const escapedKey = this.escapeXmlValue(key)
        const escapedValue = this.escapeXmlValue(String(value || ''))
        xmlContent += `    <${escapedKey}>${escapedValue}</${escapedKey}>\n`
      }
      xmlContent += '  </record>\n'
    }

    xmlContent += '</export>'
    return new Blob([xmlContent], { type: 'application/xml' })
  }

  /**
   * Generate filename for export
   */
  private generateFilename(template: CRMTemplate, options: CRMExportOptions): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    const platform = template.platform
    const templateName = template.name.toLowerCase().replace(/[^a-z0-9]/g, '-')
    const extension = template.exportFormat

    return `${platform}-${templateName}-${timestamp}.${extension}`
  }

  /**
   * Escape CSV value
   */
  private escapeCsvValue(value: any): string {
    if (value === null || value === undefined) {
      return ''
    }

    const stringValue = String(value)

    // If value contains comma, newline, or quote, wrap in quotes and escape quotes
    if (stringValue.includes(',') || stringValue.includes('\n') || stringValue.includes('"')) {
      return `"${stringValue.replace(/"/g, '""')}"`
    }

    return stringValue
  }

  /**
   * Escape XML value
   */
  private escapeXmlValue(value: string): string {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
  }

  /**
   * Get export preview
   */
  async getExportPreview(
    records: BusinessRecord[],
    template: CRMTemplate,
    options: CRMExportOptions = { template },
    maxRecords: number = 5
  ): Promise<{
    preview: Record<string, any>[]
    errors: any[]
    warnings: string[]
    totalRecords: number
  }> {
    const adapter = crmTemplateManager.getAdapter(template.platform)
    if (!adapter) {
      throw new Error(`No adapter found for platform: ${template.platform}`)
    }

    const previewRecords = records.slice(0, maxRecords)
    const transformationResult = await adapter.transformRecords(previewRecords, template, options)

    return {
      preview: transformationResult.validRecords,
      errors: transformationResult.invalidRecords.flatMap(r => r.errors),
      warnings: transformationResult.invalidRecords.flatMap(r => r.warnings),
      totalRecords: records.length,
    }
  }

  /**
   * Validate records against template
   */
  async validateRecords(
    records: BusinessRecord[],
    template: CRMTemplate
  ): Promise<{
    validCount: number
    invalidCount: number
    errors: any[]
    warnings: string[]
  }> {
    const adapter = crmTemplateManager.getAdapter(template.platform)
    if (!adapter) {
      throw new Error(`No adapter found for platform: ${template.platform}`)
    }

    const transformationResult = await adapter.transformRecords(records, template, { template })

    return {
      validCount: transformationResult.validRecords.length,
      invalidCount: transformationResult.invalidRecords.length,
      errors: transformationResult.invalidRecords.flatMap(r => r.errors),
      warnings: transformationResult.invalidRecords.flatMap(r => r.warnings),
    }
  }

  /**
   * Get available CRM platforms
   */
  getAvailablePlatforms(): Array<{
    platform: CRMPlatform
    displayName: string
    templateCount: number
  }> {
    return crmTemplateManager.getAvailablePlatforms()
  }

  /**
   * Get templates for platform
   */
  getTemplatesForPlatform(platform: CRMPlatform) {
    return crmTemplateManager.getTemplatesByPlatform(platform)
  }

  /**
   * Get template by ID
   */
  getTemplate(id: string) {
    return crmTemplateManager.getTemplate(id)
  }
}

// Export singleton instance
export const crmExportService = new CRMExportService()
