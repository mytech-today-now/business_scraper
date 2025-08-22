'use strict'

// XLSX library removed due to security vulnerabilities
// Excel exports now use CSV format for security
import jsPDF from 'jspdf'
import 'jspdf-autotable'
import { BusinessRecord } from '@/types/business'
import { formatBusinessForExport, formatCsvCell } from './formatters'
import { logger } from './logger'
import { prioritizedDataProcessor, PrioritizedBusinessRecord } from '@/lib/prioritizedDataProcessor'
import { prioritizedExportFormatter } from './prioritizedExportFormatter'

/**
 * Export format types
 */
export type ExportFormat = 'csv' | 'xlsx' | 'xls' | 'ods' | 'pdf' | 'json' | 'xml' | 'vcf' | 'sql'

/**
 * Export context interface for generating standardized filenames
 */
export interface ExportContext {
  industries?: string[]
  selectedIndustries?: string[]
  searchLocation?: string
  searchRadius?: number
  totalResults?: number
}

/**
 * Export options interface
 */
export interface ExportOptions {
  filename?: string
  includeHeaders?: boolean
  dateFormat?: string
  delimiter?: string
  encoding?: string
  template?: ExportTemplate
  filters?: ExportFilters
  sorting?: ExportSorting
  grouping?: ExportGrouping
  customFields?: CustomField[]
  compression?: boolean
  password?: string
  context?: ExportContext
  selectedBusinesses?: string[] // IDs of selected businesses for filtered export
}

/**
 * Export template for customizing output
 */
export interface ExportTemplate {
  name: string
  fields: string[]
  customHeaders?: Record<string, string>
  formatting?: Record<string, (value: any) => string>
}

/**
 * Export filters
 */
export interface ExportFilters {
  industries?: string[]
  states?: string[]
  hasEmail?: boolean
  hasPhone?: boolean
  hasWebsite?: boolean
  confidenceMin?: number
  dateRange?: { start: Date; end: Date }
}

/**
 * Export sorting options
 */
export interface ExportSorting {
  field: string
  direction: 'asc' | 'desc'
}

/**
 * Export grouping options
 */
export interface ExportGrouping {
  field: string
  includeSubtotals?: boolean
}

/**
 * Custom field definition
 */
export interface CustomField {
  name: string
  value: (business: BusinessRecord) => any
  type: 'string' | 'number' | 'date' | 'boolean'
}

/**
 * Export service for converting business data to various formats
 */
export class ExportService {
  /**
   * Generate standardized filename in format: [YYYY-MM-DD]_[HH(00–23)-MM(00–59)]_[Industry(s)]_[# of Results].[ext]
   * @param businesses - Array of business records
   * @param format - Export format
   * @param context - Export context with industry information
   * @returns Standardized filename
   */
  private generateStandardizedFilename(
    businesses: BusinessRecord[],
    format: ExportFormat,
    context?: ExportContext
  ): string {
    // Generate timestamp in required format
    const now = new Date()
    const year = now.getFullYear()
    const month = String(now.getMonth() + 1).padStart(2, '0')
    const day = String(now.getDate()).padStart(2, '0')
    const hours = String(now.getHours()).padStart(2, '0')
    const minutes = String(now.getMinutes()).padStart(2, '0')

    const dateStr = `${year}-${month}-${day}`
    const timeStr = `${hours}-${minutes}`

    // Determine industry names
    let industryPart = 'All-Industries'
    if (context?.selectedIndustries && context.selectedIndustries.length > 0) {
      if (context.selectedIndustries.length === 1) {
        // Single industry - use the industry name
        industryPart = context.selectedIndustries[0]
          .replace(/[^a-zA-Z0-9]/g, '-')
          .replace(/-+/g, '-')
          .replace(/^-|-$/g, '')
      } else if (context.selectedIndustries.length <= 3) {
        // Multiple industries (up to 3) - combine them
        industryPart = context.selectedIndustries
          .map(industry => industry.replace(/[^a-zA-Z0-9]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, ''))
          .join('-')
      } else {
        // Many industries - use "Multiple-Industries"
        industryPart = 'Multiple-Industries'
      }
    }

    // Get result count (filtered or total)
    const resultCount = context?.selectedBusinesses
      ? context.selectedBusinesses.length
      : businesses.length

    // Construct filename: [YYYY-MM-DD]_[HH(00–23)-MM(00–59)]_[Industry(s)]_[# of Results].[ext]
    return `${dateStr}_${timeStr}_${industryPart}_${resultCount}.${format}`
  }

  /**
   * Apply export template to business data
   * @param businesses - Business records
   * @param template - Export template
   * @returns Formatted data according to template
   */
  private applyTemplate(businesses: BusinessRecord[], template?: ExportTemplate): any[] {
    if (!template) {
      return businesses.map(formatBusinessForExport)
    }

    return businesses.map(business => {
      const result: any = {}

      for (const field of template.fields) {
        const value = this.getNestedValue(business, field)
        const header = template.customHeaders?.[field] || field

        // Apply custom formatting if available
        if (template.formatting?.[field]) {
          result[header] = template.formatting[field](value)
        } else {
          result[header] = this.formatValue(value, field)
        }
      }

      return result
    })
  }

  /**
   * Get nested value from object using dot notation
   * @param obj - Object to get value from
   * @param path - Dot notation path (e.g., 'address.street')
   * @returns Value at path
   */
  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj)
  }

  /**
   * Format value based on field type
   * @param value - Value to format
   * @param field - Field name for context
   * @returns Formatted value
   */
  private formatValue(value: any, field: string): string {
    if (value === null || value === undefined) {
      return ''
    }

    // Handle arrays (like email addresses)
    if (Array.isArray(value)) {
      return value.join('; ')
    }

    // Handle dates
    if (field.includes('Date') || field.includes('At') || value instanceof Date) {
      return new Date(value).toLocaleDateString()
    }

    // Handle coordinates
    if (field.includes('lat') || field.includes('lng')) {
      return typeof value === 'number' ? value.toFixed(6) : String(value)
    }

    return String(value)
  }
  /**
   * Export businesses to specified format with prioritized data processing
   * @param businesses - Array of business records
   * @param format - Export format
   * @param options - Export options
   * @returns Promise resolving to download blob or file path
   */
  async exportBusinesses(
    businesses: BusinessRecord[],
    format: ExportFormat,
    options: ExportOptions = {}
  ): Promise<{ blob: Blob; filename: string }> {
    // Filter businesses if selectedBusinesses is provided
    let businessesToExport = businesses
    if (options.selectedBusinesses) {
      businessesToExport = businesses.filter(business =>
        options.selectedBusinesses!.includes(business.id)
      )
      logger.info('ExportService', `Filtered export: ${businessesToExport.length} of ${businesses.length} businesses selected`)
    }

    // Process data with prioritized deduplication
    const { processedRecords, stats } = await prioritizedDataProcessor.processBusinessRecords(businessesToExport)

    logger.info('ExportService', `Data processing complete:`, {
      original: stats.totalRecords,
      duplicatesRemoved: stats.duplicatesRemoved,
      final: stats.finalRecords,
      withEmail: stats.recordsWithEmail,
      withPhone: stats.recordsWithPhone,
      withAddress: stats.recordsWithAddress
    })

    // Generate prioritized filename
    const filename = options.filename || prioritizedExportFormatter.generateFilename({
      industries: options.context?.industries,
      location: options.context?.searchLocation,
      totalRecords: processedRecords.length
    })

    try {
      logger.info('ExportService', `Exporting ${processedRecords.length} prioritized businesses as ${format} to ${filename}`)

      switch (format) {
        case 'csv':
          return this.exportPrioritizedToCsv(processedRecords, filename, options)
        case 'xlsx':
          return this.exportPrioritizedToXlsx(processedRecords, filename, options)
        case 'xls':
          return this.exportPrioritizedToXls(processedRecords, filename, options)
        case 'ods':
          return this.exportPrioritizedToOds(processedRecords, filename, options)
        case 'pdf':
          return this.exportPrioritizedToPdf(processedRecords, filename, options)
        case 'json':
          return this.exportPrioritizedToJson(processedRecords, filename, options)
        case 'xml':
          return this.exportToXml(businessesToExport, filename, options) // Keep original for XML
        case 'vcf':
          return this.exportToVcf(businessesToExport, filename, options) // Keep original for VCF
        case 'sql':
          return this.exportToSql(businessesToExport, filename, options) // Keep original for SQL
        default:
          throw new Error(`Unsupported export format: ${format}`)
      }
    } catch (error) {
      logger.error('ExportService', `Export failed for format ${format}`, error)
      throw error
    }
  }

  /**
   * Apply filters to business data
   */
  private applyFilters(businesses: BusinessRecord[], filters?: ExportFilters): BusinessRecord[] {
    if (!filters) return businesses

    return businesses.filter(business => {
      // Industry filter
      if (filters.industries && !filters.industries.includes(business.industry)) {
        return false
      }

      // State filter
      if (filters.states && !filters.states.includes(business.address?.state || '')) {
        return false
      }

      // Email filter
      if (filters.hasEmail !== undefined &&
          (business.email?.length > 0) !== filters.hasEmail) {
        return false
      }

      // Phone filter
      if (filters.hasPhone !== undefined &&
          Boolean(business.phone) !== filters.hasPhone) {
        return false
      }

      // Website filter
      if (filters.hasWebsite !== undefined &&
          Boolean(business.websiteUrl) !== filters.hasWebsite) {
        return false
      }

      // Confidence filter - not available in BusinessRecord
      // if (filters.confidenceMin !== undefined &&
      //     (business.confidence || 0) < filters.confidenceMin) {
      //   return false
      // }

      // Date range filter
      if (filters.dateRange) {
        const scrapedDate = new Date(business.scrapedAt)
        if (scrapedDate < filters.dateRange.start || scrapedDate > filters.dateRange.end) {
          return false
        }
      }

      return true
    })
  }

  /**
   * Apply sorting to business data
   */
  private applySorting(businesses: BusinessRecord[], sorting?: ExportSorting): BusinessRecord[] {
    if (!sorting) return businesses

    return [...businesses].sort((a, b) => {
      const aValue = (a as any)[sorting.field]
      const bValue = (b as any)[sorting.field]

      let comparison = 0
      if (aValue < bValue) comparison = -1
      else if (aValue > bValue) comparison = 1

      return sorting.direction === 'desc' ? -comparison : comparison
    })
  }

  /**
   * Add custom fields to business data
   */
  private addCustomFields(businesses: BusinessRecord[], customFields?: CustomField[]): any[] {
    if (!customFields || customFields.length === 0) return businesses

    return businesses.map(business => {
      const enhanced: any = { ...business }

      customFields.forEach(field => {
        try {
          enhanced[field.name] = field.value(business)
        } catch (error) {
          logger.warn('ExportService', `Failed to calculate custom field ${field.name}`, error)
          enhanced[field.name] = null
        }
      })

      return enhanced
    })
  }

  /**
   * Enhanced export with all preprocessing
   */
  private preprocessData(businesses: BusinessRecord[], options: ExportOptions): any[] {
    // Apply filters
    let processedData = this.applyFilters(businesses, options.filters)

    // Apply sorting
    processedData = this.applySorting(processedData, options.sorting)

    // Add custom fields
    processedData = this.addCustomFields(processedData, options.customFields)

    return processedData
  }

  /**
   * Export to CSV format
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob
   */
  private async exportToCsv(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const delimiter = options.delimiter || ','
    const includeHeaders = options.includeHeaders !== false

    // Format data for export (with template support)
    const formattedData = this.applyTemplate(businesses, options.template)
    
    let csvContent = ''

    // Add headers
    if (includeHeaders && formattedData.length > 0) {
      const headers = Object.keys(formattedData[0]!)
      csvContent += headers.map(header => formatCsvCell(header)).join(delimiter) + '\n'
    }

    // Add data rows
    for (const row of formattedData) {
      const values = Object.values(row)
      csvContent += values.map(value => formatCsvCell(value)).join(delimiter) + '\n'
    }

    // Create blob with appropriate encoding
    const encoding = options.encoding || 'utf-8'
    const blob = new Blob([csvContent], { 
      type: `text/csv;charset=${encoding}` 
    })

    return {
      blob,
      filename: filename.endsWith('.csv') ? filename : `${filename}.csv`
    }
  }

  /**
   * Export prioritized records to CSV format
   * @param records - Prioritized business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob
   */
  private async exportPrioritizedToCsv(
    records: PrioritizedBusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const csvContent = prioritizedExportFormatter.formatForCSV(records)

    const blob = new Blob([csvContent], {
      type: 'text/csv;charset=utf-8'
    })

    return {
      blob,
      filename: filename.endsWith('.csv') ? filename : `${filename}.csv`
    }
  }

  /**
   * Export prioritized records to XLSX format (CSV with xlsx extension)
   * @param records - Prioritized business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob with xlsx extension
   */
  private async exportPrioritizedToXlsx(
    records: PrioritizedBusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const csvResult = await this.exportPrioritizedToCsv(records, filename, options)

    return {
      blob: csvResult.blob,
      filename: filename.endsWith('.xlsx') ? filename : `${filename}.xlsx`
    }
  }

  /**
   * Export prioritized records to XLS format (CSV with xls extension)
   * @param records - Prioritized business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob with xls extension
   */
  private async exportPrioritizedToXls(
    records: PrioritizedBusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const csvResult = await this.exportPrioritizedToCsv(records, filename, options)

    return {
      blob: csvResult.blob,
      filename: filename.endsWith('.xls') ? filename : `${filename}.xls`
    }
  }

  /**
   * Export prioritized records to ODS format (CSV with ods extension)
   * @param records - Prioritized business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob with ods extension
   */
  private async exportPrioritizedToOds(
    records: PrioritizedBusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const csvResult = await this.exportPrioritizedToCsv(records, filename, options)

    return {
      blob: csvResult.blob,
      filename: filename.endsWith('.ods') ? filename : `${filename}.ods`
    }
  }

  /**
   * Export prioritized records to JSON format
   * @param records - Prioritized business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to JSON blob
   */
  private async exportPrioritizedToJson(
    records: PrioritizedBusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const jsonData = prioritizedExportFormatter.formatForJSON(records)
    const jsonContent = JSON.stringify(jsonData, null, 2)

    const blob = new Blob([jsonContent], {
      type: 'application/json'
    })

    return {
      blob,
      filename: filename.endsWith('.json') ? filename : `${filename}.json`
    }
  }

  /**
   * Export prioritized records to PDF format
   * @param records - Prioritized business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to PDF blob
   */
  private async exportPrioritizedToPdf(
    records: PrioritizedBusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const doc = new jsPDF()

    // Add title
    doc.setFontSize(16)
    doc.text('Business Contact Directory', 20, 20)

    // Add export summary
    const summary = prioritizedExportFormatter.generateExportSummary(records)
    doc.setFontSize(10)
    doc.text(`Total Records: ${summary.totalRecords}`, 20, 35)
    doc.text(`Records with Email: ${summary.recordsWithEmail}`, 20, 42)
    doc.text(`Records with Phone: ${summary.recordsWithPhone}`, 20, 49)
    doc.text(`Average Quality: ${Math.round(summary.averageConfidence * 100)}%`, 20, 56)

    // Prepare table data
    const tableData = records.slice(0, 100).map(record => [
      record.email || '',
      record.phone || '',
      record.businessName || '',
      record.streetAddress || '',
      record.city || '',
      record.state || '',
      record.zipCode || ''
    ])

    // Add table
    ;(doc as any).autoTable({
      head: [['Email', 'Phone', 'Business', 'Address', 'City', 'State', 'ZIP']],
      body: tableData,
      startY: 65,
      styles: { fontSize: 8 },
      headStyles: { fillColor: [66, 139, 202] }
    })

    const pdfBlob = new Blob([doc.output('blob')], { type: 'application/pdf' })

    return {
      blob: pdfBlob,
      filename: filename.endsWith('.pdf') ? filename : `${filename}.pdf`
    }
  }

  /**
   * Export to XLSX format (now uses CSV for security)
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob with xlsx extension
   */
  private async exportToXlsx(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Use CSV format for security (XLSX library had vulnerabilities)
    // This CSV file can be opened in Excel and will work the same way
    const csvResult = await this.exportToCsv(businesses, filename, options)

    // Return CSV content but with xlsx extension for user convenience
    // Excel will automatically detect and open CSV files correctly
    return {
      blob: csvResult.blob,
      filename: `${filename}.xlsx`
    }
  }

  /**
   * Export to XLS format (now uses CSV for security)
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob with xls extension
   */
  private async exportToXls(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Use CSV format for security (XLSX library had vulnerabilities)
    // This CSV file can be opened in Excel and will work the same way
    const csvResult = await this.exportToCsv(businesses, filename, options)

    // Return CSV content but with xls extension for user convenience
    // Excel will automatically detect and open CSV files correctly
    return {
      blob: csvResult.blob,
      filename: `${filename}.xls`
    }
  }

  /**
   * Export to ODS format (now uses CSV for security)
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to CSV blob with ods extension
   */
  private async exportToOds(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Use CSV format for security (XLSX library had vulnerabilities)
    // This CSV file can be opened in LibreOffice Calc and will work the same way
    const csvResult = await this.exportToCsv(businesses, filename, options)

    // Return CSV content but with ods extension for user convenience
    // LibreOffice will automatically detect and open CSV files correctly
    return {
      blob: csvResult.blob,
      filename: `${filename}.ods`
    }
  }

  /**
   * Export to PDF format
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to PDF blob
   */
  private async exportToPdf(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Create PDF document
    const doc = new jsPDF('landscape', 'mm', 'a4')

    // Add title
    doc.setFontSize(16)
    doc.text('Business Directory Export', 14, 20)
    
    // Add export date
    doc.setFontSize(10)
    doc.text(`Generated on: ${new Date().toLocaleDateString()}`, 14, 30)
    doc.text(`Total Records: ${businesses.length}`, 14, 36)

    // Prepare table data (with template support)
    const formattedData = this.applyTemplate(businesses, options.template)
    
    if (formattedData.length > 0) {
      const headers = Object.keys(formattedData[0]!)
      const rows = formattedData.map(row => Object.values(row))

      // Add table using autoTable plugin
      ;(doc as any).autoTable({
        head: [headers],
        body: rows,
        startY: 45,
        styles: {
          fontSize: 8,
          cellPadding: 2,
        },
        headStyles: {
          fillColor: [66, 139, 202],
          textColor: 255,
          fontStyle: 'bold',
        },
        columnStyles: {
          0: { cellWidth: 35 }, // Business Name
          1: { cellWidth: 45 }, // Email
          2: { cellWidth: 25 }, // Phone
          3: { cellWidth: 35 }, // Website
          4: { cellWidth: 50 }, // Address
          5: { cellWidth: 25 }, // Contact Person
          6: { cellWidth: 20 }, // Industry
          7: { cellWidth: 30 }, // Coordinates
          8: { cellWidth: 20 }, // Scraped Date
        },
        margin: { top: 45, left: 14, right: 14 },
        pageBreak: 'auto',
        showHead: 'everyPage',
      })
    }

    // Generate blob
    const pdfBlob = doc.output('blob')

    return {
      blob: pdfBlob,
      filename: `${filename}.pdf`
    }
  }

  /**
   * Export to JSON format
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to JSON blob
   */
  private async exportToJson(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Create export object with metadata
    const exportData = {
      metadata: {
        exportDate: new Date().toISOString(),
        totalRecords: businesses.length,
        version: '1.0.0',
      },
      businesses: this.applyTemplate(businesses, options.template),
    }

    const jsonContent = JSON.stringify(exportData, null, 2)
    
    const blob = new Blob([jsonContent], { 
      type: 'application/json' 
    })

    return {
      blob,
      filename: filename.endsWith('.json') ? filename : `${filename}.json`
    }
  }

  /**
   * Download blob as file
   * @param blob - Blob to download
   * @param filename - Filename for download
   */
  downloadBlob(blob: Blob, filename: string): void {
    try {
      // Create download link
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      
      // Trigger download
      document.body.appendChild(link)
      link.click()
      
      // Cleanup
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
      
      logger.info('ExportService', `File downloaded: ${filename}`)
    } catch (error) {
      logger.error('ExportService', 'Download failed', error)
      throw error
    }
  }

  /**
   * Get supported export formats
   * @param includeAll - Whether to include all formats or just primary ones
   * @returns Array of supported formats
   */
  getSupportedFormats(includeAll: boolean = false): ExportFormat[] {
    const primaryFormats: ExportFormat[] = ['csv', 'xlsx', 'pdf']
    const allFormats: ExportFormat[] = ['csv', 'xlsx', 'xls', 'ods', 'pdf', 'json', 'xml', 'vcf', 'sql']

    return includeAll ? allFormats : primaryFormats
  }

  /**
   * Get format description
   * @param format - Export format
   * @returns Format description
   */
  getFormatDescription(format: ExportFormat): string {
    const descriptions: Record<ExportFormat, string> = {
      csv: 'Comma-Separated Values - Universal format for spreadsheets',
      xlsx: 'Excel Compatible CSV - Secure CSV format that opens in Excel',
      xls: 'Excel Compatible CSV - Secure CSV format for legacy Excel',
      ods: 'LibreOffice Compatible CSV - Secure CSV format for LibreOffice',
      pdf: 'Portable Document Format - Print-ready document',
      json: 'JavaScript Object Notation - Structured data format',
      xml: 'Extensible Markup Language - Structured data format',
      vcf: 'vCard Format - Contact information format',
      sql: 'SQL Insert Statements - Database import format',
    }
    
    return descriptions[format] || 'Unknown format'
  }

  /**
   * Estimate export file size
   * @param businesses - Business records
   * @param format - Export format
   * @returns Estimated size in bytes
   */
  estimateFileSize(businesses: BusinessRecord[], format: ExportFormat): number {
    const avgRecordSize = {
      csv: 200,    // bytes per record
      xlsx: 200,   // bytes per record (now CSV format)
      xls: 200,    // bytes per record (now CSV format)
      ods: 200,    // bytes per record (now CSV format)
      pdf: 150,    // bytes per record
      json: 400,   // bytes per record
      xml: 350,    // bytes per record
      vcf: 180,    // bytes per record
      sql: 250,    // bytes per record
    }

    const baseSize = {
      csv: 100,     // header size
      xlsx: 100,    // header size (now CSV format)
      xls: 100,     // header size (now CSV format)
      ods: 100,     // header size (now CSV format)
      pdf: 5000,    // document structure
      json: 200,    // metadata
      xml: 300,     // XML structure
      vcf: 50,      // vCard header
      sql: 150,     // SQL statements
    }

    return baseSize[format] + (businesses.length * avgRecordSize[format])
  }

  /**
   * Export to XML format
   */
  private async exportToXml(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const processedData = this.preprocessData(businesses, options)

    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<businesses>\n'
    xml += `  <metadata>\n`
    xml += `    <exportDate>${new Date().toISOString()}</exportDate>\n`
    xml += `    <totalRecords>${processedData.length}</totalRecords>\n`
    xml += `  </metadata>\n`

    processedData.forEach(business => {
      xml += '  <business>\n'
      xml += `    <id>${this.escapeXml(business.id)}</id>\n`
      xml += `    <businessName>${this.escapeXml(business.businessName)}</businessName>\n`
      xml += `    <industry>${this.escapeXml(business.industry)}</industry>\n`

      if (business.email?.length) {
        xml += '    <emails>\n'
        business.email.forEach((email: string) => {
          xml += `      <email>${this.escapeXml(email)}</email>\n`
        })
        xml += '    </emails>\n'
      }

      if (business.phone) {
        xml += `    <phone>${this.escapeXml(business.phone)}</phone>\n`
      }

      if (business.websiteUrl) {
        xml += `    <website>${this.escapeXml(business.websiteUrl)}</website>\n`
      }

      if (business.address) {
        xml += '    <address>\n'
        xml += `      <street>${this.escapeXml(business.address.street)}</street>\n`
        xml += `      <city>${this.escapeXml(business.address.city)}</city>\n`
        xml += `      <state>${this.escapeXml(business.address.state)}</state>\n`
        xml += `      <zipCode>${this.escapeXml(business.address.zipCode)}</zipCode>\n`
        xml += '    </address>\n'
      }

      xml += `    <scrapedAt>${business.scrapedAt}</scrapedAt>\n`
      xml += '  </business>\n'
    })

    xml += '</businesses>'

    const blob = new Blob([xml], { type: 'application/xml' })
    return { blob, filename: `${filename}.xml` }
  }

  /**
   * Export to VCF (vCard) format
   */
  private async exportToVcf(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const processedData = this.preprocessData(businesses, options)

    let vcf = ''

    processedData.forEach(business => {
      vcf += 'BEGIN:VCARD\n'
      vcf += 'VERSION:3.0\n'
      vcf += `FN:${business.businessName}\n`
      vcf += `ORG:${business.businessName}\n`

      if (business.email?.length) {
        business.email.forEach((email: string, index: number) => {
          vcf += `EMAIL${index === 0 ? '' : `;TYPE=WORK${index}`}:${email}\n`
        })
      }

      if (business.phone) {
        vcf += `TEL;TYPE=WORK:${business.phone}\n`
      }

      if (business.websiteUrl) {
        vcf += `URL:${business.websiteUrl}\n`
      }

      if (business.address) {
        const addr = business.address
        vcf += `ADR;TYPE=WORK:;;${addr.street};${addr.city};${addr.state};${addr.zipCode};\n`
      }

      vcf += `NOTE:Industry: ${business.industry}\n`
      vcf += `REV:${new Date().toISOString()}\n`
      vcf += 'END:VCARD\n\n'
    })

    const blob = new Blob([vcf], { type: 'text/vcard' })
    return { blob, filename: `${filename}.vcf` }
  }

  /**
   * Export to SQL format
   */
  private async exportToSql(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    const processedData = this.preprocessData(businesses, options)

    let sql = '-- Business Data Export\n'
    sql += `-- Generated on ${new Date().toISOString()}\n\n`

    // Create table
    sql += 'CREATE TABLE IF NOT EXISTS businesses (\n'
    sql += '  id VARCHAR(255) PRIMARY KEY,\n'
    sql += '  business_name VARCHAR(255) NOT NULL,\n'
    sql += '  industry VARCHAR(100),\n'
    sql += '  email TEXT,\n'
    sql += '  phone VARCHAR(50),\n'
    sql += '  website VARCHAR(255),\n'
    sql += '  street VARCHAR(255),\n'
    sql += '  city VARCHAR(100),\n'
    sql += '  state VARCHAR(50),\n'
    sql += '  zip_code VARCHAR(20),\n'
    sql += '  latitude DECIMAL(10, 8),\n'
    sql += '  longitude DECIMAL(11, 8),\n'
    sql += '  confidence DECIMAL(3, 2),\n'
    sql += '  scraped_at TIMESTAMP\n'
    sql += ');\n\n'

    // Insert data
    processedData.forEach(business => {
      sql += 'INSERT INTO businesses VALUES (\n'
      sql += `  '${this.escapeSql(business.id)}',\n`
      sql += `  '${this.escapeSql(business.businessName)}',\n`
      sql += `  '${this.escapeSql(business.industry)}',\n`
      sql += `  '${this.escapeSql(business.email?.join(';') || '')}',\n`
      sql += `  '${this.escapeSql(business.phone || '')}',\n`
      sql += `  '${this.escapeSql(business.websiteUrl || '')}',\n`
      sql += `  '${this.escapeSql(business.address?.street || '')}',\n`
      sql += `  '${this.escapeSql(business.address?.city || '')}',\n`
      sql += `  '${this.escapeSql(business.address?.state || '')}',\n`
      sql += `  '${this.escapeSql(business.address?.zipCode || '')}',\n`
      sql += `  ${business.coordinates?.lat || 'NULL'},\n`
      sql += `  ${business.coordinates?.lng || 'NULL'},\n`
      sql += `  ${business.confidence || 'NULL'},\n`
      sql += `  '${business.scrapedAt}'\n`
      sql += ');\n'
    })

    const blob = new Blob([sql], { type: 'application/sql' })
    return { blob, filename: `${filename}.sql` }
  }

  /**
   * Escape XML special characters
   */
  private escapeXml(str: string): string {
    if (!str) return ''
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;')
  }

  /**
   * Escape SQL special characters
   */
  private escapeSql(str: string): string {
    if (!str) return ''
    return str.replace(/'/g, "''")
  }
}

/**
 * Default export service instance
 */
export const exportService = new ExportService()
