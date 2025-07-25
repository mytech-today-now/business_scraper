'use strict'

import * as XLSX from 'xlsx'
import jsPDF from 'jspdf'
import 'jspdf-autotable'
import { BusinessRecord } from '@/types/business'
import { formatBusinessForExport, formatCsvCell } from './formatters'
import { logger } from './logger'

/**
 * Export format types
 */
export type ExportFormat = 'csv' | 'xlsx' | 'xls' | 'ods' | 'pdf' | 'json' | 'xml' | 'vcf' | 'sql'

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
   * Export businesses to specified format
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
    const defaultFilename = `business-data-${new Date().toISOString().split('T')[0]}`
    const filename = options.filename || defaultFilename

    try {
      logger.info('ExportService', `Exporting ${businesses.length} businesses as ${format}`)

      switch (format) {
        case 'csv':
          return this.exportToCsv(businesses, filename, options)
        case 'xlsx':
          return this.exportToXlsx(businesses, filename, options)
        case 'xls':
          return this.exportToXls(businesses, filename, options)
        case 'ods':
          return this.exportToOds(businesses, filename, options)
        case 'pdf':
          return this.exportToPdf(businesses, filename, options)
        case 'json':
          return this.exportToJson(businesses, filename, options)
        case 'xml':
          return this.exportToXml(businesses, filename, options)
        case 'vcf':
          return this.exportToVcf(businesses, filename, options)
        case 'sql':
          return this.exportToSql(businesses, filename, options)
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

    // Format data for export
    const formattedData = businesses.map(formatBusinessForExport)
    
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
      filename: `${filename}.csv`
    }
  }

  /**
   * Export to XLSX format
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to XLSX blob
   */
  private async exportToXlsx(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Format data for export
    const formattedData = businesses.map(formatBusinessForExport)

    // Create workbook
    const workbook = XLSX.utils.book_new()
    
    // Create worksheet
    const worksheet = XLSX.utils.json_to_sheet(formattedData)

    // Set column widths
    const columnWidths = [
      { wch: 25 }, // Business Name
      { wch: 30 }, // Email
      { wch: 15 }, // Phone
      { wch: 25 }, // Website
      { wch: 40 }, // Address
      { wch: 20 }, // Contact Person
      { wch: 15 }, // Industry
      { wch: 20 }, // Coordinates
      { wch: 15 }, // Scraped Date
    ]
    worksheet['!cols'] = columnWidths

    // Add worksheet to workbook
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Business Data')

    // Generate buffer
    const buffer = XLSX.write(workbook, { 
      type: 'array', 
      bookType: 'xlsx' 
    })

    const blob = new Blob([buffer], { 
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' 
    })

    return {
      blob,
      filename: `${filename}.xlsx`
    }
  }

  /**
   * Export to XLS format (legacy Excel)
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to XLS blob
   */
  private async exportToXls(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Format data for export
    const formattedData = businesses.map(formatBusinessForExport)

    // Create workbook
    const workbook = XLSX.utils.book_new()
    const worksheet = XLSX.utils.json_to_sheet(formattedData)
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Business Data')

    // Generate buffer
    const buffer = XLSX.write(workbook, { 
      type: 'array', 
      bookType: 'xls' 
    })

    const blob = new Blob([buffer], { 
      type: 'application/vnd.ms-excel' 
    })

    return {
      blob,
      filename: `${filename}.xls`
    }
  }

  /**
   * Export to ODS format (OpenDocument Spreadsheet)
   * @param businesses - Business records
   * @param filename - Output filename
   * @param options - Export options
   * @returns Promise resolving to ODS blob
   */
  private async exportToOds(
    businesses: BusinessRecord[],
    filename: string,
    options: ExportOptions
  ): Promise<{ blob: Blob; filename: string }> {
    // Format data for export
    const formattedData = businesses.map(formatBusinessForExport)

    // Create workbook
    const workbook = XLSX.utils.book_new()
    const worksheet = XLSX.utils.json_to_sheet(formattedData)
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Business Data')

    // Generate buffer
    const buffer = XLSX.write(workbook, { 
      type: 'array', 
      bookType: 'ods' 
    })

    const blob = new Blob([buffer], { 
      type: 'application/vnd.oasis.opendocument.spreadsheet' 
    })

    return {
      blob,
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

    // Prepare table data
    const formattedData = businesses.map(formatBusinessForExport)
    
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
      businesses: businesses.map(formatBusinessForExport),
    }

    const jsonContent = JSON.stringify(exportData, null, 2)
    
    const blob = new Blob([jsonContent], { 
      type: 'application/json' 
    })

    return {
      blob,
      filename: `${filename}.json`
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
   * @returns Array of supported formats
   */
  getSupportedFormats(): ExportFormat[] {
    return ['csv', 'xlsx', 'xls', 'ods', 'pdf', 'json']
  }

  /**
   * Get format description
   * @param format - Export format
   * @returns Format description
   */
  getFormatDescription(format: ExportFormat): string {
    const descriptions: Record<ExportFormat, string> = {
      csv: 'Comma-Separated Values - Universal format for spreadsheets',
      xlsx: 'Excel Workbook - Modern Excel format with formatting',
      xls: 'Excel 97-2003 - Legacy Excel format for older versions',
      ods: 'OpenDocument Spreadsheet - Open standard format',
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
      xlsx: 300,   // bytes per record
      xls: 250,    // bytes per record
      ods: 280,    // bytes per record
      pdf: 150,    // bytes per record
      json: 400,   // bytes per record
      xml: 350,    // bytes per record
      vcf: 180,    // bytes per record
      sql: 250,    // bytes per record
    }

    const baseSize = {
      csv: 100,     // header size
      xlsx: 2000,   // workbook overhead
      xls: 1500,    // workbook overhead
      ods: 2500,    // document overhead
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
