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
export type ExportFormat = 'csv' | 'xlsx' | 'xls' | 'ods' | 'pdf' | 'json'

/**
 * Export options interface
 */
export interface ExportOptions {
  filename?: string
  includeHeaders?: boolean
  dateFormat?: string
  delimiter?: string
  encoding?: string
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
        default:
          throw new Error(`Unsupported export format: ${format}`)
      }
    } catch (error) {
      logger.error('ExportService', `Export failed for format ${format}`, error)
      throw error
    }
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
      const headers = Object.keys(formattedData[0])
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
      const headers = Object.keys(formattedData[0])
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
    }

    const baseSize = {
      csv: 100,     // header size
      xlsx: 2000,   // workbook overhead
      xls: 1500,    // workbook overhead
      ods: 2500,    // document overhead
      pdf: 5000,    // document structure
      json: 200,    // metadata
    }

    return baseSize[format] + (businesses.length * avgRecordSize[format])
  }
}

/**
 * Default export service instance
 */
export const exportService = new ExportService()
