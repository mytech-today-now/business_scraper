/**
 * Prioritized Export Formatter
 * 
 * Formats business data for export with priority-based field ordering
 * Matches the desired output format similar to Good_Mailing_list.ods
 */

import { PrioritizedBusinessRecord } from '@/lib/prioritizedDataProcessor'
import { logger } from './logger'

export interface ExportColumn {
  key: keyof PrioritizedBusinessRecord | string
  header: string
  priority: number
  formatter?: (value: any, record: PrioritizedBusinessRecord) => string
}

/**
 * Priority-based export columns configuration
 * Ordered by business value: Email > Phone > Address > Contact Info > Metadata
 */
export const PRIORITY_EXPORT_COLUMNS: ExportColumn[] = [
  // Priority 1: Email (Most Important)
  {
    key: 'email',
    header: 'Email',
    priority: 1,
    formatter: (value: string) => value || ''
  },
  
  // Priority 2: Phone Number
  {
    key: 'phone',
    header: 'Phone',
    priority: 2,
    formatter: (value: string) => formatPhoneForExport(value)
  },
  
  // Priority 3: Street Address
  {
    key: 'streetAddress',
    header: 'Street Address',
    priority: 3,
    formatter: (value: string) => value || ''
  },
  
  // Priority 4: City
  {
    key: 'city',
    header: 'City',
    priority: 4,
    formatter: (value: string) => value || ''
  },
  
  // Priority 5: ZIP Code
  {
    key: 'zipCode',
    header: 'ZIP',
    priority: 5,
    formatter: (value: string) => value || ''
  },
  
  // Priority 6: State
  {
    key: 'state',
    header: 'State',
    priority: 6,
    formatter: (value: string) => value || ''
  },
  
  // Priority 7: Business Name
  {
    key: 'businessName',
    header: 'Business Name',
    priority: 7,
    formatter: (value: string) => value || ''
  },
  
  // Priority 8: Contact Name
  {
    key: 'contactName',
    header: 'Contact Name',
    priority: 8,
    formatter: (value: string) => value || ''
  },
  
  // Priority 9: Website
  {
    key: 'website',
    header: 'Website',
    priority: 9,
    formatter: (value: string) => value || ''
  },
  
  // Priority 10: Coordinates
  {
    key: 'coordinates',
    header: 'Coordinates',
    priority: 10,
    formatter: (value: string) => value || ''
  },
  
  // Additional fields for comprehensive data
  {
    key: 'additionalEmails',
    header: 'Additional Emails',
    priority: 11,
    formatter: (value: string[]) => value.join('; ')
  },
  
  {
    key: 'additionalPhones',
    header: 'Additional Phones',
    priority: 12,
    formatter: (value: string[]) => value.map(formatPhoneForExport).join('; ')
  },
  
  {
    key: 'confidence',
    header: 'Data Quality',
    priority: 13,
    formatter: (value: number) => `${Math.round(value * 100)}%`
  },
  
  {
    key: 'sources',
    header: 'Sources',
    priority: 14,
    formatter: (value: string[]) => value.join('; ')
  }
]

/**
 * Prioritized Export Formatter Class
 */
export class PrioritizedExportFormatter {
  private columns: ExportColumn[]

  constructor(customColumns?: ExportColumn[]) {
    this.columns = customColumns || PRIORITY_EXPORT_COLUMNS
    this.columns.sort((a, b) => a.priority - b.priority)
  }

  /**
   * Format records for CSV export with priority-based columns
   */
  formatForCSV(records: PrioritizedBusinessRecord[]): string {
    if (records.length === 0) {
      return ''
    }

    logger.info('PrioritizedExportFormatter', `Formatting ${records.length} records for CSV export`)

    // Generate header row
    const headers = this.columns.map(col => this.escapeCSVField(col.header))
    let csv = headers.join(',') + '\n'

    // Generate data rows
    for (const record of records) {
      const row = this.columns.map(col => {
        const value = this.getFieldValue(record, col)
        const formatted = col.formatter ? col.formatter(value, record) : String(value || '')
        return this.escapeCSVField(formatted)
      })
      csv += row.join(',') + '\n'
    }

    return csv
  }

  /**
   * Format records for Excel-compatible format
   */
  formatForExcel(records: PrioritizedBusinessRecord[]): any[] {
    if (records.length === 0) {
      return []
    }

    logger.info('PrioritizedExportFormatter', `Formatting ${records.length} records for Excel export`)

    const result = []

    // Add header row
    const headerRow: any = {}
    this.columns.forEach(col => {
      headerRow[col.header] = col.header
    })
    result.push(headerRow)

    // Add data rows
    for (const record of records) {
      const row: any = {}
      this.columns.forEach(col => {
        const value = this.getFieldValue(record, col)
        const formatted = col.formatter ? col.formatter(value, record) : String(value || '')
        row[col.header] = formatted
      })
      result.push(row)
    }

    return result
  }

  /**
   * Format records for JSON export
   */
  formatForJSON(records: PrioritizedBusinessRecord[]): any {
    logger.info('PrioritizedExportFormatter', `Formatting ${records.length} records for JSON export`)

    return {
      metadata: {
        exportDate: new Date().toISOString(),
        totalRecords: records.length,
        format: 'prioritized_business_contacts',
        version: '1.0.0',
        columns: this.columns.map(col => ({
          key: col.key,
          header: col.header,
          priority: col.priority
        }))
      },
      records: records.map(record => {
        const formatted: any = {}
        this.columns.forEach(col => {
          const value = this.getFieldValue(record, col)
          const formattedValue = col.formatter ? col.formatter(value, record) : value
          formatted[col.header] = formattedValue
        })
        return formatted
      })
    }
  }

  /**
   * Get field value from record
   */
  private getFieldValue(record: PrioritizedBusinessRecord, column: ExportColumn): any {
    if (typeof column.key === 'string' && column.key in record) {
      return (record as any)[column.key]
    }
    return ''
  }

  /**
   * Escape CSV field for proper formatting
   */
  private escapeCSVField(field: string): string {
    const stringField = String(field || '')
    
    // If field contains comma, quote, or newline, wrap in quotes and escape quotes
    if (stringField.includes(',') || stringField.includes('"') || stringField.includes('\n')) {
      return `"${stringField.replace(/"/g, '""')}"`
    }
    
    return stringField
  }

  /**
   * Generate filename with timestamp and context
   */
  generateFilename(context?: {
    industries?: string[]
    location?: string
    totalRecords?: number
  }): string {
    const timestamp = new Date().toISOString().slice(0, 16).replace(/[T:]/g, '_')
    
    let filename = timestamp
    
    if (context?.industries && context.industries.length > 0) {
      const industriesStr = context.industries
        .slice(0, 2) // Limit to first 2 industries
        .map(industry => industry.replace(/[^a-zA-Z0-9]/g, '-'))
        .join('-')
      filename += `_${industriesStr}`
    }
    
    if (context?.location) {
      const locationStr = context.location.replace(/[^a-zA-Z0-9]/g, '-')
      filename += `_${locationStr}`
    }
    
    if (context?.totalRecords) {
      filename += `_${context.totalRecords}`
    }
    
    return filename
  }

  /**
   * Create export summary statistics
   */
  generateExportSummary(records: PrioritizedBusinessRecord[]): {
    totalRecords: number
    recordsWithEmail: number
    recordsWithPhone: number
    recordsWithAddress: number
    recordsWithContact: number
    averageConfidence: number
    topSources: string[]
  } {
    const summary = {
      totalRecords: records.length,
      recordsWithEmail: 0,
      recordsWithPhone: 0,
      recordsWithAddress: 0,
      recordsWithContact: 0,
      averageConfidence: 0,
      topSources: [] as string[]
    }

    if (records.length === 0) {
      return summary
    }

    let totalConfidence = 0
    const sourceCount = new Map<string, number>()

    for (const record of records) {
      if (record.email) summary.recordsWithEmail++
      if (record.phone) summary.recordsWithPhone++
      if (record.streetAddress && record.city && record.zipCode) summary.recordsWithAddress++
      if (record.contactName) summary.recordsWithContact++
      
      totalConfidence += record.confidence
      
      // Count sources
      for (const source of record.sources) {
        sourceCount.set(source, (sourceCount.get(source) || 0) + 1)
      }
    }

    summary.averageConfidence = totalConfidence / records.length

    // Get top 5 sources
    summary.topSources = Array.from(sourceCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([source]) => source)

    return summary
  }
}

/**
 * Format phone number for export display
 */
function formatPhoneForExport(phone: string): string {
  if (!phone) return ''
  
  // Remove all non-digits
  const digits = phone.replace(/\D/g, '')
  
  // Format US phone numbers
  if (digits.length === 10) {
    return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`
  } else if (digits.length === 11 && digits.startsWith('1')) {
    return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`
  }
  
  // Return original if not standard format
  return phone
}

/**
 * Default prioritized export formatter instance
 */
export const prioritizedExportFormatter = new PrioritizedExportFormatter()
