/**
 * Test suite for PrioritizedExportFormatter
 */

import { PrioritizedExportFormatter } from '@/utils/prioritizedExportFormatter'
import { PrioritizedBusinessRecord } from '@/lib/prioritizedDataProcessor'

describe('PrioritizedExportFormatter', () => {
  let formatter: PrioritizedExportFormatter

  beforeEach(() => {
    formatter = new PrioritizedExportFormatter()
  })

  const mockRecord: PrioritizedBusinessRecord = {
    id: '1',
    email: 'info@test.com',
    phone: '5551234567',
    streetAddress: '123 Main St',
    city: 'Test City',
    state: 'CA',
    zipCode: '12345',
    businessName: 'Test Company',
    contactName: 'John Doe',
    website: 'https://test.com',
    coordinates: '40.712800, -74.006000',
    additionalEmails: ['contact@test.com'],
    additionalPhones: ['5559876543'],
    confidence: 0.85,
    sources: ['https://test.com', 'https://directory.com']
  }

  describe('formatForCSV', () => {
    it('should format records for CSV export with priority-based columns', () => {
      const records = [mockRecord]
      const csv = formatter.formatForCSV(records)
      
      expect(csv).toContain('Email,Phone,Street Address,City,ZIP') // Priority headers first
      expect(csv).toContain('info@test.com,(555) 123-4567,123 Main St,Test City,12345')
    })

    it('should handle empty records array', () => {
      const csv = formatter.formatForCSV([])
      expect(csv).toBe('')
    })

    it('should escape CSV fields properly', () => {
      const recordWithCommas: PrioritizedBusinessRecord = {
        ...mockRecord,
        businessName: 'Test, Company & Associates',
        streetAddress: '123 Main St, Suite 100'
      }
      
      const csv = formatter.formatForCSV([recordWithCommas])
      expect(csv).toContain('"Test, Company & Associates"')
      expect(csv).toContain('"123 Main St, Suite 100"')
    })
  })

  describe('formatForExcel', () => {
    it('should format records for Excel export', () => {
      const records = [mockRecord]
      const excelData = formatter.formatForExcel(records)
      
      expect(excelData).toHaveLength(2) // Header + 1 data row
      expect(excelData[0]).toHaveProperty('Email', 'Email') // Header row
      expect(excelData[1]).toHaveProperty('Email', 'info@test.com') // Data row
      expect(excelData[1]).toHaveProperty('Phone', '(555) 123-4567')
    })

    it('should handle empty records array', () => {
      const excelData = formatter.formatForExcel([])
      expect(excelData).toEqual([])
    })
  })

  describe('formatForJSON', () => {
    it('should format records for JSON export with metadata', () => {
      const records = [mockRecord]
      const jsonData = formatter.formatForJSON(records)
      
      expect(jsonData).toHaveProperty('metadata')
      expect(jsonData).toHaveProperty('records')
      expect(jsonData.metadata.totalRecords).toBe(1)
      expect(jsonData.metadata.format).toBe('prioritized_business_contacts')
      expect(jsonData.records).toHaveLength(1)
      expect(jsonData.records[0]).toHaveProperty('Email', 'info@test.com')
    })

    it('should include column metadata', () => {
      const records = [mockRecord]
      const jsonData = formatter.formatForJSON(records)
      
      expect(jsonData.metadata.columns).toBeDefined()
      expect(jsonData.metadata.columns[0]).toHaveProperty('key', 'email')
      expect(jsonData.metadata.columns[0]).toHaveProperty('header', 'Email')
      expect(jsonData.metadata.columns[0]).toHaveProperty('priority', 1)
    })
  })

  describe('generateFilename', () => {
    it('should generate filename with date in YYYY-MM-DD format', () => {
      const filename = formatter.generateFilename()
      expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}_All-Industries_0$/)
    })

    it('should include all industries as separate segments', () => {
      const context = {
        industries: ['Technology', 'Healthcare'],
        totalRecords: 150
      }

      const filename = formatter.generateFilename(context)
      expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}_Technology_Healthcare_150$/)
    })

    it('should include all industries without limiting', () => {
      const context = {
        industries: ['Technology', 'Healthcare', 'Finance', 'Education'],
        totalRecords: 100
      }

      const filename = formatter.generateFilename(context)
      expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}_Technology_Healthcare_Finance_Education_100$/)
    })

    it('should sanitize industry names properly', () => {
      const context = {
        industries: ['Legal & Law Services', 'Medical/Health Care'],
        totalRecords: 50
      }

      const filename = formatter.generateFilename(context)
      expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}_Legal-Law-Services_MedicalHealth-Care_50$/)
    })

    it('should handle custom industry names', () => {
      const context = {
        industries: ['My Custom Industry', 'Another Custom Business Type'],
        totalRecords: 25
      }

      const filename = formatter.generateFilename(context)
      expect(filename).toMatch(/^\d{4}-\d{2}-\d{2}_My-Custom-Industry_Another-Custom-Business-Type_25$/)
    })
  })

  describe('generateExportSummary', () => {
    it('should generate comprehensive export summary', () => {
      const records = [
        mockRecord,
        {
          ...mockRecord,
          id: '2',
          email: '',
          phone: '',
          contactName: '',
          confidence: 0.6
        }
      ]
      
      const summary = formatter.generateExportSummary(records)
      
      expect(summary.totalRecords).toBe(2)
      expect(summary.recordsWithEmail).toBe(1)
      expect(summary.recordsWithPhone).toBe(1)
      expect(summary.recordsWithAddress).toBe(2)
      expect(summary.recordsWithContact).toBe(1)
      expect(summary.averageConfidence).toBe(0.725) // (0.85 + 0.6) / 2
      expect(summary.topSources).toContain('https://test.com')
    })

    it('should handle empty records array', () => {
      const summary = formatter.generateExportSummary([])
      
      expect(summary.totalRecords).toBe(0)
      expect(summary.recordsWithEmail).toBe(0)
      expect(summary.averageConfidence).toBe(0)
      expect(summary.topSources).toEqual([])
    })

    it('should identify top sources correctly', () => {
      const records = [
        { ...mockRecord, sources: ['https://source1.com'] },
        { ...mockRecord, id: '2', sources: ['https://source1.com', 'https://source2.com'] },
        { ...mockRecord, id: '3', sources: ['https://source2.com'] }
      ]
      
      const summary = formatter.generateExportSummary(records)
      
      expect(summary.topSources[0]).toBe('https://source1.com') // 2 occurrences
      expect(summary.topSources[1]).toBe('https://source2.com') // 2 occurrences
    })
  })

  describe('phone formatting', () => {
    it('should format 10-digit phone numbers correctly', () => {
      const record = { ...mockRecord, phone: '5551234567' }
      const csv = formatter.formatForCSV([record])
      expect(csv).toContain('(555) 123-4567')
    })

    it('should format 11-digit phone numbers with country code', () => {
      const record = { ...mockRecord, phone: '15551234567' }
      const csv = formatter.formatForCSV([record])
      expect(csv).toContain('+1 (555) 123-4567')
    })

    it('should preserve non-standard phone formats', () => {
      const record = { ...mockRecord, phone: '555.123.4567 ext 123' }
      const csv = formatter.formatForCSV([record])
      expect(csv).toContain('555.123.4567 ext 123')
    })
  })

  describe('column priority ordering', () => {
    it('should order columns by priority', () => {
      const csv = formatter.formatForCSV([mockRecord])
      const lines = csv.split('\n')
      const headers = lines[0].split(',')
      
      // Check that priority fields come first
      expect(headers[0]).toBe('Email')
      expect(headers[1]).toBe('Phone')
      expect(headers[2]).toBe('Street Address')
      expect(headers[3]).toBe('City')
      expect(headers[4]).toBe('ZIP')
    })
  })
})
