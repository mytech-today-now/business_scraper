/**
 * Tests for export service functionality
 */

import { ExportService } from '@/utils/exportService'
import { BusinessRecord } from '@/types/business'

// Mock business data for testing
const mockBusinesses: BusinessRecord[] = [
  {
    id: 'test-1',
    businessName: 'Test Business 1',
    email: ['test1@example.com', 'contact1@example.com'],
    phone: '+1-555-0123',
    websiteUrl: 'https://test1.com',
    address: {
      street: '123 Test St',
      city: 'Test City',
      state: 'TS',
      zipCode: '12345'
    },
    industry: 'Technology',
    contactPerson: 'John Doe',
    coordinates: {
      lat: 40.7128,
      lng: -74.0060
    },
    scrapedAt: new Date('2024-01-01T12:00:00Z')
  },
  {
    id: 'test-2',
    businessName: 'Test Business 2',
    email: ['test2@example.com'],
    phone: '+1-555-0456',
    websiteUrl: 'https://test2.com',
    address: {
      street: '456 Test Ave',
      city: 'Test Town',
      state: 'TS',
      zipCode: '67890'
    },
    industry: 'Retail',
    contactPerson: 'Jane Smith',
    coordinates: {
      lat: 34.0522,
      lng: -118.2437
    },
    scrapedAt: new Date('2024-01-02T12:00:00Z')
  }
]

describe('ExportService', () => {
  let exportService: ExportService

  beforeEach(() => {
    exportService = new ExportService()
  })

  describe('CSV Export', () => {
    it('should export businesses to CSV format', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'csv')
      
      expect(result.blob).toBeInstanceOf(Blob)
      expect(result.filename).toMatch(/\.csv$/)
      expect(result.blob.type).toMatch(/text\/csv/)
      
      // Read blob content using FileReader
      const text = await new Promise<string>((resolve) => {
        const reader = new FileReader()
        reader.onload = () => resolve(reader.result as string)
        reader.readAsText(result.blob)
      })
      expect(text).toContain('Business Name')
      expect(text).toContain('Test Business 1')
      expect(text).toContain('Test Business 2')
    })

    it('should handle empty business list', async () => {
      const result = await exportService.exportBusinesses([], 'csv')
      
      expect(result.blob).toBeInstanceOf(Blob)
      expect(result.filename).toMatch(/\.csv$/)
    })

    it('should use custom filename', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', {
        filename: 'custom-export'
      })
      
      expect(result.filename).toBe('custom-export.csv')
    })
  })

  describe('XLSX Export', () => {
    it('should export businesses to XLSX format', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'xlsx')
      
      expect(result.blob).toBeInstanceOf(Blob)
      expect(result.filename).toMatch(/\.xlsx$/)
      expect(result.blob.type).toBe('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    })
  })

  describe('JSON Export', () => {
    it('should export businesses to JSON format', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'json')
      
      expect(result.blob).toBeInstanceOf(Blob)
      expect(result.filename).toMatch(/\.json$/)
      expect(result.blob.type).toBe('application/json')
      
      // Read and parse JSON content using FileReader
      const text = await new Promise<string>((resolve) => {
        const reader = new FileReader()
        reader.onload = () => resolve(reader.result as string)
        reader.readAsText(result.blob)
      })
      const data = JSON.parse(text)
      
      expect(data.metadata).toBeDefined()
      expect(data.metadata.totalRecords).toBe(2)
      expect(data.businesses).toHaveLength(2)
      expect(data.businesses[0]['Business Name']).toBe('Test Business 1')
    })
  })

  describe('PDF Export', () => {
    it('should export businesses to PDF format', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'pdf')
      
      expect(result.blob).toBeInstanceOf(Blob)
      expect(result.filename).toMatch(/\.pdf$/)
      expect(result.blob.type).toBe('application/pdf')
    })
  })

  describe('Error Handling', () => {
    it('should throw error for unsupported format', async () => {
      await expect(
        exportService.exportBusinesses(mockBusinesses, 'unsupported' as any)
      ).rejects.toThrow('Unsupported export format: unsupported')
    })
  })

  describe('Export Options', () => {
    it('should respect includeHeaders option', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', {
        includeHeaders: false
      })
      
      const text = await new Promise<string>((resolve) => {
        const reader = new FileReader()
        reader.onload = () => resolve(reader.result as string)
        reader.readAsText(result.blob)
      })
      expect(text).not.toContain('Business Name')
      expect(text).toContain('Test Business 1')
    })

    it('should use custom delimiter for CSV', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', {
        delimiter: ';'
      })
      
      const text = await new Promise<string>((resolve) => {
        const reader = new FileReader()
        reader.onload = () => resolve(reader.result as string)
        reader.readAsText(result.blob)
      })
      expect(text).toContain(';')
    })
  })
})
