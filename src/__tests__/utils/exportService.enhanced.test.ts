/**
 * Enhanced Export Service Tests
 * Tests for new export functionality including filename standardization,
 * filtered exports, and custom templates
 */

import { ExportService, ExportContext, ExportTemplate } from '@/utils/exportService'
import { BusinessRecord } from '@/types/business'

// Mock business data for testing
const mockBusinesses: BusinessRecord[] = [
  {
    id: '1',
    businessName: 'Test Legal Firm',
    email: ['contact@testlegal.com'],
    phone: '+1-555-0123',
    websiteUrl: 'https://testlegal.com',
    address: {
      street: '123 Main St',
      city: 'Anytown',
      state: 'CA',
      zipCode: '12345'
    },
    industry: 'Legal Services',
    contactPerson: 'John Doe',
    coordinates: { lat: 40.7128, lng: -74.0060 },
    scrapedAt: new Date('2025-01-15T10:30:00Z'),
    confidence: 0.95,
    source: 'test'
  },
  {
    id: '2',
    businessName: 'Another Legal Office',
    email: ['info@anotherlegal.com'],
    phone: '+1-555-0456',
    websiteUrl: 'https://anotherlegal.com',
    address: {
      street: '456 Oak Ave',
      city: 'Somewhere',
      state: 'NY',
      zipCode: '67890'
    },
    industry: 'Legal Services',
    contactPerson: 'Jane Smith',
    coordinates: { lat: 40.7589, lng: -73.9851 },
    scrapedAt: new Date('2025-01-15T11:00:00Z'),
    confidence: 0.88,
    source: 'test'
  }
]

describe('ExportService Enhanced Features', () => {
  let exportService: ExportService

  // Helper function to read blob content
  const readBlobAsText = async (blob: Blob): Promise<string> => {
    return new Promise((resolve) => {
      const reader = new FileReader()
      reader.onload = () => resolve(reader.result as string)
      reader.readAsText(blob)
    })
  }

  beforeEach(() => {
    exportService = new ExportService()
    // Mock Date.now() for consistent filename testing
    jest.spyOn(Date.prototype, 'getFullYear').mockReturnValue(2025)
    jest.spyOn(Date.prototype, 'getMonth').mockReturnValue(0) // January (0-indexed)
    jest.spyOn(Date.prototype, 'getDate').mockReturnValue(19)
    jest.spyOn(Date.prototype, 'getHours').mockReturnValue(14)
    jest.spyOn(Date.prototype, 'getMinutes').mockReturnValue(30)
    // Note: Seconds removed from new filename format
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Filename Standardization', () => {
    it('should generate standardized filename for single industry', async () => {
      const context: ExportContext = {
        selectedIndustries: ['Legal Services'],
        totalResults: 2
      }

      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', { context })
      
      expect(result.filename).toBe('2025-01-19_14-30_Legal-Services_2.csv')
    })

    it('should generate standardized filename for multiple industries', async () => {
      const context: ExportContext = {
        selectedIndustries: ['Legal Services', 'Medical Services', 'Financial Services'],
        totalResults: 2
      }

      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', { context })
      
      expect(result.filename).toBe('2025-01-19_14-30_Legal-Services-Medical-Services-Financial-Services_2.csv')
    })

    it('should generate standardized filename for many industries', async () => {
      const context: ExportContext = {
        selectedIndustries: ['Legal', 'Medical', 'Financial', 'Technology', 'Retail'],
        totalResults: 2
      }

      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', { context })
      
      expect(result.filename).toBe('2025-01-19_14-30_Multiple-Industries_2.csv')
    })

    it('should handle filtered export count in filename', async () => {
      const context: ExportContext = {
        selectedIndustries: ['Legal Services'],
        totalResults: 2
      }

      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', { 
        context,
        selectedBusinesses: ['1'] // Only export first business
      })
      
      expect(result.filename).toBe('2025-01-19_14-30_Legal-Services_1.csv')
    })

    it('should sanitize industry names in filename', async () => {
      const context: ExportContext = {
        selectedIndustries: ['Legal & Law Services'],
        totalResults: 2
      }

      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', { context })
      
      expect(result.filename).toBe('2025-01-19_14-30_Legal-Law-Services_2.csv')
    })
  })

  describe('Filtered Exports', () => {
    it('should export only selected businesses', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'json', {
        selectedBusinesses: ['1']
      })

      const exportData = JSON.parse(await readBlobAsText(result.blob))
      expect(exportData.businesses).toHaveLength(1)
      expect(exportData.businesses[0]['Business Name']).toBe('Test Legal Firm')
      expect(exportData.metadata.totalRecords).toBe(1)
    })

    it('should handle empty selection gracefully', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'json', {
        selectedBusinesses: []
      })

      const exportData = JSON.parse(await readBlobAsText(result.blob))
      expect(exportData.businesses).toHaveLength(0)
      expect(exportData.metadata.totalRecords).toBe(0)
    })

    it('should handle non-existent business IDs', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'json', {
        selectedBusinesses: ['999'] // Non-existent ID
      })

      const exportData = JSON.parse(await readBlobAsText(result.blob))
      expect(exportData.businesses).toHaveLength(0)
    })
  })

  // Define templates at describe level for reuse
  const basicTemplate: ExportTemplate = {
    name: 'Basic Contact',
    fields: ['businessName', 'email', 'phone'],
    customHeaders: {
      businessName: 'Company Name',
      email: 'Email Address',
      phone: 'Phone Number'
    }
  }

  const locationTemplate: ExportTemplate = {
    name: 'Location Data',
    fields: ['businessName', 'address.street', 'address.city', 'coordinates.lat', 'coordinates.lng'],
    customHeaders: {
      businessName: 'Business Name',
      'address.street': 'Street Address',
      'address.city': 'City',
      'coordinates.lat': 'Latitude',
      'coordinates.lng': 'Longitude'
    }
  }

  describe('Custom Export Templates', () => {

    it('should apply basic template to CSV export', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', {
        template: basicTemplate
      })

      const csvContent = await readBlobAsText(result.blob)
      const lines = csvContent.split('\n')
      
      // Check headers
      expect(lines[0]).toBe('Company Name,Email Address,Phone Number')
      
      // Check first data row
      expect(lines[1]).toBe('Test Legal Firm,contact@testlegal.com,+1-555-0123')
    })

    it('should apply location template with nested fields', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', {
        template: locationTemplate
      })

      const csvContent = await readBlobAsText(result.blob)
      const lines = csvContent.split('\n')
      
      // Check headers
      expect(lines[0]).toBe('Business Name,Street Address,City,Latitude,Longitude')
      
      // Check first data row
      expect(lines[1]).toBe('Test Legal Firm,123 Main St,Anytown,40.712800,-74.006000')
    })

    it('should apply template to JSON export', async () => {
      const result = await exportService.exportBusinesses(mockBusinesses, 'json', {
        template: basicTemplate
      })

      const exportData = JSON.parse(await readBlobAsText(result.blob))
      const firstBusiness = exportData.businesses[0]
      
      expect(Object.keys(firstBusiness)).toEqual(['Company Name', 'Email Address', 'Phone Number'])
      expect(firstBusiness['Company Name']).toBe('Test Legal Firm')
      expect(firstBusiness['Email Address']).toBe('contact@testlegal.com')
    })

    it('should handle missing fields gracefully', async () => {
      const templateWithMissingField: ExportTemplate = {
        name: 'Test Template',
        fields: ['businessName', 'nonExistentField'],
        customHeaders: {
          businessName: 'Company Name',
          nonExistentField: 'Missing Field'
        }
      }

      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', {
        template: templateWithMissingField
      })

      const csvContent = await readBlobAsText(result.blob)
      const lines = csvContent.split('\n')
      
      expect(lines[0]).toBe('Company Name,Missing Field')
      expect(lines[1]).toBe('Test Legal Firm,') // Empty value for missing field
    })
  })

  describe('Format Support', () => {
    it('should return primary formats by default', () => {
      const formats = exportService.getSupportedFormats()
      expect(formats).toEqual(['csv', 'xlsx', 'pdf'])
    })

    it('should return all formats when requested', () => {
      const formats = exportService.getSupportedFormats(true)
      expect(formats).toEqual(['csv', 'xlsx', 'xls', 'ods', 'pdf', 'json', 'xml', 'vcf', 'sql'])
    })
  })

  describe('Integration Tests', () => {
    it('should combine all features: filtered export with template and custom filename', async () => {
      const context: ExportContext = {
        selectedIndustries: ['Legal Services'],
        totalResults: 2
      }

      const result = await exportService.exportBusinesses(mockBusinesses, 'csv', {
        context,
        selectedBusinesses: ['1'],
        template: basicTemplate
      })

      // Check filename
      expect(result.filename).toBe('2025-01-19_14-30_Legal-Services_1.csv')

      // Check content
      const csvContent = await readBlobAsText(result.blob)
      const lines = csvContent.split('\n')
      
      expect(lines[0]).toBe('Company Name,Email Address,Phone Number')
      expect(lines[1]).toBe('Test Legal Firm,contact@testlegal.com,+1-555-0123')
      expect(lines[2]).toBe('') // Only one business exported
    })
  })
})
