import {
  formatPhoneNumber,
  formatEmail,
  formatAddress,
  formatBusinessName,
  formatDate,
  formatFileSize,
  formatDuration,
  formatNumber,
  formatPercentage,
  truncateText,
  sanitizeText,
  formatCoordinates,
  formatIndustry,
  formatUrl,
  formatCsvCell,
  formatBusinessForExport,
  formatAppVersion,
  formatVersionWithStatus,
} from '@/utils/formatters'
import { BusinessRecord } from '@/types/business'

describe('formatters', () => {
  describe('formatPhoneNumber', () => {
    it('should format 10-digit phone numbers', () => {
      expect(formatPhoneNumber('1234567890')).toBe('(123) 456-7890')
      expect(formatPhoneNumber('555-123-4567')).toBe('(555) 123-4567')
      expect(formatPhoneNumber('(555) 123-4567')).toBe('(555) 123-4567')
    })

    it('should format 11-digit phone numbers with country code', () => {
      expect(formatPhoneNumber('11234567890')).toBe('+1 (123) 456-7890')
      expect(formatPhoneNumber('1-555-123-4567')).toBe('+1 (555) 123-4567')
    })

    it('should return original for invalid formats', () => {
      expect(formatPhoneNumber('123')).toBe('123')
      expect(formatPhoneNumber('invalid')).toBe('invalid')
      expect(formatPhoneNumber('')).toBe('')
    })
  })

  describe('formatEmail', () => {
    it('should format valid emails', () => {
      expect(formatEmail('TEST@EXAMPLE.COM')).toBe('test@example.com')
      expect(formatEmail('  user@domain.org  ')).toBe('user@domain.org')
    })

    it('should return null for invalid emails', () => {
      expect(formatEmail('invalid-email')).toBeNull()
      expect(formatEmail('user@')).toBeNull()
      expect(formatEmail('@domain.com')).toBeNull()
      expect(formatEmail('')).toBeNull()
    })
  })

  describe('formatAddress', () => {
    it('should format complete addresses', () => {
      const address = {
        street: '123 Main St',
        suite: 'Suite 100',
        city: 'Anytown',
        state: 'CA',
        zipCode: '12345',
      }
      expect(formatAddress(address)).toBe('123 Main St, Suite 100, Anytown, CA, 12345')
    })

    it('should format addresses without suite', () => {
      const address = {
        street: '456 Oak Ave',
        city: 'Springfield',
        state: 'IL',
        zipCode: '62701',
      }
      expect(formatAddress(address)).toBe('456 Oak Ave, Springfield, IL, 62701')
    })

    it('should handle empty addresses', () => {
      expect(formatAddress(null as any)).toBe('')
      expect(formatAddress({} as any)).toBe('')
    })
  })

  describe('formatBusinessName', () => {
    it('should format business names with proper capitalization', () => {
      expect(formatBusinessName('acme corporation')).toBe('Acme Corporation')
      expect(formatBusinessName('SMITH & JONES LLC')).toBe('Smith & Jones LLC')
      expect(formatBusinessName('tech solutions inc')).toBe('Tech Solutions INC')
    })

    it('should handle common business abbreviations', () => {
      expect(formatBusinessName('example llc')).toBe('Example LLC')
      expect(formatBusinessName('test corp')).toBe('Test CORP')
      expect(formatBusinessName('demo co')).toBe('Demo CO')
    })

    it('should handle empty input', () => {
      expect(formatBusinessName('')).toBe('')
      expect(formatBusinessName('   ')).toBe('')
    })
  })

  describe('formatDate', () => {
    const testDate = new Date('2024-01-15T10:30:00Z')

    it('should format dates in short format', () => {
      const result = formatDate(testDate, 'short')
      expect(result).toMatch(/Jan 15, 2024/)
    })

    it('should format dates in long format', () => {
      const result = formatDate(testDate, 'long')
      expect(result).toMatch(/Monday, January 15, 2024/)
    })

    it('should format time', () => {
      const result = formatDate(testDate, 'time')
      expect(result).toMatch(/\d{1,2}:\d{2} (AM|PM)/)
    })

    it('should handle invalid dates', () => {
      expect(formatDate(null as any)).toBe('')
      expect(formatDate('invalid' as any)).toBe('')
    })
  })

  describe('formatFileSize', () => {
    it('should format bytes correctly', () => {
      expect(formatFileSize(0)).toBe('0 Bytes')
      expect(formatFileSize(1024)).toBe('1 KB')
      expect(formatFileSize(1048576)).toBe('1 MB')
      expect(formatFileSize(1073741824)).toBe('1 GB')
    })

    it('should handle decimal values', () => {
      expect(formatFileSize(1536)).toBe('1.5 KB')
      expect(formatFileSize(2621440)).toBe('2.5 MB')
    })
  })

  describe('formatDuration', () => {
    it('should format milliseconds', () => {
      expect(formatDuration(500)).toBe('500ms')
      expect(formatDuration(1000)).toBe('1s')
      expect(formatDuration(65000)).toBe('1m 5s')
      expect(formatDuration(3665000)).toBe('1h 1m 5s')
    })
  })

  describe('formatNumber', () => {
    it('should add thousand separators', () => {
      expect(formatNumber(1000)).toBe('1,000')
      expect(formatNumber(1234567)).toBe('1,234,567')
      expect(formatNumber(123)).toBe('123')
    })
  })

  describe('formatPercentage', () => {
    it('should format percentages', () => {
      expect(formatPercentage(0.5)).toBe('50.0%')
      expect(formatPercentage(0.1234, 2)).toBe('12.34%')
      expect(formatPercentage(1)).toBe('100.0%')
    })
  })

  describe('truncateText', () => {
    it('should truncate long text', () => {
      expect(truncateText('This is a long text', 10)).toBe('This is...')
      expect(truncateText('Short', 10)).toBe('Short')
      expect(truncateText('', 10)).toBe('')
    })
  })

  describe('sanitizeText', () => {
    it('should remove HTML tags', () => {
      expect(sanitizeText('<script>alert("xss")</script>Hello')).toBe('Hello')
      expect(sanitizeText('<p>Paragraph</p>')).toBe('Paragraph')
      expect(sanitizeText('Normal text')).toBe('Normal text')
    })

    it('should remove HTML entities', () => {
      expect(sanitizeText('Hello &amp; World')).toBe('Hello  World')
      expect(sanitizeText('&lt;test&gt;')).toBe('test')
    })
  })

  describe('formatCoordinates', () => {
    it('should format coordinates with default precision', () => {
      expect(formatCoordinates(40.7128, -74.006)).toBe('40.712800, -74.006000')
    })

    it('should format coordinates with custom precision', () => {
      expect(formatCoordinates(40.7128, -74.006, 2)).toBe('40.71, -74.01')
    })
  })

  describe('formatIndustry', () => {
    it('should format industry names', () => {
      expect(formatIndustry('food-service')).toBe('Food Service')
      expect(formatIndustry('healthcare_medical')).toBe('Healthcare Medical')
      expect(formatIndustry('RETAIL SHOPPING')).toBe('Retail Shopping')
      expect(formatIndustry('')).toBe('Unknown')
    })
  })

  describe('formatUrl', () => {
    it('should format URLs for display', () => {
      expect(formatUrl('https://www.example.com')).toBe('example.com')
      expect(formatUrl('http://subdomain.example.org/path')).toBe('subdomain.example.org')
      expect(formatUrl('https://example.net')).toBe('example.net')
    })

    it('should handle invalid URLs', () => {
      expect(formatUrl('invalid-url')).toBe('invalid-url')
      expect(formatUrl('')).toBe('')
    })
  })

  describe('formatCsvCell', () => {
    it('should escape CSV special characters', () => {
      expect(formatCsvCell('Hello, World')).toBe('"Hello, World"')
      expect(formatCsvCell('Quote "test"')).toBe('"Quote ""test"""')
      expect(formatCsvCell('Line\nbreak')).toBe('"Line\nbreak"')
      expect(formatCsvCell('Normal text')).toBe('Normal text')
    })

    it('should handle null and undefined', () => {
      expect(formatCsvCell(null)).toBe('')
      expect(formatCsvCell(undefined)).toBe('')
    })
  })

  describe('formatBusinessForExport', () => {
    it('should format business record for export', () => {
      const business: BusinessRecord = {
        id: '1',
        businessName: 'test company',
        email: ['test@example.com', 'info@example.com'],
        phone: '1234567890',
        websiteUrl: 'https://example.com',
        address: {
          street: '123 Main St',
          city: 'Anytown',
          state: 'CA',
          zipCode: '12345',
        },
        contactPerson: 'John Doe',
        coordinates: { lat: 40.7128, lng: -74.006 },
        industry: 'technology',
        scrapedAt: new Date('2024-01-15T12:00:00Z'),
      }

      const formatted = formatBusinessForExport(business)

      expect(formatted['Business Name']).toBe('Test Company')
      expect(formatted['Email']).toBe('test@example.com; info@example.com')
      expect(formatted['Phone']).toBe('(123) 456-7890')
      expect(formatted['Website']).toBe('https://example.com')
      expect(formatted['Address']).toBe('123 Main St, Anytown, CA, 12345')
      expect(formatted['Contact Person']).toBe('John Doe')
      expect(formatted['Industry']).toBe('Technology')
      expect(formatted['Coordinates']).toBe('40.712800, -74.006000')
      expect(formatted['Scraped Date']).toMatch(/Jan 15, 2024/)
    })
  })

  describe('formatAppVersion', () => {
    it('should format valid version strings', () => {
      expect(formatAppVersion('1.0.0')).toBe('1.0.0')
      expect(formatAppVersion('6.5.1234')).toBe('6.5.1234')
      expect(formatAppVersion('999.10.9999')).toBe('999.10.9999')
    })

    it('should format with prefix when requested', () => {
      expect(formatAppVersion('1.0.0', true)).toBe('v1.0.0')
      expect(formatAppVersion('6.5.1234', true)).toBe('v6.5.1234')
    })

    it('should return original string for invalid versions', () => {
      expect(formatAppVersion('invalid')).toBe('invalid')
      expect(formatAppVersion('1.2.3.4')).toBe('1.2.3.4')
      expect(formatAppVersion('')).toBe('')
    })

    it('should handle v prefix in input', () => {
      expect(formatAppVersion('v1.0.0')).toBe('1.0.0')
      expect(formatAppVersion('v1.0.0', true)).toBe('v1.0.0')
    })
  })

  describe('formatVersionWithStatus', () => {
    it('should format valid versions with status', () => {
      const result = formatVersionWithStatus('1.0.0')
      expect(result.formatted).toBe('1.0.0')
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should handle invalid version format', () => {
      const result = formatVersionWithStatus('invalid')
      expect(result.formatted).toBe('invalid')
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Invalid version format. Expected: 1-999.0-10.0-9999')
    })

    it('should handle empty version string', () => {
      const result = formatVersionWithStatus('')
      expect(result.formatted).toBe('')
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Version string is empty')
    })

    it('should handle versions outside constraints', () => {
      const result = formatVersionWithStatus('1000.0.0')
      expect(result.formatted).toBe('1000.0.0')
      expect(result.isValid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })

    it('should provide warnings for edge cases', () => {
      const result = formatVersionWithStatus('999.10.9999')
      expect(result.formatted).toBe('999.10.9999')
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })
  })
})
