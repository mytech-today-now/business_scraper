/**
 * Tests for Enhanced Scraping Engine contact extraction improvements
 */

import { EnhancedScrapingEngine } from '@/lib/enhancedScrapingEngine'
import { ExtractedContact } from '@/lib/contactExtractor'

// Mock the logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('EnhancedScrapingEngine Contact Processing', () => {
  let scrapingEngine: EnhancedScrapingEngine

  beforeEach(() => {
    scrapingEngine = new EnhancedScrapingEngine()
  })

  describe('parseAndFormatAddress', () => {
    it('should parse a complete address correctly', () => {
      const rawAddress = '123 Main Street, Suite 100, New York, NY 10001'
      
      const result = (scrapingEngine as any).parseAndFormatAddress(rawAddress)
      
      expect(result).toEqual({
        street: '123 Main Street',
        suite: 'Suite 100',
        city: 'New York',
        state: 'NY',
        zipCode: '10001'
      })
    })

    it('should handle address without suite', () => {
      const rawAddress = '456 Oak Avenue, Los Angeles, CA 90210'
      
      const result = (scrapingEngine as any).parseAndFormatAddress(rawAddress)
      
      expect(result).toEqual({
        street: '456 Oak Avenue',
        suite: undefined,
        city: 'Los Angeles',
        state: 'CA',
        zipCode: '90210'
      })
    })

    it('should handle multiline address format', () => {
      const rawAddress = '789 Pine Street\nChicago, IL 60601'
      
      const result = (scrapingEngine as any).parseAndFormatAddress(rawAddress)
      
      expect(result).toEqual({
        street: '789 Pine Street',
        suite: undefined,
        city: 'Chicago',
        state: 'IL',
        zipCode: '60601'
      })
    })

    it('should handle empty or undefined address', () => {
      const result1 = (scrapingEngine as any).parseAndFormatAddress('')
      const result2 = (scrapingEngine as any).parseAndFormatAddress(undefined)
      
      const expectedEmpty = {
        street: '',
        city: '',
        state: '',
        zipCode: ''
      }
      
      expect(result1).toEqual(expectedEmpty)
      expect(result2).toEqual(expectedEmpty)
    })

    it('should handle address with apartment number', () => {
      const rawAddress = '321 Elm Street Apt 5B, Boston, MA 02101'
      
      const result = (scrapingEngine as any).parseAndFormatAddress(rawAddress)
      
      expect(result).toEqual({
        street: '321 Elm Street',
        suite: 'Apt 5B',
        city: 'Boston',
        state: 'MA',
        zipCode: '02101'
      })
    })
  })

  describe('extractContactPerson', () => {
    it('should extract contact person from structured data', () => {
      const contactInfo: ExtractedContact = {
        emails: [],
        phones: [],
        addresses: [],
        businessName: '',
        socialMedia: [],
        businessHours: [],
        contactForms: [],
        structuredData: [
          {
            type: 'Person',
            data: { name: 'John Smith' }
          }
        ],
        confidence: {
          email: 0,
          phone: 0,
          address: 0,
          businessName: 0,
          overall: 0
        }
      }
      
      const result = (scrapingEngine as any).extractContactPerson(contactInfo)
      
      expect(result).toBe('John Smith')
    })

    it('should extract contact person from organization contact point', () => {
      const contactInfo: ExtractedContact = {
        emails: [],
        phones: [],
        addresses: [],
        businessName: '',
        socialMedia: [],
        businessHours: [],
        contactForms: [],
        structuredData: [
          {
            type: 'Organization',
            data: { 
              contactPoint: { name: 'Jane Doe' }
            }
          }
        ],
        confidence: {
          email: 0,
          phone: 0,
          address: 0,
          businessName: 0,
          overall: 0
        }
      }
      
      const result = (scrapingEngine as any).extractContactPerson(contactInfo)
      
      expect(result).toBe('Jane Doe')
    })

    it('should extract contact person from business name with title', () => {
      const contactInfo: ExtractedContact = {
        emails: [],
        phones: [],
        addresses: [],
        businessName: 'Dr. Michael Johnson Medical Practice',
        socialMedia: [],
        businessHours: [],
        contactForms: [],
        structuredData: [],
        confidence: {
          email: 0,
          phone: 0,
          address: 0,
          businessName: 0,
          overall: 0
        }
      }
      
      const result = (scrapingEngine as any).extractContactPerson(contactInfo)
      
      expect(result).toBe('Michael Johnson')
    })

    it('should extract contact person from business name with professional suffix', () => {
      const contactInfo: ExtractedContact = {
        emails: [],
        phones: [],
        addresses: [],
        businessName: 'Sarah Wilson CPA',
        socialMedia: [],
        businessHours: [],
        contactForms: [],
        structuredData: [],
        confidence: {
          email: 0,
          phone: 0,
          address: 0,
          businessName: 0,
          overall: 0
        }
      }
      
      const result = (scrapingEngine as any).extractContactPerson(contactInfo)
      
      expect(result).toBe('Sarah Wilson')
    })

    it('should return undefined when no contact person found', () => {
      const contactInfo: ExtractedContact = {
        emails: [],
        phones: [],
        addresses: [],
        businessName: 'ABC Corporation',
        socialMedia: [],
        businessHours: [],
        contactForms: [],
        structuredData: [],
        confidence: {
          email: 0,
          phone: 0,
          address: 0,
          businessName: 0,
          overall: 0
        }
      }
      
      const result = (scrapingEngine as any).extractContactPerson(contactInfo)
      
      expect(result).toBeUndefined()
    })
  })

  describe('prioritizeEmails', () => {
    it('should prioritize business emails over personal ones', () => {
      const emails = [
        'noreply@example.com',
        'info@business.com',
        'john@personal.com',
        'contact@company.com'
      ]
      
      const result = (scrapingEngine as any).prioritizeEmails(emails)
      
      expect(result[0]).toBe('info@business.com')
      expect(result[1]).toBe('contact@company.com')
      expect(result).toContain('john@personal.com')
      expect(result[result.length - 1]).toBe('noreply@example.com')
    })

    it('should filter out invalid emails', () => {
      const emails = [
        'valid@business.com',
        'invalid-email',
        'another@valid.com'
      ]
      
      const result = (scrapingEngine as any).prioritizeEmails(emails)
      
      expect(result).toHaveLength(2)
      expect(result).toContain('valid@business.com')
      expect(result).toContain('another@valid.com')
    })
  })

  describe('formatPhoneNumber', () => {
    it('should format 10-digit US phone number', () => {
      const phone = '5551234567'
      
      const result = (scrapingEngine as any).formatPhoneNumber(phone)
      
      expect(result).toBe('(555) 123-4567')
    })

    it('should format 11-digit US phone number with country code', () => {
      const phone = '15551234567'
      
      const result = (scrapingEngine as any).formatPhoneNumber(phone)
      
      expect(result).toBe('+1 (555) 123-4567')
    })

    it('should handle phone number with existing formatting', () => {
      const phone = '(555) 123-4567'
      
      const result = (scrapingEngine as any).formatPhoneNumber(phone)
      
      expect(result).toBe('(555) 123-4567')
    })

    it('should return original for non-standard formats', () => {
      const phone = '+44 20 7946 0958'
      
      const result = (scrapingEngine as any).formatPhoneNumber(phone)
      
      expect(result).toBe('+44 20 7946 0958')
    })
  })
})
