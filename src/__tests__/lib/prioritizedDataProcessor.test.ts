/**
 * Test suite for PrioritizedDataProcessor
 */

import { PrioritizedDataProcessor } from '@/lib/prioritizedDataProcessor'
import { BusinessRecord } from '@/types/business'

describe('PrioritizedDataProcessor', () => {
  let processor: PrioritizedDataProcessor

  beforeEach(() => {
    processor = new PrioritizedDataProcessor()
  })

  describe('processBusinessRecords', () => {
    it('should prioritize email addresses correctly', async () => {
      const records: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'Test Company',
          email: ['noreply@test.com', 'info@test.com', 'contact@test.com'],
          phone: '555-123-4567',
          websiteUrl: 'https://test.com',
          address: {
            street: '123 Main St',
            city: 'Test City',
            state: 'CA',
            zipCode: '12345'
          },
          industry: 'Technology',
          scrapedAt: new Date()
        }
      ]

      const result = await processor.processBusinessRecords(records)
      
      expect(result.processedRecords).toHaveLength(1)
      expect(result.processedRecords[0].email).toBe('info@test.com') // Should prioritize info@ over others
      expect(result.processedRecords[0].additionalEmails).toContain('contact@test.com')
      expect(result.processedRecords[0].additionalEmails).toContain('noreply@test.com')
    })

    it('should remove duplicates based on priority fields', async () => {
      const records: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'Test Company A',
          email: ['info@test.com'],
          phone: '555-123-4567',
          websiteUrl: 'https://test.com',
          address: {
            street: '123 Main St',
            city: 'Test City',
            state: 'CA',
            zipCode: '12345'
          },
          industry: 'Technology',
          scrapedAt: new Date()
        },
        {
          id: '2',
          businessName: 'Test Company B', // Different name but same contact info
          email: ['info@test.com'], // Same email
          phone: '555-123-4567', // Same phone
          websiteUrl: 'https://test2.com',
          address: {
            street: '123 Main St', // Same address
            city: 'Test City',
            state: 'CA',
            zipCode: '12345'
          },
          industry: 'Technology',
          scrapedAt: new Date()
        }
      ]

      const result = await processor.processBusinessRecords(records)
      
      expect(result.processedRecords).toHaveLength(1) // Should deduplicate
      expect(result.stats.duplicatesRemoved).toBe(1)
      expect(result.processedRecords[0].sources).toHaveLength(2) // Should merge sources
    })

    it('should filter out records without valuable contact information', async () => {
      const records: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'Good Company',
          email: ['info@good.com'],
          phone: '555-123-4567',
          websiteUrl: 'https://good.com',
          address: {
            street: '123 Main St',
            city: 'Test City',
            state: 'CA',
            zipCode: '12345'
          },
          industry: 'Technology',
          scrapedAt: new Date()
        },
        {
          id: '2',
          businessName: 'Bad Company',
          email: [], // No email
          phone: '', // No phone
          websiteUrl: 'https://bad.com',
          address: {
            street: '', // No address
            city: '',
            state: '',
            zipCode: ''
          },
          industry: 'Technology',
          scrapedAt: new Date()
        }
      ]

      const result = await processor.processBusinessRecords(records)
      
      expect(result.processedRecords).toHaveLength(1) // Should filter out bad record
      expect(result.processedRecords[0].businessName).toBe('Good Company')
    })

    it('should calculate confidence scores correctly', async () => {
      const records: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'High Quality Company',
          email: ['info@company.com', 'sales@company.com'],
          phone: '555-123-4567',
          websiteUrl: 'https://company.com',
          address: {
            street: '123 Business Ave',
            city: 'Business City',
            state: 'CA',
            zipCode: '12345'
          },
          contactPerson: 'John Doe',
          industry: 'Technology',
          scrapedAt: new Date()
        },
        {
          id: '2',
          businessName: 'Low Quality Company',
          email: ['test@example.com'],
          phone: '',
          websiteUrl: 'https://example.com',
          address: {
            street: '',
            city: '',
            state: '',
            zipCode: ''
          },
          industry: 'Technology',
          scrapedAt: new Date()
        }
      ]

      const result = await processor.processBusinessRecords(records)
      
      expect(result.processedRecords).toHaveLength(2)
      
      const highQuality = result.processedRecords.find(r => r.businessName === 'High Quality Company')
      const lowQuality = result.processedRecords.find(r => r.businessName === 'Low Quality Company')
      
      expect(highQuality?.confidence).toBeGreaterThan(lowQuality?.confidence || 0)
    })

    it('should clean and format data correctly', async () => {
      const records: BusinessRecord[] = [
        {
          id: '1',
          businessName: '  test   company   llc  ',
          email: ['  INFO@TEST.COM  ', 'Contact@Test.Com'],
          phone: '(555) 123-4567',
          websiteUrl: 'https://test.com',
          address: {
            street: '  123   main   st  ',
            city: '  test   city  ',
            state: 'ca',
            zipCode: '12345-6789'
          },
          industry: 'Technology',
          scrapedAt: new Date()
        }
      ]

      const result = await processor.processBusinessRecords(records)
      
      expect(result.processedRecords).toHaveLength(1)
      const record = result.processedRecords[0]
      
      expect(record.businessName).toBe('test company llc') // Cleaned spacing
      expect(record.email).toBe('info@test.com') // Lowercase and trimmed
      expect(record.streetAddress).toBe('123 main st') // Cleaned spacing
      expect(record.city).toBe('test city') // Cleaned spacing
      expect(record.state).toBe('CA') // Uppercase
      expect(record.zipCode).toBe('12345-6789') // Preserved format
    })

    it('should generate processing statistics', async () => {
      const records: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'Company 1',
          email: ['info@company1.com'],
          phone: '555-123-4567',
          websiteUrl: 'https://company1.com',
          address: {
            street: '123 Main St',
            city: 'City 1',
            state: 'CA',
            zipCode: '12345'
          },
          industry: 'Technology',
          scrapedAt: new Date()
        },
        {
          id: '2',
          businessName: 'Company 2',
          email: [],
          phone: '555-987-6543',
          websiteUrl: 'https://company2.com',
          address: {
            street: '',
            city: '',
            state: '',
            zipCode: ''
          },
          industry: 'Technology',
          scrapedAt: new Date()
        }
      ]

      const result = await processor.processBusinessRecords(records)
      
      expect(result.stats.totalRecords).toBe(2)
      expect(result.stats.recordsWithEmail).toBe(1)
      expect(result.stats.recordsWithPhone).toBe(2)
      expect(result.stats.recordsWithAddress).toBe(1)
      expect(result.stats.finalRecords).toBe(2)
      expect(result.stats.duplicatesRemoved).toBe(0)
    })
  })
})
