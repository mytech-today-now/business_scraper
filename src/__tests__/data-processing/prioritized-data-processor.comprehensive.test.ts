/**
 * Prioritized Data Processor - Comprehensive Test Suite
 * Tests business record prioritization, deduplication, and processing
 */

import { prioritizedDataProcessor, PrioritizedBusinessRecord } from '@/lib/prioritizedDataProcessor'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')

const mockLogger = logger as jest.Mocked<typeof logger>

describe('Prioritized Data Processor - Comprehensive Tests', () => {
  const createMockBusinessRecord = (overrides: Partial<BusinessRecord> = {}): BusinessRecord => ({
    id: 'test-business-1',
    businessName: 'Test Business',
    email: ['test@business.com'],
    phone: '555-0123',
    websiteUrl: 'https://testbusiness.com',
    address: {
      street: '123 Main St',
      city: 'Test City',
      state: 'CA',
      zipCode: '90210',
      country: 'US',
    },
    industry: 'Technology',
    scrapedAt: new Date(),
    ...overrides,
  })

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Business Record Conversion', () => {
    it('should convert business record to prioritized format correctly', async () => {
      const business = createMockBusinessRecord({
        email: ['primary@business.com', 'secondary@business.com'],
        phone: '555-0123',
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])

      expect(result.processedRecords).toHaveLength(1)
      const prioritized = result.processedRecords[0]

      expect(prioritized.businessName).toBe('Test Business')
      expect(prioritized.email).toBe('primary@business.com') // Primary email only
      expect(prioritized.phone).toBe('5550123') // Cleaned format
      expect(prioritized.priority).toBeGreaterThan(0)
    })

    it('should handle empty contact information gracefully', async () => {
      const business = createMockBusinessRecord({
        email: [],
        phone: undefined,
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: '',
          country: 'US',
        },
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])

      expect(result.processedRecords).toHaveLength(0) // Should be filtered out
      expect(result.stats.totalRecords).toBe(1)
      expect(result.stats.finalRecords).toBe(0)
    })

    it('should prioritize businesses with complete contact information', async () => {
      const businessWithEmail = createMockBusinessRecord({
        id: 'business-1',
        email: ['contact@business1.com'],
        phone: undefined,
      })

      const businessWithPhone = createMockBusinessRecord({
        id: 'business-2',
        email: [],
        phone: '555-0123',
      })

      const businessWithBoth = createMockBusinessRecord({
        id: 'business-3',
        email: ['contact@business3.com'],
        phone: '555-0124',
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([
        businessWithEmail,
        businessWithPhone,
        businessWithBoth,
      ])

      expect(result.processedRecords).toHaveLength(3)

      // Business with both email and phone should have highest priority
      const businessWithBothProcessed = result.processedRecords.find(b => b.id === 'business-3')
      const businessWithEmailProcessed = result.processedRecords.find(b => b.id === 'business-1')

      expect(businessWithBothProcessed?.priority).toBeGreaterThan(businessWithEmailProcessed?.priority || 0)
    })
  })

  describe('Email Prioritization', () => {
    it('should prioritize business emails over personal emails', async () => {
      const business = createMockBusinessRecord({
        email: ['john@gmail.com', 'contact@business.com', 'info@business.com'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])
      const prioritized = result.processedRecords[0]

      expect(prioritized.email[0]).toBe('contact@business.com')
      expect(prioritized.email[1]).toBe('info@business.com')
      expect(prioritized.email[2]).toBe('john@gmail.com')
    })

    it('should remove invalid email addresses', async () => {
      const business = createMockBusinessRecord({
        email: ['valid@business.com', 'invalid-email', '', 'another@business.com'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])
      const prioritized = result.processedRecords[0]

      expect(prioritized.email).toEqual(['valid@business.com', 'another@business.com'])
      expect(prioritized.email).not.toContain('invalid-email')
      expect(prioritized.email).not.toContain('')
    })

    it('should remove duplicate emails', async () => {
      const business = createMockBusinessRecord({
        email: ['contact@business.com', 'CONTACT@BUSINESS.COM', 'contact@business.com'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])
      const prioritized = result.processedRecords[0]

      expect(prioritized.email).toEqual(['contact@business.com'])
    })

    it('should handle email priority patterns correctly', async () => {
      const business = createMockBusinessRecord({
        email: [
          'noreply@business.com',
          'contact@business.com',
          'sales@business.com',
          'info@business.com',
          'admin@business.com',
        ],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])
      const prioritized = result.processedRecords[0]

      // High priority emails should come first
      expect(prioritized.email[0]).toBe('contact@business.com')
      expect(prioritized.email[1]).toBe('sales@business.com')
      expect(prioritized.email[2]).toBe('info@business.com')
      // Low priority emails should come last
      expect(prioritized.email[prioritized.email.length - 1]).toBe('noreply@business.com')
    })
  })

  describe('Phone Number Processing', () => {
    it('should clean and format phone numbers', async () => {
      const business = createMockBusinessRecord({
        phone: ['(555) 123-4567', '555.987.6543', '555-111-2222'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])
      const prioritized = result.processedRecords[0]

      expect(prioritized.phone).toEqual(['5551234567', '5559876543', '5551112222'])
    })

    it('should remove invalid phone numbers', async () => {
      const business = createMockBusinessRecord({
        phone: ['555-123-4567', '123', 'invalid-phone', '555-987-6543'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])
      const prioritized = result.processedRecords[0]

      expect(prioritized.phone).toEqual(['5551234567', '5559876543'])
      expect(prioritized.phone).not.toContain('123')
      expect(prioritized.phone).not.toContain('invalid-phone')
    })

    it('should remove duplicate phone numbers', async () => {
      const business = createMockBusinessRecord({
        phone: ['555-123-4567', '(555) 123-4567', '555.123.4567'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])
      const prioritized = result.processedRecords[0]

      expect(prioritized.phone).toEqual(['5551234567'])
    })
  })

  describe('Deduplication Logic', () => {
    it('should detect and remove exact duplicates', async () => {
      const business1 = createMockBusinessRecord({
        id: 'business-1',
        businessName: 'Test Business',
        email: ['contact@test.com'],
      })

      const business2 = createMockBusinessRecord({
        id: 'business-2',
        businessName: 'Test Business',
        email: ['contact@test.com'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business1, business2])

      expect(result.processedRecords).toHaveLength(1)
      expect(result.stats.duplicatesRemoved).toBe(1)
      expect(result.stats.finalRecords).toBe(1)
    })

    it('should detect duplicates by email', async () => {
      const business1 = createMockBusinessRecord({
        id: 'business-1',
        businessName: 'Business One',
        email: ['shared@business.com'],
      })

      const business2 = createMockBusinessRecord({
        id: 'business-2',
        businessName: 'Business Two',
        email: ['shared@business.com'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business1, business2])

      expect(result.processedRecords).toHaveLength(1)
      expect(result.stats.duplicatesRemoved).toBe(1)
    })

    it('should detect duplicates by phone number', async () => {
      const business1 = createMockBusinessRecord({
        id: 'business-1',
        businessName: 'Business One',
        phone: ['555-123-4567'],
        email: ['one@business.com'],
      })

      const business2 = createMockBusinessRecord({
        id: 'business-2',
        businessName: 'Business Two',
        phone: ['(555) 123-4567'],
        email: ['two@business.com'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business1, business2])

      expect(result.processedRecords).toHaveLength(1)
      expect(result.stats.duplicatesRemoved).toBe(1)
    })

    it('should keep the record with higher priority when deduplicating', async () => {
      const businessLowPriority = createMockBusinessRecord({
        id: 'business-1',
        businessName: 'Test Business',
        email: ['contact@test.com'],
        phone: [],
      })

      const businessHighPriority = createMockBusinessRecord({
        id: 'business-2',
        businessName: 'Test Business',
        email: ['contact@test.com'],
        phone: ['555-123-4567'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([
        businessLowPriority,
        businessHighPriority,
      ])

      expect(result.processedRecords).toHaveLength(1)
      expect(result.processedRecords[0].id).toBe('business-2')
      expect(result.processedRecords[0].phone).toEqual(['5551234567'])
    })
  })

  describe('Filtering Logic', () => {
    it('should filter out businesses without valuable contact information', async () => {
      const businessWithEmail = createMockBusinessRecord({
        id: 'business-1',
        email: ['contact@business.com'],
        phone: [],
        streetName: '',
      })

      const businessWithPhone = createMockBusinessRecord({
        id: 'business-2',
        email: [],
        phone: ['555-123-4567'],
        streetName: '',
      })

      const businessWithAddress = createMockBusinessRecord({
        id: 'business-3',
        email: [],
        phone: [],
        streetName: 'Main St',
        streetNumber: '123',
        city: 'Test City',
        zipCode: '90210',
      })

      const businessWithNothing = createMockBusinessRecord({
        id: 'business-4',
        email: [],
        phone: [],
        streetName: '',
        streetNumber: '',
        city: '',
        zipCode: '',
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([
        businessWithEmail,
        businessWithPhone,
        businessWithAddress,
        businessWithNothing,
      ])

      expect(result.processedRecords).toHaveLength(3)
      expect(result.processedRecords.map(b => b.id)).toEqual([
        'business-1',
        'business-2',
        'business-3',
      ])
    })

    it('should count records with different contact types correctly', async () => {
      const businesses = [
        createMockBusinessRecord({ id: '1', email: ['test@1.com'], phone: [], streetName: '' }),
        createMockBusinessRecord({ id: '2', email: [], phone: ['555-0123'], streetName: '' }),
        createMockBusinessRecord({ id: '3', email: [], phone: [], streetName: 'Main St', city: 'City', zipCode: '12345' }),
        createMockBusinessRecord({ id: '4', email: ['test@4.com'], phone: ['555-0124'], streetName: 'Oak St' }),
      ]

      const result = await prioritizedDataProcessor.processBusinessRecords(businesses)

      expect(result.stats.recordsWithEmail).toBe(2)
      expect(result.stats.recordsWithPhone).toBe(2)
      expect(result.stats.recordsWithAddress).toBe(2)
    })
  })

  describe('Priority Calculation', () => {
    it('should calculate priority based on contact information completeness', async () => {
      const businessMinimal = createMockBusinessRecord({
        id: 'business-1',
        email: ['contact@business.com'],
        phone: [],
        website: '',
      })

      const businessComplete = createMockBusinessRecord({
        id: 'business-2',
        email: ['contact@business.com', 'sales@business.com'],
        phone: ['555-123-4567', '555-987-6543'],
        website: 'https://business.com',
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([
        businessMinimal,
        businessComplete,
      ])

      const minimalPriority = result.processedRecords.find(b => b.id === 'business-1')?.priority
      const completePriority = result.processedRecords.find(b => b.id === 'business-2')?.priority

      expect(completePriority).toBeGreaterThan(minimalPriority || 0)
    })

    it('should assign higher priority to businesses with professional emails', async () => {
      const businessPersonalEmail = createMockBusinessRecord({
        id: 'business-1',
        email: ['john@gmail.com'],
      })

      const businessProfessionalEmail = createMockBusinessRecord({
        id: 'business-2',
        email: ['contact@business.com'],
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([
        businessPersonalEmail,
        businessProfessionalEmail,
      ])

      const personalPriority = result.processedRecords.find(b => b.id === 'business-1')?.priority
      const professionalPriority = result.processedRecords.find(b => b.id === 'business-2')?.priority

      expect(professionalPriority).toBeGreaterThan(personalPriority || 0)
    })
  })

  describe('Performance and Statistics', () => {
    it('should provide accurate processing statistics', async () => {
      const businesses = [
        createMockBusinessRecord({ id: '1', email: ['test@1.com'] }),
        createMockBusinessRecord({ id: '2', email: ['test@1.com'] }), // Duplicate
        createMockBusinessRecord({ id: '3', phone: ['555-0123'] }),
        createMockBusinessRecord({ id: '4', email: [], phone: [] }), // No contact info
      ]

      const result = await prioritizedDataProcessor.processBusinessRecords(businesses)

      expect(result.stats.totalRecords).toBe(4)
      expect(result.stats.duplicatesRemoved).toBe(1)
      expect(result.stats.finalRecords).toBe(2)
      expect(result.stats.recordsWithEmail).toBe(2)
      expect(result.stats.recordsWithPhone).toBe(1)
    })

    it('should handle large datasets efficiently', async () => {
      const businesses = Array.from({ length: 1000 }, (_, i) =>
        createMockBusinessRecord({
          id: `business-${i}`,
          businessName: `Business ${i}`,
          email: [`contact${i}@business.com`],
        })
      )

      const startTime = Date.now()
      const result = await prioritizedDataProcessor.processBusinessRecords(businesses)
      const endTime = Date.now()

      expect(result.processedRecords).toHaveLength(1000)
      expect(endTime - startTime).toBeLessThan(5000) // Should complete within 5 seconds
      expect(mockLogger.info).toHaveBeenCalledWith(
        'PrioritizedDataProcessor',
        'Processing 1000 business records'
      )
    })
  })

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty input gracefully', async () => {
      const result = await prioritizedDataProcessor.processBusinessRecords([])

      expect(result.processedRecords).toHaveLength(0)
      expect(result.stats.totalRecords).toBe(0)
      expect(result.stats.finalRecords).toBe(0)
    })

    it('should handle malformed business records', async () => {
      const malformedBusiness = {
        ...createMockBusinessRecord(),
        email: null as any,
        phone: undefined as any,
      }

      const result = await prioritizedDataProcessor.processBusinessRecords([malformedBusiness])

      expect(result.processedRecords).toHaveLength(0) // Should be filtered out
    })

    it('should handle very long contact lists', async () => {
      const business = createMockBusinessRecord({
        email: Array.from({ length: 100 }, (_, i) => `email${i}@business.com`),
        phone: Array.from({ length: 50 }, (_, i) => `555-${String(i).padStart(4, '0')}`),
      })

      const result = await prioritizedDataProcessor.processBusinessRecords([business])

      expect(result.processedRecords).toHaveLength(1)
      expect(result.processedRecords[0].email.length).toBeLessThanOrEqual(100)
      expect(result.processedRecords[0].phone.length).toBeLessThanOrEqual(50)
    })
  })
})

describe('AI Lead Scoring Integration', () => {
  it('should integrate with AI lead scoring for priority calculation', async () => {
    const highValueBusiness = createMockBusinessRecord({
      id: 'high-value',
      businessName: 'Enterprise Solutions Inc',
      email: ['ceo@enterprise.com'],
      phone: ['555-0123'],
      website: 'https://enterprise.com',
      industry: 'Technology',
      description: 'Leading enterprise software provider with 500+ employees',
    })

    const lowValueBusiness = createMockBusinessRecord({
      id: 'low-value',
      businessName: 'Small Shop',
      email: ['owner@gmail.com'],
      phone: [],
      website: '',
      industry: 'Retail',
      description: 'Small local shop',
    })

    const result = await prioritizedDataProcessor.processBusinessRecords([
      highValueBusiness,
      lowValueBusiness,
    ])

    const highValueProcessed = result.processedRecords.find(b => b.id === 'high-value')
    const lowValueProcessed = result.processedRecords.find(b => b.id === 'low-value')

    expect(highValueProcessed?.priority).toBeGreaterThan(lowValueProcessed?.priority || 0)
  })
})
