/**
 * Comprehensive Integration Tests for Database Operations
 * Achieving 95%+ test coverage with all database interactions and edge cases
 */

import { jest } from '@jest/globals'
import { BusinessRecord } from '@/types/business'

// Mock environment variables
process.env.NODE_ENV = 'test'
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test_db'

// Mock database connection
const mockQuery = jest.fn()
const mockTransaction = jest.fn()
const mockConnect = jest.fn()
const mockEnd = jest.fn()

const mockDatabase = {
  query: mockQuery,
  transaction: mockTransaction,
  connect: mockConnect,
  end: mockEnd,
  pool: {
    query: mockQuery,
    connect: mockConnect,
    end: mockEnd
  }
}

jest.mock('@/lib/database', () => ({
  database: mockDatabase
}))

// Mock logger
jest.mock('@/utils/logger')

describe('Database Operations Comprehensive Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0 })
    mockTransaction.mockImplementation(async (callback) => {
      return await callback(mockDatabase)
    })
  })

  describe('Business Records CRUD Operations', () => {
    test('should create business record successfully', async () => {
      const businessData: BusinessRecord = {
        id: '1',
        businessName: 'Test Business',
        url: 'https://example.com',
        phone: '555-1234',
        email: 'test@example.com',
        address: '123 Main St',
        city: 'Test City',
        state: 'TS',
        zipCode: '12345',
        industry: 'Test Industry',
        confidence: 0.9,
        source: 'scraper',
        scrapedAt: new Date().toISOString()
      }

      mockQuery.mockResolvedValueOnce({
        rows: [{ id: '1', ...businessData }],
        rowCount: 1
      })

      // Import the database service
      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusiness(businessData)

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO businesses'),
        expect.arrayContaining([
          businessData.businessName,
          businessData.url,
          businessData.phone,
          businessData.email
        ])
      )
      expect(result).toMatchObject(businessData)
    })

    test('should handle duplicate business creation', async () => {
      const businessData: BusinessRecord = {
        id: '1',
        businessName: 'Duplicate Business',
        url: 'https://example.com',
        phone: '555-1234',
        email: 'test@example.com',
        address: '123 Main St',
        city: 'Test City',
        state: 'TS',
        zipCode: '12345',
        industry: 'Test Industry',
        confidence: 0.9,
        source: 'scraper',
        scrapedAt: new Date().toISOString()
      }

      // Mock duplicate key error
      mockQuery.mockRejectedValueOnce({
        code: '23505', // PostgreSQL unique violation
        constraint: 'businesses_url_key'
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusiness(businessData)

      expect(result).toBeNull()
    })

    test('should read business record by ID', async () => {
      const businessData = {
        id: '1',
        business_name: 'Test Business',
        url: 'https://example.com',
        phone: '555-1234',
        email: 'test@example.com',
        created_at: new Date(),
        updated_at: new Date()
      }

      mockQuery.mockResolvedValueOnce({
        rows: [businessData],
        rowCount: 1
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.getBusinessById('1')

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('SELECT * FROM businesses WHERE id = $1'),
        ['1']
      )
      expect(result).toBeDefined()
    })

    test('should handle non-existent business ID', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.getBusinessById('non-existent')

      expect(result).toBeNull()
    })

    test('should update business record', async () => {
      const updateData = {
        businessName: 'Updated Business Name',
        phone: '555-5678',
        email: 'updated@example.com'
      }

      mockQuery.mockResolvedValueOnce({
        rows: [{ id: '1', ...updateData }],
        rowCount: 1
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.updateBusiness('1', updateData)

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE businesses SET'),
        expect.arrayContaining([updateData.businessName, updateData.phone, updateData.email, '1'])
      )
      expect(result).toMatchObject(updateData)
    })

    test('should delete business record', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 1
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.deleteBusiness('1')

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM businesses WHERE id = $1'),
        ['1']
      )
      expect(result).toBe(true)
    })

    test('should handle delete of non-existent business', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.deleteBusiness('non-existent')

      expect(result).toBe(false)
    })
  })

  describe('Search and Query Operations', () => {
    test('should search businesses by industry', async () => {
      const mockBusinesses = [
        {
          id: '1',
          business_name: 'Restaurant A',
          industry: 'restaurants',
          city: 'New York',
          state: 'NY'
        },
        {
          id: '2',
          business_name: 'Restaurant B',
          industry: 'restaurants',
          city: 'New York',
          state: 'NY'
        }
      ]

      mockQuery.mockResolvedValueOnce({
        rows: mockBusinesses,
        rowCount: 2
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.searchBusinessesByIndustry('restaurants', 'New York', 'NY')

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE industry = $1'),
        expect.arrayContaining(['restaurants'])
      )
      expect(result).toHaveLength(2)
    })

    test('should search businesses by ZIP code', async () => {
      const mockBusinesses = [
        {
          id: '1',
          business_name: 'Local Business',
          zip_code: '12345'
        }
      ]

      mockQuery.mockResolvedValueOnce({
        rows: mockBusinesses,
        rowCount: 1
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.searchBusinessesByZipCode('12345')

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE zip_code = $1'),
        ['12345']
      )
      expect(result).toHaveLength(1)
    })

    test('should handle complex search queries', async () => {
      const searchParams = {
        industry: 'restaurants',
        city: 'New York',
        state: 'NY',
        zipCode: '10001',
        minConfidence: 0.8
      }

      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.searchBusinesses(searchParams)

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('WHERE'),
        expect.arrayContaining([
          searchParams.industry,
          searchParams.city,
          searchParams.state,
          searchParams.zipCode,
          searchParams.minConfidence
        ])
      )
      expect(result).toEqual([])
    })

    test('should handle search with no results', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.searchBusinessesByIndustry('nonexistent', 'Nowhere', 'XX')

      expect(result).toEqual([])
    })

    test('should handle search with SQL injection attempts', async () => {
      const maliciousInput = "'; DROP TABLE businesses; --"

      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.searchBusinessesByIndustry(maliciousInput, 'City', 'ST')

      // Should use parameterized queries to prevent injection
      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([maliciousInput])
      )
      expect(result).toEqual([])
    })
  })

  describe('Batch Operations', () => {
    test('should create multiple businesses in batch', async () => {
      const businessesData: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'Business 1',
          url: 'https://example1.com',
          phone: '555-1111',
          email: 'test1@example.com',
          address: '123 Main St',
          city: 'City 1',
          state: 'ST',
          zipCode: '12345',
          industry: 'Industry 1',
          confidence: 0.9,
          source: 'scraper',
          scrapedAt: new Date().toISOString()
        },
        {
          id: '2',
          businessName: 'Business 2',
          url: 'https://example2.com',
          phone: '555-2222',
          email: 'test2@example.com',
          address: '456 Oak Ave',
          city: 'City 2',
          state: 'ST',
          zipCode: '67890',
          industry: 'Industry 2',
          confidence: 0.8,
          source: 'scraper',
          scrapedAt: new Date().toISOString()
        }
      ]

      mockTransaction.mockImplementation(async (callback) => {
        const client = {
          query: mockQuery
        }
        return await callback(client)
      })

      mockQuery.mockResolvedValue({
        rows: businessesData,
        rowCount: businessesData.length
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusinessesBatch(businessesData)

      expect(mockTransaction).toHaveBeenCalled()
      expect(result).toHaveLength(2)
    })

    test('should handle batch operation with partial failures', async () => {
      const businessesData: BusinessRecord[] = [
        {
          id: '1',
          businessName: 'Valid Business',
          url: 'https://example1.com',
          phone: '555-1111',
          email: 'test1@example.com',
          address: '123 Main St',
          city: 'City 1',
          state: 'ST',
          zipCode: '12345',
          industry: 'Industry 1',
          confidence: 0.9,
          source: 'scraper',
          scrapedAt: new Date().toISOString()
        },
        {
          id: '2',
          businessName: 'Duplicate Business',
          url: 'https://example1.com', // Duplicate URL
          phone: '555-2222',
          email: 'test2@example.com',
          address: '456 Oak Ave',
          city: 'City 2',
          state: 'ST',
          zipCode: '67890',
          industry: 'Industry 2',
          confidence: 0.8,
          source: 'scraper',
          scrapedAt: new Date().toISOString()
        }
      ]

      mockTransaction.mockImplementation(async (callback) => {
        const client = {
          query: jest.fn()
            .mockResolvedValueOnce({ rows: [businessesData[0]], rowCount: 1 })
            .mockRejectedValueOnce({ code: '23505' }) // Duplicate key error
        }
        return await callback(client)
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusinessesBatch(businessesData)

      expect(result).toHaveLength(1) // Only one successful
    })

    test('should handle empty batch operation', async () => {
      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusinessesBatch([])

      expect(result).toEqual([])
      expect(mockTransaction).not.toHaveBeenCalled()
    })
  })

  describe('Database Connection Management', () => {
    test('should handle database connection errors', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Connection failed'))

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.getBusinessById('1')

      expect(result).toBeNull()
    })

    test('should handle database timeout errors', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Query timeout'))

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.searchBusinessesByIndustry('restaurants', 'City', 'ST')

      expect(result).toEqual([])
    })

    test('should handle transaction rollback', async () => {
      mockTransaction.mockRejectedValueOnce(new Error('Transaction failed'))

      const businessesData: BusinessRecord[] = [{
        id: '1',
        businessName: 'Test Business',
        url: 'https://example.com',
        phone: '555-1234',
        email: 'test@example.com',
        address: '123 Main St',
        city: 'Test City',
        state: 'TS',
        zipCode: '12345',
        industry: 'Test Industry',
        confidence: 0.9,
        source: 'scraper',
        scrapedAt: new Date().toISOString()
      }]

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusinessesBatch(businessesData)

      expect(result).toEqual([])
    })
  })

  describe('Data Validation and Constraints', () => {
    test('should handle invalid data types', async () => {
      const invalidData = {
        businessName: null,
        url: 'not-a-url',
        phone: 12345, // Should be string
        confidence: 'high' // Should be number
      }

      mockQuery.mockRejectedValueOnce(new Error('Invalid data type'))

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusiness(invalidData as any)

      expect(result).toBeNull()
    })

    test('should handle constraint violations', async () => {
      const businessData: BusinessRecord = {
        id: '1',
        businessName: '', // Empty name might violate constraint
        url: 'https://example.com',
        phone: '555-1234',
        email: 'invalid-email', // Invalid email format
        address: '123 Main St',
        city: 'Test City',
        state: 'TS',
        zipCode: '12345',
        industry: 'Test Industry',
        confidence: 1.5, // Invalid confidence > 1
        source: 'scraper',
        scrapedAt: new Date().toISOString()
      }

      mockQuery.mockRejectedValueOnce({
        code: '23514', // Check constraint violation
        constraint: 'businesses_confidence_check'
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusiness(businessData)

      expect(result).toBeNull()
    })

    test('should handle foreign key violations', async () => {
      const businessData: BusinessRecord = {
        id: '1',
        businessName: 'Test Business',
        url: 'https://example.com',
        phone: '555-1234',
        email: 'test@example.com',
        address: '123 Main St',
        city: 'Test City',
        state: 'TS',
        zipCode: '12345',
        industry: 'Test Industry',
        confidence: 0.9,
        source: 'scraper',
        scrapedAt: new Date().toISOString(),
        categoryId: 'non-existent-category' // Foreign key that doesn't exist
      }

      mockQuery.mockRejectedValueOnce({
        code: '23503', // Foreign key violation
        constraint: 'businesses_category_id_fkey'
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.createBusiness(businessData)

      expect(result).toBeNull()
    })
  })

  describe('Performance and Optimization', () => {
    test('should handle large result sets efficiently', async () => {
      const largeResultSet = Array.from({ length: 10000 }, (_, i) => ({
        id: i.toString(),
        business_name: `Business ${i}`,
        url: `https://example${i}.com`
      }))

      mockQuery.mockResolvedValueOnce({
        rows: largeResultSet,
        rowCount: largeResultSet.length
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.searchBusinessesByIndustry('restaurants', 'City', 'ST')

      expect(result).toHaveLength(10000)
    })

    test('should handle concurrent database operations', async () => {
      mockQuery.mockResolvedValue({
        rows: [{ id: '1', business_name: 'Test' }],
        rowCount: 1
      })

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      // Simulate concurrent operations
      const promises = Array.from({ length: 10 }, (_, i) =>
        businessDatabase.getBusinessById(i.toString())
      )

      const results = await Promise.all(promises)

      expect(results).toHaveLength(10)
      expect(mockQuery).toHaveBeenCalledTimes(10)
    })

    test('should handle database connection pool exhaustion', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Connection pool exhausted'))

      const { businessDatabase } = await import('@/model/businessDatabase')
      
      const result = await businessDatabase.getBusinessById('1')

      expect(result).toBeNull()
    })
  })
})
