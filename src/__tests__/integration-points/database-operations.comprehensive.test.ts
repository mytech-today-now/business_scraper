/**
 * Database Operations - Comprehensive Integration Points Tests
 * 
 * Tests all database integration points including:
 * - PostgreSQL database operations
 * - IndexedDB client-side storage
 * - Database connection management
 * - Transaction handling
 * - Query optimization
 * - Data migration and schema updates
 * - Performance monitoring
 */

import { createDatabase } from '@/lib/database'
import { PostgreSQLDatabase } from '@/lib/postgresql-database'
import { IndexedDBDatabase } from '@/lib/indexeddb-database'
import { BusinessRecord } from '@/types/business'
import { DatabaseConfig } from '@/types/database'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/lib/metrics')
jest.mock('@/lib/security')

// Mock PostgreSQL client
const mockQuery = jest.fn()
const mockConnect = jest.fn()
const mockEnd = jest.fn()

jest.mock('pg', () => ({
  Pool: jest.fn().mockImplementation(() => ({
    query: mockQuery,
    connect: mockConnect,
    end: mockEnd,
  })),
}))

// Mock IndexedDB
const mockIndexedDB = {
  open: jest.fn(),
  deleteDatabase: jest.fn(),
}

Object.defineProperty(global, 'indexedDB', {
  value: mockIndexedDB,
  writable: true,
})

describe('Database Operations - Comprehensive Integration Points Tests', () => {
  let mockBusinessRecord: BusinessRecord

  beforeEach(() => {
    jest.clearAllMocks()
    
    mockBusinessRecord = {
      id: 'test-business-1',
      businessName: 'Test Restaurant',
      email: ['contact@testrestaurant.com'],
      phone: '555-1234',
      websiteUrl: 'https://testrestaurant.com',
      address: {
        street: '123 Main St',
        city: 'Test City',
        state: 'CA',
        zipCode: '90210',
        country: 'US'
      },
      contactPerson: 'John Doe',
      coordinates: { lat: 34.0522, lng: -118.2437 },
      industry: 'Restaurant',
      scrapedAt: new Date(),
    }
  })

  describe('Database Factory', () => {
    it('should create PostgreSQL database in server environment', async () => {
      // Mock server environment
      Object.defineProperty(global, 'window', { value: undefined })
      
      const config: DatabaseConfig = {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'business_scraper',
        username: 'test_user',
        password: 'test_password',
        ssl: false,
        maxConnections: 10,
        connectionTimeout: 5000,
      }

      const database = await createDatabase(config)
      expect(database).toBeInstanceOf(PostgreSQLDatabase)
    })

    it('should create IndexedDB database in browser environment', async () => {
      // Mock browser environment
      Object.defineProperty(global, 'window', { value: {} })
      
      const config: DatabaseConfig = {
        type: 'indexeddb',
        databaseName: 'business_scraper',
        version: 1,
      }

      const database = await createDatabase(config)
      expect(database).toBeInstanceOf(IndexedDBDatabase)
    })

    it('should fallback to IndexedDB when PostgreSQL unavailable in browser', async () => {
      // Mock browser environment
      Object.defineProperty(global, 'window', { value: {} })
      
      const config: DatabaseConfig = {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'business_scraper',
        username: 'test_user',
        password: 'test_password',
      }

      const database = await createDatabase(config)
      expect(database).toBeInstanceOf(IndexedDBDatabase)
    })
  })

  describe('PostgreSQL Database Operations', () => {
    let postgresDB: PostgreSQLDatabase
    let config: DatabaseConfig

    beforeEach(() => {
      config = {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'business_scraper',
        username: 'test_user',
        password: 'test_password',
        ssl: false,
        maxConnections: 10,
        connectionTimeout: 5000,
      }
      
      postgresDB = new PostgreSQLDatabase(config)
    })

    it('should initialize database connection', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [{ version: 'PostgreSQL 14.0' }] })
      
      await postgresDB.initialize()
      
      expect(mockQuery).toHaveBeenCalledWith('SELECT version()')
    })

    it('should create business record', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: 'test-business-1' }]
      })

      const businessId = await postgresDB.createBusiness(mockBusinessRecord)
      
      expect(businessId).toBe('test-business-1')
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO businesses'),
        expect.arrayContaining([
          'test-business-1',
          'Test Restaurant',
          expect.any(String), // JSON stringified email array
          '555-1234',
          'https://testrestaurant.com'
        ])
      )
    })

    it('should get business record by ID', async () => {
      const mockRow = {
        id: 'test-business-1',
        business_name: 'Test Restaurant',
        email: JSON.stringify(['contact@testrestaurant.com']),
        phone: '555-1234',
        website_url: 'https://testrestaurant.com',
        address: JSON.stringify(mockBusinessRecord.address),
        contact_person: 'John Doe',
        coordinates: JSON.stringify(mockBusinessRecord.coordinates),
        industry: 'Restaurant',
        scraped_at: new Date(),
      }

      mockQuery.mockResolvedValueOnce({ rows: [mockRow] })

      const business = await postgresDB.getBusiness('test-business-1')
      
      expect(business).toBeDefined()
      expect(business.businessName).toBe('Test Restaurant')
      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM businesses WHERE id = $1',
        ['test-business-1']
      )
    })

    it('should update business record', async () => {
      const updates = {
        businessName: 'Updated Restaurant Name',
        phone: '555-5678'
      }

      mockQuery.mockResolvedValueOnce({
        rows: [{ id: 'test-business-1' }]
      })

      await postgresDB.updateBusiness('test-business-1', updates)
      
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE businesses SET'),
        expect.arrayContaining(['Updated Restaurant Name', '555-5678', 'test-business-1'])
      )
    })

    it('should delete business record', async () => {
      mockQuery.mockResolvedValueOnce({ rowCount: 1 })

      await postgresDB.deleteBusiness('test-business-1')
      
      expect(mockQuery).toHaveBeenCalledWith(
        'DELETE FROM businesses WHERE id = $1',
        ['test-business-1']
      )
    })

    it('should search businesses with filters', async () => {
      const mockRows = [
        {
          id: 'test-business-1',
          business_name: 'Test Restaurant',
          industry: 'Restaurant',
          // ... other fields
        }
      ]

      mockQuery.mockResolvedValueOnce({ rows: mockRows })

      const results = await postgresDB.searchBusinesses({
        query: 'restaurant',
        industry: 'Restaurant',
        location: 'Test City',
        limit: 10,
        offset: 0
      })
      
      expect(results).toHaveLength(1)
      expect(results[0].businessName).toBe('Test Restaurant')
    })

    it('should handle database transactions', async () => {
      const mockClient = {
        query: jest.fn(),
        release: jest.fn(),
      }

      mockConnect.mockResolvedValueOnce(mockClient)
      mockClient.query.mockResolvedValueOnce({ rows: [] }) // BEGIN
      mockClient.query.mockResolvedValueOnce({ rows: [{ id: 'test-1' }] }) // INSERT
      mockClient.query.mockResolvedValueOnce({ rows: [{ id: 'test-2' }] }) // INSERT
      mockClient.query.mockResolvedValueOnce({ rows: [] }) // COMMIT

      const businessRecords = [
        mockBusinessRecord,
        { ...mockBusinessRecord, id: 'test-business-2' }
      ]

      await postgresDB.createBusinessBatch(businessRecords)
      
      expect(mockClient.query).toHaveBeenCalledWith('BEGIN')
      expect(mockClient.query).toHaveBeenCalledWith('COMMIT')
      expect(mockClient.release).toHaveBeenCalled()
    })

    it('should rollback transaction on error', async () => {
      const mockClient = {
        query: jest.fn(),
        release: jest.fn(),
      }

      mockConnect.mockResolvedValueOnce(mockClient)
      mockClient.query.mockResolvedValueOnce({ rows: [] }) // BEGIN
      mockClient.query.mockRejectedValueOnce(new Error('Database error')) // INSERT fails
      mockClient.query.mockResolvedValueOnce({ rows: [] }) // ROLLBACK

      const businessRecords = [mockBusinessRecord]

      await expect(postgresDB.createBusinessBatch(businessRecords)).rejects.toThrow('Database error')
      
      expect(mockClient.query).toHaveBeenCalledWith('BEGIN')
      expect(mockClient.query).toHaveBeenCalledWith('ROLLBACK')
      expect(mockClient.release).toHaveBeenCalled()
    })

    it('should handle connection pool management', async () => {
      await postgresDB.initialize()
      await postgresDB.close()
      
      expect(mockEnd).toHaveBeenCalled()
    })

    it('should track query performance', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], duration: 150 })

      await postgresDB.getBusiness('test-business-1')
      
      // Verify performance tracking was called
      expect(mockQuery).toHaveBeenCalled()
    })
  })

  describe('IndexedDB Database Operations', () => {
    let indexedDB: IndexedDBDatabase
    let mockDB: any
    let mockTransaction: any
    let mockObjectStore: any

    beforeEach(() => {
      mockObjectStore = {
        add: jest.fn(),
        get: jest.fn(),
        put: jest.fn(),
        delete: jest.fn(),
        getAll: jest.fn(),
        index: jest.fn(),
        createIndex: jest.fn(),
      }

      mockTransaction = {
        objectStore: jest.fn().mockReturnValue(mockObjectStore),
        oncomplete: null,
        onerror: null,
      }

      mockDB = {
        transaction: jest.fn().mockReturnValue(mockTransaction),
        createObjectStore: jest.fn().mockReturnValue(mockObjectStore),
        close: jest.fn(),
        version: 1,
        objectStoreNames: {
          contains: jest.fn().mockReturnValue(false),
        },
      }

      const mockRequest = {
        result: mockDB,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
      }

      mockIndexedDB.open.mockReturnValue(mockRequest)
      
      indexedDB = new IndexedDBDatabase()
    })

    it('should initialize IndexedDB database', async () => {
      const initPromise = indexedDB.initialize()
      
      // Simulate successful database opening
      const openRequest = mockIndexedDB.open.mock.results[0].value
      openRequest.onsuccess({ target: { result: mockDB } })
      
      await initPromise
      
      expect(mockIndexedDB.open).toHaveBeenCalledWith('business_scraper', 1)
    })

    it('should handle database upgrade', async () => {
      const initPromise = indexedDB.initialize()
      
      const openRequest = mockIndexedDB.open.mock.results[0].value
      
      // Simulate upgrade needed
      openRequest.onupgradeneeded({
        target: { result: mockDB },
        oldVersion: 0,
        newVersion: 1,
      })
      
      // Then success
      openRequest.onsuccess({ target: { result: mockDB } })
      
      await initPromise
      
      expect(mockDB.createObjectStore).toHaveBeenCalledWith('businesses', { keyPath: 'id' })
    })

    it('should create business record in IndexedDB', async () => {
      // Initialize first
      const initPromise = indexedDB.initialize()
      const openRequest = mockIndexedDB.open.mock.results[0].value
      openRequest.onsuccess({ target: { result: mockDB } })
      await initPromise

      // Mock successful add operation
      mockObjectStore.add.mockImplementation(() => {
        const request = { onsuccess: null, onerror: null }
        setTimeout(() => request.onsuccess({ target: { result: 'test-business-1' } }), 0)
        return request
      })

      const businessId = await indexedDB.createBusiness(mockBusinessRecord)
      
      expect(businessId).toBe('test-business-1')
      expect(mockObjectStore.add).toHaveBeenCalledWith(
        expect.objectContaining({
          id: 'test-business-1',
          businessName: 'Test Restaurant'
        })
      )
    })

    it('should get business record from IndexedDB', async () => {
      // Initialize first
      const initPromise = indexedDB.initialize()
      const openRequest = mockIndexedDB.open.mock.results[0].value
      openRequest.onsuccess({ target: { result: mockDB } })
      await initPromise

      // Mock successful get operation
      mockObjectStore.get.mockImplementation(() => {
        const request = { onsuccess: null, onerror: null }
        setTimeout(() => request.onsuccess({ target: { result: mockBusinessRecord } }), 0)
        return request
      })

      const business = await indexedDB.getBusiness('test-business-1')
      
      expect(business).toEqual(mockBusinessRecord)
      expect(mockObjectStore.get).toHaveBeenCalledWith('test-business-1')
    })

    it('should search businesses in IndexedDB', async () => {
      // Initialize first
      const initPromise = indexedDB.initialize()
      const openRequest = mockIndexedDB.open.mock.results[0].value
      openRequest.onsuccess({ target: { result: mockDB } })
      await initPromise

      const mockResults = [mockBusinessRecord]

      // Mock index search
      const mockIndex = {
        getAll: jest.fn().mockImplementation(() => {
          const request = { onsuccess: null, onerror: null }
          setTimeout(() => request.onsuccess({ target: { result: mockResults } }), 0)
          return request
        })
      }

      mockObjectStore.index.mockReturnValue(mockIndex)

      const results = await indexedDB.searchBusinesses({
        query: 'restaurant',
        limit: 10
      })
      
      expect(results).toEqual(mockResults)
    })

    it('should handle IndexedDB errors', async () => {
      const initPromise = indexedDB.initialize()
      
      const openRequest = mockIndexedDB.open.mock.results[0].value
      openRequest.onerror({ target: { error: new Error('IndexedDB error') } })
      
      await expect(initPromise).rejects.toThrow('IndexedDB error')
    })
  })

  describe('Database Performance and Monitoring', () => {
    it('should track query execution time', async () => {
      const config: DatabaseConfig = {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'business_scraper',
        username: 'test_user',
        password: 'test_password',
      }
      
      const postgresDB = new PostgreSQLDatabase(config)
      
      mockQuery.mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => resolve({ rows: [] }), 100)
        })
      })

      const startTime = Date.now()
      await postgresDB.getBusiness('test-business-1')
      const endTime = Date.now()
      
      expect(endTime - startTime).toBeGreaterThanOrEqual(100)
    })

    it('should handle connection timeouts', async () => {
      const config: DatabaseConfig = {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'business_scraper',
        username: 'test_user',
        password: 'test_password',
        connectionTimeout: 1000,
      }
      
      const postgresDB = new PostgreSQLDatabase(config)
      
      mockQuery.mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Connection timeout')), 1500)
        })
      })

      await expect(postgresDB.initialize()).rejects.toThrow('Connection timeout')
    })

    it('should monitor database health', async () => {
      const config: DatabaseConfig = {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'business_scraper',
        username: 'test_user',
        password: 'test_password',
      }
      
      const postgresDB = new PostgreSQLDatabase(config)
      
      mockQuery.mockResolvedValueOnce({
        rows: [{
          active_connections: 5,
          max_connections: 100,
          database_size: '50MB'
        }]
      })

      const healthStatus = await postgresDB.getHealthStatus()
      
      expect(healthStatus).toEqual({
        status: 'healthy',
        activeConnections: 5,
        maxConnections: 100,
        databaseSize: '50MB'
      })
    })
  })
})
