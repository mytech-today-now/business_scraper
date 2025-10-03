/**
 * Caching and Storage - Comprehensive Integration Points Tests
 * 
 * Tests all caching and storage integration points including:
 * - Redis caching
 * - In-memory caching
 * - Browser localStorage/sessionStorage
 * - IndexedDB storage
 * - Cache invalidation strategies
 * - Cache warming and preloading
 * - Storage quota management
 * - Data persistence and recovery
 */

import { CacheManager } from '@/lib/cache'
import { storage } from '@/lib/storage'
import { BusinessRecord } from '@/types/business'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/lib/metrics')

// Mock Redis client
const mockRedisClient = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  exists: jest.fn(),
  expire: jest.fn(),
  flushall: jest.fn(),
  keys: jest.fn(),
  mget: jest.fn(),
  mset: jest.fn(),
  pipeline: jest.fn(),
  quit: jest.fn(),
  on: jest.fn(),
  connect: jest.fn(),
}

jest.mock('redis', () => ({
  createClient: jest.fn(() => mockRedisClient),
}))

// Mock browser storage APIs
const mockLocalStorage = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
  length: 0,
  key: jest.fn(),
}

const mockSessionStorage = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
  length: 0,
  key: jest.fn(),
}

Object.defineProperty(global, 'localStorage', {
  value: mockLocalStorage,
  writable: true,
})

Object.defineProperty(global, 'sessionStorage', {
  value: mockSessionStorage,
  writable: true,
})

describe('Caching and Storage - Comprehensive Integration Points Tests', () => {
  let cacheManager: CacheManager
  let mockBusinessRecord: BusinessRecord

  beforeEach(() => {
    jest.clearAllMocks()
    
    cacheManager = new CacheManager({
      redis: {
        host: 'localhost',
        port: 6379,
        password: 'test-password',
        db: 0,
      },
      defaultTTL: 3600,
      enableCompression: true,
    })

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

  describe('Redis Caching', () => {
    it('should initialize Redis connection', async () => {
      mockRedisClient.connect.mockResolvedValueOnce(undefined)
      
      await cacheManager.initialize()
      
      expect(mockRedisClient.connect).toHaveBeenCalled()
      expect(mockRedisClient.on).toHaveBeenCalledWith('error', expect.any(Function))
    })

    it('should cache business record in Redis', async () => {
      mockRedisClient.set.mockResolvedValueOnce('OK')
      
      await cacheManager.set('business:test-business-1', mockBusinessRecord, 3600)
      
      expect(mockRedisClient.set).toHaveBeenCalledWith(
        'business:test-business-1',
        JSON.stringify(mockBusinessRecord),
        'EX',
        3600
      )
    })

    it('should retrieve business record from Redis', async () => {
      mockRedisClient.get.mockResolvedValueOnce(JSON.stringify(mockBusinessRecord))
      
      const result = await cacheManager.get('business:test-business-1')
      
      expect(result).toEqual(mockBusinessRecord)
      expect(mockRedisClient.get).toHaveBeenCalledWith('business:test-business-1')
    })

    it('should handle Redis cache miss', async () => {
      mockRedisClient.get.mockResolvedValueOnce(null)
      
      const result = await cacheManager.get('business:nonexistent')
      
      expect(result).toBeNull()
    })

    it('should delete cached item from Redis', async () => {
      mockRedisClient.del.mockResolvedValueOnce(1)
      
      await cacheManager.delete('business:test-business-1')
      
      expect(mockRedisClient.del).toHaveBeenCalledWith('business:test-business-1')
    })

    it('should check if key exists in Redis', async () => {
      mockRedisClient.exists.mockResolvedValueOnce(1)
      
      const exists = await cacheManager.exists('business:test-business-1')
      
      expect(exists).toBe(true)
      expect(mockRedisClient.exists).toHaveBeenCalledWith('business:test-business-1')
    })

    it('should set expiration for cached item', async () => {
      mockRedisClient.expire.mockResolvedValueOnce(1)
      
      await cacheManager.expire('business:test-business-1', 7200)
      
      expect(mockRedisClient.expire).toHaveBeenCalledWith('business:test-business-1', 7200)
    })

    it('should handle Redis connection errors', async () => {
      mockRedisClient.connect.mockRejectedValueOnce(new Error('Connection failed'))
      
      await expect(cacheManager.initialize()).rejects.toThrow('Connection failed')
    })

    it('should implement cache warming', async () => {
      const businessRecords = [
        mockBusinessRecord,
        { ...mockBusinessRecord, id: 'test-business-2' },
        { ...mockBusinessRecord, id: 'test-business-3' },
      ]

      mockRedisClient.pipeline.mockReturnValue({
        set: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValueOnce([['OK'], ['OK'], ['OK']]),
      })

      await cacheManager.warmCache('businesses', businessRecords)
      
      expect(mockRedisClient.pipeline).toHaveBeenCalled()
    })

    it('should implement bulk operations', async () => {
      const keys = ['business:1', 'business:2', 'business:3']
      const values = [
        JSON.stringify(mockBusinessRecord),
        JSON.stringify({ ...mockBusinessRecord, id: 'test-business-2' }),
        JSON.stringify({ ...mockBusinessRecord, id: 'test-business-3' }),
      ]

      mockRedisClient.mget.mockResolvedValueOnce(values)
      
      const results = await cacheManager.getMultiple(keys)
      
      expect(results).toHaveLength(3)
      expect(mockRedisClient.mget).toHaveBeenCalledWith(keys)
    })
  })

  describe('In-Memory Caching', () => {
    it('should fallback to in-memory cache when Redis unavailable', async () => {
      mockRedisClient.connect.mockRejectedValueOnce(new Error('Redis unavailable'))
      
      await cacheManager.initialize()
      
      // Should still work with in-memory cache
      await cacheManager.set('test-key', 'test-value')
      const result = await cacheManager.get('test-key')
      
      expect(result).toBe('test-value')
    })

    it('should implement LRU eviction in memory cache', async () => {
      const memoryCache = new CacheManager({
        type: 'memory',
        maxSize: 2, // Only 2 items
      })

      await memoryCache.set('key1', 'value1')
      await memoryCache.set('key2', 'value2')
      await memoryCache.set('key3', 'value3') // Should evict key1
      
      const result1 = await memoryCache.get('key1')
      const result2 = await memoryCache.get('key2')
      const result3 = await memoryCache.get('key3')
      
      expect(result1).toBeNull() // Evicted
      expect(result2).toBe('value2')
      expect(result3).toBe('value3')
    })

    it('should handle memory cache TTL expiration', async () => {
      const memoryCache = new CacheManager({
        type: 'memory',
        defaultTTL: 1, // 1 second
      })

      await memoryCache.set('test-key', 'test-value')
      
      // Should exist immediately
      let result = await memoryCache.get('test-key')
      expect(result).toBe('test-value')
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 1100))
      
      // Should be expired
      result = await memoryCache.get('test-key')
      expect(result).toBeNull()
    })
  })

  describe('Browser Storage', () => {
    describe('localStorage Integration', () => {
      it('should store business record in localStorage', async () => {
        mockLocalStorage.setItem.mockImplementation(() => {})
        
        await storage.saveToLocalStorage('business:test-business-1', mockBusinessRecord)
        
        expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
          'business:test-business-1',
          JSON.stringify(mockBusinessRecord)
        )
      })

      it('should retrieve business record from localStorage', async () => {
        mockLocalStorage.getItem.mockReturnValue(JSON.stringify(mockBusinessRecord))
        
        const result = await storage.getFromLocalStorage('business:test-business-1')
        
        expect(result).toEqual(mockBusinessRecord)
        expect(mockLocalStorage.getItem).toHaveBeenCalledWith('business:test-business-1')
      })

      it('should handle localStorage quota exceeded', async () => {
        mockLocalStorage.setItem.mockImplementation(() => {
          throw new Error('QuotaExceededError')
        })
        
        await expect(
          storage.saveToLocalStorage('large-key', mockBusinessRecord)
        ).rejects.toThrow('QuotaExceededError')
      })

      it('should implement localStorage cleanup', async () => {
        mockLocalStorage.key.mockImplementation((index) => {
          const keys = ['business:old-1', 'business:old-2', 'other:key']
          return keys[index] || null
        })
        mockLocalStorage.length = 3
        mockLocalStorage.getItem.mockImplementation((key) => {
          if (key.startsWith('business:')) {
            return JSON.stringify({
              ...mockBusinessRecord,
              timestamp: Date.now() - 86400000 // 1 day old
            })
          }
          return null
        })

        await storage.cleanupExpiredItems('business:', 3600) // 1 hour TTL
        
        expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('business:old-1')
        expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('business:old-2')
      })
    })

    describe('sessionStorage Integration', () => {
      it('should store temporary data in sessionStorage', async () => {
        mockSessionStorage.setItem.mockImplementation(() => {})
        
        await storage.saveToSessionStorage('temp:search-results', { results: [] })
        
        expect(mockSessionStorage.setItem).toHaveBeenCalledWith(
          'temp:search-results',
          JSON.stringify({ results: [] })
        )
      })

      it('should retrieve temporary data from sessionStorage', async () => {
        const tempData = { results: [mockBusinessRecord] }
        mockSessionStorage.getItem.mockReturnValue(JSON.stringify(tempData))
        
        const result = await storage.getFromSessionStorage('temp:search-results')
        
        expect(result).toEqual(tempData)
      })

      it('should clear session storage on logout', async () => {
        await storage.clearSessionData()
        
        expect(mockSessionStorage.clear).toHaveBeenCalled()
      })
    })
  })

  describe('IndexedDB Storage', () => {
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
        clear: jest.fn(),
        count: jest.fn(),
      }

      mockTransaction = {
        objectStore: jest.fn().mockReturnValue(mockObjectStore),
        oncomplete: null,
        onerror: null,
      }

      mockDB = {
        transaction: jest.fn().mockReturnValue(mockTransaction),
        close: jest.fn(),
      }

      const mockRequest = {
        result: mockDB,
        onsuccess: null,
        onerror: null,
      }

      global.indexedDB = {
        open: jest.fn().mockReturnValue(mockRequest),
        deleteDatabase: jest.fn(),
      } as any
    })

    it('should store large datasets in IndexedDB', async () => {
      const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
        ...mockBusinessRecord,
        id: `business-${i}`,
      }))

      mockObjectStore.add.mockImplementation(() => {
        const request = { onsuccess: null, onerror: null }
        setTimeout(() => request.onsuccess({}), 0)
        return request
      })

      await storage.saveLargeDataset('businesses', largeDataset)
      
      expect(mockObjectStore.add).toHaveBeenCalledTimes(1000)
    })

    it('should implement IndexedDB pagination', async () => {
      const mockResults = Array.from({ length: 50 }, (_, i) => ({
        ...mockBusinessRecord,
        id: `business-${i}`,
      }))

      mockObjectStore.getAll.mockImplementation(() => {
        const request = { onsuccess: null, onerror: null }
        setTimeout(() => request.onsuccess({ target: { result: mockResults } }), 0)
        return request
      })

      const results = await storage.getPaginatedData('businesses', 0, 50)
      
      expect(results).toHaveLength(50)
      expect(results[0].id).toBe('business-0')
    })

    it('should handle IndexedDB storage quota', async () => {
      mockObjectStore.add.mockImplementation(() => {
        const request = { onsuccess: null, onerror: null }
        setTimeout(() => {
          const error = new Error('QuotaExceededError')
          error.name = 'QuotaExceededError'
          request.onerror({ target: { error } })
        }, 0)
        return request
      })

      await expect(
        storage.saveToIndexedDB('large-data', mockBusinessRecord)
      ).rejects.toThrow('QuotaExceededError')
    })

    it('should implement IndexedDB cleanup strategies', async () => {
      mockObjectStore.count.mockImplementation(() => {
        const request = { onsuccess: null, onerror: null }
        setTimeout(() => request.onsuccess({ target: { result: 10000 } }), 0)
        return request
      })

      mockObjectStore.clear.mockImplementation(() => {
        const request = { onsuccess: null, onerror: null }
        setTimeout(() => request.onsuccess({}), 0)
        return request
      })

      await storage.cleanupIndexedDB('businesses', 5000) // Keep only 5000 records
      
      expect(mockObjectStore.clear).toHaveBeenCalled()
    })
  })

  describe('Cache Invalidation Strategies', () => {
    it('should implement time-based invalidation', async () => {
      mockRedisClient.set.mockResolvedValueOnce('OK')
      mockRedisClient.get.mockResolvedValueOnce(null) // Expired
      
      await cacheManager.set('business:test', mockBusinessRecord, 1) // 1 second TTL
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 1100))
      
      const result = await cacheManager.get('business:test')
      expect(result).toBeNull()
    })

    it('should implement tag-based invalidation', async () => {
      mockRedisClient.keys.mockResolvedValueOnce([
        'business:restaurant:1',
        'business:restaurant:2',
        'business:retail:1'
      ])
      mockRedisClient.del.mockResolvedValueOnce(2)
      
      await cacheManager.invalidateByTag('restaurant')
      
      expect(mockRedisClient.keys).toHaveBeenCalledWith('business:restaurant:*')
      expect(mockRedisClient.del).toHaveBeenCalledWith([
        'business:restaurant:1',
        'business:restaurant:2'
      ])
    })

    it('should implement event-based invalidation', async () => {
      const eventEmitter = cacheManager.getEventEmitter()
      
      mockRedisClient.del.mockResolvedValueOnce(1)
      
      // Simulate business update event
      eventEmitter.emit('business:updated', { id: 'test-business-1' })
      
      // Wait for async invalidation
      await new Promise(resolve => setTimeout(resolve, 100))
      
      expect(mockRedisClient.del).toHaveBeenCalledWith('business:test-business-1')
    })
  })

  describe('Cache Performance and Monitoring', () => {
    it('should track cache hit rates', async () => {
      // Simulate cache hits and misses
      mockRedisClient.get
        .mockResolvedValueOnce(JSON.stringify(mockBusinessRecord)) // Hit
        .mockResolvedValueOnce(null) // Miss
        .mockResolvedValueOnce(JSON.stringify(mockBusinessRecord)) // Hit
        .mockResolvedValueOnce(null) // Miss

      await cacheManager.get('key1')
      await cacheManager.get('key2')
      await cacheManager.get('key3')
      await cacheManager.get('key4')
      
      const stats = await cacheManager.getStats()
      
      expect(stats.hitRate).toBe(0.5) // 50% hit rate
      expect(stats.totalRequests).toBe(4)
      expect(stats.hits).toBe(2)
      expect(stats.misses).toBe(2)
    })

    it('should monitor cache memory usage', async () => {
      const memoryCache = new CacheManager({ type: 'memory' })
      
      await memoryCache.set('key1', 'a'.repeat(1000)) // 1KB
      await memoryCache.set('key2', 'b'.repeat(2000)) // 2KB
      
      const stats = await memoryCache.getStats()
      
      expect(stats.memoryUsage).toBeGreaterThan(3000) // At least 3KB
    })

    it('should implement cache warming strategies', async () => {
      const popularBusinesses = [
        mockBusinessRecord,
        { ...mockBusinessRecord, id: 'popular-1' },
        { ...mockBusinessRecord, id: 'popular-2' },
      ]

      mockRedisClient.pipeline.mockReturnValue({
        set: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValueOnce([['OK'], ['OK'], ['OK']]),
      })

      await cacheManager.warmPopularItems('businesses', popularBusinesses)
      
      expect(mockRedisClient.pipeline).toHaveBeenCalled()
    })
  })

  describe('Data Persistence and Recovery', () => {
    it('should implement cache persistence to disk', async () => {
      mockRedisClient.keys.mockResolvedValueOnce(['business:1', 'business:2'])
      mockRedisClient.mget.mockResolvedValueOnce([
        JSON.stringify(mockBusinessRecord),
        JSON.stringify({ ...mockBusinessRecord, id: 'business-2' })
      ])

      const backup = await cacheManager.createBackup()
      
      expect(backup).toHaveProperty('timestamp')
      expect(backup.data).toHaveLength(2)
    })

    it('should restore cache from backup', async () => {
      const backup = {
        timestamp: Date.now(),
        data: [
          { key: 'business:1', value: JSON.stringify(mockBusinessRecord) },
          { key: 'business:2', value: JSON.stringify({ ...mockBusinessRecord, id: 'business-2' }) }
        ]
      }

      mockRedisClient.pipeline.mockReturnValue({
        set: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValueOnce([['OK'], ['OK']]),
      })

      await cacheManager.restoreFromBackup(backup)
      
      expect(mockRedisClient.pipeline).toHaveBeenCalled()
    })

    it('should handle cache corruption recovery', async () => {
      mockRedisClient.get.mockResolvedValueOnce('invalid-json-data')
      
      const result = await cacheManager.get('corrupted-key')
      
      expect(result).toBeNull()
      expect(mockRedisClient.del).toHaveBeenCalledWith('corrupted-key')
    })
  })
})
