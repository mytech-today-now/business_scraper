/**
 * Comprehensive Unit Tests for Storage Service
 * Tests IndexedDB operations and data persistence
 */

import { storage } from '@/model/storage'
import { BusinessRecord, ScrapingConfig, IndustryCategory } from '@/types/business'
import { createMockBusinessRecord, createMockScrapingConfig, createMockIndustryCategory } from '../utils/testHelpers'
import { jest } from '@jest/globals'

// Mock IndexedDB
const mockDB = {
  transaction: jest.fn(),
  close: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
}

const mockTransaction = {
  objectStore: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
}

const mockObjectStore = {
  add: jest.fn(),
  put: jest.fn(),
  get: jest.fn(),
  delete: jest.fn(),
  clear: jest.fn(),
  getAll: jest.fn(),
  index: jest.fn(),
  createIndex: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
}

const mockIndex = {
  getAll: jest.fn(),
  get: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
}

// Mock IDB
jest.mock('idb', () => ({
  openDB: jest.fn().mockResolvedValue(mockDB),
}))

describe('Storage Service', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Setup default mock behaviors
    mockDB.transaction.mockReturnValue(mockTransaction)
    mockTransaction.objectStore.mockReturnValue(mockObjectStore)
    mockObjectStore.index.mockReturnValue(mockIndex)
    
    // Mock successful operations
    mockObjectStore.add.mockImplementation(() => ({
      addEventListener: jest.fn((event, callback) => {
        if (event === 'success') setTimeout(callback, 0)
      })
    }))
    
    mockObjectStore.put.mockImplementation(() => ({
      addEventListener: jest.fn((event, callback) => {
        if (event === 'success') setTimeout(callback, 0)
      })
    }))
    
    mockObjectStore.get.mockImplementation(() => ({
      addEventListener: jest.fn((event, callback) => {
        if (event === 'success') setTimeout(() => callback({ target: { result: null } }), 0)
      })
    }))
    
    mockObjectStore.delete.mockImplementation(() => ({
      addEventListener: jest.fn((event, callback) => {
        if (event === 'success') setTimeout(callback, 0)
      })
    }))
    
    mockObjectStore.getAll.mockImplementation(() => ({
      addEventListener: jest.fn((event, callback) => {
        if (event === 'success') setTimeout(() => callback({ target: { result: [] } }), 0)
      })
    }))
  })

  describe('Initialization', () => {
    it('should initialize database successfully', async () => {
      await expect(storage.initialize()).resolves.not.toThrow()
    })

    it('should handle initialization errors gracefully', async () => {
      const { openDB } = require('idb')
      openDB.mockRejectedValueOnce(new Error('DB initialization failed'))

      await expect(storage.initialize()).rejects.toThrow('DB initialization failed')
    })
  })

  describe('Business Records Operations', () => {
    const mockBusiness = createMockBusinessRecord({
      id: 'test-business-1',
      businessName: 'Test Business',
      industry: 'Technology'
    })

    it('should save business record successfully', async () => {
      mockObjectStore.add.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') setTimeout(callback, 0)
        })
      }))

      await expect(storage.saveBusiness(mockBusiness)).resolves.not.toThrow()
      expect(mockObjectStore.add).toHaveBeenCalledWith(mockBusiness)
    })

    it('should get business record by ID', async () => {
      mockObjectStore.get.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: mockBusiness } }), 0)
          }
        })
      }))

      const result = await storage.getBusiness('test-business-1')
      expect(result).toEqual(mockBusiness)
      expect(mockObjectStore.get).toHaveBeenCalledWith('test-business-1')
    })

    it('should return null for non-existent business', async () => {
      mockObjectStore.get.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: undefined } }), 0)
          }
        })
      }))

      const result = await storage.getBusiness('non-existent')
      expect(result).toBeNull()
    })

    it('should get all businesses', async () => {
      const mockBusinesses = [
        createMockBusinessRecord({ id: 'business-1' }),
        createMockBusinessRecord({ id: 'business-2' })
      ]

      mockObjectStore.getAll.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: mockBusinesses } }), 0)
          }
        })
      }))

      const result = await storage.getAllBusinesses()
      expect(result).toEqual(mockBusinesses)
    })

    it('should get businesses by industry', async () => {
      const techBusinesses = [
        createMockBusinessRecord({ id: 'tech-1', industry: 'Technology' }),
        createMockBusinessRecord({ id: 'tech-2', industry: 'Technology' })
      ]

      mockIndex.getAll.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: techBusinesses } }), 0)
          }
        })
      }))

      const result = await storage.getBusinessesByIndustry('Technology')
      expect(result).toEqual(techBusinesses)
      expect(mockObjectStore.index).toHaveBeenCalledWith('by-industry')
    })

    it('should delete business record', async () => {
      await expect(storage.deleteBusiness('test-business-1')).resolves.not.toThrow()
      expect(mockObjectStore.delete).toHaveBeenCalledWith('test-business-1')
    })

    it('should update business record', async () => {
      const updatedBusiness = { ...mockBusiness, businessName: 'Updated Business' }

      await expect(storage.updateBusiness(updatedBusiness)).resolves.not.toThrow()
      expect(mockObjectStore.put).toHaveBeenCalledWith(updatedBusiness)
    })
  })

  describe('Industry Categories Operations', () => {
    const mockIndustry = createMockIndustryCategory({
      id: 'test-industry-1',
      name: 'Technology',
      keywords: ['software', 'tech', 'IT']
    })

    it('should save industry category', async () => {
      await expect(storage.saveIndustry(mockIndustry)).resolves.not.toThrow()
      expect(mockObjectStore.add).toHaveBeenCalledWith(mockIndustry)
    })

    it('should get all industries', async () => {
      const mockIndustries = [
        createMockIndustryCategory({ id: 'industry-1', name: 'Technology' }),
        createMockIndustryCategory({ id: 'industry-2', name: 'Healthcare' })
      ]

      mockObjectStore.getAll.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: mockIndustries } }), 0)
          }
        })
      }))

      const result = await storage.getAllIndustries()
      expect(result).toEqual(mockIndustries)
    })

    it('should delete industry category', async () => {
      await expect(storage.deleteIndustry('test-industry-1')).resolves.not.toThrow()
      expect(mockObjectStore.delete).toHaveBeenCalledWith('test-industry-1')
    })

    it('should update industry category', async () => {
      const updatedIndustry = { ...mockIndustry, name: 'Updated Technology' }

      await expect(storage.updateIndustry(updatedIndustry)).resolves.not.toThrow()
      expect(mockObjectStore.put).toHaveBeenCalledWith(updatedIndustry)
    })
  })

  describe('Configuration Operations', () => {
    const mockConfig = createMockScrapingConfig({
      id: 'test-config-1',
      maxResults: 100,
      timeout: 30000
    })

    it('should save configuration', async () => {
      await expect(storage.saveConfig(mockConfig)).resolves.not.toThrow()
      expect(mockObjectStore.put).toHaveBeenCalledWith(mockConfig)
    })

    it('should get configuration', async () => {
      mockObjectStore.get.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: mockConfig } }), 0)
          }
        })
      }))

      const result = await storage.getConfig('test-config-1')
      expect(result).toEqual(mockConfig)
    })

    it('should delete configuration', async () => {
      await expect(storage.deleteConfig('test-config-1')).resolves.not.toThrow()
      expect(mockObjectStore.delete).toHaveBeenCalledWith('test-config-1')
    })
  })

  describe('Session Management', () => {
    const mockSession = {
      id: 'session-1',
      name: 'Test Session',
      businesses: ['business-1', 'business-2'],
      createdAt: new Date(),
      updatedAt: new Date()
    }

    it('should save session', async () => {
      await expect(storage.saveSession(mockSession)).resolves.not.toThrow()
      expect(mockObjectStore.put).toHaveBeenCalledWith(mockSession)
    })

    it('should get all sessions', async () => {
      const mockSessions = [mockSession]

      mockObjectStore.getAll.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: mockSessions } }), 0)
          }
        })
      }))

      const result = await storage.getAllSessions()
      expect(result).toEqual(mockSessions)
    })

    it('should delete session', async () => {
      await expect(storage.deleteSession('session-1')).resolves.not.toThrow()
      expect(mockObjectStore.delete).toHaveBeenCalledWith('session-1')
    })
  })

  describe('Domain Blacklist Operations', () => {
    const mockBlacklist = {
      id: 'blacklist-1',
      domains: ['spam.com', 'malicious.net'],
      createdAt: new Date(),
      updatedAt: new Date()
    }

    it('should save domain blacklist', async () => {
      await expect(storage.saveDomainBlacklist(mockBlacklist)).resolves.not.toThrow()
      expect(mockObjectStore.put).toHaveBeenCalledWith(mockBlacklist)
    })

    it('should get domain blacklist', async () => {
      mockObjectStore.get.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'success') {
            setTimeout(() => callback({ target: { result: mockBlacklist } }), 0)
          }
        })
      }))

      const result = await storage.getDomainBlacklist('blacklist-1')
      expect(result).toEqual(mockBlacklist)
    })
  })

  describe('Error Handling', () => {
    it('should handle database transaction errors', async () => {
      mockObjectStore.add.mockImplementation(() => ({
        addEventListener: jest.fn((event, callback) => {
          if (event === 'error') {
            setTimeout(() => callback({ target: { error: new Error('Transaction failed') } }), 0)
          }
        })
      }))

      const mockBusiness = createMockBusinessRecord()
      await expect(storage.saveBusiness(mockBusiness)).rejects.toThrow('Transaction failed')
    })

    it('should handle database connection errors', async () => {
      mockDB.transaction.mockImplementation(() => {
        throw new Error('Database not available')
      })

      const mockBusiness = createMockBusinessRecord()
      await expect(storage.saveBusiness(mockBusiness)).rejects.toThrow('Database not available')
    })
  })

  describe('Performance Tests', () => {
    it('should handle bulk operations efficiently', async () => {
      const businesses = Array.from({ length: 100 }, (_, i) => 
        createMockBusinessRecord({ id: `bulk-business-${i}` })
      )

      const start = performance.now()
      
      // Mock successful bulk operations
      for (const business of businesses) {
        await storage.saveBusiness(business)
      }
      
      const end = performance.now()
      expect(end - start).toBeLessThan(1000) // Should complete in under 1 second
    })

    it('should handle concurrent operations', async () => {
      const businesses = Array.from({ length: 10 }, (_, i) => 
        createMockBusinessRecord({ id: `concurrent-business-${i}` })
      )

      const promises = businesses.map(business => storage.saveBusiness(business))
      
      await expect(Promise.all(promises)).resolves.not.toThrow()
    })
  })

  describe('Data Integrity', () => {
    it('should maintain data consistency during updates', async () => {
      const originalBusiness = createMockBusinessRecord({ id: 'consistency-test' })
      const updatedBusiness = { ...originalBusiness, businessName: 'Updated Name' }

      await storage.saveBusiness(originalBusiness)
      await storage.updateBusiness(updatedBusiness)

      expect(mockObjectStore.put).toHaveBeenCalledWith(updatedBusiness)
    })

    it('should handle duplicate IDs appropriately', async () => {
      const business1 = createMockBusinessRecord({ id: 'duplicate-test' })
      const business2 = createMockBusinessRecord({ id: 'duplicate-test' })

      await storage.saveBusiness(business1)
      
      // Second save with same ID should use put (update) instead of add
      await expect(storage.updateBusiness(business2)).resolves.not.toThrow()
    })
  })
})
