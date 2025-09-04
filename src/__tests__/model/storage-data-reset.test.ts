/**
 * Comprehensive Unit Tests for Storage Data Reset Functionality
 * Tests the fix for null reference errors during data reset operations
 */

import { StorageService } from '@/model/storage'
import { DataResetService } from '@/utils/dataReset'
import { jest } from '@jest/globals'

// Mock IndexedDB for testing
const mockIndexedDB = {
  open: jest.fn(),
  deleteDatabase: jest.fn(),
}

const mockDB = {
  transaction: jest.fn(),
  close: jest.fn(),
  clear: jest.fn(),
  delete: jest.fn(),
  put: jest.fn(),
  get: jest.fn(),
  getAll: jest.fn(),
}

// Mock the global indexedDB
Object.defineProperty(global, 'indexedDB', {
  value: mockIndexedDB,
  writable: true,
})

// Mock the openDB function from idb
const mockOpenDB = jest.fn()
jest.mock('idb', () => ({
  openDB: mockOpenDB,
}))

describe('Storage Data Reset - Null Reference Fix', () => {
  let storageService: StorageService

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks()

    // Create a new storage service instance for each test
    storageService = new StorageService()

    // Mock successful database operations by default
    mockDB.clear.mockResolvedValue(undefined)
    mockDB.delete.mockResolvedValue(undefined)
    mockDB.put.mockResolvedValue(undefined)
    mockDB.get.mockResolvedValue(null)
    mockDB.getAll.mockResolvedValue([])
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Database Initialization Failure Handling', () => {
    it('should handle clearIndustries when database initialization fails', async () => {
      // Mock database initialization to fail
      const mockOpenDB = require('idb').openDB
      mockOpenDB.mockRejectedValue(new Error('Database initialization timeout after 10 seconds'))

      // Attempt to clear industries - should throw proper error instead of null reference
      await expect(storageService.clearIndustries()).rejects.toThrow(
        'Database not available - initialization may have failed or timed out'
      )

      // Verify that the error is properly handled and logged
      expect(mockOpenDB).toHaveBeenCalled()
    })

    it('should handle clearBusinesses when database initialization fails', async () => {
      // Mock database initialization to fail
      const mockOpenDB = require('idb').openDB
      mockOpenDB.mockRejectedValue(new Error('Database initialization timeout after 10 seconds'))

      // Attempt to clear businesses - should throw proper error instead of null reference
      await expect(storageService.clearBusinesses()).rejects.toThrow(
        'Database not available - initialization may have failed or timed out'
      )
    })

    it('should handle clearSessions when database initialization fails', async () => {
      // Mock database initialization to fail
      const mockOpenDB = require('idb').openDB
      mockOpenDB.mockRejectedValue(new Error('Database initialization timeout after 10 seconds'))

      // Attempt to clear sessions - should throw proper error instead of null reference
      await expect(storageService.clearSessions()).rejects.toThrow(
        'Database not available - initialization may have failed or timed out'
      )
    })

    it('should handle clearDomainBlacklist when database initialization fails', async () => {
      // Mock database initialization to fail
      const mockOpenDB = require('idb').openDB
      mockOpenDB.mockRejectedValue(new Error('Database initialization timeout after 10 seconds'))

      // Attempt to clear domain blacklist - should throw proper error instead of null reference
      await expect(storageService.clearDomainBlacklist()).rejects.toThrow(
        'Database not available - initialization may have failed or timed out'
      )
    })
  })

  describe('Database Initialization Success Handling', () => {
    beforeEach(() => {
      // Mock successful database initialization
      const mockOpenDB = require('idb').openDB
      mockOpenDB.mockResolvedValue(mockDB)
    })

    it('should successfully clear industries when database is available', async () => {
      mockDB.clear.mockResolvedValue(undefined)

      await expect(storageService.clearIndustries()).resolves.not.toThrow()
      expect(mockDB.clear).toHaveBeenCalledWith('industries')
    })

    it('should successfully clear businesses when database is available', async () => {
      mockDB.clear.mockResolvedValue(undefined)

      await expect(storageService.clearBusinesses()).resolves.not.toThrow()
      expect(mockDB.clear).toHaveBeenCalledWith('businesses')
    })

    it('should successfully clear sessions when database is available', async () => {
      mockDB.clear.mockResolvedValue(undefined)

      await expect(storageService.clearSessions()).resolves.not.toThrow()
      expect(mockDB.clear).toHaveBeenCalledWith('sessions')
    })

    it('should successfully clear domain blacklist when database is available', async () => {
      mockDB.delete.mockResolvedValue(undefined)

      await expect(storageService.clearDomainBlacklist()).resolves.not.toThrow()
      expect(mockDB.delete).toHaveBeenCalledWith('domainBlacklist', 'global-blacklist')
    })
  })

  describe('Data Reset Service Integration', () => {
    beforeEach(() => {
      // Mock successful database initialization
      const mockOpenDB = require('idb').openDB
      mockOpenDB.mockResolvedValue(mockDB)
    })

    it('should handle complete data reset without null reference errors', async () => {
      // Mock all clear operations to succeed
      mockDB.clear.mockResolvedValue(undefined)
      mockDB.delete.mockResolvedValue(undefined)

      const result = await DataResetService.resetAllData({
        includeApiCredentials: true,
        includeLocalStorage: true,
        useAggressiveReset: false,
        confirmationRequired: false,
      })

      expect(result.success).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should handle aggressive data reset without null reference errors', async () => {
      // Mock database reset operations
      mockIndexedDB.deleteDatabase.mockImplementation((name, callback) => {
        if (callback && typeof callback === 'function') {
          callback()
        }
        return Promise.resolve()
      })

      const result = await DataResetService.resetAllData({
        includeApiCredentials: true,
        includeLocalStorage: true,
        useAggressiveReset: true,
        confirmationRequired: false,
      })

      expect(result.success).toBe(true)
      expect(result.fallbackUsed).toBe(true)
    })
  })

  describe('Error Handling and Logging', () => {
    it('should properly log errors when database operations fail', async () => {
      // Mock database initialization to succeed but clear operation to fail
      const mockOpenDB = require('idb').openDB
      mockOpenDB.mockResolvedValue(mockDB)
      mockDB.clear.mockRejectedValue(new Error('Clear operation failed'))

      // Mock console.error to capture log messages
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation()

      await expect(storageService.clearIndustries()).rejects.toThrow('Clear operation failed')

      // Verify error was logged
      expect(consoleSpy).toHaveBeenCalled()

      consoleSpy.mockRestore()
    })
  })
})
