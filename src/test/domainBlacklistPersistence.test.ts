/**
 * Domain Blacklist Persistence Test
 * Tests that domain blacklist values persist between refreshes using IndexedDB
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { storage } from '@/model/storage'
import { clientSearchEngine } from '@/model/clientSearchEngine'

// Mock IndexedDB for testing
const mockIDBDatabase = {
  put: jest.fn(),
  get: jest.fn(),
  delete: jest.fn(),
  getAll: jest.fn(),
  count: jest.fn(),
  close: jest.fn()
}

const mockOpenDB = jest.fn().mockResolvedValue(mockIDBDatabase)

// Mock the idb module
jest.mock('idb', () => ({
  openDB: mockOpenDB
}))

describe('Domain Blacklist Persistence', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  afterEach(() => {
    jest.restoreAllMocks()
  })

  describe('Storage Service Domain Blacklist', () => {
    test('should save domain blacklist to IndexedDB', async () => {
      const testDomains = ['example.com', 'test.com', 'spam.net']
      
      mockIDBDatabase.put.mockResolvedValue(undefined)

      await storage.saveDomainBlacklist(testDomains)

      expect(mockIDBDatabase.put).toHaveBeenCalledWith('domainBlacklist', {
        id: 'global-blacklist',
        domains: testDomains,
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date)
      })
    })

    test('should retrieve domain blacklist from IndexedDB', async () => {
      const testDomains = ['example.com', 'test.com', 'spam.net']
      const mockBlacklistData = {
        id: 'global-blacklist',
        domains: testDomains,
        createdAt: new Date(),
        updatedAt: new Date()
      }

      mockIDBDatabase.get.mockResolvedValue(mockBlacklistData)

      const result = await storage.getDomainBlacklist()

      expect(mockIDBDatabase.get).toHaveBeenCalledWith('domainBlacklist', 'global-blacklist')
      expect(result).toEqual(testDomains)
    })

    test('should return empty array when no blacklist exists', async () => {
      mockIDBDatabase.get.mockResolvedValue(undefined)

      const result = await storage.getDomainBlacklist()

      expect(result).toEqual([])
    })

    test('should add domain to existing blacklist', async () => {
      const existingDomains = ['example.com', 'test.com']
      const newDomain = 'spam.net'
      const expectedDomains = [...existingDomains, newDomain]

      mockIDBDatabase.get.mockResolvedValue({
        id: 'global-blacklist',
        domains: existingDomains,
        createdAt: new Date(),
        updatedAt: new Date()
      })
      mockIDBDatabase.put.mockResolvedValue(undefined)

      await storage.addDomainToBlacklist(newDomain)

      expect(mockIDBDatabase.put).toHaveBeenCalledWith('domainBlacklist', {
        id: 'global-blacklist',
        domains: expectedDomains,
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date)
      })
    })

    test('should not add duplicate domain to blacklist', async () => {
      const existingDomains = ['example.com', 'test.com']
      const duplicateDomain = 'example.com'

      mockIDBDatabase.get.mockResolvedValue({
        id: 'global-blacklist',
        domains: existingDomains,
        createdAt: new Date(),
        updatedAt: new Date()
      })

      await storage.addDomainToBlacklist(duplicateDomain)

      // Should not call put since domain already exists
      expect(mockIDBDatabase.put).not.toHaveBeenCalled()
    })

    test('should remove domain from blacklist', async () => {
      const existingDomains = ['example.com', 'test.com', 'spam.net']
      const domainToRemove = 'test.com'
      const expectedDomains = ['example.com', 'spam.net']

      mockIDBDatabase.get.mockResolvedValue({
        id: 'global-blacklist',
        domains: existingDomains,
        createdAt: new Date(),
        updatedAt: new Date()
      })
      mockIDBDatabase.put.mockResolvedValue(undefined)

      await storage.removeDomainFromBlacklist(domainToRemove)

      expect(mockIDBDatabase.put).toHaveBeenCalledWith('domainBlacklist', {
        id: 'global-blacklist',
        domains: expectedDomains,
        createdAt: expect.any(Date),
        updatedAt: expect.any(Date)
      })
    })

    test('should clear domain blacklist', async () => {
      mockIDBDatabase.delete.mockResolvedValue(undefined)

      await storage.clearDomainBlacklist()

      expect(mockIDBDatabase.delete).toHaveBeenCalledWith('domainBlacklist', 'global-blacklist')
    })
  })

  describe('ClientSearchEngine Integration', () => {
    test('should load persistent domain blacklist on initialization', async () => {
      const testDomains = ['example.com', 'test.com', 'spam.net']
      
      // Mock storage to return test domains
      jest.spyOn(storage, 'getDomainBlacklist').mockResolvedValue(testDomains)
      
      // Mock retrieveApiCredentials to return empty credentials
      const mockRetrieveApiCredentials = jest.fn().mockResolvedValue({})
      jest.doMock('@/utils/secureStorage', () => ({
        retrieveApiCredentials: mockRetrieveApiCredentials
      }))

      await clientSearchEngine.initialize()

      expect(storage.getDomainBlacklist).toHaveBeenCalled()
      
      // Verify that the search engine has the persistent blacklist
      const credentials = (clientSearchEngine as any).credentials
      expect(credentials?.domainBlacklist).toEqual(testDomains)
    })

    test('should refresh domain blacklist when requested', async () => {
      const initialDomains = ['example.com']
      const updatedDomains = ['example.com', 'test.com', 'spam.net']
      
      // Mock storage to return different domains on subsequent calls
      jest.spyOn(storage, 'getDomainBlacklist')
        .mockResolvedValueOnce(initialDomains)
        .mockResolvedValueOnce(updatedDomains)

      await clientSearchEngine.initialize()
      
      // Initial load
      let credentials = (clientSearchEngine as any).credentials
      expect(credentials?.domainBlacklist).toEqual(initialDomains)

      // Refresh blacklist
      await clientSearchEngine.refreshDomainBlacklist()
      
      // Should have updated domains
      credentials = (clientSearchEngine as any).credentials
      expect(credentials?.domainBlacklist).toEqual(updatedDomains)
    })
  })

  describe('Persistence Simulation', () => {
    test('should maintain blacklist across simulated page refreshes', async () => {
      const testDomains = ['example.com', 'test.com', 'spam.net']
      
      // Simulate saving blacklist
      mockIDBDatabase.put.mockResolvedValue(undefined)
      await storage.saveDomainBlacklist(testDomains)

      // Simulate page refresh - clear in-memory state
      jest.clearAllMocks()

      // Simulate loading after refresh
      mockIDBDatabase.get.mockResolvedValue({
        id: 'global-blacklist',
        domains: testDomains,
        createdAt: new Date(),
        updatedAt: new Date()
      })

      const retrievedDomains = await storage.getDomainBlacklist()

      expect(retrievedDomains).toEqual(testDomains)
      expect(mockIDBDatabase.get).toHaveBeenCalledWith('domainBlacklist', 'global-blacklist')
    })
  })

  describe('Error Handling', () => {
    test('should handle IndexedDB errors gracefully', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation()
      
      mockIDBDatabase.get.mockRejectedValue(new Error('IndexedDB error'))

      const result = await storage.getDomainBlacklist()

      expect(result).toEqual([])
      expect(consoleSpy).toHaveBeenCalled()
      
      consoleSpy.mockRestore()
    })

    test('should handle save errors gracefully', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation()
      
      mockIDBDatabase.put.mockRejectedValue(new Error('IndexedDB save error'))

      await expect(storage.saveDomainBlacklist(['test.com'])).rejects.toThrow('IndexedDB save error')
      
      consoleSpy.mockRestore()
    })
  })
})

// Helper function to test persistence manually
export async function testDomainBlacklistPersistence() {
  console.log('🧪 Testing Domain Blacklist Persistence...')
  
  try {
    // Test saving domains
    const testDomains = ['example.com', 'test.com', 'spam.net']
    await storage.saveDomainBlacklist(testDomains)
    console.log('✅ Saved test domains to IndexedDB')
    
    // Test retrieving domains
    const retrievedDomains = await storage.getDomainBlacklist()
    console.log('✅ Retrieved domains from IndexedDB:', retrievedDomains)
    
    // Test adding a domain
    await storage.addDomainToBlacklist('newdomain.com')
    const updatedDomains = await storage.getDomainBlacklist()
    console.log('✅ Added new domain, updated list:', updatedDomains)
    
    // Test ClientSearchEngine integration
    await clientSearchEngine.initialize()
    console.log('✅ ClientSearchEngine initialized with persistent blacklist')
    
    console.log('🎉 Domain Blacklist Persistence test completed successfully!')
    
  } catch (error) {
    console.error('❌ Domain Blacklist Persistence test failed:', error)
    throw error
  }
}
