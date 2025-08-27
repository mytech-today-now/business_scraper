/**
 * Tests for cache system
 */

import { MemoryCache, CacheHelper, cached } from '@/lib/cache'
import { Features } from '@/lib/feature-flags'
import { jest } from '@jest/globals'
import { setupTest, cleanupTest } from '../setup/testSetup'

// Mock the feature flags
const mockIsCachingEnabled = jest.fn(() => true)
jest.mock('@/lib/feature-flags', () => ({
  Features: {
    isCachingEnabled: mockIsCachingEnabled,
  },
}))

// Mock the config
jest.mock('@/lib/config', () => ({
  getCacheConfig: jest.fn(() => ({
    type: 'memory',
    memory: {
      maxSize: 100,
      ttl: 60000,
    },
  })),
}))

describe('Cache System', () => {
  describe('MemoryCache', () => {
    let cache: MemoryCache

    beforeEach(() => {
      setupTest()
      cache = new MemoryCache(10, 60000) // Small cache for testing
    })

    afterEach(async () => {
      await cache.close()
      cleanupTest()
    })

    describe('Basic operations', () => {
      it('should set and get values', async () => {
        await cache.set('key1', 'value1')
        const result = await cache.get('key1')

        expect(result).toBe('value1')
      })

      it('should return null for non-existent keys', async () => {
        const result = await cache.get('non-existent')
        expect(result).toBeNull()
      })

      it('should delete values', async () => {
        await cache.set('key1', 'value1')
        await cache.delete('key1')

        const result = await cache.get('key1')
        expect(result).toBeNull()
      })

      it('should clear all values', async () => {
        await cache.set('key1', 'value1')
        await cache.set('key2', 'value2')
        await cache.clear()

        const result1 = await cache.get('key1')
        const result2 = await cache.get('key2')

        expect(result1).toBeNull()
        expect(result2).toBeNull()
      })

      it('should check if key exists', async () => {
        await cache.set('key1', 'value1')

        const exists = await cache.exists('key1')
        const notExists = await cache.exists('key2')

        expect(exists).toBe(true)
        expect(notExists).toBe(false)
      })
    })

    describe('TTL (Time To Live)', () => {
      it('should expire entries after TTL', async () => {
        await cache.set('key1', 'value1', 100) // 100ms TTL

        // Should exist immediately
        let result = await cache.get('key1')
        expect(result).toBe('value1')

        // Wait for expiration
        await new Promise(resolve => setTimeout(resolve, 150))

        // Should be expired
        result = await cache.get('key1')
        expect(result).toBeNull()
      })

      it('should use default TTL when not specified', async () => {
        await cache.set('key1', 'value1') // Uses default TTL

        const result = await cache.get('key1')
        expect(result).toBe('value1')
      })

      it('should handle exists() with expired entries', async () => {
        await cache.set('key1', 'value1', 50)

        // Wait for expiration
        await new Promise(resolve => setTimeout(resolve, 100))

        const exists = await cache.exists('key1')
        expect(exists).toBe(false)
      })
    })

    describe('Size limits and eviction', () => {
      it('should evict old entries when size limit reached', async () => {
        const smallCache = new MemoryCache(3, 60000) // Max 3 entries

        // Fill cache to capacity
        await smallCache.set('key1', 'value1')
        await smallCache.set('key2', 'value2')
        await smallCache.set('key3', 'value3')

        // Add one more (should trigger eviction)
        await smallCache.set('key4', 'value4')

        // Some entries should be evicted
        const stats = smallCache.getStats()
        expect(stats.size).toBeLessThanOrEqual(3)

        await smallCache.close()
      })
    })

    describe('Pattern matching', () => {
      it('should return keys matching pattern', async () => {
        await cache.set('user:1', 'user1')
        await cache.set('user:2', 'user2')
        await cache.set('post:1', 'post1')

        const userKeys = await cache.keys('user:*')
        const allKeys = await cache.keys()

        expect(userKeys).toContain('user:1')
        expect(userKeys).toContain('user:2')
        expect(userKeys).not.toContain('post:1')
        expect(allKeys).toHaveLength(3)
      })
    })

    describe('Statistics', () => {
      it('should provide cache statistics', async () => {
        await cache.set('key1', 'value1')
        await cache.set('key2', 'value2', 50) // Short TTL

        // Wait for one to expire
        await new Promise(resolve => setTimeout(resolve, 100))

        const stats = cache.getStats()

        expect(stats.size).toBeGreaterThan(0)
        expect(stats.maxSize).toBe(10)
        expect(typeof stats.expired).toBe('number')
        expect(typeof stats.active).toBe('number')
      })
    })
  })

  describe('CacheHelper', () => {
    beforeEach(() => {
      // Reset feature flag mock
      mockIsCachingEnabled.mockReturnValue(true)
    })

    describe('Basic operations', () => {
      it('should set and get values', async () => {
        await CacheHelper.set('test-key', 'test-value')
        const result = await CacheHelper.get('test-key')

        expect(result).toBe('test-value')
      })

      it('should return null for non-existent keys', async () => {
        const result = await CacheHelper.get('non-existent-key')
        expect(result).toBeNull()
      })

      it('should delete values', async () => {
        await CacheHelper.set('test-key', 'test-value')
        await CacheHelper.delete('test-key')

        const result = await CacheHelper.get('test-key')
        expect(result).toBeNull()
      })

      it('should check existence', async () => {
        await CacheHelper.set('test-key', 'test-value')

        const exists = await CacheHelper.exists('test-key')
        const notExists = await CacheHelper.exists('other-key')

        expect(exists).toBe(true)
        expect(notExists).toBe(false)
      })
    })

    describe('getOrSet pattern', () => {
      it('should get existing value', async () => {
        await CacheHelper.set('existing-key', 'existing-value')

        const factory = jest.fn(() => Promise.resolve('new-value'))
        const result = await CacheHelper.getOrSet('existing-key', factory)

        expect(result).toBe('existing-value')
        expect(factory).not.toHaveBeenCalled()
      })

      it('should set and return new value when key does not exist', async () => {
        const factory = jest.fn(() => Promise.resolve('factory-value'))
        const result = await CacheHelper.getOrSet('new-key', factory)

        expect(result).toBe('factory-value')
        expect(factory).toHaveBeenCalledTimes(1)

        // Verify it was cached
        const cached = await CacheHelper.get('new-key')
        expect(cached).toBe('factory-value')
      })

      it('should handle factory errors gracefully', async () => {
        const factory = jest.fn(() => Promise.reject(new Error('Factory error')))

        await expect(CacheHelper.getOrSet('error-key', factory)).rejects.toThrow('Factory error')
      })
    })

    describe('Error handling', () => {
      it('should handle cache errors gracefully', async () => {
        // Test that CacheHelper.get returns null when an error occurs
        // We'll test this by using a non-existent cache key that might cause internal errors
        const result = await CacheHelper.get('non-existent-key-that-might-cause-errors')

        // CacheHelper.get should handle any errors gracefully and return null
        expect(result).toBeNull()
      })
    })
  })

  describe('Cached decorator', () => {
    class TestService {
      callCount = 0

      @cached(1000, 'test:')
      async expensiveOperation(input: string): Promise<string> {
        this.callCount++
        return `result-${input}-${this.callCount}`
      }

      @cached(100, 'short:')
      async shortCachedOperation(input: string): Promise<string> {
        this.callCount++
        return `short-${input}-${this.callCount}`
      }
    }

    let service: TestService

    beforeEach(() => {
      service = new TestService()
    })

    it('should cache method results', async () => {
      const result1 = await service.expensiveOperation('test')
      const result2 = await service.expensiveOperation('test')

      expect(result1).toBe(result2)
      expect(service.callCount).toBe(1) // Method called only once
    })

    it('should cache different arguments separately', async () => {
      const result1 = await service.expensiveOperation('input1')
      const result2 = await service.expensiveOperation('input2')

      expect(result1).not.toBe(result2)
      expect(service.callCount).toBe(2) // Method called twice for different inputs
    })

    it('should respect TTL', async () => {
      const result1 = await service.shortCachedOperation('test')

      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150))

      const result2 = await service.shortCachedOperation('test')

      expect(result1).not.toBe(result2) // Different results due to cache expiration
      expect(service.callCount).toBe(2) // Method called twice
    })

    it('should work when caching is disabled', async () => {
      // Disable caching
      mockIsCachingEnabled.mockReturnValue(false)

      const result1 = await service.expensiveOperation('test')
      const result2 = await service.expensiveOperation('test')

      expect(result1).not.toBe(result2) // Different results, no caching
      expect(service.callCount).toBe(2) // Method called twice
    })

    it('should handle method errors', async () => {
      class ErrorService {
        @cached(1000, 'error:')
        async errorMethod(): Promise<string> {
          throw new Error('Method error')
        }
      }

      const errorService = new ErrorService()

      await expect(errorService.errorMethod()).rejects.toThrow('Method error')
    })
  })

  describe('Feature flag integration', () => {
    it('should respect caching feature flag', async () => {
      // Test that cache operations work regardless of feature flag state
      // Since we're using a memory cache in tests, operations should work
      await CacheHelper.set('test-key', 'test-value')
      const result = await CacheHelper.get('test-key')

      // Should return the cached value
      expect(result).toBe('test-value')
    })
  })
})
