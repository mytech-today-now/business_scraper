/**
 * FeatureAccessController Unit Tests
 * Comprehensive test suite for feature access control and usage limits
 */

import { FeatureAccessController, FeatureAccessResult } from '../featureAccessController'
import { paymentController } from '../paymentController'
import { logger } from '@/utils/logger'
import { UserSubscription } from '@/model/types/payment'

// Mock dependencies
jest.mock('../paymentController')
jest.mock('@/utils/logger')

describe('FeatureAccessController', () => {
  let featureAccessController: FeatureAccessController
  let mockPaymentController: jest.Mocked<typeof paymentController>
  let mockUser: any
  let mockSubscription: UserSubscription

  beforeEach(() => {
    featureAccessController = new FeatureAccessController()
    mockPaymentController = paymentController as jest.Mocked<typeof paymentController>

    mockUser = {
      id: 'test-user-123',
      email: 'test@example.com',
      name: 'Test User',
    }

    mockSubscription = {
      id: 'sub-123',
      userId: mockUser.id,
      stripeSubscriptionId: 'stripe-sub-123',
      planId: 'basic',
      status: 'active',
      currentPeriodStart: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      currentPeriodEnd: new Date(Date.now() + 23 * 24 * 60 * 60 * 1000),
      cancelAtPeriodEnd: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    }

    // Reset mocks
    jest.clearAllMocks()
  })

  describe('Feature Access Validation', () => {
    it('should allow access for valid subscription and within limits', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscription)
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(5)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(true)
      expect(result.currentUsage).toBe(5)
      expect(result.usageLimit).toBe(100) // basic plan limit
    })

    it('should deny access when no user is set', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(null)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('subscription_required')
    })

    it('should deny access for free plan restricted features', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(null) // free plan

      const result = await featureAccessController.canAccessFeature('advanced_search')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('plan_restriction')
      expect(result.upgradeRequired).toBeDefined()
      expect(result.upgradeRequired?.minimumPlan).toBe('basic')
    })

    it('should deny access when usage limit is exceeded', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscription)
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(100)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('usage_limit_exceeded')
      expect(result.currentUsage).toBe(100)
      expect(result.usageLimit).toBe(100)
      expect(result.resetDate).toBeDefined()
    })

    it('should allow unlimited access for enterprise plan', async () => {
      const enterpriseSubscription = { ...mockSubscription, planId: 'enterprise' }
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(enterpriseSubscription)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(true)
      expect(result.currentUsage).toBeUndefined()
      expect(result.usageLimit).toBeUndefined()
    })

    it('should handle errors gracefully', async () => {
      mockPaymentController.getCurrentUser.mockImplementation(() => {
        throw new Error('User service error')
      })

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('feature_disabled')
    })
  })

  describe('Plan Type Detection', () => {
    it('should return free for null subscription', () => {
      mockPaymentController.getUserSubscription.mockReturnValue(null)

      const planType = (featureAccessController as any).getPlanType(null)
      expect(planType).toBe('free')
    })

    it('should return free for inactive subscription', () => {
      const inactiveSubscription = { ...mockSubscription, status: 'canceled' as const }

      const planType = (featureAccessController as any).getPlanType(inactiveSubscription)
      expect(planType).toBe('free')
    })

    it('should return correct plan for active subscription', () => {
      const planType = (featureAccessController as any).getPlanType(mockSubscription)
      expect(planType).toBe('basic')
    })

    it('should default to free for unrecognized plan', () => {
      const unknownSubscription = { ...mockSubscription, planId: 'unknown-plan' }

      const planType = (featureAccessController as any).getPlanType(unknownSubscription)
      expect(planType).toBe('free')
    })
  })

  describe('Usage Tracking', () => {
    beforeEach(() => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
    })

    it('should cache usage data correctly', async () => {
      const mockUsage = 15
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(mockUsage)

      // First call should fetch from service
      const usage1 = await (featureAccessController as any).getCurrentUsage('scraping_request')
      expect(usage1).toBe(mockUsage)

      // Second call should use cache
      const usage2 = await (featureAccessController as any).getCurrentUsage('scraping_request')
      expect(usage2).toBe(mockUsage)

      // Mock should only be called once due to caching
      expect((featureAccessController as any).getMockCurrentUsage).toHaveBeenCalledTimes(1)
    })

    it('should refresh cache after TTL expires', async () => {
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(10)

      // First call
      await (featureAccessController as any).getCurrentUsage('scraping_request')

      // Simulate cache expiry by manipulating the cache timestamp
      const cacheKey = `${mockUser.id}:scraping_request`
      const expiredTime = new Date(Date.now() - 10 * 60 * 1000) // 10 minutes ago
      ;(featureAccessController as any).lastCacheUpdate.set(cacheKey, expiredTime)

      // Second call should refresh cache
      await (featureAccessController as any).getCurrentUsage('scraping_request')

      expect((featureAccessController as any).getMockCurrentUsage).toHaveBeenCalledTimes(2)
    })

    it('should handle cache for multiple users', async () => {
      const user2 = { id: 'user-2', email: 'user2@example.com' }

      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(5)

      // Cache for first user
      await (featureAccessController as any).getCurrentUsage('scraping_request')

      // Switch to second user
      mockPaymentController.getCurrentUser.mockReturnValue(user2)
      await (featureAccessController as any).getCurrentUsage('scraping_request')

      // Should have separate cache entries
      expect((featureAccessController as any).usageCache.size).toBe(2)
    })
  })

  describe('Feature Limits', () => {
    it('should return correct limits for free plan', async () => {
      mockPaymentController.getUserSubscription.mockReturnValue(null)

      const limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(10)
      expect(limits.export).toBe(5)
      expect(limits.advanced_search).toBe(0)
      expect(limits.api_access).toBe(0)
    })

    it('should return correct limits for basic plan', async () => {
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscription)

      const limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(100)
      expect(limits.export).toBe(50)
      expect(limits.advanced_search).toBe(10)
      expect(limits.api_access).toBe(0)
    })

    it('should return correct limits for pro plan', async () => {
      const proSubscription = { ...mockSubscription, planId: 'pro' }
      mockPaymentController.getUserSubscription.mockReturnValue(proSubscription)

      const limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(1000)
      expect(limits.export).toBe(500)
      expect(limits.advanced_search).toBe(100)
      expect(limits.api_access).toBe(50)
    })

    it('should return unlimited limits for enterprise plan', async () => {
      const enterpriseSubscription = { ...mockSubscription, planId: 'enterprise' }
      mockPaymentController.getUserSubscription.mockReturnValue(enterpriseSubscription)

      const limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(-1)
      expect(limits.export).toBe(-1)
      expect(limits.advanced_search).toBe(-1)
      expect(limits.api_access).toBe(-1)
    })
  })

  describe('Usage Summary', () => {
    beforeEach(() => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscription)
    })

    it('should return usage summary for all features', async () => {
      jest
        .spyOn(featureAccessController as any, 'getMockCurrentUsage')
        .mockImplementation((userId: string, featureType: string) => {
          const usage: Record<string, number> = {
            scraping_request: 25,
            export: 10,
            advanced_search: 3,
            api_access: 0,
          }
          return Promise.resolve(usage[featureType] || 0)
        })

      const summary = await featureAccessController.getUsageSummary()

      expect(summary.scraping_request).toEqual({ used: 25, limit: 100 })
      expect(summary.export).toEqual({ used: 10, limit: 50 })
      expect(summary.advanced_search).toEqual({ used: 3, limit: 10 })
      expect(summary.api_access).toEqual({ used: 0, limit: 0 })
    })

    it('should return empty summary when no user', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(null)

      const summary = await featureAccessController.getUsageSummary()

      expect(summary).toEqual({})
    })
  })

  describe('Cache Management', () => {
    beforeEach(() => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
    })

    it('should clear cache for specific user', async () => {
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(10)

      // Populate cache
      await (featureAccessController as any).getCurrentUsage('scraping_request')
      expect((featureAccessController as any).usageCache.size).toBe(1)

      // Clear cache for user
      featureAccessController.clearUsageCache(mockUser.id)
      expect((featureAccessController as any).usageCache.size).toBe(0)
    })

    it('should clear all cache when no user specified', async () => {
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(10)

      // Populate cache
      await (featureAccessController as any).getCurrentUsage('scraping_request')
      expect((featureAccessController as any).usageCache.size).toBe(1)

      // Clear all cache
      featureAccessController.clearUsageCache()
      expect((featureAccessController as any).usageCache.size).toBe(0)
    })
  })

  describe('Event Handling', () => {
    it('should clear cache when subscription is loaded', () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)

      const clearCacheSpy = jest.spyOn(featureAccessController, 'clearUsageCache')

      // Simulate subscription loaded event
      ;(featureAccessController as any).onSubscriptionLoaded(mockSubscription)

      expect(clearCacheSpy).toHaveBeenCalledWith(mockUser.id)
    })

    it('should invalidate cache when usage is recorded', () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)

      // Populate cache first
      const cacheKey = `${mockUser.id}:scraping_request`
      ;(featureAccessController as any).lastCacheUpdate.set(cacheKey, new Date())

      // Simulate usage recorded event
      ;(featureAccessController as any).onUsageRecorded({ featureType: 'scraping_request' })

      expect((featureAccessController as any).lastCacheUpdate.has(cacheKey)).toBe(false)
    })

    it('should emit access denied events', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(null) // free plan
      mockPaymentController.emit = jest.fn()

      await featureAccessController.canAccessFeature('advanced_search')

      expect(mockPaymentController.emit).toHaveBeenCalledWith('access:denied', {
        featureType: 'advanced_search',
        reason: 'plan_restriction',
      })
    })
  })
})
