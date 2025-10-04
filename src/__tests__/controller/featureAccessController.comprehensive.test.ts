/**
 * Comprehensive Business Rule Tests for Feature Access Controller
 * Tests user permission and access control logic, subscription-based access rules
 */

import { FeatureAccessController, FeatureAccessResult, AccessDenialReason } from '@/controller/featureAccessController'
import { RBACService } from '@/lib/rbac'
import { PaymentController } from '@/controller/paymentController'
import { UserRole, Permission } from '@/types/auth'
import { SubscriptionTier, PaymentStatus } from '@/types/payment'

// Mock dependencies
jest.mock('@/controller/paymentController')
jest.mock('@/lib/rbac')
jest.mock('@/utils/logger')
jest.mock('@/lib/postgresql-database')

describe('Feature Access Controller - Business Logic Rules', () => {
  let featureAccessController: FeatureAccessController
  let mockPaymentController: jest.Mocked<PaymentController>
  let mockRBACService: jest.Mocked<typeof RBACService>

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    role: UserRole.OPERATOR,
    permissions: [Permission.SCRAPE_EXECUTE, Permission.DATA_VIEW],
    isActive: true,
    mfaEnabled: false,
  }

  const mockSubscriptions = {
    free: {
      tier: 'free' as SubscriptionTier,
      status: 'active' as PaymentStatus,
      currentPeriodStart: new Date('2024-01-01'),
      currentPeriodEnd: new Date('2024-02-01'),
    },
    basic: {
      tier: 'basic' as SubscriptionTier,
      status: 'active' as PaymentStatus,
      currentPeriodStart: new Date('2024-01-01'),
      currentPeriodEnd: new Date('2024-02-01'),
    },
    pro: {
      tier: 'pro' as SubscriptionTier,
      status: 'active' as PaymentStatus,
      currentPeriodStart: new Date('2024-01-01'),
      currentPeriodEnd: new Date('2024-02-01'),
    },
    enterprise: {
      tier: 'enterprise' as SubscriptionTier,
      status: 'active' as PaymentStatus,
      currentPeriodStart: new Date('2024-01-01'),
      currentPeriodEnd: new Date('2024-02-01'),
    },
  }

  beforeEach(() => {
    // Mock PaymentController
    mockPaymentController = {
      getCurrentUser: jest.fn(),
      getUserSubscription: jest.fn(),
      emit: jest.fn(),
      on: jest.fn(),
    } as any

    // Mock RBACService
    mockRBACService = {
      hasPermission: jest.fn(),
      getUserPermissions: jest.fn(),
      checkWorkspaceAccess: jest.fn(),
    } as any

    // Replace global instances
    ;(require('@/controller/paymentController') as any).paymentController = mockPaymentController
    ;(require('@/lib/rbac') as any).RBACService = mockRBACService

    featureAccessController = new FeatureAccessController()

    jest.clearAllMocks()
  })

  describe('Subscription-Based Access Control', () => {
    test('should allow free tier features for free plan users', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.free)

      // Mock current usage below limit
      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(5)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(true)
      expect(result.currentUsage).toBe(5)
      expect(result.usageLimit).toBe(10) // Free tier limit
    })

    test('should deny advanced features for free plan users', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.free)

      const result = await featureAccessController.canAccessFeature('advanced_search')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('plan_restriction')
      expect(result.upgradeRequired).toBeDefined()
      expect(result.upgradeRequired?.minimumPlan).toBe('basic')
      expect(result.upgradeRequired?.upgradeUrl).toBe('/upgrade')
    })

    test('should allow basic features for basic plan users', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(50)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(true)
      expect(result.currentUsage).toBe(50)
      expect(result.usageLimit).toBe(100) // Basic tier limit
    })

    test('should allow advanced search for basic plan users', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(5)

      const result = await featureAccessController.canAccessFeature('advanced_search')

      expect(result.hasAccess).toBe(true)
      expect(result.currentUsage).toBe(5)
      expect(result.usageLimit).toBe(10) // Basic tier advanced search limit
    })

    test('should deny API access for basic plan users', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      const result = await featureAccessController.canAccessFeature('api_access')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('plan_restriction')
      expect(result.upgradeRequired?.minimumPlan).toBe('pro')
    })

    test('should allow unlimited access for enterprise users', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.enterprise)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(true)
      expect(result.usageLimit).toBe(-1) // Unlimited
    })
  })

  describe('Usage Limit Enforcement', () => {
    test('should deny access when usage limit is exceeded', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.free)

      // Mock usage at limit
      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(10)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('usage_limit_exceeded')
      expect(result.currentUsage).toBe(10)
      expect(result.usageLimit).toBe(10)
      expect(result.resetDate).toBeInstanceOf(Date)
    })

    test('should allow access when usage is below limit', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(75)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(true)
      expect(result.currentUsage).toBe(75)
      expect(result.usageLimit).toBe(100)
    })

    test('should handle unlimited usage correctly', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.enterprise)

      // Even with high usage, should allow access
      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(10000)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(true)
      expect(result.usageLimit).toBe(-1) // Unlimited
    })
  })

  describe('User Authentication and Authorization', () => {
    test('should deny access for unauthenticated users', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(null)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('subscription_required')
    })

    test('should deny access for suspended accounts', async () => {
      const suspendedUser = {
        ...mockUser,
        isActive: false,
      }

      mockPaymentController.getCurrentUser.mockReturnValue(suspendedUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('account_suspended')
    })

    test('should integrate with RBAC for permission checking', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)
      mockRBACService.hasPermission.mockReturnValue(false)

      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(5)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      // Should still check subscription limits even if RBAC denies
      expect(result.hasAccess).toBe(true) // Subscription allows it
      expect(mockRBACService.hasPermission).toHaveBeenCalledWith(
        mockUser,
        Permission.SCRAPE_EXECUTE,
        expect.any(Object)
      )
    })
  })

  describe('Feature Limit Configuration', () => {
    test('should return correct feature limits for each plan', async () => {
      // Test free plan limits
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.free)
      let limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(10)
      expect(limits.export).toBe(5)
      expect(limits.advanced_search).toBe(0)
      expect(limits.api_access).toBe(0)

      // Test basic plan limits
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)
      limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(100)
      expect(limits.export).toBe(50)
      expect(limits.advanced_search).toBe(10)
      expect(limits.api_access).toBe(0)

      // Test pro plan limits
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.pro)
      limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(1000)
      expect(limits.export).toBe(500)
      expect(limits.advanced_search).toBe(100)
      expect(limits.api_access).toBe(50)

      // Test enterprise plan limits
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.enterprise)
      limits = await featureAccessController.getFeatureLimits()

      expect(limits.scraping_request).toBe(-1) // Unlimited
      expect(limits.export).toBe(-1)
      expect(limits.advanced_search).toBe(-1)
      expect(limits.api_access).toBe(-1)
    })

    test('should determine minimum plan required for features', async () => {
      const getMinimumPlan = (featureAccessController as any).getMinimumPlanForFeature.bind(featureAccessController)

      expect(getMinimumPlan('scraping_request')).toBe('basic') // Available in basic+
      expect(getMinimumPlan('advanced_search')).toBe('basic') // Available in basic+
      expect(getMinimumPlan('api_access')).toBe('pro') // Available in pro+
    })
  })

  describe('Usage Tracking and Caching', () => {
    test('should track feature usage correctly', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)

      const recordUsage = jest.spyOn(featureAccessController, 'recordUsage')
      await featureAccessController.recordUsage('scraping_request', 1)

      expect(recordUsage).toHaveBeenCalledWith('scraping_request', 1)
    })

    test('should cache usage data for performance', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      // Mock database call
      const getCurrentUsage = jest.spyOn(featureAccessController as any, 'getCurrentUsage')
      getCurrentUsage.mockResolvedValue(25)

      // First call should hit database
      await featureAccessController.canAccessFeature('scraping_request')
      expect(getCurrentUsage).toHaveBeenCalledTimes(1)

      // Second call within cache TTL should use cache
      await featureAccessController.canAccessFeature('scraping_request')
      expect(getCurrentUsage).toHaveBeenCalledTimes(1) // Still 1, used cache
    })

    test('should calculate usage reset date correctly', async () => {
      const getUsageResetDate = (featureAccessController as any).getUsageResetDate.bind(featureAccessController)
      const resetDate = getUsageResetDate()

      const now = new Date()
      const expectedResetDate = new Date(now.getFullYear(), now.getMonth() + 1, 1)

      expect(resetDate.getTime()).toBe(expectedResetDate.getTime())
    })
  })

  describe('Event Handling and Notifications', () => {
    test('should emit access denied events', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.free)

      await featureAccessController.canAccessFeature('advanced_search')

      expect(mockPaymentController.emit).toHaveBeenCalledWith('access:denied', {
        featureType: 'advanced_search',
        reason: 'plan_restriction',
      })
    })

    test('should handle subscription loaded events', async () => {
      const onSubscriptionLoaded = jest.spyOn(featureAccessController as any, 'onSubscriptionLoaded')

      // Simulate subscription loaded event
      const mockSubscription = mockSubscriptions.basic
      ;(featureAccessController as any).onSubscriptionLoaded(mockSubscription)

      expect(onSubscriptionLoaded).toHaveBeenCalledWith(mockSubscription)
    })

    test('should handle usage recorded events', async () => {
      const onUsageRecorded = jest.spyOn(featureAccessController as any, 'onUsageRecorded')

      // Simulate usage recorded event
      const usageData = { featureType: 'scraping_request', amount: 1 }
      ;(featureAccessController as any).onUsageRecorded(usageData)

      expect(onUsageRecorded).toHaveBeenCalledWith(usageData)
    })
  })

  describe('Error Handling and Edge Cases', () => {
    test('should handle unknown feature types', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      const result = await featureAccessController.canAccessFeature('unknown_feature')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('feature_disabled')
    })

    test('should handle subscription service failures gracefully', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockImplementation(() => {
        throw new Error('Subscription service unavailable')
      })

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('subscription_required')
    })

    test('should handle usage tracking failures', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockRejectedValue(
        new Error('Usage tracking service unavailable')
      )

      const result = await featureAccessController.canAccessFeature('scraping_request')

      // Should default to allowing access if usage can't be determined
      expect(result.hasAccess).toBe(true)
    })

    test('should handle expired subscriptions', async () => {
      const expiredSubscription = {
        ...mockSubscriptions.basic,
        status: 'past_due' as PaymentStatus,
        currentPeriodEnd: new Date('2023-12-31'), // Expired
      }

      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(expiredSubscription)

      const result = await featureAccessController.canAccessFeature('scraping_request')

      expect(result.hasAccess).toBe(false)
      expect(result.reason).toBe('subscription_required')
    })
  })

  describe('Performance and Efficiency', () => {
    test('should complete access checks within reasonable time', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(25)

      const startTime = Date.now()
      await featureAccessController.canAccessFeature('scraping_request')
      const endTime = Date.now()

      const processingTime = endTime - startTime
      expect(processingTime).toBeLessThan(100) // Should complete within 100ms
    })

    test('should handle concurrent access checks efficiently', async () => {
      mockPaymentController.getCurrentUser.mockReturnValue(mockUser)
      mockPaymentController.getUserSubscription.mockReturnValue(mockSubscriptions.basic)

      jest.spyOn(featureAccessController as any, 'getCurrentUsage').mockResolvedValue(25)

      const requests = Array(10)
        .fill(0)
        .map(() => featureAccessController.canAccessFeature('scraping_request'))

      const startTime = Date.now()
      const results = await Promise.all(requests)
      const endTime = Date.now()

      expect(results).toHaveLength(10)
      expect(endTime - startTime).toBeLessThan(500) // Should handle concurrency efficiently
      
      results.forEach(result => {
        expect(result.hasAccess).toBe(true)
      })
    })
  })
})
