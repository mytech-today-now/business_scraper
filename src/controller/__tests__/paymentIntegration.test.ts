/**
 * Payment System Integration Tests
 * Tests the integration between PaymentController and FeatureAccessController
 */

import { PaymentController } from '../paymentController'
import { FeatureAccessController } from '../featureAccessController'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/model/userPaymentService')
jest.mock('@/model/stripeService')

describe('Payment System Integration', () => {
  let paymentController: PaymentController
  let featureAccessController: FeatureAccessController
  let mockUser: any

  beforeEach(async () => {
    paymentController = new PaymentController()
    featureAccessController = new FeatureAccessController()

    mockUser = {
      id: 'integration-test-user',
      email: 'integration@example.com',
      name: 'Integration Test User',
    }

    // Initialize payment system
    await paymentController.initializePaymentSystem()

    jest.clearAllMocks()
  })

  afterEach(() => {
    paymentController.removeAllListeners()
  })

  describe('User Subscription Workflow', () => {
    it('should handle complete subscription creation workflow', async () => {
      // Set user
      await paymentController.setCurrentUser(mockUser)

      // Check initial free tier access
      let accessResult = await featureAccessController.canAccessFeature('scraping_request')
      expect(accessResult.hasAccess).toBe(true)
      expect(accessResult.usageLimit).toBe(10) // free tier limit

      // Advanced search should be denied on free tier
      let advancedSearchAccess = await featureAccessController.canAccessFeature('advanced_search')
      expect(advancedSearchAccess.hasAccess).toBe(false)
      expect(advancedSearchAccess.reason).toBe('plan_restriction')

      // Create subscription
      const subscription = await paymentController.createSubscription('basic')
      expect(subscription).toBeDefined()

      // Mock that user now has basic subscription
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-integration-test',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-integration',
        planId: 'basic',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Check upgraded access
      accessResult = await featureAccessController.canAccessFeature('scraping_request')
      expect(accessResult.hasAccess).toBe(true)
      expect(accessResult.usageLimit).toBe(100) // basic tier limit

      // Advanced search should now be available
      advancedSearchAccess = await featureAccessController.canAccessFeature('advanced_search')
      expect(advancedSearchAccess.hasAccess).toBe(true)
      expect(advancedSearchAccess.usageLimit).toBe(10) // basic tier advanced search limit
    })

    it('should handle subscription cancellation workflow', async () => {
      await paymentController.setCurrentUser(mockUser)

      // Create and then cancel subscription
      await paymentController.createSubscription('pro')

      // Mock active subscription
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-to-cancel',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-to-cancel',
        planId: 'pro',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Verify pro access
      let accessResult = await featureAccessController.canAccessFeature('api_access')
      expect(accessResult.hasAccess).toBe(true)
      expect(accessResult.usageLimit).toBe(50) // pro tier API access

      // Cancel subscription
      await paymentController.cancelSubscription()

      // Mock that subscription is now canceled (user reverts to free)
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue(null)

      // Verify access is downgraded
      accessResult = await featureAccessController.canAccessFeature('api_access')
      expect(accessResult.hasAccess).toBe(false)
      expect(accessResult.reason).toBe('plan_restriction')
    })
  })

  describe('Feature Usage and Limits Integration', () => {
    beforeEach(async () => {
      await paymentController.setCurrentUser(mockUser)
    })

    it('should track usage and enforce limits correctly', async () => {
      // Mock basic subscription
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-usage-test',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-usage',
        planId: 'basic',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Mock usage at limit
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(100)

      // Check that access is denied when at limit
      const accessResult = await featureAccessController.canAccessFeature('scraping_request')
      expect(accessResult.hasAccess).toBe(false)
      expect(accessResult.reason).toBe('usage_limit_exceeded')
      expect(accessResult.currentUsage).toBe(100)
      expect(accessResult.usageLimit).toBe(100)

      // Record usage should still work (for tracking purposes)
      await expect(
        paymentController.recordFeatureUsage('scraping_request', { test: true })
      ).resolves.toBeUndefined()
    })

    it('should handle enterprise unlimited access correctly', async () => {
      // Mock enterprise subscription
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-enterprise-test',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-enterprise',
        planId: 'enterprise',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Mock very high usage
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(10000)

      // Should still have access due to unlimited plan
      const accessResult = await featureAccessController.canAccessFeature('scraping_request')
      expect(accessResult.hasAccess).toBe(true)
      expect(accessResult.currentUsage).toBeUndefined()
      expect(accessResult.usageLimit).toBeUndefined()
    })
  })

  describe('Event-Driven Integration', () => {
    it('should handle subscription events and cache invalidation', async () => {
      await paymentController.setCurrentUser(mockUser)

      // Set up event listeners
      const subscriptionLoadedSpy = jest.fn()
      const usageRecordedSpy = jest.fn()
      const accessDeniedSpy = jest.fn()

      paymentController.on('subscription:loaded', subscriptionLoadedSpy)
      paymentController.on('usage:recorded', usageRecordedSpy)
      paymentController.on('access:denied', accessDeniedSpy)

      // Load user payment data (should trigger subscription:loaded)
      await paymentController.loadUserPaymentData()
      expect(subscriptionLoadedSpy).toHaveBeenCalled()

      // Record usage (should trigger usage:recorded)
      await paymentController.recordFeatureUsage('export', { format: 'csv' })
      expect(usageRecordedSpy).toHaveBeenCalledWith({
        featureType: 'export',
        metadata: { format: 'csv' },
      })

      // Try to access restricted feature (should trigger access:denied)
      await featureAccessController.canAccessFeature('api_access') // not available on free tier
      expect(accessDeniedSpy).toHaveBeenCalledWith({
        featureType: 'api_access',
        reason: 'plan_restriction',
      })
    })

    it('should handle cache invalidation on subscription changes', async () => {
      await paymentController.setCurrentUser(mockUser)

      // Populate cache with initial usage
      jest.spyOn(featureAccessController as any, 'getMockCurrentUsage').mockResolvedValue(5)
      await featureAccessController.canAccessFeature('scraping_request')

      // Verify cache is populated
      const cacheSize = (featureAccessController as any).usageCache.size
      expect(cacheSize).toBeGreaterThan(0)

      // Simulate subscription change
      const newSubscription = {
        id: 'sub-new',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-new',
        planId: 'pro',
        status: 'active' as const,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      // Trigger subscription loaded event (simulates cache invalidation)
      ;(featureAccessController as any).onSubscriptionLoaded(newSubscription)

      // Cache should be cleared for the user
      const userCache = (featureAccessController as any).usageCache.get(mockUser.id)
      expect(userCache).toBeUndefined()
    })
  })

  describe('Error Handling Integration', () => {
    it('should handle payment controller errors gracefully in feature access', async () => {
      await paymentController.setCurrentUser(mockUser)

      // Mock payment controller to throw error
      jest.spyOn(paymentController, 'getCurrentUser').mockImplementation(() => {
        throw new Error('Payment controller error')
      })

      // Feature access should handle the error gracefully
      const accessResult = await featureAccessController.canAccessFeature('scraping_request')
      expect(accessResult.hasAccess).toBe(false)
      expect(accessResult.reason).toBe('feature_disabled')
    })

    it('should handle feature access errors in payment workflows', async () => {
      await paymentController.setCurrentUser(mockUser)

      // Mock feature access to throw error
      jest
        .spyOn(featureAccessController, 'canAccessFeature')
        .mockRejectedValue(new Error('Feature access error'))

      // Payment controller should handle the error gracefully
      const hasAccess = await paymentController.checkFeatureAccess('scraping_request')
      expect(hasAccess).toBe(false)
    })
  })

  describe('Usage Summary Integration', () => {
    it('should provide comprehensive usage summary across all features', async () => {
      await paymentController.setCurrentUser(mockUser)

      // Mock basic subscription
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-summary-test',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-summary',
        planId: 'basic',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Mock different usage levels for different features
      jest
        .spyOn(featureAccessController as any, 'getMockCurrentUsage')
        .mockImplementation((userId: string, featureType: string) => {
          const usage: Record<string, number> = {
            scraping_request: 75, // 75/100
            export: 30, // 30/50
            advanced_search: 8, // 8/10
            api_access: 0, // 0/0 (not available in basic)
          }
          return Promise.resolve(usage[featureType] || 0)
        })

      const summary = await featureAccessController.getUsageSummary()

      expect(summary).toEqual({
        scraping_request: { used: 75, limit: 100 },
        export: { used: 30, limit: 50 },
        advanced_search: { used: 8, limit: 10 },
        api_access: { used: 0, limit: 0 },
      })
    })
  })

  describe('Plan Upgrade/Downgrade Scenarios', () => {
    it('should handle plan upgrade scenario correctly', async () => {
      await paymentController.setCurrentUser(mockUser)

      // Start with basic plan
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-upgrade-test',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-upgrade',
        planId: 'basic',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Verify basic plan limits
      let limits = await featureAccessController.getFeatureLimits()
      expect(limits.api_access).toBe(0) // No API access in basic

      // Upgrade to pro
      await paymentController.createSubscription('pro')

      // Mock pro subscription
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-upgrade-test',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-upgrade',
        planId: 'pro',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      })

      // Verify pro plan limits
      limits = await featureAccessController.getFeatureLimits()
      expect(limits.api_access).toBe(50) // API access available in pro
      expect(limits.scraping_request).toBe(1000) // Higher scraping limit

      // Verify API access is now available
      const apiAccess = await featureAccessController.canAccessFeature('api_access')
      expect(apiAccess.hasAccess).toBe(true)
    })
  })
})
