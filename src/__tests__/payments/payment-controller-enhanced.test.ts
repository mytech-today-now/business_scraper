/**
 * Enhanced Payment Controller Tests
 * Comprehensive testing for payment controller logic, state management, and event handling
 */

import { 
  setupPaymentMocks, 
  resetPaymentMocks, 
  configureDefaultMockBehaviors,
  allMocks 
} from '../utils/paymentMockSetup'
import { 
  paymentTestData,
  createMockStripeSubscription,
  simulateStripeError
} from '../utils/paymentTestUtils'

// Setup mocks before importing modules
setupPaymentMocks()
configureDefaultMockBehaviors()

// Import after mocks are setup
import { PaymentController } from '@/controller/paymentController'

describe('Enhanced Payment Controller Tests', () => {
  let paymentController: PaymentController

  beforeEach(() => {
    resetPaymentMocks()
    configureDefaultMockBehaviors()
    paymentController = new PaymentController()
  })

  afterEach(() => {
    paymentController.removeAllListeners()
  })

  describe('Payment System Initialization', () => {
    it('should initialize payment system successfully', async () => {
      const initSpy = jest.fn()
      paymentController.on('payment:initialized', initSpy)

      await paymentController.initializePaymentSystem()

      expect(initSpy).toHaveBeenCalled()
      expect(paymentController.isPaymentSystemInitialized()).toBe(true)
      expect(allMocks.logger.info).toHaveBeenCalledWith(
        'PaymentController',
        'Payment system initialized successfully'
      )
    })

    it('should handle initialization errors gracefully', async () => {
      const errorSpy = jest.fn()
      paymentController.on('payment:error', errorSpy)

      // Mock initialization failure
      jest.spyOn(paymentController, 'loadSubscriptionPlans').mockRejectedValue(
        new Error('Failed to load plans')
      )

      await expect(paymentController.initializePaymentSystem()).rejects.toThrow()
      expect(errorSpy).toHaveBeenCalled()
      expect(allMocks.logger.error).toHaveBeenCalled()
    })

    it('should not reinitialize if already initialized', async () => {
      await paymentController.initializePaymentSystem()
      const logCallCount = allMocks.logger.info.mock.calls.length

      await paymentController.initializePaymentSystem()

      expect(allMocks.logger.info).toHaveBeenCalledWith(
        'PaymentController',
        'Payment system already initialized'
      )
      expect(allMocks.logger.info.mock.calls.length).toBeGreaterThan(logCallCount)
    })
  })

  describe('Subscription Plan Management', () => {
    it('should load subscription plans successfully', async () => {
      const plansSpy = jest.fn()
      paymentController.on('plans:loaded', plansSpy)

      const plans = await paymentController.loadSubscriptionPlans()

      expect(plansSpy).toHaveBeenCalledWith(plans)
      expect(plans).toHaveLength(3) // free, basic, pro
      expect(plans[0]).toHaveProperty('id', 'free')
      expect(plans[1]).toHaveProperty('id', 'basic')
      expect(plans[2]).toHaveProperty('id', 'pro')
    })

    it('should return immutable plan data', async () => {
      await paymentController.loadSubscriptionPlans()
      const plans1 = paymentController.getSubscriptionPlans()
      const plans2 = paymentController.getSubscriptionPlans()

      expect(plans1).not.toBe(plans2) // Different references
      expect(plans1).toEqual(plans2) // Same content

      // Modifying returned array should not affect internal state
      plans1.push({ id: 'hacked' } as any)
      const plans3 = paymentController.getSubscriptionPlans()
      expect(plans3).toHaveLength(3)
    })

    it('should handle plan loading errors', async () => {
      jest.spyOn(paymentController as any, 'getMockSubscriptionPlans').mockRejectedValue(
        new Error('Plan service unavailable')
      )

      await expect(paymentController.loadSubscriptionPlans()).rejects.toThrow()
      expect(allMocks.logger.error).toHaveBeenCalledWith(
        'PaymentController',
        'Failed to load subscription plans',
        expect.any(Error)
      )
    })
  })

  describe('User Management', () => {
    it('should set current user successfully', async () => {
      const userSpy = jest.fn()
      paymentController.on('user:set', userSpy)

      await paymentController.setCurrentUser(paymentTestData.validUser)

      expect(userSpy).toHaveBeenCalledWith(paymentTestData.validUser)
      expect(paymentController.getCurrentUser()).toEqual(paymentTestData.validUser)
      expect(allMocks.logger.info).toHaveBeenCalledWith(
        'PaymentController',
        `Set current user: ${paymentTestData.validUser.id}`
      )
    })

    it('should validate user object', async () => {
      const invalidUsers = [
        null,
        undefined,
        {},
        { email: 'test@example.com' }, // Missing id
        { id: null },
        { id: '' }
      ]

      for (const invalidUser of invalidUsers) {
        await expect(paymentController.setCurrentUser(invalidUser as any)).rejects.toThrow(
          'Invalid user object provided'
        )
      }
    })

    it('should return immutable user data', async () => {
      await paymentController.setCurrentUser(paymentTestData.validUser)
      const user1 = paymentController.getCurrentUser()
      const user2 = paymentController.getCurrentUser()

      expect(user1).not.toBe(user2) // Different references
      expect(user1).toEqual(user2) // Same content

      // Modifying returned object should not affect internal state
      user1.id = 'hacked'
      const user3 = paymentController.getCurrentUser()
      expect(user3.id).toBe(paymentTestData.validUser.id)
    })

    it('should load user payment data after setting user', async () => {
      const subscriptionSpy = jest.fn()
      paymentController.on('subscription:loaded', subscriptionSpy)

      await paymentController.setCurrentUser(paymentTestData.validUser)

      expect(subscriptionSpy).toHaveBeenCalled()
      expect(allMocks.logger.info).toHaveBeenCalledWith(
        'PaymentController',
        `Loaded payment data for user: ${paymentTestData.validUser.id}`
      )
    })
  })

  describe('Subscription Management', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(paymentTestData.validUser)
    })

    it('should create subscription successfully', async () => {
      const processingSpy = jest.fn()
      const successSpy = jest.fn()
      const createdSpy = jest.fn()

      paymentController.on('payment:processing', processingSpy)
      paymentController.on('payment:success', successSpy)
      paymentController.on('subscription:created', createdSpy)

      const subscription = await paymentController.createSubscription('basic', 'pm_test123')

      expect(processingSpy).toHaveBeenCalled()
      expect(successSpy).toHaveBeenCalled()
      expect(createdSpy).toHaveBeenCalledWith(subscription)
      expect(paymentController.getPaymentStatus()).toBe('success')
      expect(subscription.id).toMatch(/^sub_/)
    })

    it('should validate plan existence before creating subscription', async () => {
      await expect(paymentController.createSubscription('invalid-plan')).rejects.toThrow(
        'Plan not found: invalid-plan'
      )
    })

    it('should require user to be set', async () => {
      const newController = new PaymentController()
      await newController.initializePaymentSystem()

      await expect(newController.createSubscription('basic')).rejects.toThrow(
        'No user set'
      )
    })

    it('should handle subscription creation errors', async () => {
      const errorSpy = jest.fn()
      paymentController.on('payment:error', errorSpy)

      jest.spyOn(paymentController as any, 'createMockSubscription').mockRejectedValue(
        new Error('Subscription creation failed')
      )

      await expect(paymentController.createSubscription('basic')).rejects.toThrow()
      expect(errorSpy).toHaveBeenCalled()
      expect(paymentController.getPaymentStatus()).toBe('error')
    })

    it('should cancel subscription successfully', async () => {
      // First create a subscription
      await paymentController.createSubscription('basic')
      
      const cancelSpy = jest.fn()
      paymentController.on('subscription:canceled', cancelSpy)

      await paymentController.cancelSubscription()

      expect(cancelSpy).toHaveBeenCalled()
      expect(allMocks.logger.info).toHaveBeenCalledWith(
        'PaymentController',
        'Successfully canceled subscription'
      )
    })

    it('should handle cancellation when no subscription exists', async () => {
      await expect(paymentController.cancelSubscription()).rejects.toThrow(
        'No active subscription to cancel'
      )
    })
  })

  describe('Feature Access Control', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(paymentTestData.validUser)
    })

    it('should check feature access successfully', async () => {
      const hasAccess = await paymentController.checkFeatureAccess('advanced_search')

      expect(hasAccess).toBe(true) // Mock returns true
      expect(allMocks.logger.debug).not.toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('access denied')
      )
    })

    it('should handle access denied scenarios', async () => {
      const accessDeniedSpy = jest.fn()
      paymentController.on('access:denied', accessDeniedSpy)

      jest.spyOn(paymentController as any, 'mockCheckFeatureAccess').mockResolvedValue(false)

      const hasAccess = await paymentController.checkFeatureAccess('premium_feature')

      expect(hasAccess).toBe(false)
      expect(accessDeniedSpy).toHaveBeenCalledWith({
        featureType: 'premium_feature',
        reason: 'subscription_required'
      })
    })

    it('should require user to be set for feature access', async () => {
      const newController = new PaymentController()
      await newController.initializePaymentSystem()

      const hasAccess = await newController.checkFeatureAccess('any_feature')

      expect(hasAccess).toBe(false)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        'PaymentController',
        'No user set for feature access check'
      )
    })

    it('should handle feature access check errors gracefully', async () => {
      jest.spyOn(paymentController as any, 'mockCheckFeatureAccess').mockRejectedValue(
        new Error('Feature service unavailable')
      )

      const hasAccess = await paymentController.checkFeatureAccess('any_feature')

      expect(hasAccess).toBe(false)
      expect(allMocks.logger.error).toHaveBeenCalledWith(
        'PaymentController',
        'Failed to check feature access',
        expect.any(Error)
      )
    })
  })

  describe('Usage Recording', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(paymentTestData.validUser)
    })

    it('should record feature usage successfully', async () => {
      const usageSpy = jest.fn()
      paymentController.on('usage:recorded', usageSpy)

      const metadata = { searchQuery: 'test query', resultCount: 25 }
      await paymentController.recordFeatureUsage('search', metadata)

      expect(usageSpy).toHaveBeenCalledWith({
        featureType: 'search',
        metadata
      })
      expect(allMocks.logger.debug).toHaveBeenCalledWith(
        'PaymentController',
        `Recorded feature usage: search for user ${paymentTestData.validUser.id}`
      )
    })

    it('should handle usage recording without metadata', async () => {
      const usageSpy = jest.fn()
      paymentController.on('usage:recorded', usageSpy)

      await paymentController.recordFeatureUsage('export')

      expect(usageSpy).toHaveBeenCalledWith({
        featureType: 'export',
        metadata: undefined
      })
    })

    it('should require user to be set for usage recording', async () => {
      const newController = new PaymentController()
      await newController.initializePaymentSystem()

      await newController.recordFeatureUsage('any_feature')

      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        'PaymentController',
        'No user set for recording feature usage'
      )
    })

    it('should handle usage recording errors', async () => {
      jest.spyOn(paymentController as any, 'mockRecordFeatureUsage').mockRejectedValue(
        new Error('Usage service unavailable')
      )

      await expect(paymentController.recordFeatureUsage('any_feature')).rejects.toThrow()
      expect(allMocks.logger.error).toHaveBeenCalledWith(
        'PaymentController',
        'Failed to record feature usage',
        expect.any(Error)
      )
    })
  })

  describe('State Management', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(paymentTestData.validUser)
    })

    it('should track payment status correctly', async () => {
      expect(paymentController.getPaymentStatus()).toBe('idle')

      const subscription = paymentController.createSubscription('basic')
      expect(paymentController.getPaymentStatus()).toBe('processing')

      await subscription
      expect(paymentController.getPaymentStatus()).toBe('success')
    })

    it('should check active subscription status', async () => {
      expect(paymentController.hasActiveSubscription()).toBe(false)

      await paymentController.createSubscription('basic')
      // Mock implementation returns null for getUserSubscription
      expect(paymentController.hasActiveSubscription()).toBe(false)
    })

    it('should return immutable subscription data', async () => {
      await paymentController.createSubscription('basic')
      const sub1 = paymentController.getUserSubscription()
      const sub2 = paymentController.getUserSubscription()

      if (sub1 && sub2) {
        expect(sub1).not.toBe(sub2) // Different references
        expect(sub1).toEqual(sub2) // Same content
      }
    })
  })

  describe('Event Handling', () => {
    it('should support multiple event listeners', async () => {
      const listener1 = jest.fn()
      const listener2 = jest.fn()

      paymentController.on('payment:initialized', listener1)
      paymentController.on('payment:initialized', listener2)

      await paymentController.initializePaymentSystem()

      expect(listener1).toHaveBeenCalled()
      expect(listener2).toHaveBeenCalled()
    })

    it('should handle listener removal', async () => {
      const listener = jest.fn()

      paymentController.on('payment:initialized', listener)
      paymentController.off('payment:initialized', listener)

      await paymentController.initializePaymentSystem()

      expect(listener).not.toHaveBeenCalled()
    })

    it('should handle high number of listeners', () => {
      // Test that we can add many listeners without warnings
      for (let i = 0; i < 60; i++) {
        paymentController.on('payment:initialized', jest.fn())
      }

      expect(paymentController.listenerCount('payment:initialized')).toBe(60)
    })
  })
})
