/**
 * PaymentController Unit Tests
 * Comprehensive test suite for payment state management and subscription lifecycle
 */

import { PaymentController } from '../paymentController'
import { logger } from '@/utils/logger'
import { SubscriptionPlan, UserSubscription } from '@/model/types/payment'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/model/userPaymentService')
jest.mock('@/model/stripeService')

describe('PaymentController', () => {
  let paymentController: PaymentController
  let mockUser: any

  beforeEach(() => {
    paymentController = new PaymentController()
    mockUser = {
      id: 'test-user-123',
      email: 'test@example.com',
      name: 'Test User'
    }
    
    // Clear all mocks
    jest.clearAllMocks()
  })

  afterEach(() => {
    // Clean up event listeners
    paymentController.removeAllListeners()
  })

  describe('Initialization', () => {
    it('should initialize payment system successfully', async () => {
      const initSpy = jest.fn()
      paymentController.on('payment:initialized', initSpy)

      await paymentController.initializePaymentSystem()

      expect(initSpy).toHaveBeenCalled()
      expect(paymentController.isPaymentSystemInitialized()).toBe(true)
    })

    it('should handle initialization errors gracefully', async () => {
      const errorSpy = jest.fn()
      paymentController.on('payment:error', errorSpy)

      // Mock loadSubscriptionPlans to throw error
      jest.spyOn(paymentController as any, 'getMockSubscriptionPlans').mockRejectedValue(new Error('Init failed'))

      await expect(paymentController.initializePaymentSystem()).rejects.toThrow('Init failed')
      expect(errorSpy).toHaveBeenCalled()
    })

    it('should not reinitialize if already initialized', async () => {
      await paymentController.initializePaymentSystem()
      const loggerSpy = jest.spyOn(logger, 'info')

      await paymentController.initializePaymentSystem()

      expect(loggerSpy).toHaveBeenCalledWith('PaymentController', 'Payment system already initialized')
    })
  })

  describe('Subscription Plans', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
    })

    it('should load subscription plans successfully', async () => {
      const plansSpy = jest.fn()
      paymentController.on('plans:loaded', plansSpy)

      const plans = await paymentController.loadSubscriptionPlans()

      expect(plans).toHaveLength(3) // free, basic, pro
      expect(plans[0]).toHaveProperty('id', 'free')
      expect(plans[1]).toHaveProperty('id', 'basic')
      expect(plans[2]).toHaveProperty('id', 'pro')
      expect(plansSpy).toHaveBeenCalledWith(plans)
    })

    it('should return cached subscription plans', () => {
      const plans = paymentController.getSubscriptionPlans()
      expect(plans).toHaveLength(3)
      expect(plans[0].id).toBe('free')
    })

    it('should handle plan loading errors', async () => {
      const newController = new PaymentController()
      jest.spyOn(newController as any, 'getMockSubscriptionPlans').mockRejectedValue(new Error('Plans failed'))

      await expect(newController.loadSubscriptionPlans()).rejects.toThrow('Plans failed')
    })
  })

  describe('User Management', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
    })

    it('should set current user successfully', async () => {
      const userSpy = jest.fn()
      paymentController.on('user:set', userSpy)

      await paymentController.setCurrentUser(mockUser)

      expect(paymentController.getCurrentUser()).toEqual(mockUser)
      expect(userSpy).toHaveBeenCalledWith(mockUser)
    })

    it('should reject invalid user objects', async () => {
      await expect(paymentController.setCurrentUser(null)).rejects.toThrow('Invalid user object provided')
      await expect(paymentController.setCurrentUser({})).rejects.toThrow('Invalid user object provided')
      await expect(paymentController.setCurrentUser({ name: 'No ID' })).rejects.toThrow('Invalid user object provided')
    })

    it('should load user payment data after setting user', async () => {
      const subscriptionSpy = jest.fn()
      paymentController.on('subscription:loaded', subscriptionSpy)

      await paymentController.setCurrentUser(mockUser)

      expect(subscriptionSpy).toHaveBeenCalled()
    })

    it('should handle user payment data loading errors', async () => {
      jest.spyOn(paymentController as any, 'getMockUserSubscription').mockRejectedValue(new Error('Load failed'))

      await expect(paymentController.setCurrentUser(mockUser)).rejects.toThrow('Load failed')
    })
  })

  describe('Subscription Management', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)
    })

    it('should create subscription successfully', async () => {
      const processingSpy = jest.fn()
      const successSpy = jest.fn()
      const createdSpy = jest.fn()

      paymentController.on('payment:processing', processingSpy)
      paymentController.on('payment:success', successSpy)
      paymentController.on('subscription:created', createdSpy)

      const subscription = await paymentController.createSubscription('basic')

      expect(processingSpy).toHaveBeenCalled()
      expect(successSpy).toHaveBeenCalled()
      expect(createdSpy).toHaveBeenCalledWith(subscription)
      expect(paymentController.getPaymentStatus()).toBe('success')
    })

    it('should reject subscription creation without user', async () => {
      const newController = new PaymentController()
      await newController.initializePaymentSystem()

      await expect(newController.createSubscription('basic')).rejects.toThrow('No user set')
    })

    it('should reject subscription creation with invalid plan', async () => {
      await expect(paymentController.createSubscription('invalid-plan')).rejects.toThrow('Plan not found: invalid-plan')
    })

    it('should handle subscription creation errors', async () => {
      const errorSpy = jest.fn()
      paymentController.on('payment:error', errorSpy)

      jest.spyOn(paymentController as any, 'createMockSubscription').mockRejectedValue(new Error('Creation failed'))

      await expect(paymentController.createSubscription('basic')).rejects.toThrow('Creation failed')
      expect(errorSpy).toHaveBeenCalled()
      expect(paymentController.getPaymentStatus()).toBe('error')
    })

    it('should cancel subscription successfully', async () => {
      // First create a subscription
      await paymentController.createSubscription('basic')
      
      // Mock that user has a subscription
      jest.spyOn(paymentController, 'getUserSubscription').mockReturnValue({
        id: 'sub-123',
        userId: mockUser.id,
        stripeSubscriptionId: 'stripe-sub-123',
        planId: 'basic',
        status: 'active',
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        cancelAtPeriodEnd: false,
        createdAt: new Date(),
        updatedAt: new Date()
      })

      const canceledSpy = jest.fn()
      paymentController.on('subscription:canceled', canceledSpy)

      await paymentController.cancelSubscription()

      expect(canceledSpy).toHaveBeenCalled()
    })

    it('should reject cancellation without active subscription', async () => {
      await expect(paymentController.cancelSubscription()).rejects.toThrow('No active subscription to cancel')
    })
  })

  describe('Feature Access', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)
    })

    it('should check feature access successfully', async () => {
      const hasAccess = await paymentController.checkFeatureAccess('scraping_request')
      expect(hasAccess).toBe(true)
    })

    it('should return false for feature access without user', async () => {
      const newController = new PaymentController()
      await newController.initializePaymentSystem()

      const hasAccess = await newController.checkFeatureAccess('scraping_request')
      expect(hasAccess).toBe(false)
    })

    it('should handle feature access check errors', async () => {
      jest.spyOn(paymentController as any, 'mockCheckFeatureAccess').mockRejectedValue(new Error('Access check failed'))

      const hasAccess = await paymentController.checkFeatureAccess('scraping_request')
      expect(hasAccess).toBe(false)
    })
  })

  describe('Usage Recording', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)
    })

    it('should record feature usage successfully', async () => {
      const usageSpy = jest.fn()
      paymentController.on('usage:recorded', usageSpy)

      const metadata = { query: 'test query', results: 10 }
      await paymentController.recordFeatureUsage('scraping_request', metadata)

      expect(usageSpy).toHaveBeenCalledWith({ featureType: 'scraping_request', metadata })
    })

    it('should handle usage recording without user gracefully', async () => {
      const newController = new PaymentController()
      await newController.initializePaymentSystem()

      // Should not throw error
      await expect(newController.recordFeatureUsage('scraping_request')).resolves.toBeUndefined()
    })

    it('should handle usage recording errors', async () => {
      jest.spyOn(paymentController as any, 'mockRecordFeatureUsage').mockRejectedValue(new Error('Recording failed'))

      await expect(paymentController.recordFeatureUsage('scraping_request')).rejects.toThrow('Recording failed')
    })
  })

  describe('Getters and State', () => {
    beforeEach(async () => {
      await paymentController.initializePaymentSystem()
    })

    it('should return subscription status correctly', () => {
      expect(paymentController.hasActiveSubscription()).toBe(false)
    })

    it('should return payment status correctly', () => {
      expect(paymentController.getPaymentStatus()).toBe('idle')
    })

    it('should return null for user subscription initially', () => {
      expect(paymentController.getUserSubscription()).toBeNull()
    })

    it('should return initialization status correctly', () => {
      expect(paymentController.isPaymentSystemInitialized()).toBe(true)
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

    it('should handle event listener errors gracefully', async () => {
      const errorListener = jest.fn(() => {
        throw new Error('Listener error')
      })

      paymentController.on('payment:initialized', errorListener)

      // Should not throw error even if listener throws
      await expect(paymentController.initializePaymentSystem()).resolves.toBeUndefined()
    })
  })
})
