/**
 * Payment Controller Unit Tests
 * Comprehensive test suite for payment controller with 100% coverage
 */

import { PaymentController } from '@/controller/paymentController'
import { userPaymentService } from '@/model/userPaymentService'
import { stripeService } from '@/model/stripeService'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/model/userPaymentService')
jest.mock('@/model/stripeService')
jest.mock('@/utils/logger')

// Mock config to prevent environment variable requirements
jest.mock('@/lib/config', () => ({
  loadConfig: jest.fn().mockReturnValue({
    stripe: {
      publishableKey: 'pk_test_mock',
      secretKey: 'sk_test_mock',
      webhookSecret: 'whsec_test_mock',
    },
    payment: {
      successUrl: 'http://localhost:3000/success',
      cancelUrl: 'http://localhost:3000/cancel',
    },
  }),
  getPaymentConfig: jest.fn().mockReturnValue({
    stripe: {
      publishableKey: 'pk_test_mock',
      secretKey: 'sk_test_mock',
      webhookSecret: 'whsec_test_mock',
    },
    successUrl: 'http://localhost:3000/success',
    cancelUrl: 'http://localhost:3000/cancel',
  }),
}))

// Type the mocked services
const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>
const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('PaymentController', () => {
  let paymentController: PaymentController
  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
  }

  beforeEach(() => {
    paymentController = new PaymentController()
    jest.clearAllMocks()

    // Reset controller state
    paymentController['isInitialized'] = false
    paymentController['currentUser'] = null
    paymentController['subscriptionPlans'] = []
    paymentController['userSubscription'] = null
    paymentController['paymentStatus'] = 'idle'
  })

  afterEach(() => {
    paymentController.removeAllListeners()
  })

  describe('initialization', () => {
    it('should initialize payment system successfully', async () => {
      const mockPlans = [
        {
          id: 'plan-1',
          stripePriceId: 'price_123',
          name: 'Basic',
          description: 'Basic plan',
          priceCents: 999,
          currency: 'USD',
          interval: 'month',
          features: ['Feature 1'],
          isActive: true,
          createdAt: new Date(),
        },
      ]

      // Mock the private method
      jest.spyOn(paymentController as any, 'getMockSubscriptionPlans').mockResolvedValue(mockPlans)

      const initSpy = jest.fn()
      paymentController.on('payment:initialized', initSpy)

      await paymentController.initializePaymentSystem()

      expect(paymentController.getSubscriptionPlans()).toEqual(mockPlans)
      expect(paymentController.isPaymentSystemInitialized()).toBe(true)
      expect(initSpy).toHaveBeenCalled()
      expect(mockLogger.info).toHaveBeenCalledWith(
        'PaymentController',
        'Payment system initialized successfully'
      )
    })

    it('should handle initialization errors', async () => {
      const error = new Error('Failed to load plans')
      jest.spyOn(paymentController as any, 'getMockSubscriptionPlans').mockRejectedValue(error)

      const errorSpy = jest.fn()
      paymentController.on('payment:error', errorSpy)

      await expect(paymentController.initializePaymentSystem()).rejects.toThrow(error)
      expect(errorSpy).toHaveBeenCalledWith(error)
      expect(paymentController.isPaymentSystemInitialized()).toBe(false)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentController',
        'Failed to initialize payment system',
        error
      )
    })

    it('should not reinitialize if already initialized', async () => {
      paymentController['isInitialized'] = true

      await paymentController.initializePaymentSystem()

      expect(mockLogger.info).toHaveBeenCalledWith(
        'PaymentController',
        'Payment system already initialized'
      )
    })
  })

  describe('user management', () => {
    beforeEach(async () => {
      const mockPlans = [
        {
          id: 'plan-1',
          stripePriceId: 'price_123',
          name: 'Basic',
          priceCents: 999,
          currency: 'USD',
          interval: 'month',
          features: ['Feature 1'],
          isActive: true,
          createdAt: new Date(),
        },
      ]
      jest.spyOn(paymentController as any, 'getMockSubscriptionPlans').mockResolvedValue(mockPlans)
      await paymentController.initializePaymentSystem()
    })

    it('should set current user successfully', async () => {
      jest.spyOn(paymentController as any, 'getMockUserSubscription').mockResolvedValue(null)

      const userSpy = jest.fn()
      const subscriptionSpy = jest.fn()
      paymentController.on('user:set', userSpy)
      paymentController.on('subscription:loaded', subscriptionSpy)

      await paymentController.setCurrentUser(mockUser)

      expect(paymentController.getCurrentUser()).toEqual(mockUser)
      expect(userSpy).toHaveBeenCalledWith(mockUser)
      expect(subscriptionSpy).toHaveBeenCalledWith(null)
      expect(mockLogger.info).toHaveBeenCalledWith(
        'PaymentController',
        `Set current user: ${mockUser.id}`
      )
    })

    it('should handle invalid user object', async () => {
      const invalidUser = { email: 'test@example.com' } // missing id

      await expect(paymentController.setCurrentUser(invalidUser as any)).rejects.toThrow(
        'Invalid user object provided'
      )

      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentController',
        'Failed to set current user',
        expect.any(Error)
      )
    })

    it('should load user payment data with subscription', async () => {
      const mockSubscription = {
        id: 'sub_123',
        userId: mockUser.id,
        planId: 'plan-1',
        status: 'active' as const,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(),
        createdAt: new Date(),
      }

      jest
        .spyOn(paymentController as any, 'getMockUserSubscription')
        .mockResolvedValue(mockSubscription)

      await paymentController.setCurrentUser(mockUser)

      expect(paymentController.getUserSubscription()).toEqual(mockSubscription)
      expect(paymentController.hasActiveSubscription()).toBe(true)
    })
  })

  describe('subscription management', () => {
    beforeEach(async () => {
      const mockPlans = [
        {
          id: 'plan-1',
          stripePriceId: 'price_123',
          name: 'Basic',
          priceCents: 999,
          currency: 'USD',
          interval: 'month',
          features: ['Feature 1'],
          isActive: true,
          createdAt: new Date(),
        },
      ]
      jest.spyOn(paymentController as any, 'getMockSubscriptionPlans').mockResolvedValue(mockPlans)
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)
    })

    it('should create subscription successfully', async () => {
      const mockSubscription = {
        id: 'sub_123',
        userId: mockUser.id,
        planId: 'plan-1',
        status: 'active',
        createdAt: new Date(),
      }

      jest
        .spyOn(paymentController as any, 'createMockSubscription')
        .mockResolvedValue(mockSubscription)
      jest
        .spyOn(paymentController as any, 'getMockUserSubscription')
        .mockResolvedValue(null)
        .mockResolvedValueOnce(null) // First call during setCurrentUser
        .mockResolvedValueOnce(mockSubscription) // Second call after subscription creation

      const processingSpyStart = jest.fn()
      const processingSpyEnd = jest.fn()
      const successSpy = jest.fn()
      const createdSpy = jest.fn()

      paymentController.on('payment:processing', processingSpyStart)
      paymentController.on('payment:success', processingSpyEnd)
      paymentController.on('subscription:created', createdSpy)

      const result = await paymentController.createSubscription('plan-1')

      expect(result).toEqual(mockSubscription)
      expect(paymentController.getPaymentStatus()).toBe('success')
      expect(processingSpyStart).toHaveBeenCalled()
      expect(processingSpyEnd).toHaveBeenCalled()
      expect(createdSpy).toHaveBeenCalledWith(mockSubscription)
      expect(mockLogger.info).toHaveBeenCalledWith(
        'PaymentController',
        `Successfully created subscription: ${mockSubscription.id}`
      )
    })

    it('should handle subscription creation errors', async () => {
      const error = new Error('Payment failed')
      jest.spyOn(paymentController as any, 'createMockSubscription').mockRejectedValue(error)

      const errorSpy = jest.fn()
      paymentController.on('payment:error', errorSpy)

      await expect(paymentController.createSubscription('plan-1')).rejects.toThrow(error)
      expect(errorSpy).toHaveBeenCalledWith(error)
      expect(paymentController.getPaymentStatus()).toBe('error')
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentController',
        'Failed to create subscription',
        error
      )
    })

    it('should handle invalid plan ID', async () => {
      await expect(paymentController.createSubscription('invalid-plan')).rejects.toThrow(
        'Plan not found: invalid-plan'
      )
    })

    it('should handle subscription creation without user', async () => {
      paymentController['currentUser'] = null

      await expect(paymentController.createSubscription('plan-1')).rejects.toThrow('No user set')
    })

    it('should cancel subscription successfully', async () => {
      const mockSubscription = {
        id: 'sub_123',
        userId: mockUser.id,
        planId: 'plan-1',
        status: 'active' as const,
        currentPeriodStart: new Date(),
        currentPeriodEnd: new Date(),
        createdAt: new Date(),
      }

      paymentController['userSubscription'] = mockSubscription

      jest.spyOn(paymentController as any, 'cancelMockSubscription').mockResolvedValue(undefined)
      jest.spyOn(paymentController as any, 'getMockUserSubscription').mockResolvedValue(null)

      const cancelSpy = jest.fn()
      paymentController.on('subscription:canceled', cancelSpy)

      await paymentController.cancelSubscription()

      expect(cancelSpy).toHaveBeenCalled()
      expect(mockLogger.info).toHaveBeenCalledWith(
        'PaymentController',
        'Successfully canceled subscription'
      )
    })

    it('should handle cancellation without active subscription', async () => {
      paymentController['userSubscription'] = null

      await expect(paymentController.cancelSubscription()).rejects.toThrow(
        'No active subscription to cancel'
      )
    })
  })

  describe('feature access', () => {
    beforeEach(async () => {
      await paymentController.setCurrentUser(mockUser)
    })

    it('should check feature access correctly', async () => {
      jest.spyOn(paymentController as any, 'mockCheckFeatureAccess').mockResolvedValue(true)

      const hasAccess = await paymentController.checkFeatureAccess('advanced_search')

      expect(hasAccess).toBe(true)
    })

    it('should handle feature access denial', async () => {
      jest.spyOn(paymentController as any, 'mockCheckFeatureAccess').mockResolvedValue(false)

      const deniedSpy = jest.fn()
      paymentController.on('access:denied', deniedSpy)

      const hasAccess = await paymentController.checkFeatureAccess('advanced_search')

      expect(hasAccess).toBe(false)
      expect(deniedSpy).toHaveBeenCalledWith({
        featureType: 'advanced_search',
        reason: 'subscription_required',
      })
    })

    it('should handle feature access check without user', async () => {
      paymentController['currentUser'] = null

      const hasAccess = await paymentController.checkFeatureAccess('advanced_search')

      expect(hasAccess).toBe(false)
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentController',
        'No user set for feature access check'
      )
    })

    it('should record feature usage', async () => {
      const metadata = { searchQuery: 'test' }
      jest.spyOn(paymentController as any, 'mockRecordFeatureUsage').mockResolvedValue(undefined)

      const usageSpy = jest.fn()
      paymentController.on('usage:recorded', usageSpy)

      await paymentController.recordFeatureUsage('advanced_search', metadata)

      expect(usageSpy).toHaveBeenCalledWith({
        featureType: 'advanced_search',
        metadata,
      })
      expect(mockLogger.debug).toHaveBeenCalledWith(
        'PaymentController',
        `Recorded feature usage: advanced_search for user ${mockUser.id}`
      )
    })

    it('should handle feature usage recording without user', async () => {
      paymentController['currentUser'] = null

      await paymentController.recordFeatureUsage('advanced_search')

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentController',
        'No user set for recording feature usage'
      )
    })

    it('should handle feature usage recording errors', async () => {
      const error = new Error('Recording failed')
      jest.spyOn(paymentController as any, 'mockRecordFeatureUsage').mockRejectedValue(error)

      await expect(paymentController.recordFeatureUsage('advanced_search')).rejects.toThrow(error)

      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentController',
        'Failed to record feature usage',
        error
      )
    })
  })

  describe('getters and state management', () => {
    it('should return empty subscription plans initially', () => {
      expect(paymentController.getSubscriptionPlans()).toEqual([])
    })

    it('should return null user subscription initially', () => {
      expect(paymentController.getUserSubscription()).toBeNull()
    })

    it('should return idle payment status initially', () => {
      expect(paymentController.getPaymentStatus()).toBe('idle')
    })

    it('should return false for active subscription initially', () => {
      expect(paymentController.hasActiveSubscription()).toBe(false)
    })

    it('should return null current user initially', () => {
      expect(paymentController.getCurrentUser()).toBeNull()
    })

    it('should return false for payment system initialization initially', () => {
      expect(paymentController.isPaymentSystemInitialized()).toBe(false)
    })

    it('should return deep copies of objects to prevent mutation', async () => {
      await paymentController.setCurrentUser(mockUser)

      const user = paymentController.getCurrentUser()
      user!.name = 'Modified Name'

      expect(paymentController.getCurrentUser()!.name).toBe('Test User')
    })
  })
})
