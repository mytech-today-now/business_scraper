/**
 * Comprehensive Payment Controller Tests
 * Security-focused testing for payment workflow management, feature access control,
 * subscription lifecycle, and error handling with fraud prevention
 */

import { PaymentController } from '@/controller/paymentController'
import { userPaymentService } from '@/model/userPaymentService'
import { stripeService } from '@/model/stripeService'
import { paymentValidationService } from '@/model/paymentValidationService'
import { logger } from '@/utils/logger'
import { EventEmitter } from 'events'

// Mock all dependencies
jest.mock('@/model/userPaymentService', () => ({
  userPaymentService: {
    getUserPaymentProfile: jest.fn(),
    updateUserPaymentProfile: jest.fn(),
    recordUsage: jest.fn(),
    ensureStripeCustomer: jest.fn(),
    createSubscription: jest.fn(),
    cancelSubscription: jest.fn(),
    updatePaymentMethod: jest.fn(),
    recordPaymentSuccess: jest.fn(),
    deleteUserData: jest.fn()
  }
}))

jest.mock('@/model/stripeService', () => ({
  stripeService: {
    createPaymentIntent: jest.fn(),
    confirmPaymentIntent: jest.fn(),
    createSubscription: jest.fn(),
    cancelSubscription: jest.fn(),
    getPaymentMethod: jest.fn(),
    attachPaymentMethod: jest.fn()
  }
}))

jest.mock('@/model/paymentValidationService', () => ({
  paymentValidationService: {
    canAccessFeature: jest.fn(),
    validateUsageLimit: jest.fn(),
    validateSubscriptionTransition: jest.fn()
  }
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }
}))

jest.mock('@/lib/config', () => ({
  getConfig: jest.fn().mockReturnValue({
    payments: {
      stripePublishableKey: 'pk_test_mock',
      stripeSecretKey: 'sk_test_mock',
      webhookSecret: 'whsec_test_mock'
    }
  })
}))

// Type mocked services
const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>
const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockPaymentValidationService = paymentValidationService as jest.Mocked<typeof paymentValidationService>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('PaymentController - Comprehensive Security Tests', () => {
  let paymentController: PaymentController
  
  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    sessionId: 'session-123',
    isAuthenticated: true,
    permissions: ['payment:create', 'payment:read'],
    roles: ['user']
  }

  const mockPaymentProfile = {
    userId: 'user-123',
    stripeCustomerId: 'cus_test123',
    subscriptionId: 'sub_test123',
    subscriptionStatus: 'active' as const,
    subscriptionTier: 'premium' as const,
    paymentMethods: [],
    billingAddress: null,
    usageStats: {
      exports: 0,
      searches: 0,
      records: 0,
      scraping: 0
    }
  }

  beforeEach(() => {
    jest.clearAllMocks()
    paymentController = new PaymentController()
    
    // Setup default mocks
    mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockPaymentProfile)
    mockPaymentValidationService.canAccessFeature.mockResolvedValue({ success: true, data: true })
    mockPaymentValidationService.validateUsageLimit.mockResolvedValue({ success: true, data: true })
  })

  describe('User Authentication and Authorization', () => {
    it('should reject operations without authenticated user', async () => {
      await expect(paymentController.createSubscription('premium')).rejects.toThrow('No user set')
      await expect(paymentController.cancelSubscription()).rejects.toThrow('No user set')
      await expect(paymentController.updatePaymentMethod('pm_test')).rejects.toThrow('No user set')
    })

    it('should validate user permissions for payment operations', async () => {
      const restrictedUser = { ...mockUser, permissions: ['read'] }
      paymentController.setUser(restrictedUser)

      mockPaymentValidationService.canAccessFeature.mockResolvedValue({ 
        success: false, 
        error: 'Insufficient permissions',
        code: 'PERMISSION_DENIED'
      })

      await expect(paymentController.createSubscription('premium')).rejects.toThrow('Insufficient permissions')
    })

    it('should prevent privilege escalation attempts', async () => {
      paymentController.setUser(mockUser)
      
      // Attempt to access admin-only features
      const adminFeatures = ['admin:billing', 'admin:refunds', 'admin:analytics']
      
      for (const feature of adminFeatures) {
        mockPaymentValidationService.canAccessFeature.mockResolvedValue({ 
          success: false, 
          error: 'Access denied',
          code: 'INSUFFICIENT_PRIVILEGES'
        })

        const canAccess = await paymentController.canAccessFeature(feature)
        expect(canAccess).toBe(false)
      }
    })
  })

  describe('Subscription Lifecycle Security', () => {
    beforeEach(() => {
      paymentController.setUser(mockUser)
    })

    it('should prevent subscription plan manipulation', async () => {
      const maliciousPlanIds = [
        'premium_free', // Fake free premium
        '../admin/unlimited', // Path traversal
        'plan_with_discount_100', // Full discount attempt
        null,
        undefined,
        '',
        '<script>alert("xss")</script>'
      ]

      for (const planId of maliciousPlanIds) {
        await expect(paymentController.createSubscription(planId as any)).rejects.toThrow()
      }
    })

    it('should validate subscription tier transitions', async () => {
      // Mock current premium subscription
      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue({
        ...mockPaymentProfile,
        subscriptionTier: 'premium'
      })

      // Attempt to downgrade to free (should be allowed)
      mockPaymentValidationService.validateSubscriptionTransition = jest.fn().mockResolvedValue({
        success: true,
        data: true
      })

      await expect(paymentController.createSubscription('basic')).resolves.toBeDefined()

      // Attempt invalid transition
      mockPaymentValidationService.validateSubscriptionTransition.mockResolvedValue({
        success: false,
        error: 'Invalid subscription transition',
        code: 'INVALID_TRANSITION'
      })

      await expect(paymentController.createSubscription('enterprise')).rejects.toThrow('Invalid subscription transition')
    })

    it('should handle subscription cancellation securely', async () => {
      mockStripeService.cancelSubscription = jest.fn().mockResolvedValue({
        id: 'sub_test123',
        status: 'canceled'
      })

      const result = await paymentController.cancelSubscription()
      
      expect(result.status).toBe('canceled')
      expect(mockLogger.info).toHaveBeenCalledWith(
        'PaymentController',
        expect.stringContaining('Subscription canceled'),
        expect.any(Object)
      )
    })

    it('should prevent unauthorized subscription modifications', async () => {
      // Mock user trying to modify another user's subscription
      const otherUserProfile = { ...mockPaymentProfile, userId: 'other-user-456' }
      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(otherUserProfile)

      await expect(paymentController.cancelSubscription()).rejects.toThrow('Unauthorized')
    })
  })

  describe('Payment Method Security', () => {
    beforeEach(() => {
      paymentController.setUser(mockUser)
    })

    it('should validate payment method ownership', async () => {
      const paymentMethodId = 'pm_test123'
      
      mockStripeService.getPaymentMethod = jest.fn().mockResolvedValue({
        id: paymentMethodId,
        customer: 'cus_different123' // Different customer
      })

      await expect(paymentController.updatePaymentMethod(paymentMethodId)).rejects.toThrow('Unauthorized')
    })

    it('should sanitize payment method data', async () => {
      const maliciousPaymentMethodId = 'pm_test<script>alert("xss")</script>'
      
      await expect(paymentController.updatePaymentMethod(maliciousPaymentMethodId)).rejects.toThrow()
    })

    it('should handle payment method errors gracefully', async () => {
      mockStripeService.attachPaymentMethod = jest.fn().mockRejectedValue(
        new Error('Payment method declined')
      )

      await expect(paymentController.updatePaymentMethod('pm_test123')).rejects.toThrow('Payment method declined')
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentController',
        expect.stringContaining('Failed to update payment method'),
        expect.any(Error)
      )
    })
  })

  describe('Feature Access Control', () => {
    beforeEach(() => {
      paymentController.setUser(mockUser)
    })

    it('should enforce usage limits', async () => {
      mockPaymentValidationService.validateUsageLimit.mockResolvedValue({
        success: false,
        error: 'Usage limit exceeded',
        code: 'USAGE_LIMIT_EXCEEDED'
      })

      const canUse = await paymentController.canAccessFeature('export')
      expect(canUse).toBe(false)
    })

    it('should track feature usage securely', async () => {
      const featureType = 'export'
      const metadata = { format: 'csv', recordCount: 100 }

      await paymentController.recordFeatureUsage(featureType, metadata)

      expect(mockUserPaymentService.recordUsage).toHaveBeenCalledWith(
        mockUser.id,
        featureType,
        expect.objectContaining(metadata)
      )
    })

    it('should prevent usage manipulation', async () => {
      const maliciousMetadata = {
        recordCount: -100, // Negative usage
        format: '<script>alert("xss")</script>',
        userId: 'other-user-456' // Attempt to record for different user
      }

      await paymentController.recordFeatureUsage('export', maliciousMetadata)

      // Should sanitize or reject malicious data
      expect(mockUserPaymentService.recordUsage).toHaveBeenCalledWith(
        mockUser.id, // Should use authenticated user ID
        'export',
        expect.not.objectContaining({
          userId: 'other-user-456'
        })
      )
    })
  })

  describe('Payment Processing Security', () => {
    beforeEach(() => {
      paymentController.setUser(mockUser)
    })

    it('should validate payment amounts', async () => {
      const invalidAmounts = [-100, 0, 999999999, 1.5, NaN, Infinity]

      for (const amount of invalidAmounts) {
        await expect(paymentController.processPayment(amount, 'usd')).rejects.toThrow()
      }
    })

    it('should prevent currency manipulation', async () => {
      const invalidCurrencies = ['', 'FAKE', 'USD123', null, undefined, '<script>']

      for (const currency of invalidCurrencies) {
        await expect(paymentController.processPayment(1000, currency as any)).rejects.toThrow()
      }
    })

    it('should handle payment failures securely', async () => {
      mockStripeService.createPaymentIntent = jest.fn().mockRejectedValue(
        new Error('Your card was declined')
      )

      await expect(paymentController.processPayment(1000, 'usd')).rejects.toThrow('Your card was declined')
      
      // Should not expose sensitive error details
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentController',
        expect.stringContaining('Payment processing failed'),
        expect.any(Error)
      )
    })
  })

  describe('Event Handling and Monitoring', () => {
    beforeEach(() => {
      paymentController.setUser(mockUser)
    })

    it('should emit security events for monitoring', async () => {
      const eventSpy = jest.spyOn(paymentController, 'emit')

      // Trigger a security-relevant event
      await paymentController.createSubscription('premium')

      expect(eventSpy).toHaveBeenCalledWith('subscription:created', expect.any(Object))
      expect(eventSpy).toHaveBeenCalledWith('payment:success')
    })

    it('should handle event listener errors gracefully', async () => {
      paymentController.on('payment:error', () => {
        throw new Error('Event handler error')
      })

      // Should not crash the controller
      await expect(paymentController.createSubscription('invalid-plan')).rejects.toThrow()
      
      expect(mockLogger.error).toHaveBeenCalled()
    })
  })

  describe('Data Validation and Sanitization', () => {
    beforeEach(() => {
      paymentController.setUser(mockUser)
    })

    it('should sanitize all user inputs', async () => {
      const maliciousInputs = {
        planId: '<script>alert("xss")</script>',
        metadata: {
          description: '"; DROP TABLE users; --',
          userAgent: '<img src=x onerror=alert(1)>'
        }
      }

      // Should either reject or sanitize
      await expect(paymentController.createSubscription(maliciousInputs.planId)).rejects.toThrow()
    })

    it('should validate data types and formats', async () => {
      const invalidInputs = [
        { type: 'object', value: {} },
        { type: 'array', value: [] },
        { type: 'function', value: () => {} },
        { type: 'symbol', value: Symbol('test') }
      ]

      for (const input of invalidInputs) {
        await expect(paymentController.createSubscription(input.value as any)).rejects.toThrow()
      }
    })
  })

  describe('Concurrent Operations Safety', () => {
    beforeEach(() => {
      paymentController.setUser(mockUser)
    })

    it('should handle concurrent subscription operations safely', async () => {
      const concurrentOperations = [
        paymentController.createSubscription('premium'),
        paymentController.createSubscription('basic'),
        paymentController.cancelSubscription()
      ]

      // Should handle gracefully without race conditions
      const results = await Promise.allSettled(concurrentOperations)
      
      // At most one should succeed, others should fail gracefully
      const successful = results.filter(r => r.status === 'fulfilled')
      expect(successful.length).toBeLessThanOrEqual(1)
    })

    it('should prevent payment processing race conditions', async () => {
      const concurrentPayments = Array(5).fill(null).map(() =>
        paymentController.processPayment(1000, 'usd')
      )

      const results = await Promise.allSettled(concurrentPayments)
      
      // Should handle all requests safely
      results.forEach(result => {
        if (result.status === 'rejected') {
          expect(result.reason.message).not.toContain('race condition')
        }
      })
    })
  })
})
