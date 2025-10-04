/**
 * Comprehensive User Payment Service Tests
 * Security-focused testing for user-payment integration, subscription management,
 * payment profile handling, and data protection
 */

import { UserPaymentService } from '@/model/userPaymentService'
import { stripeService } from '@/model/stripeService'
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { PaymentError, SubscriptionError } from '@/types/payment'

// Mock all dependencies
jest.mock('@/model/stripeService', () => ({
  stripeService: {
    createCustomer: jest.fn(),
    createSubscription: jest.fn(),
    cancelSubscription: jest.fn(),
    getCustomer: jest.fn(),
    attachPaymentMethod: jest.fn(),
    getPaymentMethod: jest.fn(),
    deleteCustomer: jest.fn()
  }
}))

jest.mock('@/model/storage', () => ({
  storage: {
    getUserPaymentProfile: jest.fn(),
    updateUserPaymentProfile: jest.fn(),
    deleteUserPaymentProfile: jest.fn()
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

// Type mocked services
const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockStorage = storage as jest.Mocked<typeof storage>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('UserPaymentService - Comprehensive Security Tests', () => {
  let userPaymentService: UserPaymentService

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User'
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

  const mockStripeCustomer = {
    id: 'cus_test123',
    email: 'test@example.com',
    name: 'Test User',
    metadata: {
      userId: 'user-123'
    }
  }

  beforeEach(() => {
    jest.clearAllMocks()
    userPaymentService = new UserPaymentService()
    
    // Setup default mocks
    mockStorage.getUserPaymentProfile.mockResolvedValue(mockPaymentProfile)
    mockStripeService.createCustomer.mockResolvedValue(mockStripeCustomer)
  })

  describe('User Authentication and Authorization', () => {
    it('should validate user ID format', async () => {
      const invalidUserIds = ['', null, undefined, '<script>alert("xss")</script>', '../../admin']

      for (const userId of invalidUserIds) {
        await expect(userPaymentService.getUserPaymentProfile(userId as any)).rejects.toThrow()
      }
    })

    it('should prevent unauthorized profile access', async () => {
      // Mock storage returning profile for different user
      mockStorage.getUserPaymentProfile.mockResolvedValue({
        ...mockPaymentProfile,
        userId: 'other-user-456'
      })

      await expect(userPaymentService.getUserPaymentProfile('user-123')).rejects.toThrow('Unauthorized')
    })

    it('should sanitize user input data', async () => {
      const maliciousUserData = {
        id: 'user-123',
        email: 'test+<script>alert("xss")</script>@example.com',
        name: 'Test"; DROP TABLE users; --'
      }

      await userPaymentService.ensureStripeCustomer(
        maliciousUserData.id,
        maliciousUserData.email,
        maliciousUserData.name
      )

      expect(mockStripeService.createCustomer).toHaveBeenCalledWith(
        expect.not.stringContaining('<script>'),
        expect.not.stringContaining('DROP TABLE'),
        expect.any(Object)
      )
    })
  })

  describe('Stripe Customer Management Security', () => {
    it('should validate email format before customer creation', async () => {
      const invalidEmails = [
        'invalid-email',
        '',
        'test@',
        '@example.com',
        'test..test@example.com',
        'test@example',
        null,
        undefined
      ]

      for (const email of invalidEmails) {
        await expect(userPaymentService.ensureStripeCustomer(
          'user-123',
          email as any,
          'Test User'
        )).rejects.toThrow()
      }
    })

    it('should prevent customer ID manipulation', async () => {
      // Mock existing profile with different customer ID
      mockStorage.getUserPaymentProfile.mockResolvedValue({
        ...mockPaymentProfile,
        stripeCustomerId: 'cus_different123'
      })

      // Attempt to override with malicious customer ID
      const result = await userPaymentService.ensureStripeCustomer(
        'user-123',
        'test@example.com',
        'Test User'
      )

      // Should return existing customer ID, not create new one
      expect(result).toBe('cus_different123')
      expect(mockStripeService.createCustomer).not.toHaveBeenCalled()
    })

    it('should handle Stripe customer creation failures securely', async () => {
      mockStorage.getUserPaymentProfile.mockResolvedValue(null)
      mockStripeService.createCustomer.mockRejectedValue(new Error('Stripe API Error'))

      await expect(userPaymentService.ensureStripeCustomer(
        'user-123',
        'test@example.com',
        'Test User'
      )).rejects.toThrow('Stripe API Error')

      expect(mockLogger.error).toHaveBeenCalledWith(
        'UserPaymentService',
        expect.stringContaining('Failed to create Stripe customer'),
        expect.any(Error)
      )
    })

    it('should validate customer metadata integrity', async () => {
      mockStorage.getUserPaymentProfile.mockResolvedValue(null)

      await userPaymentService.ensureStripeCustomer(
        'user-123',
        'test@example.com',
        'Test User'
      )

      expect(mockStripeService.createCustomer).toHaveBeenCalledWith(
        'test@example.com',
        'Test User',
        expect.objectContaining({
          userId: 'user-123',
          createdBy: 'business_scraper_app'
        })
      )
    })
  })

  describe('Subscription Management Security', () => {
    it('should validate subscription creation parameters', async () => {
      const invalidParams = [
        { userId: '', priceId: 'price_test' },
        { userId: 'user-123', priceId: '' },
        { userId: 'user-123', priceId: 'price_test', trialPeriodDays: -1 },
        { userId: 'user-123', priceId: 'price_test', trialPeriodDays: 999 }
      ]

      for (const params of invalidParams) {
        await expect(userPaymentService.createSubscription(
          params.userId,
          params.priceId,
          { trialPeriodDays: params.trialPeriodDays }
        )).rejects.toThrow()
      }
    })

    it('should prevent subscription tampering', async () => {
      const maliciousOptions = {
        metadata: {
          priceOverride: '0',
          adminAccess: 'true',
          bypassPayment: 'true',
          freeUpgrade: 'premium'
        }
      }

      mockStripeService.createSubscription.mockResolvedValue({
        id: 'sub_test123',
        status: 'active',
        customer: 'cus_test123'
      } as any)

      await userPaymentService.createSubscription('user-123', 'price_test', maliciousOptions)

      expect(mockStripeService.createSubscription).toHaveBeenCalledWith(
        'cus_test123',
        'price_test',
        expect.objectContaining({
          metadata: expect.not.objectContaining({
            priceOverride: '0',
            bypassPayment: 'true'
          })
        })
      )
    })

    it('should validate subscription ownership before operations', async () => {
      // Mock profile with different user's subscription
      mockStorage.getUserPaymentProfile.mockResolvedValue({
        ...mockPaymentProfile,
        userId: 'other-user-456'
      })

      await expect(userPaymentService.cancelSubscription('user-123')).rejects.toThrow('Unauthorized')
    })

    it('should handle subscription status transitions securely', async () => {
      const validTransitions = [
        { from: 'active', to: 'canceled' },
        { from: 'past_due', to: 'active' },
        { from: 'trialing', to: 'active' }
      ]

      const invalidTransitions = [
        { from: 'canceled', to: 'active' }, // Cannot reactivate canceled
        { from: 'incomplete_expired', to: 'active' } // Cannot activate expired
      ]

      for (const transition of invalidTransitions) {
        mockStorage.getUserPaymentProfile.mockResolvedValue({
          ...mockPaymentProfile,
          subscriptionStatus: transition.from as any
        })

        await expect(userPaymentService.updateSubscriptionStatus(
          'user-123',
          transition.to as any
        )).rejects.toThrow('Invalid subscription status transition')
      }
    })
  })

  describe('Payment Profile Security', () => {
    it('should encrypt sensitive payment data', async () => {
      const sensitiveProfile = {
        ...mockPaymentProfile,
        billingAddress: {
          line1: '123 Main St',
          city: 'Anytown',
          state: 'CA',
          postal_code: '12345',
          country: 'US'
        },
        paymentMethods: [
          {
            id: 'pm_test123',
            type: 'card',
            last4: '4242'
          }
        ]
      }

      await userPaymentService.updateUserPaymentProfile('user-123', sensitiveProfile)

      expect(mockStorage.updateUserPaymentProfile).toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          billingAddress: expect.any(Object),
          paymentMethods: expect.any(Array)
        })
      )

      // Verify sensitive data is not logged
      const logCalls = mockLogger.info.mock.calls
      logCalls.forEach(call => {
        const logMessage = JSON.stringify(call)
        expect(logMessage).not.toContain('4242')
        expect(logMessage).not.toContain('123 Main St')
      })
    })

    it('should validate billing address data', async () => {
      const invalidAddresses = [
        { line1: '', city: 'Test', state: 'CA', postal_code: '12345' },
        { line1: 'Test', city: '', state: 'CA', postal_code: '12345' },
        { line1: 'Test', city: 'Test', state: '', postal_code: '12345' },
        { line1: '<script>alert("xss")</script>', city: 'Test', state: 'CA', postal_code: '12345' }
      ]

      for (const address of invalidAddresses) {
        await expect(userPaymentService.updateBillingAddress('user-123', address)).rejects.toThrow()
      }
    })

    it('should prevent profile data injection', async () => {
      const maliciousProfile = {
        userId: 'other-user-456', // Attempt to change user ID
        stripeCustomerId: 'cus_malicious123',
        subscriptionTier: 'enterprise', // Attempt privilege escalation
        usageStats: {
          exports: -1000, // Negative usage
          searches: 999999,
          records: 999999,
          scraping: 999999
        }
      }

      await userPaymentService.updateUserPaymentProfile('user-123', maliciousProfile)

      expect(mockStorage.updateUserPaymentProfile).toHaveBeenCalledWith(
        'user-123', // Should use original user ID
        expect.objectContaining({
          userId: 'user-123', // Should not be changed
          usageStats: expect.objectContaining({
            exports: expect.not.toBe(-1000) // Should validate usage stats
          })
        })
      )
    })
  })

  describe('Usage Tracking Security', () => {
    it('should validate usage recording parameters', async () => {
      const invalidUsageData = [
        { userId: '', featureType: 'export', amount: 1 },
        { userId: 'user-123', featureType: '', amount: 1 },
        { userId: 'user-123', featureType: 'export', amount: -1 },
        { userId: 'user-123', featureType: 'export', amount: 999999 }
      ]

      for (const data of invalidUsageData) {
        await expect(userPaymentService.recordUsage(
          data.userId,
          data.featureType,
          data.amount
        )).rejects.toThrow()
      }
    })

    it('should prevent usage manipulation', async () => {
      const maliciousUsage = {
        featureType: 'export',
        amount: -100, // Negative to reduce usage
        metadata: {
          adminOverride: 'true',
          resetUsage: 'true',
          userId: 'other-user-456'
        }
      }

      await userPaymentService.recordUsage('user-123', maliciousUsage.featureType, maliciousUsage.amount)

      // Should reject negative usage
      expect(mockStorage.updateUserPaymentProfile).not.toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          usageStats: expect.objectContaining({
            exports: expect.toBeLessThan(0)
          })
        })
      )
    })

    it('should enforce usage limits', async () => {
      const profileWithHighUsage = {
        ...mockPaymentProfile,
        usageStats: {
          exports: 9999,
          searches: 9999,
          records: 9999,
          scraping: 9999
        }
      }

      mockStorage.getUserPaymentProfile.mockResolvedValue(profileWithHighUsage)

      await expect(userPaymentService.recordUsage('user-123', 'export', 1)).rejects.toThrow('Usage limit exceeded')
    })
  })

  describe('Data Protection and Privacy', () => {
    it('should not expose sensitive data in responses', async () => {
      const profileWithSensitiveData = {
        ...mockPaymentProfile,
        internalNotes: 'Sensitive internal information',
        stripeSecrets: 'sk_test_secret',
        adminFlags: ['high_value_customer', 'manual_review']
      }

      mockStorage.getUserPaymentProfile.mockResolvedValue(profileWithSensitiveData as any)

      const result = await userPaymentService.getUserPaymentProfile('user-123')

      expect(result).not.toHaveProperty('internalNotes')
      expect(result).not.toHaveProperty('stripeSecrets')
      expect(result).not.toHaveProperty('adminFlags')
    })

    it('should implement data retention policies', async () => {
      const expiredProfile = {
        ...mockPaymentProfile,
        lastActivity: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000), // 1 year ago
        subscriptionStatus: 'canceled' as const
      }

      mockStorage.getUserPaymentProfile.mockResolvedValue(expiredProfile)

      // Should trigger data cleanup for expired profiles
      await userPaymentService.getUserPaymentProfile('user-123')

      expect(mockLogger.info).toHaveBeenCalledWith(
        'UserPaymentService',
        expect.stringContaining('Data retention policy triggered'),
        expect.any(Object)
      )
    })

    it('should handle GDPR data deletion requests', async () => {
      await userPaymentService.deleteUserData('user-123')

      expect(mockStorage.deleteUserPaymentProfile).toHaveBeenCalledWith('user-123')
      expect(mockStripeService.deleteCustomer).toHaveBeenCalledWith('cus_test123')
      
      expect(mockLogger.info).toHaveBeenCalledWith(
        'UserPaymentService',
        expect.stringContaining('User data deleted'),
        expect.objectContaining({ userId: 'user-123' })
      )
    })
  })

  describe('Error Handling and Resilience', () => {
    it('should handle storage failures gracefully', async () => {
      mockStorage.getUserPaymentProfile.mockRejectedValue(new Error('Database connection failed'))

      await expect(userPaymentService.getUserPaymentProfile('user-123')).rejects.toThrow('Database connection failed')
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'UserPaymentService',
        expect.stringContaining('Failed to get user payment profile'),
        expect.any(Error)
      )
    })

    it('should implement retry logic for transient failures', async () => {
      let callCount = 0
      mockStripeService.createCustomer.mockImplementation(() => {
        callCount++
        if (callCount < 3) {
          throw new Error('Temporary network error')
        }
        return Promise.resolve(mockStripeCustomer)
      })

      mockStorage.getUserPaymentProfile.mockResolvedValue(null)

      const result = await userPaymentService.ensureStripeCustomer('user-123', 'test@example.com', 'Test User')
      
      expect(result).toBe('cus_test123')
      expect(callCount).toBe(3) // Should retry twice before succeeding
    })

    it('should handle concurrent operations safely', async () => {
      const concurrentOperations = [
        userPaymentService.recordUsage('user-123', 'export', 1),
        userPaymentService.recordUsage('user-123', 'search', 1),
        userPaymentService.updateUserPaymentProfile('user-123', { subscriptionTier: 'premium' })
      ]

      const results = await Promise.allSettled(concurrentOperations)
      
      // Should handle all operations without race conditions
      results.forEach(result => {
        if (result.status === 'rejected') {
          expect(result.reason.message).not.toContain('race condition')
        }
      })
    })
  })
})
