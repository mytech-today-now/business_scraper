/**
 * Unit Tests for Payment Models and Data Structures
 * Comprehensive test coverage for TypeScript interfaces and Zod schemas
 */

import {
  SubscriptionPlan,
  UserSubscription,
  PaymentTransaction,
  FeatureUsage,
  SubscriptionPlanSchema,
  UserSubscriptionSchema,
  PaymentTransactionSchema,
  FeatureUsageSchema,
  validateSubscriptionPlan,
  validateUserSubscription,
  validatePaymentTransaction,
  validateFeatureUsage,
  isSubscriptionPlan,
  isUserSubscription,
  isPaymentTransaction,
  isFeatureUsage,
  centsTodollars,
  dollarsToCents,
  formatCurrency,
  isSubscriptionActive,
  getDaysUntilExpiration,
  getFeatureUsageSummary,
} from '@/model/types/payment'

describe('Payment Models and Data Structures', () => {
  // ============================================================================
  // SUBSCRIPTION PLAN TESTS
  // ============================================================================

  describe('SubscriptionPlan', () => {
    const validSubscriptionPlan: SubscriptionPlan = {
      id: 'plan_123',
      stripePriceId: 'price_1234567890',
      name: 'Professional Plan',
      description: 'Advanced features for professional users',
      priceCents: 2999,
      currency: 'USD',
      interval: 'month',
      features: ['Advanced Search', 'API Access', 'Priority Support'],
      isActive: true,
      createdAt: new Date('2024-01-01T00:00:00Z'),
    }

    it('should validate valid subscription plan data', () => {
      const result = validateSubscriptionPlan(validSubscriptionPlan)
      expect(result.success).toBe(true)
      expect(result.data).toEqual(validSubscriptionPlan)
      expect(result.errors).toBeUndefined()
    })

    it('should reject subscription plan with missing required fields', () => {
      const invalidPlan = { ...validSubscriptionPlan }
      delete (invalidPlan as any).id

      const result = validateSubscriptionPlan(invalidPlan)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('id: Required')
    })

    it('should reject subscription plan with invalid price', () => {
      const invalidPlan = { ...validSubscriptionPlan, priceCents: -100 }

      const result = validateSubscriptionPlan(invalidPlan)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('priceCents: Price must be non-negative')
    })

    it('should reject subscription plan with invalid currency', () => {
      const invalidPlan = { ...validSubscriptionPlan, currency: 'usd' }

      const result = validateSubscriptionPlan(invalidPlan)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('currency: Currency must be uppercase')
    })

    it('should reject subscription plan with invalid interval', () => {
      const invalidPlan = { ...validSubscriptionPlan, interval: 'week' as any }

      const result = validateSubscriptionPlan(invalidPlan)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('interval: Interval must be month or year')
    })

    it('should validate type guard correctly', () => {
      expect(isSubscriptionPlan(validSubscriptionPlan)).toBe(true)
      expect(isSubscriptionPlan({ invalid: 'data' })).toBe(false)
      expect(isSubscriptionPlan(null)).toBe(false)
    })
  })

  // ============================================================================
  // USER SUBSCRIPTION TESTS
  // ============================================================================

  describe('UserSubscription', () => {
    const validUserSubscription: UserSubscription = {
      id: 'sub_123',
      userId: 'user_456',
      stripeSubscriptionId: 'sub_stripe_789',
      planId: 'plan_123',
      status: 'active',
      currentPeriodStart: new Date('2024-01-01T00:00:00Z'),
      currentPeriodEnd: new Date('2024-02-01T00:00:00Z'),
      cancelAtPeriodEnd: false,
      createdAt: new Date('2024-01-01T00:00:00Z'),
      updatedAt: new Date('2024-01-01T00:00:00Z'),
    }

    it('should validate valid user subscription data', () => {
      const result = validateUserSubscription(validUserSubscription)
      expect(result.success).toBe(true)
      expect(result.data).toEqual(validUserSubscription)
      expect(result.errors).toBeUndefined()
    })

    it('should reject user subscription with invalid status', () => {
      const invalidSubscription = { ...validUserSubscription, status: 'invalid' as any }

      const result = validateUserSubscription(invalidSubscription)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('status: Invalid subscription status')
    })

    it('should validate subscription activity correctly', () => {
      expect(isSubscriptionActive(validUserSubscription)).toBe(false) // Past date

      const activeSubscription = {
        ...validUserSubscription,
        currentPeriodStart: new Date(Date.now() - 86400000), // Yesterday
        currentPeriodEnd: new Date(Date.now() + 86400000), // Tomorrow
      }
      expect(isSubscriptionActive(activeSubscription)).toBe(true)
    })

    it('should calculate days until expiration correctly', () => {
      const futureSubscription = {
        ...validUserSubscription,
        currentPeriodEnd: new Date(Date.now() + 86400000 * 5), // 5 days from now
      }
      const days = getDaysUntilExpiration(futureSubscription)
      expect(days).toBe(5)

      const expiredSubscription = {
        ...validUserSubscription,
        currentPeriodEnd: new Date(Date.now() - 86400000), // Yesterday
      }
      expect(getDaysUntilExpiration(expiredSubscription)).toBeNull()
    })

    it('should validate type guard correctly', () => {
      expect(isUserSubscription(validUserSubscription)).toBe(true)
      expect(isUserSubscription({ invalid: 'data' })).toBe(false)
    })
  })

  // ============================================================================
  // PAYMENT TRANSACTION TESTS
  // ============================================================================

  describe('PaymentTransaction', () => {
    const validPaymentTransaction: PaymentTransaction = {
      id: 'txn_123',
      userId: 'user_456',
      stripePaymentIntentId: 'pi_stripe_789',
      amountCents: 2999,
      currency: 'USD',
      status: 'succeeded',
      description: 'Monthly subscription payment',
      metadata: { planId: 'plan_123', period: 'monthly' },
      createdAt: new Date('2024-01-01T00:00:00Z'),
    }

    it('should validate valid payment transaction data', () => {
      const result = validatePaymentTransaction(validPaymentTransaction)
      expect(result.success).toBe(true)
      expect(result.data).toEqual(validPaymentTransaction)
      expect(result.errors).toBeUndefined()
    })

    it('should reject payment transaction with invalid amount', () => {
      const invalidTransaction = { ...validPaymentTransaction, amountCents: 0 }

      const result = validatePaymentTransaction(invalidTransaction)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('amountCents: Amount must be positive')
    })

    it('should validate type guard correctly', () => {
      expect(isPaymentTransaction(validPaymentTransaction)).toBe(true)
      expect(isPaymentTransaction({ invalid: 'data' })).toBe(false)
    })
  })

  // ============================================================================
  // FEATURE USAGE TESTS
  // ============================================================================

  describe('FeatureUsage', () => {
    const validFeatureUsage: FeatureUsage = {
      id: 'usage_123',
      userId: 'user_456',
      featureType: 'scraping_request',
      usageCount: 10,
      date: new Date('2024-01-01T00:00:00Z'),
      metadata: { searchQuery: 'restaurants', location: 'New York' },
      createdAt: new Date('2024-01-01T12:00:00Z'),
    }

    it('should validate valid feature usage data', () => {
      const result = validateFeatureUsage(validFeatureUsage)
      expect(result.success).toBe(true)
      expect(result.data).toEqual(validFeatureUsage)
      expect(result.errors).toBeUndefined()
    })

    it('should reject feature usage with invalid feature type', () => {
      const invalidUsage = { ...validFeatureUsage, featureType: 'invalid_feature' as any }

      const result = validateFeatureUsage(invalidUsage)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('featureType: Invalid feature type')
    })

    it('should calculate usage summary correctly', () => {
      const usageRecords: FeatureUsage[] = [
        { ...validFeatureUsage, featureType: 'scraping_request', usageCount: 5 },
        { ...validFeatureUsage, featureType: 'export', usageCount: 3 },
        { ...validFeatureUsage, featureType: 'scraping_request', usageCount: 2 },
      ]

      const summary = getFeatureUsageSummary(
        usageRecords,
        new Date('2024-01-01'),
        new Date('2024-01-02')
      )

      expect(summary['scraping_request']).toBe(7)
      expect(summary['export']).toBe(3)
    })

    it('should validate type guard correctly', () => {
      expect(isFeatureUsage(validFeatureUsage)).toBe(true)
      expect(isFeatureUsage({ invalid: 'data' })).toBe(false)
    })
  })

  // ============================================================================
  // UTILITY FUNCTION TESTS
  // ============================================================================

  describe('Utility Functions', () => {
    it('should convert cents to dollars correctly', () => {
      expect(centsTodollars(2999)).toBe(29.99)
      expect(centsTodollars(100)).toBe(1.0)
      expect(centsTodollars(0)).toBe(0.0)
    })

    it('should convert dollars to cents correctly', () => {
      expect(dollarsToCents(29.99)).toBe(2999)
      expect(dollarsToCents(1.0)).toBe(100)
      expect(dollarsToCents(0)).toBe(0)
    })

    it('should format currency correctly', () => {
      expect(formatCurrency(2999, 'USD')).toBe('$29.99')
      expect(formatCurrency(100, 'USD')).toBe('$1.00')
    })
  })

  // ============================================================================
  // SCHEMA DIRECT TESTS
  // ============================================================================

  describe('Zod Schemas Direct Validation', () => {
    it('should validate all schemas directly', () => {
      const validPlan = {
        id: 'plan_123',
        stripePriceId: 'price_123',
        name: 'Test Plan',
        description: 'Test Description',
        priceCents: 1000,
        currency: 'USD',
        interval: 'month',
        features: ['Feature 1'],
        isActive: true,
        createdAt: new Date(),
      }

      expect(() => SubscriptionPlanSchema.parse(validPlan)).not.toThrow()
    })
  })

  // ============================================================================
  // ERROR HANDLING TESTS
  // ============================================================================

  describe('Error Handling', () => {
    it('should handle unknown validation errors gracefully', () => {
      // Mock Zod to throw a non-ZodError
      const originalParse = SubscriptionPlanSchema.parse
      SubscriptionPlanSchema.parse = jest.fn().mockImplementation(() => {
        throw new Error('Unknown error')
      })

      const result = validateSubscriptionPlan({})
      expect(result.success).toBe(false)
      expect(result.errors).toEqual(['Unknown validation error'])

      // Restore original function
      SubscriptionPlanSchema.parse = originalParse
    })

    it('should handle edge cases in utility functions', () => {
      expect(centsTodollars(1)).toBe(0.01)
      expect(dollarsToCents(0.01)).toBe(1)
      expect(formatCurrency(1, 'eur')).toContain('€')
    })

    it('should handle empty usage records in summary', () => {
      const summary = getFeatureUsageSummary([], new Date(), new Date())
      expect(summary).toEqual({})
    })

    it('should handle subscription edge cases', () => {
      const expiredSubscription: UserSubscription = {
        id: 'sub_123',
        userId: 'user_456',
        stripeSubscriptionId: 'sub_stripe_789',
        planId: 'plan_123',
        status: 'canceled',
        currentPeriodStart: new Date('2024-01-01T00:00:00Z'),
        currentPeriodEnd: new Date('2024-02-01T00:00:00Z'),
        cancelAtPeriodEnd: false,
        createdAt: new Date('2024-01-01T00:00:00Z'),
        updatedAt: new Date('2024-01-01T00:00:00Z'),
      }

      expect(isSubscriptionActive(expiredSubscription)).toBe(false)
    })
  })

  // ============================================================================
  // CONSTANTS TESTS
  // ============================================================================

  describe('Constants', () => {
    it('should export all required constants', () => {
      const {
        SUPPORTED_CURRENCIES,
        SUBSCRIPTION_STATUSES,
        PAYMENT_STATUSES,
        FEATURE_TYPES,
        BILLING_INTERVALS,
      } = require('@/model/types/payment')

      expect(SUPPORTED_CURRENCIES).toBeDefined()
      expect(SUBSCRIPTION_STATUSES).toBeDefined()
      expect(PAYMENT_STATUSES).toBeDefined()
      expect(FEATURE_TYPES).toBeDefined()
      expect(BILLING_INTERVALS).toBeDefined()
    })
  })
})
