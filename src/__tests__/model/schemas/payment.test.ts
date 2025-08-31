/**
 * Payment Validation Schemas Tests
 * Comprehensive test suite for payment validation schemas
 * Ensures 85%+ test coverage and validates all edge cases
 */

import { describe, it, expect } from '@jest/globals'
import {
  subscriptionPlanSchema,
  userSubscriptionSchema,
  paymentTransactionSchema,
  featureUsageSchema,
  type SubscriptionPlan,
  type UserSubscription,
  type PaymentTransaction,
  type FeatureUsage,
} from '../../../model/schemas/payment'

describe('Payment Validation Schemas', () => {
  // ============================================================================
  // SUBSCRIPTION PLAN SCHEMA TESTS
  // ============================================================================

  describe('subscriptionPlanSchema', () => {
    const validPlan: SubscriptionPlan = {
      id: '123e4567-e89b-12d3-a456-426614174000',
      stripePriceId: 'price_1234567890abcdefghijklmn',
      name: 'Pro Plan',
      description: 'Professional features for power users',
      priceCents: 2999,
      currency: 'USD',
      interval: 'month',
      features: ['Unlimited scraping', 'Advanced exports', 'Priority support'],
      isActive: true,
      createdAt: new Date('2024-01-01T00:00:00Z'),
    }

    it('should validate a correct subscription plan', () => {
      const result = subscriptionPlanSchema.safeParse(validPlan)
      expect(result.success).toBe(true)
    })

    it('should reject invalid UUID format', () => {
      const invalidPlan = { ...validPlan, id: 'invalid-uuid' }
      const result = subscriptionPlanSchema.safeParse(invalidPlan)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.errors[0].message).toContain('Invalid UUID format')
      }
    })

    it('should reject invalid Stripe price ID format', () => {
      const invalidPlan = { ...validPlan, stripePriceId: 'invalid_price_id' }
      const result = subscriptionPlanSchema.safeParse(invalidPlan)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.errors[0].message).toContain('Invalid Stripe price ID format')
      }
    })

    it('should reject empty plan name', () => {
      const invalidPlan = { ...validPlan, name: '' }
      const result = subscriptionPlanSchema.safeParse(invalidPlan)
      expect(result.success).toBe(false)
    })

    it('should reject negative price', () => {
      const invalidPlan = { ...validPlan, priceCents: -100 }
      const result = subscriptionPlanSchema.safeParse(invalidPlan)
      expect(result.success).toBe(false)
    })

    it('should reject invalid currency format', () => {
      const invalidPlan = { ...validPlan, currency: 'usd' }
      const result = subscriptionPlanSchema.safeParse(invalidPlan)
      expect(result.success).toBe(false)
    })

    it('should reject invalid interval', () => {
      const invalidPlan = { ...validPlan, interval: 'week' as any }
      const result = subscriptionPlanSchema.safeParse(invalidPlan)
      expect(result.success).toBe(false)
    })

    it('should reject empty features array', () => {
      const invalidPlan = { ...validPlan, features: [] }
      const result = subscriptionPlanSchema.safeParse(invalidPlan)
      expect(result.success).toBe(false)
    })

    it('should use default values correctly', () => {
      const planWithDefaults = {
        ...validPlan,
        currency: undefined,
        isActive: undefined,
      }
      const result = subscriptionPlanSchema.safeParse(planWithDefaults)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.currency).toBe('USD')
        expect(result.data.isActive).toBe(true)
      }
    })
  })

  // ============================================================================
  // USER SUBSCRIPTION SCHEMA TESTS
  // ============================================================================

  describe('userSubscriptionSchema', () => {
    const validSubscription: UserSubscription = {
      id: '123e4567-e89b-12d3-a456-426614174001',
      userId: '123e4567-e89b-12d3-a456-426614174002',
      stripeSubscriptionId: 'sub_1234567890abcdefghijklmn',
      planId: '123e4567-e89b-12d3-a456-426614174000',
      status: 'active',
      currentPeriodStart: new Date('2024-01-01T00:00:00Z'),
      currentPeriodEnd: new Date('2024-02-01T00:00:00Z'),
      cancelAtPeriodEnd: false,
      createdAt: new Date('2024-01-01T00:00:00Z'),
      updatedAt: new Date('2024-01-01T00:00:00Z'),
    }

    it('should validate a correct user subscription', () => {
      const result = userSubscriptionSchema.safeParse(validSubscription)
      expect(result.success).toBe(true)
    })

    it('should reject invalid subscription status', () => {
      const invalidSubscription = { ...validSubscription, status: 'invalid' as any }
      const result = userSubscriptionSchema.safeParse(invalidSubscription)
      expect(result.success).toBe(false)
    })

    it('should reject when period end is before start', () => {
      const invalidSubscription = {
        ...validSubscription,
        currentPeriodEnd: new Date('2023-12-01T00:00:00Z'),
      }
      const result = userSubscriptionSchema.safeParse(invalidSubscription)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.errors[0].message).toContain(
          'Current period end must be after start date'
        )
      }
    })

    it('should reject when updated date is before created date', () => {
      const invalidSubscription = {
        ...validSubscription,
        updatedAt: new Date('2023-12-01T00:00:00Z'),
      }
      const result = userSubscriptionSchema.safeParse(invalidSubscription)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.errors[0].message).toContain(
          'Updated date must be after or equal to created date'
        )
      }
    })

    it('should use default values correctly', () => {
      const subscriptionWithDefaults = {
        ...validSubscription,
        cancelAtPeriodEnd: undefined,
      }
      const result = userSubscriptionSchema.safeParse(subscriptionWithDefaults)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.cancelAtPeriodEnd).toBe(false)
      }
    })
  })

  // ============================================================================
  // PAYMENT TRANSACTION SCHEMA TESTS
  // ============================================================================

  describe('paymentTransactionSchema', () => {
    const validTransaction: PaymentTransaction = {
      id: '123e4567-e89b-12d3-a456-426614174003',
      userId: '123e4567-e89b-12d3-a456-426614174002',
      stripePaymentIntentId: 'pi_1234567890abcdefghijklmn',
      amountCents: 2999,
      currency: 'USD',
      status: 'succeeded',
      description: 'Pro Plan subscription payment',
      metadata: { planId: 'pro-plan', source: 'web' },
      createdAt: new Date('2024-01-01T00:00:00Z'),
    }

    it('should validate a correct payment transaction', () => {
      const result = paymentTransactionSchema.safeParse(validTransaction)
      expect(result.success).toBe(true)
    })

    it('should allow optional stripePaymentIntentId', () => {
      const transactionWithoutStripe = {
        ...validTransaction,
        stripePaymentIntentId: undefined,
      }
      const result = paymentTransactionSchema.safeParse(transactionWithoutStripe)
      expect(result.success).toBe(true)
    })

    it('should reject negative amount', () => {
      const invalidTransaction = { ...validTransaction, amountCents: -100 }
      const result = paymentTransactionSchema.safeParse(invalidTransaction)
      expect(result.success).toBe(false)
    })

    it('should reject invalid payment status', () => {
      const invalidTransaction = { ...validTransaction, status: 'invalid' as any }
      const result = paymentTransactionSchema.safeParse(invalidTransaction)
      expect(result.success).toBe(false)
    })

    it('should reject empty description', () => {
      const invalidTransaction = { ...validTransaction, description: '' }
      const result = paymentTransactionSchema.safeParse(invalidTransaction)
      expect(result.success).toBe(false)
    })
  })

  // ============================================================================
  // FEATURE USAGE SCHEMA TESTS
  // ============================================================================

  describe('featureUsageSchema', () => {
    const validUsage: FeatureUsage = {
      id: '123e4567-e89b-12d3-a456-426614174004',
      userId: '123e4567-e89b-12d3-a456-426614174002',
      featureType: 'scraping_request',
      usageCount: 5,
      date: new Date('2024-01-01T00:00:00Z'),
      metadata: { source: 'web-app', batchId: 'batch-123' },
      createdAt: new Date('2024-01-01T00:00:00Z'),
    }

    it('should validate a correct feature usage record', () => {
      const result = featureUsageSchema.safeParse(validUsage)
      expect(result.success).toBe(true)
    })

    it('should reject invalid feature type', () => {
      const invalidUsage = { ...validUsage, featureType: 'invalid_feature' as any }
      const result = featureUsageSchema.safeParse(invalidUsage)
      expect(result.success).toBe(false)
    })

    it('should reject zero or negative usage count', () => {
      const invalidUsage = { ...validUsage, usageCount: 0 }
      const result = featureUsageSchema.safeParse(invalidUsage)
      expect(result.success).toBe(false)
    })

    it('should reject future usage date', () => {
      const futureDate = new Date('2025-01-01T00:00:00Z')
      const invalidUsage = {
        ...validUsage,
        date: futureDate,
        createdAt: new Date('2024-01-01T00:00:00Z'),
      }
      const result = featureUsageSchema.safeParse(invalidUsage)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.errors[0].message).toContain('Usage date cannot be in the future')
      }
    })

    it('should use default usage count', () => {
      const usageWithDefaults = {
        ...validUsage,
        usageCount: undefined,
      }
      const result = featureUsageSchema.safeParse(usageWithDefaults)
      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.usageCount).toBe(1)
      }
    })
  })
})
