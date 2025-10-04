/**
 * Comprehensive Business Rule Tests for Subscription and Billing
 * Tests payment validation, subscription management, and billing calculations
 */

import { StripeService } from '@/model/stripeService'
import { UserPaymentService } from '@/model/userPaymentService'
import { PaymentValidationService } from '@/model/paymentValidationService'
import { 
  UserPaymentProfile, 
  PaymentTransaction, 
  SubscriptionPlan,
  UserSubscription,
  PaymentStatus,
  SubscriptionTier 
} from '@/types/payment'
import Stripe from 'stripe'

// Mock dependencies
jest.mock('stripe')
jest.mock('@/lib/config')
jest.mock('@/utils/logger')
jest.mock('@/lib/postgresql-database')

describe('Subscription and Billing - Business Logic Rules', () => {
  let stripeService: StripeService
  let userPaymentService: UserPaymentService
  let paymentValidationService: PaymentValidationService
  let mockStripe: jest.Mocked<Stripe>

  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
  }

  const mockSubscriptionPlan: SubscriptionPlan = {
    id: 'plan-basic',
    stripePriceId: 'price_basic_monthly',
    name: 'Basic Plan',
    description: 'Basic subscription plan',
    priceCents: 2999, // $29.99
    currency: 'USD',
    interval: 'month',
    features: ['basic_scraping', 'export_csv', 'email_support'],
    isActive: true,
    createdAt: new Date(),
  }

  const mockPaymentProfile: UserPaymentProfile = {
    userId: 'user-123',
    stripeCustomerId: 'cus_test123',
    email: 'test@example.com',
    name: 'Test User',
    subscriptionStatus: 'active',
    subscriptionTier: 'basic',
    subscriptionId: 'sub_test123',
    currentPeriodStart: new Date('2024-01-01'),
    currentPeriodEnd: new Date('2024-02-01'),
    cancelAtPeriodEnd: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  }

  beforeEach(() => {
    // Mock Stripe instance
    mockStripe = {
      customers: {
        create: jest.fn(),
        retrieve: jest.fn(),
        update: jest.fn(),
        list: jest.fn(),
      },
      subscriptions: {
        create: jest.fn(),
        retrieve: jest.fn(),
        update: jest.fn(),
        cancel: jest.fn(),
        list: jest.fn(),
      },
      paymentIntents: {
        create: jest.fn(),
        retrieve: jest.fn(),
        confirm: jest.fn(),
        cancel: jest.fn(),
      },
      webhooks: {
        constructEvent: jest.fn(),
      },
      prices: {
        list: jest.fn(),
        retrieve: jest.fn(),
      },
    } as any

    // Mock config
    require('@/lib/config').getConfig = jest.fn().mockReturnValue({
      payments: {
        stripeSecretKey: 'sk_test_123',
        stripeWebhookSecret: 'whsec_test_123',
      },
    })

    stripeService = new StripeService()
    userPaymentService = new UserPaymentService()
    paymentValidationService = new PaymentValidationService()

    // Inject mocked Stripe
    ;(stripeService as any).stripe = mockStripe

    jest.clearAllMocks()
  })

  describe('Subscription Creation Logic', () => {
    test('should create subscription with proper validation', async () => {
      const mockCustomer = {
        id: 'cus_test123',
        email: 'test@example.com',
        name: 'Test User',
      }

      const mockSubscription = {
        id: 'sub_test123',
        customer: 'cus_test123',
        status: 'active',
        current_period_start: Math.floor(Date.now() / 1000),
        current_period_end: Math.floor(Date.now() / 1000) + 2592000, // 30 days
        items: {
          data: [{ price: { id: 'price_basic_monthly' } }],
        },
        metadata: { userId: 'user-123' },
      }

      mockStripe.customers.create.mockResolvedValue(mockCustomer as any)
      mockStripe.subscriptions.create.mockResolvedValue(mockSubscription as any)

      // Mock user payment service methods
      jest.spyOn(userPaymentService, 'getUserPaymentProfile').mockResolvedValue(null)
      jest.spyOn(userPaymentService, 'updateUserPaymentProfile').mockResolvedValue({
        success: true,
        data: mockPaymentProfile,
      })

      const result = await userPaymentService.createSubscription(
        mockUser.id,
        'price_basic_monthly'
      )

      expect(result.success).toBe(true)
      expect(result.data).toBeDefined()
      expect(mockStripe.subscriptions.create).toHaveBeenCalledWith({
        customer: 'cus_test123',
        items: [{ price: 'price_basic_monthly' }],
        payment_behavior: 'default_incomplete',
        payment_settings: { save_default_payment_method: 'on_subscription' },
        expand: ['latest_invoice.payment_intent'],
        metadata: expect.objectContaining({
          userId: 'user-123',
        }),
        proration_behavior: 'create_prorations',
      })
    })

    test('should handle subscription creation with trial period', async () => {
      const mockSubscription = {
        id: 'sub_trial123',
        customer: 'cus_test123',
        status: 'trialing',
        trial_end: Math.floor(Date.now() / 1000) + 1209600, // 14 days
        current_period_start: Math.floor(Date.now() / 1000),
        current_period_end: Math.floor(Date.now() / 1000) + 2592000,
      }

      mockStripe.subscriptions.create.mockResolvedValue(mockSubscription as any)

      jest.spyOn(userPaymentService, 'getUserPaymentProfile').mockResolvedValue({
        ...mockPaymentProfile,
        stripeCustomerId: 'cus_test123',
      })

      const result = await userPaymentService.createSubscription(
        mockUser.id,
        'price_basic_monthly',
        { trialPeriodDays: 14 }
      )

      expect(result.success).toBe(true)
      expect(mockStripe.subscriptions.create).toHaveBeenCalledWith(
        expect.objectContaining({
          trial_period_days: 14,
        })
      )
    })

    test('should validate subscription plan before creation', async () => {
      const invalidPriceId = 'price_invalid'

      // Mock validation failure
      jest.spyOn(paymentValidationService, 'validateSubscriptionPlan').mockResolvedValue({
        isValid: false,
        errors: ['Invalid price ID'],
        warnings: [],
      })

      await expect(
        userPaymentService.createSubscription(mockUser.id, invalidPriceId)
      ).rejects.toThrow('Invalid subscription plan')
    })
  })

  describe('Payment Processing Logic', () => {
    test('should create payment intent with proper amount validation', async () => {
      const amount = 2999 // $29.99 in cents
      const currency = 'usd'

      const mockPaymentIntent = {
        id: 'pi_test123',
        amount,
        currency,
        status: 'requires_payment_method',
        client_secret: 'pi_test123_secret_123',
      }

      mockStripe.paymentIntents.create.mockResolvedValue(mockPaymentIntent as any)

      const result = await stripeService.createPaymentIntent(amount, currency, {
        customerId: 'cus_test123',
        description: 'Basic Plan Subscription',
      })

      expect(result.id).toBe('pi_test123')
      expect(result.amount).toBe(amount)
      expect(result.currency).toBe(currency)

      expect(mockStripe.paymentIntents.create).toHaveBeenCalledWith({
        amount,
        currency,
        customer: 'cus_test123',
        automatic_payment_methods: { enabled: true },
        metadata: {},
        description: 'Basic Plan Subscription',
      })
    })

    test('should validate payment amounts against business rules', async () => {
      // Test minimum amount validation
      const tooSmallAmount = 50 // $0.50 - below minimum

      jest.spyOn(paymentValidationService, 'validatePaymentAmount').mockReturnValue({
        isValid: false,
        errors: ['Amount below minimum threshold'],
        warnings: [],
      })

      await expect(
        stripeService.createPaymentIntent(tooSmallAmount, 'usd')
      ).rejects.toThrow('Invalid payment amount')

      // Test maximum amount validation
      const tooLargeAmount = 10000000 // $100,000 - above maximum

      jest.spyOn(paymentValidationService, 'validatePaymentAmount').mockReturnValue({
        isValid: false,
        errors: ['Amount exceeds maximum threshold'],
        warnings: [],
      })

      await expect(
        stripeService.createPaymentIntent(tooLargeAmount, 'usd')
      ).rejects.toThrow('Invalid payment amount')
    })

    test('should handle payment method validation', async () => {
      const paymentMethodId = 'pm_test123'

      jest.spyOn(paymentValidationService, 'validatePaymentMethod').mockResolvedValue({
        isValid: true,
        errors: [],
        warnings: [],
        paymentMethod: {
          id: paymentMethodId,
          type: 'card',
          card: {
            brand: 'visa',
            last4: '4242',
            exp_month: 12,
            exp_year: 2025,
          },
        },
      })

      const validation = await paymentValidationService.validatePaymentMethod(paymentMethodId)

      expect(validation.isValid).toBe(true)
      expect(validation.paymentMethod?.id).toBe(paymentMethodId)
    })
  })

  describe('Billing Calculation Logic', () => {
    test('should calculate prorated amounts correctly', async () => {
      const currentPlan = { priceCents: 2999, interval: 'month' } // $29.99/month
      const newPlan = { priceCents: 4999, interval: 'month' } // $49.99/month
      const daysRemaining = 15 // Half month remaining

      const proratedAmount = paymentValidationService.calculateProration(
        currentPlan,
        newPlan,
        daysRemaining,
        30 // days in month
      )

      // Expected: (49.99 - 29.99) * (15/30) = 20.00 * 0.5 = 10.00
      const expectedAmount = Math.round(((4999 - 2999) * (15 / 30)))
      expect(proratedAmount).toBe(expectedAmount)
    })

    test('should calculate subscription renewal amounts', async () => {
      const subscription = {
        ...mockPaymentProfile,
        subscriptionTier: 'basic' as SubscriptionTier,
        currentPeriodEnd: new Date('2024-02-01'),
      }

      const renewalAmount = paymentValidationService.calculateRenewalAmount(
        subscription,
        mockSubscriptionPlan
      )

      expect(renewalAmount).toBe(2999) // Full plan price for renewal
    })

    test('should apply discounts and coupons correctly', async () => {
      const baseAmount = 2999 // $29.99
      const discountPercent = 20 // 20% off

      const discountedAmount = paymentValidationService.applyDiscount(
        baseAmount,
        discountPercent,
        'percentage'
      )

      const expectedAmount = Math.round(baseAmount * (1 - discountPercent / 100))
      expect(discountedAmount).toBe(expectedAmount) // $23.99
    })

    test('should calculate tax amounts based on location', async () => {
      const baseAmount = 2999 // $29.99
      const taxRate = 0.08 // 8% tax rate

      const taxAmount = paymentValidationService.calculateTax(baseAmount, taxRate)
      const totalAmount = baseAmount + taxAmount

      expect(taxAmount).toBe(Math.round(baseAmount * taxRate)) // $2.40
      expect(totalAmount).toBe(baseAmount + taxAmount) // $32.39
    })
  })

  describe('Subscription State Management', () => {
    test('should handle subscription status transitions', async () => {
      const activeSubscription = {
        ...mockPaymentProfile,
        subscriptionStatus: 'active' as PaymentStatus,
      }

      // Test transition to past_due
      const pastDueUpdate = await userPaymentService.updateSubscriptionStatus(
        mockUser.id,
        'past_due'
      )

      expect(pastDueUpdate.success).toBe(true)

      // Test transition to canceled
      const canceledUpdate = await userPaymentService.updateSubscriptionStatus(
        mockUser.id,
        'canceled'
      )

      expect(canceledUpdate.success).toBe(true)
    })

    test('should validate subscription status transitions', async () => {
      // Invalid transition: active -> trial (not allowed)
      jest.spyOn(paymentValidationService, 'validateStatusTransition').mockReturnValue({
        isValid: false,
        errors: ['Invalid status transition from active to trial'],
        warnings: [],
      })

      await expect(
        userPaymentService.updateSubscriptionStatus(mockUser.id, 'trial')
      ).rejects.toThrow('Invalid status transition')
    })

    test('should handle subscription cancellation logic', async () => {
      const mockCanceledSubscription = {
        id: 'sub_test123',
        status: 'canceled',
        canceled_at: Math.floor(Date.now() / 1000),
        cancel_at_period_end: false,
      }

      mockStripe.subscriptions.cancel.mockResolvedValue(mockCanceledSubscription as any)

      const result = await userPaymentService.cancelSubscription(mockUser.id)

      expect(result.success).toBe(true)
      expect(mockStripe.subscriptions.cancel).toHaveBeenCalledWith('sub_test123')
    })

    test('should handle subscription upgrade/downgrade logic', async () => {
      const newPriceId = 'price_professional_monthly'

      const mockUpdatedSubscription = {
        id: 'sub_test123',
        status: 'active',
        items: {
          data: [{ id: 'si_test123', price: { id: newPriceId } }],
        },
      }

      mockStripe.subscriptions.update.mockResolvedValue(mockUpdatedSubscription as any)

      const result = await userPaymentService.updateSubscription(
        mockUser.id,
        newPriceId
      )

      expect(result.success).toBe(true)
      expect(mockStripe.subscriptions.update).toHaveBeenCalledWith(
        'sub_test123',
        expect.objectContaining({
          items: expect.arrayContaining([
            expect.objectContaining({
              price: newPriceId,
            }),
          ]),
          proration_behavior: 'create_prorations',
        })
      )
    })
  })

  describe('Webhook Processing Logic', () => {
    test('should process subscription created webhook', async () => {
      const webhookEvent = {
        id: 'evt_test123',
        type: 'customer.subscription.created',
        data: {
          object: {
            id: 'sub_test123',
            customer: 'cus_test123',
            status: 'active',
            metadata: { userId: 'user-123' },
          },
        },
      }

      mockStripe.webhooks.constructEvent.mockReturnValue(webhookEvent as any)

      const result = await stripeService.processWebhook(
        JSON.stringify(webhookEvent),
        'test_signature'
      )

      expect(result.processed).toBe(true)
      expect(result.eventType).toBe('customer.subscription.created')
    })

    test('should process payment succeeded webhook', async () => {
      const webhookEvent = {
        id: 'evt_payment123',
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: 'pi_test123',
            amount: 2999,
            currency: 'usd',
            status: 'succeeded',
            metadata: { userId: 'user-123' },
          },
        },
      }

      mockStripe.webhooks.constructEvent.mockReturnValue(webhookEvent as any)

      const result = await stripeService.processWebhook(
        JSON.stringify(webhookEvent),
        'test_signature'
      )

      expect(result.processed).toBe(true)
      expect(result.eventType).toBe('payment_intent.succeeded')
    })

    test('should handle webhook signature validation', async () => {
      const invalidSignature = 'invalid_signature'

      mockStripe.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('Invalid signature')
      })

      await expect(
        stripeService.processWebhook('{}', invalidSignature)
      ).rejects.toThrow('Invalid signature')
    })
  })

  describe('Error Handling and Edge Cases', () => {
    test('should handle Stripe API errors gracefully', async () => {
      const stripeError = new Error('Your card was declined') as any
      stripeError.type = 'card_error'
      stripeError.code = 'card_declined'

      mockStripe.paymentIntents.create.mockRejectedValue(stripeError)

      await expect(
        stripeService.createPaymentIntent(2999, 'usd')
      ).rejects.toThrow('Your card was declined')
    })

    test('should handle network timeouts', async () => {
      const timeoutError = new Error('Request timeout')
      mockStripe.customers.create.mockRejectedValue(timeoutError)

      await expect(
        stripeService.createCustomer('test@example.com')
      ).rejects.toThrow('Request timeout')
    })

    test('should handle duplicate subscription creation', async () => {
      jest.spyOn(userPaymentService, 'getUserPaymentProfile').mockResolvedValue({
        ...mockPaymentProfile,
        subscriptionStatus: 'active',
        subscriptionId: 'sub_existing123',
      })

      await expect(
        userPaymentService.createSubscription(mockUser.id, 'price_basic_monthly')
      ).rejects.toThrow('User already has an active subscription')
    })

    test('should handle invalid currency codes', async () => {
      await expect(
        stripeService.createPaymentIntent(2999, 'invalid_currency')
      ).rejects.toThrow('Invalid currency')
    })
  })

  describe('Performance and Security', () => {
    test('should complete payment operations within reasonable time', async () => {
      const startTime = Date.now()

      await stripeService.createPaymentIntent(2999, 'usd', {
        customerId: 'cus_test123',
      })

      const endTime = Date.now()
      const processingTime = endTime - startTime

      expect(processingTime).toBeLessThan(1000) // Should complete within 1 second
    })

    test('should sanitize sensitive data in logs', async () => {
      const loggerSpy = jest.spyOn(require('@/utils/logger').logger, 'info')

      await stripeService.createCustomer('test@example.com', 'Test User')

      // Verify no sensitive data is logged
      const logCalls = loggerSpy.mock.calls
      logCalls.forEach(call => {
        const logMessage = JSON.stringify(call)
        expect(logMessage).not.toContain('sk_test_') // No secret keys
        expect(logMessage).not.toContain('whsec_') // No webhook secrets
      })
    })

    test('should handle concurrent payment requests', async () => {
      const requests = Array(5)
        .fill(0)
        .map(() => stripeService.createPaymentIntent(2999, 'usd'))

      const startTime = Date.now()
      const results = await Promise.all(requests)
      const endTime = Date.now()

      expect(results).toHaveLength(5)
      expect(endTime - startTime).toBeLessThan(3000) // Should handle concurrency efficiently
    })
  })
})
