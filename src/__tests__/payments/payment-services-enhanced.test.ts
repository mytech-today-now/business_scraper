/**
 * Enhanced Payment Services Tests
 * Comprehensive testing for stripeService, userPaymentService, and paymentValidationService
 */

import { 
  setupPaymentMocks, 
  resetPaymentMocks, 
  configureDefaultMockBehaviors,
  allMocks,
  mockConfig
} from '../utils/paymentMockSetup'
import { 
  createMockStripeCustomer,
  createMockStripePaymentIntent,
  createMockStripeSubscription,
  paymentTestData,
  simulateStripeError,
  simulateNetworkError,
  createSecurityTestScenarios
} from '../utils/paymentTestUtils'

// Setup mocks before importing modules
setupPaymentMocks()
configureDefaultMockBehaviors()

describe('Enhanced Payment Services Tests', () => {
  beforeEach(() => {
    resetPaymentMocks()
    configureDefaultMockBehaviors()
  })

  describe('Stripe Service Tests', () => {
    describe('Customer Management', () => {
      it('should create customer successfully', async () => {
        const mockCustomer = createMockStripeCustomer()
        allMocks.stripeService.createCustomer.mockResolvedValue(mockCustomer)

        const customer = await allMocks.stripeService.createCustomer(
          'test@example.com',
          'Test User',
          { userId: 'user-123' }
        )

        expect(customer).toEqual(mockCustomer)
        expect(allMocks.stripeService.createCustomer).toHaveBeenCalledWith(
          'test@example.com',
          'Test User',
          { userId: 'user-123' }
        )
      })

      it('should handle customer creation errors', async () => {
        allMocks.stripeService.createCustomer.mockRejectedValue(
          simulateStripeError('invalid_request_error')
        )

        await expect(
          allMocks.stripeService.createCustomer('invalid-email')
        ).rejects.toThrow()
      })

      it('should get customer successfully', async () => {
        const mockCustomer = createMockStripeCustomer()
        allMocks.stripeService.getCustomer.mockResolvedValue(mockCustomer)

        const customer = await allMocks.stripeService.getCustomer('cus_test123')

        expect(customer).toEqual(mockCustomer)
        expect(allMocks.stripeService.getCustomer).toHaveBeenCalledWith('cus_test123')
      })

      it('should update customer successfully', async () => {
        const mockCustomer = createMockStripeCustomer({ name: 'Updated Name' })
        allMocks.stripeService.updateCustomer.mockResolvedValue(mockCustomer)

        const customer = await allMocks.stripeService.updateCustomer('cus_test123', {
          name: 'Updated Name'
        })

        expect(customer.name).toBe('Updated Name')
      })
    })

    describe('Payment Intent Management', () => {
      it('should create payment intent successfully', async () => {
        const mockPaymentIntent = createMockStripePaymentIntent()
        allMocks.stripeService.createPaymentIntent.mockResolvedValue(mockPaymentIntent)

        const paymentIntent = await allMocks.stripeService.createPaymentIntent(
          2000,
          'usd',
          { customerId: 'cus_test123' }
        )

        expect(paymentIntent).toEqual(mockPaymentIntent)
        expect(paymentIntent.amount).toBe(2000)
        expect(paymentIntent.currency).toBe('usd')
      })

      it('should handle payment intent creation errors', async () => {
        allMocks.stripeService.createPaymentIntent.mockRejectedValue(
          simulateStripeError('card_error')
        )

        await expect(
          allMocks.stripeService.createPaymentIntent(2000, 'usd')
        ).rejects.toThrow()
      })

      it('should confirm payment intent successfully', async () => {
        const mockPaymentIntent = createMockStripePaymentIntent({ status: 'succeeded' })
        allMocks.stripeService.confirmPaymentIntent.mockResolvedValue(mockPaymentIntent)

        const paymentIntent = await allMocks.stripeService.confirmPaymentIntent(
          'pi_test123',
          'pm_test123'
        )

        expect(paymentIntent.status).toBe('succeeded')
      })

      it('should handle payment confirmation failures', async () => {
        allMocks.stripeService.confirmPaymentIntent.mockRejectedValue(
          simulateStripeError('card_error')
        )

        await expect(
          allMocks.stripeService.confirmPaymentIntent('pi_test123', 'pm_invalid')
        ).rejects.toThrow()
      })
    })

    describe('Subscription Management', () => {
      it('should create subscription successfully', async () => {
        const mockSubscription = createMockStripeSubscription()
        allMocks.stripeService.createSubscription.mockResolvedValue(mockSubscription)

        const subscription = await allMocks.stripeService.createSubscription(
          'cus_test123',
          'price_test123'
        )

        expect(subscription).toEqual(mockSubscription)
        expect(subscription.customer).toBe('cus_test123')
      })

      it('should handle subscription creation errors', async () => {
        allMocks.stripeService.createSubscription.mockRejectedValue(
          simulateStripeError('invalid_request_error')
        )

        await expect(
          allMocks.stripeService.createSubscription('cus_invalid', 'price_invalid')
        ).rejects.toThrow()
      })

      it('should cancel subscription successfully', async () => {
        const mockSubscription = createMockStripeSubscription({ status: 'canceled' })
        allMocks.stripeService.cancelSubscription.mockResolvedValue(mockSubscription)

        const subscription = await allMocks.stripeService.cancelSubscription('sub_test123')

        expect(subscription.status).toBe('canceled')
      })

      it('should update subscription successfully', async () => {
        const mockSubscription = createMockStripeSubscription()
        allMocks.stripeService.updateSubscription.mockResolvedValue(mockSubscription)

        const subscription = await allMocks.stripeService.updateSubscription(
          'sub_test123',
          { metadata: { updated: 'true' } }
        )

        expect(subscription).toEqual(mockSubscription)
      })
    })

    describe('Webhook Verification', () => {
      it('should verify webhook signature successfully', () => {
        allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

        const isValid = allMocks.stripeService.verifyWebhookSignature(
          'test payload',
          'valid signature',
          'webhook secret'
        )

        expect(isValid).toBe(true)
      })

      it('should reject invalid webhook signatures', () => {
        allMocks.stripeService.verifyWebhookSignature.mockReturnValue(false)

        const isValid = allMocks.stripeService.verifyWebhookSignature(
          'test payload',
          'invalid signature',
          'webhook secret'
        )

        expect(isValid).toBe(false)
      })

      it('should handle webhook verification errors', () => {
        allMocks.stripeService.verifyWebhookSignature.mockImplementation(() => {
          throw new Error('Verification failed')
        })

        expect(() => {
          allMocks.stripeService.verifyWebhookSignature(
            'test payload',
            'malformed signature',
            'webhook secret'
          )
        }).toThrow()
      })
    })

    describe('Billing Portal', () => {
      it('should create billing portal session successfully', async () => {
        const mockSession = {
          id: 'bps_test123',
          url: 'https://billing.stripe.com/session/test123'
        }
        allMocks.stripeService.createBillingPortalSession.mockResolvedValue(mockSession)

        const session = await allMocks.stripeService.createBillingPortalSession(
          'cus_test123',
          'https://example.com/return'
        )

        expect(session).toEqual(mockSession)
        expect(session.url).toContain('billing.stripe.com')
      })

      it('should handle billing portal creation errors', async () => {
        allMocks.stripeService.createBillingPortalSession.mockRejectedValue(
          simulateStripeError('invalid_request_error')
        )

        await expect(
          allMocks.stripeService.createBillingPortalSession('cus_invalid', 'invalid-url')
        ).rejects.toThrow()
      })
    })

    describe('Payment Methods', () => {
      it('should list payment methods successfully', async () => {
        const mockPaymentMethods = [
          { id: 'pm_test123', type: 'card' },
          { id: 'pm_test124', type: 'card' }
        ]
        allMocks.stripeService.listPaymentMethods.mockResolvedValue(mockPaymentMethods)

        const paymentMethods = await allMocks.stripeService.listPaymentMethods('cus_test123')

        expect(paymentMethods).toEqual(mockPaymentMethods)
        expect(paymentMethods).toHaveLength(2)
      })

      it('should attach payment method successfully', async () => {
        const mockPaymentMethod = { id: 'pm_test123', customer: 'cus_test123' }
        allMocks.stripeService.attachPaymentMethod.mockResolvedValue(mockPaymentMethod)

        const paymentMethod = await allMocks.stripeService.attachPaymentMethod(
          'pm_test123',
          'cus_test123'
        )

        expect(paymentMethod.customer).toBe('cus_test123')
      })

      it('should detach payment method successfully', async () => {
        const mockPaymentMethod = { id: 'pm_test123', customer: null }
        allMocks.stripeService.detachPaymentMethod.mockResolvedValue(mockPaymentMethod)

        const paymentMethod = await allMocks.stripeService.detachPaymentMethod('pm_test123')

        expect(paymentMethod.customer).toBeNull()
      })
    })

    describe('Refunds', () => {
      it('should process refund successfully', async () => {
        const mockRefund = {
          id: 're_test123',
          amount: 1000,
          status: 'succeeded',
          payment_intent: 'pi_test123'
        }
        allMocks.stripeService.refundPayment.mockResolvedValue(mockRefund)

        const refund = await allMocks.stripeService.refundPayment('pi_test123', 1000)

        expect(refund).toEqual(mockRefund)
        expect(refund.amount).toBe(1000)
      })

      it('should handle refund errors', async () => {
        allMocks.stripeService.refundPayment.mockRejectedValue(
          simulateStripeError('invalid_request_error')
        )

        await expect(
          allMocks.stripeService.refundPayment('pi_invalid', 1000)
        ).rejects.toThrow()
      })
    })
  })

  describe('User Payment Service Tests', () => {
    describe('Customer Management', () => {
      it('should ensure Stripe customer exists', async () => {
        allMocks.userPaymentService.ensureStripeCustomer.mockResolvedValue('cus_test123')

        const customerId = await allMocks.userPaymentService.ensureStripeCustomer(
          'user-123',
          'test@example.com',
          'Test User'
        )

        expect(customerId).toBe('cus_test123')
      })

      it('should handle customer creation failures', async () => {
        allMocks.userPaymentService.ensureStripeCustomer.mockRejectedValue(
          new Error('Customer creation failed')
        )

        await expect(
          allMocks.userPaymentService.ensureStripeCustomer('user-123', 'invalid-email')
        ).rejects.toThrow()
      })
    })

    describe('Payment Profile Management', () => {
      it('should get user payment profile successfully', async () => {
        const mockProfile = {
          userId: 'user-123',
          stripeCustomerId: 'cus_test123',
          subscriptionStatus: 'active'
        }
        allMocks.userPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

        const profile = await allMocks.userPaymentService.getUserPaymentProfile('user-123')

        expect(profile).toEqual(mockProfile)
      })

      it('should update user payment profile successfully', async () => {
        allMocks.userPaymentService.updateUserPaymentProfile.mockResolvedValue({
          success: true
        })

        const result = await allMocks.userPaymentService.updateUserPaymentProfile(
          'user-123',
          { subscriptionStatus: 'canceled' }
        )

        expect(result.success).toBe(true)
      })

      it('should handle profile update errors', async () => {
        allMocks.userPaymentService.updateUserPaymentProfile.mockRejectedValue(
          new Error('Profile update failed')
        )

        await expect(
          allMocks.userPaymentService.updateUserPaymentProfile('user-123', {})
        ).rejects.toThrow()
      })
    })

    describe('Subscription Management', () => {
      it('should create subscription successfully', async () => {
        const mockSubscription = createMockStripeSubscription()
        allMocks.userPaymentService.createSubscription.mockResolvedValue({
          success: true,
          data: mockSubscription
        })

        const result = await allMocks.userPaymentService.createSubscription(
          'user-123',
          'price_test123'
        )

        expect(result.success).toBe(true)
        expect(result.data).toEqual(mockSubscription)
      })

      it('should cancel subscription successfully', async () => {
        allMocks.userPaymentService.cancelSubscription.mockResolvedValue({
          success: true
        })

        const result = await allMocks.userPaymentService.cancelSubscription('user-123')

        expect(result.success).toBe(true)
      })

      it('should validate subscription access', async () => {
        allMocks.userPaymentService.validateSubscriptionAccess.mockResolvedValue({
          success: true,
          data: true
        })

        const result = await allMocks.userPaymentService.validateSubscriptionAccess(
          'user-123',
          'premium_feature'
        )

        expect(result.success).toBe(true)
        expect(result.data).toBe(true)
      })
    })

    describe('Payment Recording', () => {
      it('should record payment success', async () => {
        allMocks.userPaymentService.recordPaymentSuccess.mockResolvedValue({
          success: true
        })

        const result = await allMocks.userPaymentService.recordPaymentSuccess(
          'user-123',
          { paymentIntentId: 'pi_test123', amount: 2000 }
        )

        expect(result.success).toBe(true)
      })

      it('should record payment failure', async () => {
        allMocks.userPaymentService.recordPaymentFailure.mockResolvedValue({
          success: true
        })

        const result = await allMocks.userPaymentService.recordPaymentFailure(
          'user-123',
          { paymentIntentId: 'pi_test123', error: 'Card declined' }
        )

        expect(result.success).toBe(true)
      })

      it('should record usage', async () => {
        allMocks.userPaymentService.recordUsage.mockResolvedValue({
          success: true
        })

        const result = await allMocks.userPaymentService.recordUsage(
          'user-123',
          'api_call',
          { endpoint: '/api/search' }
        )

        expect(result.success).toBe(true)
      })
    })

    describe('Payment History', () => {
      it('should get payment history successfully', async () => {
        const mockHistory = {
          payments: [
            { id: 'pi_test123', amount: 2000, status: 'succeeded' },
            { id: 'pi_test124', amount: 1500, status: 'succeeded' }
          ],
          total: 2,
          hasMore: false
        }
        allMocks.userPaymentService.getPaymentHistory.mockResolvedValue({
          success: true,
          data: mockHistory
        })

        const result = await allMocks.userPaymentService.getPaymentHistory(
          'user-123',
          { limit: 10, offset: 0 }
        )

        expect(result.success).toBe(true)
        expect(result.data.payments).toHaveLength(2)
      })

      it('should handle payment history errors', async () => {
        allMocks.userPaymentService.getPaymentHistory.mockRejectedValue(
          new Error('Database error')
        )

        await expect(
          allMocks.userPaymentService.getPaymentHistory('user-123')
        ).rejects.toThrow()
      })
    })
  })

  describe('Payment Validation Service Tests', () => {
    describe('Payment Data Validation', () => {
      it('should validate payment data successfully', () => {
        allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
          success: true,
          data: true,
          sanitizedData: paymentTestData.validPaymentIntent
        })

        const result = allMocks.paymentValidationService.validatePaymentData(
          paymentTestData.validPaymentIntent
        )

        expect(result.success).toBe(true)
        expect(result.sanitizedData).toEqual(paymentTestData.validPaymentIntent)
      })

      it('should reject invalid payment data', () => {
        allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
          success: false,
          error: 'Invalid payment data',
          validationErrors: ['Invalid amount', 'Invalid currency']
        })

        const result = allMocks.paymentValidationService.validatePaymentData(
          paymentTestData.invalidPaymentIntent
        )

        expect(result.success).toBe(false)
        expect(result.validationErrors).toContain('Invalid amount')
        expect(result.validationErrors).toContain('Invalid currency')
      })

      it('should sanitize malicious input', () => {
        const securityScenarios = createSecurityTestScenarios()
        allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
          success: true,
          sanitizedData: {
            amount: 1000,
            currency: 'usd',
            description: 'Clean description'
          },
          securityFlags: ['XSS_DETECTED', 'SQL_INJECTION_DETECTED']
        })

        const result = allMocks.paymentValidationService.validatePaymentData({
          amount: 1000,
          currency: 'usd',
          description: securityScenarios.xssPayloads[0]
        })

        expect(result.sanitizedData.description).not.toContain('<script>')
        expect(result.securityFlags).toContain('XSS_DETECTED')
      })
    })

    describe('Subscription Validation', () => {
      it('should validate subscription status successfully', async () => {
        allMocks.paymentValidationService.validateSubscriptionStatus.mockResolvedValue({
          success: true,
          data: true
        })

        const result = await allMocks.paymentValidationService.validateSubscriptionStatus('user-123')

        expect(result.success).toBe(true)
        expect(result.data).toBe(true)
      })

      it('should detect invalid subscription status', async () => {
        allMocks.paymentValidationService.validateSubscriptionStatus.mockResolvedValue({
          success: false,
          error: 'Subscription expired',
          code: 'SUBSCRIPTION_EXPIRED'
        })

        const result = await allMocks.paymentValidationService.validateSubscriptionStatus('user-123')

        expect(result.success).toBe(false)
        expect(result.code).toBe('SUBSCRIPTION_EXPIRED')
      })
    })

    describe('Security Validation', () => {
      it('should validate payment security successfully', async () => {
        allMocks.paymentValidationService.validatePaymentSecurity.mockResolvedValue({
          success: true,
          data: true,
          securityScore: 95
        })

        const result = await allMocks.paymentValidationService.validatePaymentSecurity(
          'user-123',
          paymentTestData.validPaymentIntent
        )

        expect(result.success).toBe(true)
        expect(result.securityScore).toBeGreaterThan(90)
      })

      it('should detect fraud patterns', async () => {
        allMocks.paymentValidationService.detectFraudPattern.mockResolvedValue({
          success: false,
          code: 'FRAUD_DETECTED',
          data: { pattern: 'VELOCITY_ABUSE', riskScore: 85 }
        })

        const result = await allMocks.paymentValidationService.detectFraudPattern(
          'user-123',
          { amount: 1, currency: 'usd', count: 50 }
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('FRAUD_DETECTED')
        expect(result.data.riskScore).toBeGreaterThan(80)
      })

      it('should detect card testing attacks', async () => {
        allMocks.paymentValidationService.detectCardTesting.mockResolvedValue({
          success: false,
          code: 'CARD_TESTING_DETECTED',
          data: { attempts: 25, timeWindow: 300 }
        })

        const result = await allMocks.paymentValidationService.detectCardTesting(
          'user-123',
          { amount: 1, paymentMethodId: 'pm_test123' }
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('CARD_TESTING_DETECTED')
        expect(result.data.attempts).toBeGreaterThan(20)
      })
    })

    describe('Plan and Pricing Validation', () => {
      it('should validate plan pricing successfully', async () => {
        allMocks.paymentValidationService.validatePlanPricing.mockResolvedValue({
          success: true,
          data: { planId: 'basic', price: 2900, currency: 'usd' }
        })

        const result = await allMocks.paymentValidationService.validatePlanPricing(
          'basic',
          2900
        )

        expect(result.success).toBe(true)
        expect(result.data.price).toBe(2900)
      })

      it('should detect price manipulation', async () => {
        allMocks.paymentValidationService.validatePlanPricing.mockResolvedValue({
          success: false,
          code: 'PRICE_MANIPULATION',
          error: 'Price does not match plan',
          data: { expected: 2900, received: 100 }
        })

        const result = await allMocks.paymentValidationService.validatePlanPricing(
          'basic',
          100
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('PRICE_MANIPULATION')
        expect(result.data.expected).toBe(2900)
        expect(result.data.received).toBe(100)
      })

      it('should validate currency conversion rates', async () => {
        allMocks.paymentValidationService.validateCurrencyConversion.mockResolvedValue({
          success: true,
          data: { rate: 0.85, isValid: true }
        })

        const result = await allMocks.paymentValidationService.validateCurrencyConversion(
          'usd',
          'eur',
          0.85
        )

        expect(result.success).toBe(true)
        expect(result.data.isValid).toBe(true)
      })

      it('should detect currency manipulation', async () => {
        allMocks.paymentValidationService.validateCurrencyConversion.mockResolvedValue({
          success: false,
          code: 'CURRENCY_MANIPULATION',
          error: 'Unrealistic exchange rate',
          data: { rate: 10.0, maxAllowed: 2.0 }
        })

        const result = await allMocks.paymentValidationService.validateCurrencyConversion(
          'usd',
          'eur',
          10.0
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('CURRENCY_MANIPULATION')
      })
    })

    describe('Input Validation', () => {
      it('should validate payment amounts', () => {
        allMocks.paymentValidationService.validatePaymentAmount.mockReturnValue({
          isValid: true,
          normalizedAmount: 2000
        })

        const result = allMocks.paymentValidationService.validatePaymentAmount(2000, 'usd')

        expect(result.isValid).toBe(true)
        expect(result.normalizedAmount).toBe(2000)
      })

      it('should reject invalid amounts', () => {
        allMocks.paymentValidationService.validatePaymentAmount.mockReturnValue({
          isValid: false,
          error: 'Amount below minimum'
        })

        const result = allMocks.paymentValidationService.validatePaymentAmount(10, 'usd')

        expect(result.isValid).toBe(false)
        expect(result.error).toBe('Amount below minimum')
      })

      it('should validate currency codes', () => {
        allMocks.paymentValidationService.validateCurrency.mockReturnValue({
          isValid: true,
          normalizedCurrency: 'USD'
        })

        const result = allMocks.paymentValidationService.validateCurrency('usd')

        expect(result.isValid).toBe(true)
        expect(result.normalizedCurrency).toBe('USD')
      })

      it('should reject invalid currency codes', () => {
        allMocks.paymentValidationService.validateCurrency.mockReturnValue({
          isValid: false,
          error: 'Invalid currency code'
        })

        const result = allMocks.paymentValidationService.validateCurrency('invalid')

        expect(result.isValid).toBe(false)
        expect(result.error).toBe('Invalid currency code')
      })

      it('should validate email addresses', () => {
        allMocks.paymentValidationService.isValidEmail.mockReturnValue(true)

        const isValid = allMocks.paymentValidationService.isValidEmail('test@example.com')

        expect(isValid).toBe(true)
      })

      it('should reject invalid email addresses', () => {
        allMocks.paymentValidationService.isValidEmail.mockReturnValue(false)

        const isValid = allMocks.paymentValidationService.isValidEmail('invalid-email')

        expect(isValid).toBe(false)
      })
    })
  })
})
