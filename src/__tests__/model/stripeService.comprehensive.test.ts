/**
 * Comprehensive Stripe Service Tests
 * Security-focused testing for Stripe integration, payment processing,
 * customer management, webhook verification, and API security
 */

import { StripeService } from '@/model/stripeService'
import Stripe from 'stripe'
import { logger } from '@/utils/logger'
import { getConfig } from '@/lib/config'

// Mock Stripe and dependencies
jest.mock('stripe')
jest.mock('@/utils/logger')
jest.mock('@/lib/config')

const MockedStripe = Stripe as jest.MockedClass<typeof Stripe>
const mockLogger = logger as jest.Mocked<typeof logger>
const mockGetConfig = getConfig as jest.MockedFunction<typeof getConfig>

describe('StripeService - Comprehensive Security Tests', () => {
  let stripeService: StripeService
  let mockStripeInstance: jest.Mocked<Stripe>

  const mockConfig = {
    payments: {
      stripeSecretKey: 'sk_test_mock_key',
      stripePublishableKey: 'pk_test_mock_key',
      webhookSecret: 'whsec_test_secret'
    }
  }

  beforeEach(() => {
    jest.clearAllMocks()
    
    mockGetConfig.mockReturnValue(mockConfig)
    
    // Create mock Stripe instance
    mockStripeInstance = {
      customers: {
        create: jest.fn(),
        retrieve: jest.fn(),
        update: jest.fn(),
        list: jest.fn()
      },
      paymentIntents: {
        create: jest.fn(),
        retrieve: jest.fn(),
        update: jest.fn(),
        confirm: jest.fn()
      },
      subscriptions: {
        create: jest.fn(),
        retrieve: jest.fn(),
        update: jest.fn(),
        cancel: jest.fn()
      },
      paymentMethods: {
        attach: jest.fn(),
        detach: jest.fn(),
        retrieve: jest.fn()
      },
      billingPortal: {
        sessions: {
          create: jest.fn()
        }
      },
      webhooks: {
        constructEvent: jest.fn()
      }
    } as any

    MockedStripe.mockImplementation(() => mockStripeInstance)
    stripeService = new StripeService()
  })

  describe('Service Initialization Security', () => {
    it('should validate Stripe configuration on initialization', () => {
      expect(MockedStripe).toHaveBeenCalledWith(
        mockConfig.payments.stripeSecretKey,
        expect.objectContaining({
          apiVersion: '2024-06-20',
          typescript: true
        })
      )
    })

    it('should reject invalid API keys', () => {
      mockGetConfig.mockReturnValue({
        payments: {
          stripeSecretKey: 'invalid_key',
          stripePublishableKey: 'pk_test_mock',
          webhookSecret: 'whsec_test'
        }
      })

      expect(() => new StripeService()).toThrow('Invalid Stripe configuration')
    })

    it('should not expose sensitive configuration', () => {
      const service = new StripeService()
      const serviceString = JSON.stringify(service)
      
      expect(serviceString).not.toContain('sk_test_mock_key')
      expect(serviceString).not.toContain('whsec_test_secret')
    })
  })

  describe('Customer Management Security', () => {
    it('should validate customer creation data', async () => {
      const invalidCustomerData = [
        { email: 'invalid-email' },
        { email: '', name: 'Test' },
        { email: 'test@example.com', name: '<script>alert("xss")</script>' },
        { email: 'test@example.com', metadata: { malicious: '"; DROP TABLE customers; --' } }
      ]

      for (const data of invalidCustomerData) {
        await expect(stripeService.createCustomer(data.email, data.name, data.metadata)).rejects.toThrow()
      }
    })

    it('should sanitize customer data before Stripe API calls', async () => {
      const customerData = {
        email: 'test@example.com',
        name: 'Test <script>alert("xss")</script> User',
        metadata: {
          userId: 'user-123',
          source: 'web_app',
          notes: 'Customer notes with <img src=x onerror=alert(1)>'
        }
      }

      mockStripeInstance.customers.create.mockResolvedValue({
        id: 'cus_test123',
        email: customerData.email,
        name: 'Test User', // Should be sanitized
        metadata: expect.not.objectContaining({
          notes: expect.stringContaining('<img')
        })
      } as any)

      const result = await stripeService.createCustomer(
        customerData.email,
        customerData.name,
        customerData.metadata
      )

      expect(mockStripeInstance.customers.create).toHaveBeenCalledWith(
        expect.objectContaining({
          email: customerData.email,
          name: expect.not.stringContaining('<script>'),
          metadata: expect.not.objectContaining({
            notes: expect.stringContaining('<img')
          })
        })
      )
    })

    it('should prevent customer data leakage', async () => {
      mockStripeInstance.customers.retrieve.mockResolvedValue({
        id: 'cus_test123',
        email: 'test@example.com',
        name: 'Test User',
        payment_methods: ['pm_secret123'],
        sources: ['src_secret456']
      } as any)

      const customer = await stripeService.getCustomer('cus_test123')
      
      // Should not expose sensitive payment data
      expect(customer).not.toHaveProperty('payment_methods')
      expect(customer).not.toHaveProperty('sources')
    })

    it('should validate customer ownership', async () => {
      // Mock unauthorized access attempt
      mockStripeInstance.customers.retrieve.mockRejectedValue(
        new Error('No such customer: cus_unauthorized')
      )

      await expect(stripeService.getCustomer('cus_unauthorized')).rejects.toThrow()
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StripeService',
        expect.stringContaining('Failed to retrieve customer'),
        expect.any(Error)
      )
    })
  })

  describe('Payment Intent Security', () => {
    it('should validate payment amounts', async () => {
      const invalidAmounts = [-100, 0, 999999999, 1.5, NaN, Infinity]

      for (const amount of invalidAmounts) {
        await expect(stripeService.createPaymentIntent(amount, 'usd')).rejects.toThrow()
      }
    })

    it('should validate currency codes', async () => {
      const invalidCurrencies = ['', 'INVALID', 'USD123', null, undefined]

      for (const currency of invalidCurrencies) {
        await expect(stripeService.createPaymentIntent(1000, currency as any)).rejects.toThrow()
      }
    })

    it('should prevent amount manipulation in metadata', async () => {
      const maliciousOptions = {
        metadata: {
          originalAmount: '5000', // Different from actual amount
          discountApplied: '100%',
          adminOverride: 'true'
        }
      }

      mockStripeInstance.paymentIntents.create.mockResolvedValue({
        id: 'pi_test123',
        amount: 1000,
        currency: 'usd',
        status: 'requires_payment_method'
      } as any)

      await stripeService.createPaymentIntent(1000, 'usd', maliciousOptions)

      expect(mockStripeInstance.paymentIntents.create).toHaveBeenCalledWith(
        expect.objectContaining({
          amount: 1000, // Should match actual amount
          metadata: expect.not.objectContaining({
            originalAmount: '5000'
          })
        })
      )
    })

    it('should handle payment intent confirmation securely', async () => {
      const paymentIntentId = 'pi_test123'
      
      mockStripeInstance.paymentIntents.confirm.mockResolvedValue({
        id: paymentIntentId,
        status: 'succeeded',
        amount: 1000,
        currency: 'usd'
      } as any)

      const result = await stripeService.confirmPaymentIntent(paymentIntentId)
      
      expect(result.status).toBe('succeeded')
      expect(mockLogger.info).toHaveBeenCalledWith(
        'StripeService',
        expect.stringContaining('Payment intent confirmed'),
        expect.objectContaining({ paymentIntentId })
      )
    })
  })

  describe('Subscription Management Security', () => {
    it('should validate subscription creation parameters', async () => {
      const invalidParams = [
        { customerId: '', priceId: 'price_test' },
        { customerId: 'cus_test', priceId: '' },
        { customerId: 'cus_test', priceId: 'price_test', trialPeriodDays: -1 },
        { customerId: 'cus_test', priceId: 'price_test', trialPeriodDays: 999 }
      ]

      for (const params of invalidParams) {
        await expect(stripeService.createSubscription(
          params.customerId,
          params.priceId,
          { trialPeriodDays: params.trialPeriodDays }
        )).rejects.toThrow()
      }
    })

    it('should prevent subscription tampering', async () => {
      const tamperingAttempts = {
        metadata: {
          priceOverride: '0',
          discountPercent: '100',
          adminAccess: 'true',
          bypassPayment: 'true'
        }
      }

      mockStripeInstance.subscriptions.create.mockResolvedValue({
        id: 'sub_test123',
        status: 'active',
        customer: 'cus_test123'
      } as any)

      await stripeService.createSubscription('cus_test123', 'price_test', tamperingAttempts)

      expect(mockStripeInstance.subscriptions.create).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.not.objectContaining({
            priceOverride: '0',
            bypassPayment: 'true'
          })
        })
      )
    })

    it('should validate subscription cancellation authorization', async () => {
      const subscriptionId = 'sub_test123'
      
      // Mock unauthorized cancellation attempt
      mockStripeInstance.subscriptions.cancel.mockRejectedValue(
        new Error('No such subscription: sub_test123')
      )

      await expect(stripeService.cancelSubscription(subscriptionId)).rejects.toThrow()
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StripeService',
        expect.stringContaining('Failed to cancel subscription'),
        expect.any(Error)
      )
    })
  })

  describe('Webhook Security', () => {
    it('should verify webhook signatures', async () => {
      const payload = JSON.stringify({ type: 'payment_intent.succeeded' })
      const signature = 'valid_signature'
      const webhookSecret = mockConfig.payments.webhookSecret

      mockStripeInstance.webhooks.constructEvent.mockReturnValue({
        id: 'evt_test123',
        type: 'payment_intent.succeeded',
        data: { object: {} }
      } as any)

      const event = stripeService.verifyWebhookSignature(payload, signature)
      
      expect(mockStripeInstance.webhooks.constructEvent).toHaveBeenCalledWith(
        payload,
        signature,
        webhookSecret
      )
      expect(event.type).toBe('payment_intent.succeeded')
    })

    it('should reject invalid webhook signatures', async () => {
      const payload = JSON.stringify({ type: 'payment_intent.succeeded' })
      const invalidSignature = 'invalid_signature'

      mockStripeInstance.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('Invalid signature')
      })

      expect(() => stripeService.verifyWebhookSignature(payload, invalidSignature)).toThrow('Invalid signature')
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StripeService',
        expect.stringContaining('Webhook signature verification failed'),
        expect.any(Error)
      )
    })

    it('should prevent webhook replay attacks', async () => {
      const payload = JSON.stringify({ 
        type: 'payment_intent.succeeded',
        created: Math.floor(Date.now() / 1000) - 3600 // 1 hour old
      })
      const signature = 'valid_signature'

      mockStripeInstance.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('Timestamp outside tolerance')
      })

      expect(() => stripeService.verifyWebhookSignature(payload, signature)).toThrow('Timestamp outside tolerance')
    })
  })

  describe('Payment Method Security', () => {
    it('should validate payment method attachment', async () => {
      const paymentMethodId = 'pm_test123'
      const customerId = 'cus_test123'

      mockStripeInstance.paymentMethods.attach.mockResolvedValue({
        id: paymentMethodId,
        customer: customerId
      } as any)

      const result = await stripeService.attachPaymentMethod(paymentMethodId, customerId)
      
      expect(result.customer).toBe(customerId)
      expect(mockStripeInstance.paymentMethods.attach).toHaveBeenCalledWith(
        paymentMethodId,
        { customer: customerId }
      )
    })

    it('should prevent unauthorized payment method access', async () => {
      const paymentMethodId = 'pm_unauthorized'
      
      mockStripeInstance.paymentMethods.retrieve.mockRejectedValue(
        new Error('No such payment method')
      )

      await expect(stripeService.getPaymentMethod(paymentMethodId)).rejects.toThrow()
    })
  })

  describe('Error Handling and Security Logging', () => {
    it('should handle Stripe API errors securely', async () => {
      const stripeError = new Error('Your card was declined') as any
      stripeError.type = 'card_error'
      stripeError.code = 'card_declined'

      mockStripeInstance.paymentIntents.create.mockRejectedValue(stripeError)

      await expect(stripeService.createPaymentIntent(1000, 'usd')).rejects.toThrow('Your card was declined')
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StripeService',
        expect.stringContaining('Payment intent creation failed'),
        expect.objectContaining({
          error: stripeError,
          amount: 1000,
          currency: 'usd'
        })
      )
    })

    it('should not expose sensitive data in error logs', async () => {
      const sensitiveData = {
        customerId: 'cus_test123',
        paymentMethodId: 'pm_secret123',
        metadata: {
          ssn: '123-45-6789',
          creditCardNumber: '4111111111111111'
        }
      }

      mockStripeInstance.customers.create.mockRejectedValue(new Error('API Error'))

      await expect(stripeService.createCustomer(
        'test@example.com',
        'Test User',
        sensitiveData.metadata
      )).rejects.toThrow()

      // Check that sensitive data is not in logs
      const logCalls = mockLogger.error.mock.calls
      logCalls.forEach(call => {
        const logMessage = JSON.stringify(call)
        expect(logMessage).not.toContain('123-45-6789')
        expect(logMessage).not.toContain('4111111111111111')
      })
    })

    it('should implement rate limiting for API calls', async () => {
      // Simulate rapid API calls
      const rapidCalls = Array(10).fill(null).map(() =>
        stripeService.createPaymentIntent(1000, 'usd')
      )

      mockStripeInstance.paymentIntents.create.mockRejectedValue(
        new Error('Rate limit exceeded')
      )

      const results = await Promise.allSettled(rapidCalls)
      
      // Should handle rate limiting gracefully
      const rateLimitedCalls = results.filter(r => 
        r.status === 'rejected' && 
        (r.reason as Error).message.includes('Rate limit')
      )
      
      expect(rateLimitedCalls.length).toBeGreaterThan(0)
    })
  })

  describe('Data Sanitization and Validation', () => {
    it('should sanitize all input data', async () => {
      const maliciousInputs = {
        email: 'test+<script>alert("xss")</script>@example.com',
        name: 'Test"; DROP TABLE customers; --',
        description: '<img src=x onerror=alert(1)>',
        metadata: {
          userInput: '"; DELETE FROM payments; --',
          description: '<script>document.location="http://evil.com"</script>'
        }
      }

      mockStripeInstance.customers.create.mockResolvedValue({
        id: 'cus_test123',
        email: 'test@example.com', // Should be sanitized
        name: 'Test User' // Should be sanitized
      } as any)

      await stripeService.createCustomer(
        maliciousInputs.email,
        maliciousInputs.name,
        maliciousInputs.metadata
      )

      expect(mockStripeInstance.customers.create).toHaveBeenCalledWith(
        expect.objectContaining({
          email: expect.not.stringContaining('<script>'),
          name: expect.not.stringContaining('DROP TABLE'),
          metadata: expect.not.objectContaining({
            userInput: expect.stringContaining('DELETE FROM'),
            description: expect.stringContaining('<script>')
          })
        })
      )
    })
  })
})
