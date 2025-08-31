/**
 * @jest-environment jsdom
 */

import { StripeService, stripeService } from '@/model/stripeService'
import { PaymentError, SubscriptionError } from '@/types/payment'
import Stripe from 'stripe'

// Mock Stripe
jest.mock('stripe')
const MockedStripe = Stripe as jest.MockedClass<typeof Stripe>

// Mock config
jest.mock('@/lib/config', () => ({
  getConfig: () => ({
    payments: {
      stripeSecretKey: 'sk_test_mock_key',
      stripeWebhookSecret: 'whsec_mock_secret',
    },
  }),
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}))

describe('StripeService', () => {
  let mockStripe: jest.Mocked<Stripe>
  let service: StripeService

  beforeEach(() => {
    jest.clearAllMocks()

    // Create mock Stripe instance
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
      },
      paymentIntents: {
        create: jest.fn(),
        confirm: jest.fn(),
      },
      paymentMethods: {
        attach: jest.fn(),
        detach: jest.fn(),
        list: jest.fn(),
      },
      invoices: {
        retrieve: jest.fn(),
        list: jest.fn(),
      },
      webhooks: {
        constructEvent: jest.fn(),
      },
    } as any

    MockedStripe.mockImplementation(() => mockStripe)
    service = new StripeService()
  })

  describe('Customer Management', () => {
    it('should create a customer successfully', async () => {
      const mockCustomer = {
        id: 'cus_test123',
        email: 'test@example.com',
        name: 'Test User',
      } as Stripe.Customer

      mockStripe.customers.create.mockResolvedValue(mockCustomer)

      const result = await service.createCustomer('test@example.com', 'Test User')

      expect(result).toEqual(mockCustomer)
      expect(mockStripe.customers.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        name: 'Test User',
        metadata: {
          source: 'business_scraper_app',
        },
      })
    })

    it('should handle customer creation failure', async () => {
      const error = new Error('Stripe error')
      mockStripe.customers.create.mockRejectedValue(error)

      await expect(service.createCustomer('test@example.com')).rejects.toThrow(PaymentError)
    })

    it('should retrieve a customer successfully', async () => {
      const mockCustomer = {
        id: 'cus_test123',
        email: 'test@example.com',
      } as Stripe.Customer

      mockStripe.customers.retrieve.mockResolvedValue(mockCustomer)

      const result = await service.getCustomer('cus_test123')

      expect(result).toEqual(mockCustomer)
      expect(mockStripe.customers.retrieve).toHaveBeenCalledWith('cus_test123')
    })

    it('should return null when customer retrieval fails', async () => {
      mockStripe.customers.retrieve.mockRejectedValue(new Error('Not found'))

      const result = await service.getCustomer('cus_invalid')

      expect(result).toBeNull()
    })

    it('should update a customer successfully', async () => {
      const mockCustomer = {
        id: 'cus_test123',
        email: 'updated@example.com',
      } as Stripe.Customer

      mockStripe.customers.update.mockResolvedValue(mockCustomer)

      const result = await service.updateCustomer('cus_test123', { email: 'updated@example.com' })

      expect(result).toEqual(mockCustomer)
      expect(mockStripe.customers.update).toHaveBeenCalledWith('cus_test123', {
        email: 'updated@example.com',
      })
    })
  })

  describe('Subscription Management', () => {
    it('should create a subscription successfully', async () => {
      const mockSubscription = {
        id: 'sub_test123',
        customer: 'cus_test123',
        status: 'active',
      } as Stripe.Subscription

      mockStripe.subscriptions.create.mockResolvedValue(mockSubscription)

      const result = await service.createSubscription('cus_test123', 'price_test123')

      expect(result).toEqual(mockSubscription)
      expect(mockStripe.subscriptions.create).toHaveBeenCalledWith({
        customer: 'cus_test123',
        items: [{ price: 'price_test123' }],
        payment_behavior: 'default_incomplete',
        payment_settings: { save_default_payment_method: 'on_subscription' },
        expand: ['latest_invoice.payment_intent'],
        trial_period_days: undefined,
        proration_behavior: 'create_prorations',
        metadata: {},
      })
    })

    it('should handle subscription creation failure', async () => {
      mockStripe.subscriptions.create.mockRejectedValue(new Error('Stripe error'))

      await expect(service.createSubscription('cus_test123', 'price_test123')).rejects.toThrow(
        SubscriptionError
      )
    })

    it('should retrieve a subscription successfully', async () => {
      const mockSubscription = {
        id: 'sub_test123',
        status: 'active',
      } as Stripe.Subscription

      mockStripe.subscriptions.retrieve.mockResolvedValue(mockSubscription)

      const result = await service.getSubscription('sub_test123')

      expect(result).toEqual(mockSubscription)
      expect(mockStripe.subscriptions.retrieve).toHaveBeenCalledWith('sub_test123', {
        expand: ['latest_invoice', 'customer', 'default_payment_method'],
      })
    })

    it('should cancel a subscription successfully', async () => {
      const mockSubscription = {
        id: 'sub_test123',
        cancel_at_period_end: true,
      } as Stripe.Subscription

      mockStripe.subscriptions.update.mockResolvedValue(mockSubscription)

      const result = await service.cancelSubscription('sub_test123', true)

      expect(result).toEqual(mockSubscription)
      expect(mockStripe.subscriptions.update).toHaveBeenCalledWith('sub_test123', {
        cancel_at_period_end: true,
      })
    })
  })

  describe('Payment Intent Management', () => {
    it('should create a payment intent successfully', async () => {
      const mockPaymentIntent = {
        id: 'pi_test123',
        amount: 2000,
        currency: 'usd',
      } as Stripe.PaymentIntent

      mockStripe.paymentIntents.create.mockResolvedValue(mockPaymentIntent)

      const result = await service.createPaymentIntent(2000, 'usd')

      expect(result).toEqual(mockPaymentIntent)
      expect(mockStripe.paymentIntents.create).toHaveBeenCalledWith({
        amount: 2000,
        currency: 'usd',
        customer: undefined,
        automatic_payment_methods: { enabled: true },
        metadata: {},
        description: undefined,
        setup_future_usage: undefined,
      })
    })

    it('should confirm a payment intent successfully', async () => {
      const mockPaymentIntent = {
        id: 'pi_test123',
        status: 'succeeded',
      } as Stripe.PaymentIntent

      mockStripe.paymentIntents.confirm.mockResolvedValue(mockPaymentIntent)

      const result = await service.confirmPaymentIntent('pi_test123', 'pm_test123')

      expect(result).toEqual(mockPaymentIntent)
      expect(mockStripe.paymentIntents.confirm).toHaveBeenCalledWith('pi_test123', {
        payment_method: 'pm_test123',
      })
    })
  })

  describe('Payment Method Management', () => {
    it('should attach a payment method successfully', async () => {
      const mockPaymentMethod = {
        id: 'pm_test123',
        customer: 'cus_test123',
      } as Stripe.PaymentMethod

      mockStripe.paymentMethods.attach.mockResolvedValue(mockPaymentMethod)

      const result = await service.attachPaymentMethod('pm_test123', 'cus_test123')

      expect(result).toEqual(mockPaymentMethod)
      expect(mockStripe.paymentMethods.attach).toHaveBeenCalledWith('pm_test123', {
        customer: 'cus_test123',
      })
    })

    it('should list payment methods successfully', async () => {
      const mockPaymentMethods = {
        data: [
          { id: 'pm_test123', type: 'card' },
          { id: 'pm_test456', type: 'card' },
        ],
      } as Stripe.ApiList<Stripe.PaymentMethod>

      mockStripe.paymentMethods.list.mockResolvedValue(mockPaymentMethods)

      const result = await service.listPaymentMethods('cus_test123')

      expect(result).toEqual(mockPaymentMethods.data)
      expect(mockStripe.paymentMethods.list).toHaveBeenCalledWith({
        customer: 'cus_test123',
        type: 'card',
      })
    })
  })

  describe('Webhook Management', () => {
    it('should verify webhook signature successfully', () => {
      const mockEvent = {
        id: 'evt_test123',
        type: 'customer.created',
      } as Stripe.Event

      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent)

      const result = service.verifyWebhookSignature('payload', 'signature')

      expect(result).toEqual(mockEvent)
      expect(mockStripe.webhooks.constructEvent).toHaveBeenCalledWith(
        'payload',
        'signature',
        'whsec_mock_secret'
      )
    })

    it('should handle webhook verification failure', () => {
      mockStripe.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('Invalid signature')
      })

      expect(() => service.verifyWebhookSignature('payload', 'invalid')).toThrow(PaymentError)
    })
  })

  describe('Utility Methods', () => {
    it('should find customer by email successfully', async () => {
      const mockCustomers = {
        data: [{ id: 'cus_test123', email: 'test@example.com' }],
      } as Stripe.ApiList<Stripe.Customer>

      mockStripe.customers.list.mockResolvedValue(mockCustomers)

      const result = await service.getCustomerByEmail('test@example.com')

      expect(result).toEqual(mockCustomers.data[0])
      expect(mockStripe.customers.list).toHaveBeenCalledWith({
        email: 'test@example.com',
        limit: 1,
      })
    })

    it('should format amount correctly', () => {
      const result = service.formatAmount(2000, 'usd')
      expect(result).toBe('$20.00')
    })
  })
})
