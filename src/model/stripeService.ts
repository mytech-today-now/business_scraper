/**
 * Core Stripe Service for Payment Processing
 * Provides comprehensive Stripe integration with customer management,
 * subscription handling, payment intents, and webhook verification
 */

import Stripe from 'stripe'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'
import { 
  PaymentError, 
  SubscriptionError, 
  ServiceResponse,
  PaymentTransaction,
  StripeWebhookEvent,
  WebhookProcessingResult
} from '@/types/payment'

export class StripeService {
  private stripe: Stripe
  private config = getConfig()

  constructor() {
    this.stripe = new Stripe(this.config.payments.stripeSecretKey, {
      apiVersion: '2023-10-16',
      typescript: true,
    })
  }

  // Customer Management
  async createCustomer(email: string, name?: string, metadata?: Record<string, string>): Promise<Stripe.Customer> {
    try {
      const customer = await this.stripe.customers.create({
        email,
        name,
        metadata: { 
          source: 'business_scraper_app',
          ...metadata 
        }
      })
      logger.info('StripeService', `Customer created: ${customer.id}`)
      return customer
    } catch (error) {
      logger.error('StripeService', 'Failed to create customer', error)
      throw new PaymentError(
        'Failed to create customer',
        'CUSTOMER_CREATION_FAILED',
        error as Stripe.StripeError
      )
    }
  }

  async getCustomer(customerId: string): Promise<Stripe.Customer | null> {
    try {
      const customer = await this.stripe.customers.retrieve(customerId)
      return customer as Stripe.Customer
    } catch (error) {
      logger.error('StripeService', `Failed to retrieve customer: ${customerId}`, error)
      return null
    }
  }

  async updateCustomer(
    customerId: string, 
    updates: Partial<Stripe.CustomerUpdateParams>
  ): Promise<Stripe.Customer> {
    try {
      const customer = await this.stripe.customers.update(customerId, updates)
      logger.info('StripeService', `Customer updated: ${customerId}`)
      return customer
    } catch (error) {
      logger.error('StripeService', `Failed to update customer: ${customerId}`, error)
      throw new PaymentError(
        'Failed to update customer',
        'CUSTOMER_UPDATE_FAILED',
        error as Stripe.StripeError
      )
    }
  }

  // Subscription Management
  async createSubscription(
    customerId: string,
    priceId: string,
    options?: {
      trialPeriodDays?: number
      metadata?: Record<string, string>
      prorationBehavior?: 'create_prorations' | 'none'
      paymentBehavior?: 'default_incomplete' | 'error_if_incomplete'
    }
  ): Promise<Stripe.Subscription> {
    try {
      const subscription = await this.stripe.subscriptions.create({
        customer: customerId,
        items: [{ price: priceId }],
        payment_behavior: options?.paymentBehavior || 'default_incomplete',
        payment_settings: { save_default_payment_method: 'on_subscription' },
        expand: ['latest_invoice.payment_intent'],
        trial_period_days: options?.trialPeriodDays,
        proration_behavior: options?.prorationBehavior || 'create_prorations',
        metadata: options?.metadata || {}
      })
      
      logger.info('StripeService', `Subscription created: ${subscription.id}`)
      return subscription
    } catch (error) {
      logger.error('StripeService', 'Failed to create subscription', error)
      throw new SubscriptionError(
        'Failed to create subscription',
        'SUBSCRIPTION_CREATION_FAILED'
      )
    }
  }

  async getSubscription(subscriptionId: string): Promise<Stripe.Subscription | null> {
    try {
      const subscription = await this.stripe.subscriptions.retrieve(subscriptionId, {
        expand: ['latest_invoice', 'customer', 'default_payment_method']
      })
      return subscription
    } catch (error) {
      logger.error('StripeService', `Failed to retrieve subscription: ${subscriptionId}`, error)
      return null
    }
  }

  async updateSubscription(
    subscriptionId: string,
    updates: Partial<Stripe.SubscriptionUpdateParams>
  ): Promise<Stripe.Subscription> {
    try {
      const subscription = await this.stripe.subscriptions.update(subscriptionId, updates)
      logger.info('StripeService', `Subscription updated: ${subscriptionId}`)
      return subscription
    } catch (error) {
      logger.error('StripeService', `Failed to update subscription: ${subscriptionId}`, error)
      throw new SubscriptionError(
        'Failed to update subscription',
        'SUBSCRIPTION_UPDATE_FAILED',
        subscriptionId
      )
    }
  }

  async cancelSubscription(
    subscriptionId: string,
    cancelAtPeriodEnd: boolean = true
  ): Promise<Stripe.Subscription> {
    try {
      const subscription = await this.stripe.subscriptions.update(subscriptionId, {
        cancel_at_period_end: cancelAtPeriodEnd
      })
      
      if (!cancelAtPeriodEnd) {
        await this.stripe.subscriptions.cancel(subscriptionId)
      }
      
      logger.info('StripeService', `Subscription canceled: ${subscriptionId}`)
      return subscription
    } catch (error) {
      logger.error('StripeService', `Failed to cancel subscription: ${subscriptionId}`, error)
      throw new SubscriptionError(
        'Failed to cancel subscription',
        'SUBSCRIPTION_CANCELLATION_FAILED',
        subscriptionId
      )
    }
  }

  // Payment Intent Management
  async createPaymentIntent(
    amount: number,
    currency: string = 'usd',
    options?: {
      customerId?: string
      metadata?: Record<string, string>
      description?: string
      setupFutureUsage?: 'on_session' | 'off_session'
    }
  ): Promise<Stripe.PaymentIntent> {
    try {
      const paymentIntent = await this.stripe.paymentIntents.create({
        amount,
        currency,
        customer: options?.customerId,
        automatic_payment_methods: { enabled: true },
        metadata: options?.metadata || {},
        description: options?.description,
        setup_future_usage: options?.setupFutureUsage
      })
      
      logger.info('StripeService', `Payment intent created: ${paymentIntent.id}`)
      return paymentIntent
    } catch (error) {
      logger.error('StripeService', 'Failed to create payment intent', error)
      throw new PaymentError(
        'Failed to create payment intent',
        'PAYMENT_INTENT_CREATION_FAILED',
        error as Stripe.StripeError
      )
    }
  }

  async confirmPaymentIntent(
    paymentIntentId: string,
    paymentMethodId?: string
  ): Promise<Stripe.PaymentIntent> {
    try {
      const paymentIntent = await this.stripe.paymentIntents.confirm(paymentIntentId, {
        payment_method: paymentMethodId
      })
      
      logger.info('StripeService', `Payment intent confirmed: ${paymentIntentId}`)
      return paymentIntent
    } catch (error) {
      logger.error('StripeService', `Failed to confirm payment intent: ${paymentIntentId}`, error)
      throw new PaymentError(
        'Failed to confirm payment intent',
        'PAYMENT_INTENT_CONFIRMATION_FAILED',
        error as Stripe.StripeError
      )
    }
  }

  // Payment Method Management
  async attachPaymentMethod(
    paymentMethodId: string,
    customerId: string
  ): Promise<Stripe.PaymentMethod> {
    try {
      const paymentMethod = await this.stripe.paymentMethods.attach(paymentMethodId, {
        customer: customerId
      })
      
      logger.info('StripeService', `Payment method attached: ${paymentMethodId}`)
      return paymentMethod
    } catch (error) {
      logger.error('StripeService', `Failed to attach payment method: ${paymentMethodId}`, error)
      throw new PaymentError(
        'Failed to attach payment method',
        'PAYMENT_METHOD_ATTACH_FAILED',
        error as Stripe.StripeError
      )
    }
  }

  async detachPaymentMethod(paymentMethodId: string): Promise<Stripe.PaymentMethod> {
    try {
      const paymentMethod = await this.stripe.paymentMethods.detach(paymentMethodId)
      logger.info('StripeService', `Payment method detached: ${paymentMethodId}`)
      return paymentMethod
    } catch (error) {
      logger.error('StripeService', `Failed to detach payment method: ${paymentMethodId}`, error)
      throw new PaymentError(
        'Failed to detach payment method',
        'PAYMENT_METHOD_DETACH_FAILED',
        error as Stripe.StripeError
      )
    }
  }

  async listPaymentMethods(customerId: string, type: string = 'card'): Promise<Stripe.PaymentMethod[]> {
    try {
      const paymentMethods = await this.stripe.paymentMethods.list({
        customer: customerId,
        type: type as Stripe.PaymentMethodListParams.Type
      })
      return paymentMethods.data
    } catch (error) {
      logger.error('StripeService', `Failed to list payment methods for customer: ${customerId}`, error)
      return []
    }
  }

  // Invoice Management
  async getInvoice(invoiceId: string): Promise<Stripe.Invoice | null> {
    try {
      const invoice = await this.stripe.invoices.retrieve(invoiceId)
      return invoice
    } catch (error) {
      logger.error('StripeService', `Failed to retrieve invoice: ${invoiceId}`, error)
      return null
    }
  }

  async listInvoices(customerId: string, limit: number = 10): Promise<Stripe.Invoice[]> {
    try {
      const invoices = await this.stripe.invoices.list({
        customer: customerId,
        limit
      })
      return invoices.data
    } catch (error) {
      logger.error('StripeService', `Failed to list invoices for customer: ${customerId}`, error)
      return []
    }
  }

  // Webhook Management
  verifyWebhookSignature(payload: string, signature: string): Stripe.Event {
    try {
      return this.stripe.webhooks.constructEvent(
        payload,
        signature,
        this.config.payments.stripeWebhookSecret
      )
    } catch (error) {
      logger.error('StripeService', 'Webhook signature verification failed', error)
      throw new PaymentError(
        'Webhook signature verification failed',
        'WEBHOOK_VERIFICATION_FAILED',
        error as Stripe.StripeError
      )
    }
  }

  // Utility Methods
  async getCustomerByEmail(email: string): Promise<Stripe.Customer | null> {
    try {
      const customers = await this.stripe.customers.list({
        email,
        limit: 1
      })
      return customers.data.length > 0 ? customers.data[0] : null
    } catch (error) {
      logger.error('StripeService', `Failed to find customer by email: ${email}`, error)
      return null
    }
  }

  formatAmount(amount: number, currency: string = 'usd'): string {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase()
    }).format(amount / 100)
  }
}

// Singleton instance
export const stripeService = new StripeService()
