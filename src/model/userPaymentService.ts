/**
 * User-Payment Integration Service
 * Manages user-Stripe customer relationships and payment profiles
 */

import { stripeService } from './stripeService'
import { storage } from './storage'
import { logger } from '@/utils/logger'
import { emailService } from './emailService'
import {
  UserPaymentProfile,
  PaymentStatus,
  SubscriptionTier,
  BillingAddress,
  PaymentMethodInfo,
  ServiceResponse,
  PaymentError,
  SubscriptionError,
} from '@/types/payment'
import Stripe from 'stripe'

export class UserPaymentService {
  /**
   * Create or retrieve Stripe customer for user
   */
  async ensureStripeCustomer(userId: string, email: string, name?: string): Promise<string> {
    try {
      // Check if user already has a Stripe customer ID
      const existingProfile = await this.getUserPaymentProfile(userId)
      if (existingProfile?.stripeCustomerId) {
        // Verify customer still exists in Stripe
        const customer = await stripeService.getCustomer(existingProfile.stripeCustomerId)
        if (customer) {
          return existingProfile.stripeCustomerId
        }
      }

      // Create new Stripe customer
      const customer = await stripeService.createCustomer(email, name, {
        userId,
        createdBy: 'business_scraper_app',
      })

      // Store customer ID in user profile
      await this.updateUserPaymentProfile(userId, {
        stripeCustomerId: customer.id,
        email,
        name,
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        updatedAt: new Date(),
      })

      logger.info('UserPaymentService', `Stripe customer created for user: ${userId}`)
      return customer.id
    } catch (error) {
      logger.error('UserPaymentService', 'Failed to ensure Stripe customer', error)
      throw new PaymentError('Failed to create or retrieve customer', 'CUSTOMER_ENSURE_FAILED')
    }
  }

  /**
   * Get user payment profile
   */
  async getUserPaymentProfile(userId: string): Promise<UserPaymentProfile | null> {
    try {
      // This would typically come from your user database
      // For now, we'll use the storage system as a placeholder
      const profile = await storage.getItem('userPaymentProfiles', userId)
      return profile as UserPaymentProfile | null
    } catch (error) {
      logger.error('UserPaymentService', `Failed to get payment profile for user: ${userId}`, error)
      return null
    }
  }

  /**
   * Update user payment profile
   */
  async updateUserPaymentProfile(
    userId: string,
    updates: Partial<UserPaymentProfile>
  ): Promise<UserPaymentProfile> {
    try {
      const existingProfile = await this.getUserPaymentProfile(userId)

      const updatedProfile: UserPaymentProfile = {
        userId,
        email: updates.email || existingProfile?.email || '',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: existingProfile?.createdAt || new Date(),
        updatedAt: new Date(),
        ...existingProfile,
        ...updates,
      }

      // Store updated profile
      await storage.setItem('userPaymentProfiles', userId, updatedProfile)

      logger.info('UserPaymentService', `Payment profile updated for user: ${userId}`)
      return updatedProfile
    } catch (error) {
      logger.error(
        'UserPaymentService',
        `Failed to update payment profile for user: ${userId}`,
        error
      )
      throw new PaymentError('Failed to update payment profile', 'PROFILE_UPDATE_FAILED')
    }
  }

  /**
   * Create subscription for user
   */
  async createSubscription(
    userId: string,
    priceId: string,
    options?: {
      trialPeriodDays?: number
      metadata?: Record<string, string>
    }
  ): Promise<ServiceResponse<Stripe.Subscription>> {
    try {
      const profile = await this.getUserPaymentProfile(userId)
      if (!profile?.stripeCustomerId) {
        throw new SubscriptionError('User does not have a Stripe customer', 'NO_STRIPE_CUSTOMER')
      }

      const subscription = await stripeService.createSubscription(
        profile.stripeCustomerId,
        priceId,
        {
          trialPeriodDays: options?.trialPeriodDays,
          metadata: {
            userId,
            ...options?.metadata,
          },
        }
      )

      // Update user profile with subscription info
      await this.updateUserPaymentProfile(userId, {
        subscriptionId: subscription.id,
        subscriptionStatus: this.mapStripeStatusToPaymentStatus(subscription.status),
        subscriptionTier: this.getSubscriptionTierFromPriceId(priceId),
      })

      // Send subscription welcome email
      const user = await this.getUserById(profile.stripeCustomerId)
      const plan = await this.getSubscriptionPlan(priceId)

      if (user && plan) {
        await emailService.sendSubscriptionWelcome(
          user.email,
          user.name || 'Valued Customer',
          {
            planName: plan.name,
            price: plan.priceCents,
            currency: plan.currency,
            interval: plan.interval,
            features: plan.features,
            nextBillingDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
          },
          user.id
        )
      }

      logger.info(
        'UserPaymentService',
        `Subscription created and welcome email sent for user: ${userId}`
      )
      return { success: true, data: subscription }
    } catch (error) {
      logger.error('UserPaymentService', `Failed to create subscription for user: ${userId}`, error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof SubscriptionError ? error.code : 'SUBSCRIPTION_CREATION_FAILED',
      }
    }
  }

  /**
   * Cancel user subscription
   */
  async cancelSubscription(
    userId: string,
    cancelAtPeriodEnd: boolean = true
  ): Promise<ServiceResponse<Stripe.Subscription>> {
    try {
      const profile = await this.getUserPaymentProfile(userId)
      if (!profile?.subscriptionId) {
        throw new SubscriptionError(
          'User does not have an active subscription',
          'NO_ACTIVE_SUBSCRIPTION'
        )
      }

      const subscription = await stripeService.cancelSubscription(
        profile.subscriptionId,
        cancelAtPeriodEnd
      )

      // Update user profile
      await this.updateUserPaymentProfile(userId, {
        subscriptionStatus: this.mapStripeStatusToPaymentStatus(subscription.status),
        cancelAtPeriodEnd: subscription.cancel_at_period_end,
      })

      // Send subscription cancellation email
      const user = await this.getUserById(profile.stripeCustomerId || '')
      const plan = await this.getSubscriptionPlan(profile.subscriptionId || '')

      if (user && plan) {
        await emailService.sendSubscriptionCancellation(
          user.email,
          user.name || 'Valued Customer',
          {
            planName: plan.name,
            endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
            reason: 'User requested cancellation',
          },
          user.id
        )
      }

      logger.info('UserPaymentService', `Subscription canceled and email sent for user: ${userId}`)
      return { success: true, data: subscription }
    } catch (error) {
      logger.error('UserPaymentService', `Failed to cancel subscription for user: ${userId}`, error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: error instanceof SubscriptionError ? error.code : 'SUBSCRIPTION_CANCELLATION_FAILED',
      }
    }
  }

  /**
   * Update user billing address
   */
  async updateBillingAddress(
    userId: string,
    billingAddress: BillingAddress
  ): Promise<ServiceResponse<UserPaymentProfile>> {
    try {
      const profile = await this.getUserPaymentProfile(userId)
      if (!profile?.stripeCustomerId) {
        throw new PaymentError('User does not have a Stripe customer', 'NO_STRIPE_CUSTOMER')
      }

      // Update Stripe customer
      await stripeService.updateCustomer(profile.stripeCustomerId, {
        address: {
          line1: billingAddress.line1,
          line2: billingAddress.line2,
          city: billingAddress.city,
          state: billingAddress.state,
          postal_code: billingAddress.postalCode,
          country: billingAddress.country,
        },
      })

      // Update local profile
      const updatedProfile = await this.updateUserPaymentProfile(userId, {
        billingAddress,
      })

      logger.info('UserPaymentService', `Billing address updated for user: ${userId}`)
      return { success: true, data: updatedProfile }
    } catch (error) {
      logger.error(
        'UserPaymentService',
        `Failed to update billing address for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'BILLING_ADDRESS_UPDATE_FAILED',
      }
    }
  }

  /**
   * Get user payment methods
   */
  async getUserPaymentMethods(userId: string): Promise<PaymentMethodInfo[]> {
    try {
      const profile = await this.getUserPaymentProfile(userId)
      if (!profile?.stripeCustomerId) {
        return []
      }

      const paymentMethods = await stripeService.listPaymentMethods(profile.stripeCustomerId)

      return paymentMethods.map(pm => ({
        id: pm.id,
        type: pm.type as any,
        card: pm.card
          ? {
              brand: pm.card.brand,
              last4: pm.card.last4,
              expMonth: pm.card.exp_month,
              expYear: pm.card.exp_year,
            }
          : undefined,
        isDefault: pm.id === profile.defaultPaymentMethodId,
        createdAt: new Date(pm.created * 1000),
      }))
    } catch (error) {
      logger.error('UserPaymentService', `Failed to get payment methods for user: ${userId}`, error)
      return []
    }
  }

  /**
   * Set default payment method
   */
  async setDefaultPaymentMethod(
    userId: string,
    paymentMethodId: string
  ): Promise<ServiceResponse<boolean>> {
    try {
      const profile = await this.getUserPaymentProfile(userId)
      if (!profile?.stripeCustomerId) {
        throw new PaymentError('User does not have a Stripe customer', 'NO_STRIPE_CUSTOMER')
      }

      // Update Stripe customer default payment method
      await stripeService.updateCustomer(profile.stripeCustomerId, {
        invoice_settings: {
          default_payment_method: paymentMethodId,
        },
      })

      // Update local profile
      await this.updateUserPaymentProfile(userId, {
        defaultPaymentMethodId: paymentMethodId,
      })

      logger.info('UserPaymentService', `Default payment method set for user: ${userId}`)
      return { success: true, data: true }
    } catch (error) {
      logger.error(
        'UserPaymentService',
        `Failed to set default payment method for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'DEFAULT_PAYMENT_METHOD_FAILED',
      }
    }
  }

  /**
   * Sync user data with Stripe
   */
  async syncWithStripe(userId: string): Promise<ServiceResponse<UserPaymentProfile>> {
    try {
      const profile = await this.getUserPaymentProfile(userId)
      if (!profile?.stripeCustomerId) {
        throw new PaymentError('User does not have a Stripe customer', 'NO_STRIPE_CUSTOMER')
      }

      // Get latest data from Stripe
      const customer = await stripeService.getCustomer(profile.stripeCustomerId)
      if (!customer) {
        throw new PaymentError('Stripe customer not found', 'STRIPE_CUSTOMER_NOT_FOUND')
      }

      let subscription: Stripe.Subscription | null = null
      if (profile.subscriptionId) {
        subscription = await stripeService.getSubscription(profile.subscriptionId)
      }

      // Update profile with Stripe data
      const updates: Partial<UserPaymentProfile> = {
        email: customer.email || profile.email,
        name: customer.name || profile.name,
      }

      if (subscription) {
        updates.subscriptionStatus = this.mapStripeStatusToPaymentStatus(subscription.status)
        updates.currentPeriodStart = new Date(subscription.current_period_start * 1000)
        updates.currentPeriodEnd = new Date(subscription.current_period_end * 1000)
        updates.cancelAtPeriodEnd = subscription.cancel_at_period_end
        updates.trialEnd = subscription.trial_end
          ? new Date(subscription.trial_end * 1000)
          : undefined
      }

      const updatedProfile = await this.updateUserPaymentProfile(userId, updates)

      logger.info('UserPaymentService', `User data synced with Stripe: ${userId}`)
      return { success: true, data: updatedProfile }
    } catch (error) {
      logger.error('UserPaymentService', `Failed to sync user data with Stripe: ${userId}`, error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'STRIPE_SYNC_FAILED',
      }
    }
  }

  /**
   * Record payment success and send confirmation email
   */
  async recordPaymentSuccess(paymentIntent: any): Promise<void> {
    try {
      // Get user information
      const user = await this.getUserById(paymentIntent.customer)
      if (!user) {
        logger.warn('UserPaymentService', `User not found for customer: ${paymentIntent.customer}`)
        return
      }

      // Send payment confirmation email
      await emailService.sendPaymentConfirmation(
        user.email,
        user.name || 'Valued Customer',
        {
          amount: paymentIntent.amount,
          currency: paymentIntent.currency,
          description: paymentIntent.description || 'Payment',
          transactionId: paymentIntent.id,
          date: new Date(),
        },
        user.id
      )

      logger.info(
        'UserPaymentService',
        `Payment success recorded and email sent for user: ${user.id}`
      )
    } catch (error) {
      logger.error('UserPaymentService', 'Failed to record payment success', error)
      throw error
    }
  }

  /**
   * Record payment failure and send notification email
   */
  async recordPaymentFailure(paymentIntent: any): Promise<void> {
    try {
      // Get user information
      const user = await this.getUserById(paymentIntent.customer)
      if (!user) {
        logger.warn('UserPaymentService', `User not found for customer: ${paymentIntent.customer}`)
        return
      }

      // Send payment failed notification
      await emailService.sendPaymentFailed(
        user.email,
        user.name || 'Valued Customer',
        {
          amount: paymentIntent.amount,
          currency: paymentIntent.currency,
          reason: paymentIntent.last_payment_error?.message || 'Payment failed',
        },
        user.id
      )

      logger.info(
        'UserPaymentService',
        `Payment failure recorded and email sent for user: ${user.id}`
      )
    } catch (error) {
      logger.error('UserPaymentService', 'Failed to record payment failure', error)
      throw error
    }
  }

  /**
   * Send invoice notification
   */
  async sendInvoiceNotification(
    userId: string,
    invoiceDetails: {
      invoiceNumber: string
      amount: number
      currency: string
      dueDate: Date
      downloadUrl: string
    }
  ): Promise<void> {
    try {
      const user = await this.getUserById(userId)
      if (!user) {
        logger.warn('UserPaymentService', `User not found for invoice notification: ${userId}`)
        return
      }

      await emailService.sendInvoiceNotification(
        user.email,
        user.name || 'Valued Customer',
        invoiceDetails,
        user.id
      )

      logger.info('UserPaymentService', `Invoice notification sent for user: ${userId}`)
    } catch (error) {
      logger.error('UserPaymentService', 'Failed to send invoice notification', error)
      throw error
    }
  }

  /**
   * Helper method to get user by ID (placeholder implementation)
   */
  private async getUserById(
    customerId: string
  ): Promise<{ id: string; email: string; name?: string } | null> {
    try {
      // This would typically query your user database
      // For now, we'll use a placeholder implementation
      const profile = await this.getUserPaymentProfile(customerId)
      if (profile) {
        return {
          id: profile.userId,
          email: profile.email,
          name: profile.name,
        }
      }
      return null
    } catch (error) {
      logger.error('UserPaymentService', `Failed to get user by ID: ${customerId}`, error)
      return null
    }
  }

  /**
   * Helper method to map Stripe subscription status to our PaymentStatus
   */
  private mapStripeStatusToPaymentStatus(stripeStatus: Stripe.Subscription.Status): PaymentStatus {
    switch (stripeStatus) {
      case 'active':
        return 'active'
      case 'trialing':
        return 'trial'
      case 'past_due':
        return 'past_due'
      case 'canceled':
        return 'canceled'
      case 'unpaid':
        return 'unpaid'
      default:
        return 'free'
    }
  }

  /**
   * Get subscription plan details from price ID
   */
  private async getSubscriptionPlan(priceId: string): Promise<{
    name: string
    priceCents: number
    currency: string
    interval: string
    features: string[]
  } | null> {
    // This would typically query your pricing configuration
    // For now, we'll use a placeholder implementation
    const plans: Record<string, any> = {
      price_basic: {
        name: 'Basic Plan',
        priceCents: 999,
        currency: 'USD',
        interval: 'month',
        features: ['Basic scraping', 'Email support', '1,000 searches/month'],
      },
      price_professional: {
        name: 'Professional Plan',
        priceCents: 2999,
        currency: 'USD',
        interval: 'month',
        features: ['Advanced scraping', 'Priority support', '10,000 searches/month', 'API access'],
      },
      price_enterprise: {
        name: 'Enterprise Plan',
        priceCents: 9999,
        currency: 'USD',
        interval: 'month',
        features: [
          'Unlimited scraping',
          '24/7 support',
          'Unlimited searches',
          'Custom integrations',
        ],
      },
    }

    return (
      plans[priceId] || {
        name: 'Unknown Plan',
        priceCents: 0,
        currency: 'USD',
        interval: 'month',
        features: [],
      }
    )
  }

  /**
   * Get subscription tier from price ID
   */
  private getSubscriptionTierFromPriceId(priceId: string): SubscriptionTier {
    // This would typically be configured based on your pricing structure
    if (priceId.includes('basic')) return 'basic'
    if (priceId.includes('professional')) return 'professional'
    if (priceId.includes('enterprise')) return 'enterprise'
    return 'free'
  }
}

// Singleton instance
export const userPaymentService = new UserPaymentService()
