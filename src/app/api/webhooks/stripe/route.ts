/**
 * Stripe Webhook Handler API Endpoint
 * Processes Stripe webhooks with comprehensive event handling and error management
 */

import { NextRequest, NextResponse } from 'next/server'
import { stripeService } from '@/model/stripeService'
import { userPaymentService } from '@/model/userPaymentService'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'
import Stripe from 'stripe'

/**
 * Disable body parser for webhook signature verification
 */
export const runtime = 'nodejs'

/**
 * POST /api/webhooks/stripe - Process Stripe webhooks
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)

  try {
    // Get raw body for signature verification
    const body = await request.text()
    const signature = request.headers.get('stripe-signature')

    if (!signature) {
      logger.error('StripeWebhook', 'Missing stripe-signature header', { ip })
      return NextResponse.json({ error: 'Missing signature' }, { status: 400 })
    }

    // Verify webhook signature
    let event: Stripe.Event
    try {
      event = stripeService.verifyWebhookSignature(body, signature)
    } catch (error) {
      logger.error('StripeWebhook', 'Webhook signature verification failed', { error, ip })
      return NextResponse.json({ error: 'Invalid signature' }, { status: 400 })
    }

    logger.info('StripeWebhook', `Processing event: ${event.type}`, {
      eventId: event.id,
      ip,
      created: new Date(event.created * 1000).toISOString(),
    })

    // Process webhook event
    try {
      await processWebhookEvent(event)

      logger.info('StripeWebhook', `Successfully processed event: ${event.type}`, {
        eventId: event.id,
        ip,
      })

      return NextResponse.json({ received: true })
    } catch (error) {
      logger.error('StripeWebhook', `Failed to process event: ${event.type}`, {
        error,
        eventId: event.id,
        ip,
      })

      // Return 200 to prevent Stripe from retrying if it's a business logic error
      // Return 500 for actual processing errors that should be retried
      const shouldRetry = error instanceof Error && error.message.includes('retry')

      return NextResponse.json(
        {
          error: 'Webhook processing failed',
          eventId: event.id,
          shouldRetry,
        },
        { status: shouldRetry ? 500 : 200 }
      )
    }
  } catch (error) {
    logger.error('StripeWebhook', 'Webhook request processing failed', { error, ip })
    return NextResponse.json({ error: 'Webhook processing failed' }, { status: 400 })
  }
}

/**
 * Process individual webhook events
 */
async function processWebhookEvent(event: Stripe.Event): Promise<void> {
  switch (event.type) {
    // Subscription events
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
      await handleSubscriptionUpdate(event.data.object as Stripe.Subscription)
      break

    case 'customer.subscription.deleted':
      await handleSubscriptionCancellation(event.data.object as Stripe.Subscription)
      break

    // Payment intent events
    case 'payment_intent.succeeded':
      await handlePaymentSuccess(event.data.object as Stripe.PaymentIntent)
      break

    case 'payment_intent.payment_failed':
      await handlePaymentFailure(event.data.object as Stripe.PaymentIntent)
      break

    case 'payment_intent.canceled':
      await handlePaymentCancellation(event.data.object as Stripe.PaymentIntent)
      break

    // Invoice events
    case 'invoice.payment_succeeded':
      await handleInvoicePaymentSuccess(event.data.object as Stripe.Invoice)
      break

    case 'invoice.payment_failed':
      await handleInvoicePaymentFailure(event.data.object as Stripe.Invoice)
      break

    // Customer events
    case 'customer.created':
      await handleCustomerCreated(event.data.object as Stripe.Customer)
      break

    case 'customer.updated':
      await handleCustomerUpdated(event.data.object as Stripe.Customer)
      break

    case 'customer.deleted':
      await handleCustomerDeleted(event.data.object as Stripe.Customer)
      break

    // Payment method events
    case 'payment_method.attached':
      await handlePaymentMethodAttached(event.data.object as Stripe.PaymentMethod)
      break

    case 'payment_method.detached':
      await handlePaymentMethodDetached(event.data.object as Stripe.PaymentMethod)
      break

    default:
      logger.info('StripeWebhook', `Unhandled event type: ${event.type}`, {
        eventId: event.id,
      })
  }
}

/**
 * Handle subscription creation/update
 */
async function handleSubscriptionUpdate(subscription: Stripe.Subscription): Promise<void> {
  try {
    const customerId = subscription.customer as string
    const userId = await getUserIdFromCustomerId(customerId)

    if (!userId) {
      logger.warn('StripeWebhook', `No user found for customer: ${customerId}`)
      return
    }

    // Update user subscription status
    await userPaymentService.updateUserPaymentProfile(userId, {
      subscriptionId: subscription.id,
      subscriptionStatus: mapStripeStatusToPaymentStatus(subscription.status),
      currentPeriodStart: new Date(subscription.current_period_start * 1000),
      currentPeriodEnd: new Date(subscription.current_period_end * 1000),
      cancelAtPeriodEnd: subscription.cancel_at_period_end,
      trialEnd: subscription.trial_end ? new Date(subscription.trial_end * 1000) : undefined,
    })

    logger.info('StripeWebhook', `Subscription updated: ${subscription.id} for user: ${userId}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to update subscription', {
      error,
      subscriptionId: subscription.id,
    })
    throw error
  }
}

/**
 * Handle subscription cancellation
 */
async function handleSubscriptionCancellation(subscription: Stripe.Subscription): Promise<void> {
  try {
    const customerId = subscription.customer as string
    const userId = await getUserIdFromCustomerId(customerId)

    if (!userId) {
      logger.warn('StripeWebhook', `No user found for customer: ${customerId}`)
      return
    }

    // Update user subscription to canceled
    await userPaymentService.updateUserPaymentProfile(userId, {
      subscriptionStatus: 'canceled',
      cancelAtPeriodEnd: true,
    })

    logger.info('StripeWebhook', `Subscription canceled: ${subscription.id} for user: ${userId}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to cancel subscription', {
      error,
      subscriptionId: subscription.id,
    })
    throw error
  }
}

/**
 * Handle successful payment
 */
async function handlePaymentSuccess(paymentIntent: Stripe.PaymentIntent): Promise<void> {
  try {
    const customerId = paymentIntent.customer as string
    const userId = await getUserIdFromCustomerId(customerId)

    if (!userId) {
      logger.warn('StripeWebhook', `No user found for customer: ${customerId}`)
      return
    }

    // Record successful payment
    // This would typically update a payment transaction record
    logger.info('StripeWebhook', `Payment succeeded: ${paymentIntent.id} for user: ${userId}`, {
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
    })
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to record payment success', {
      error,
      paymentIntentId: paymentIntent.id,
    })
    throw error
  }
}

/**
 * Handle failed payment
 */
async function handlePaymentFailure(paymentIntent: Stripe.PaymentIntent): Promise<void> {
  try {
    const customerId = paymentIntent.customer as string
    const userId = await getUserIdFromCustomerId(customerId)

    if (!userId) {
      logger.warn('StripeWebhook', `No user found for customer: ${customerId}`)
      return
    }

    // Record failed payment
    logger.warn('StripeWebhook', `Payment failed: ${paymentIntent.id} for user: ${userId}`, {
      amount: paymentIntent.amount,
      currency: paymentIntent.currency,
      lastPaymentError: paymentIntent.last_payment_error,
    })
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to record payment failure', {
      error,
      paymentIntentId: paymentIntent.id,
    })
    throw error
  }
}

/**
 * Handle payment cancellation
 */
async function handlePaymentCancellation(paymentIntent: Stripe.PaymentIntent): Promise<void> {
  try {
    logger.info('StripeWebhook', `Payment canceled: ${paymentIntent.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to handle payment cancellation', {
      error,
      paymentIntentId: paymentIntent.id,
    })
    throw error
  }
}

/**
 * Handle successful invoice payment
 */
async function handleInvoicePaymentSuccess(invoice: Stripe.Invoice): Promise<void> {
  try {
    const customerId = invoice.customer as string
    const userId = await getUserIdFromCustomerId(customerId)

    if (!userId) {
      logger.warn('StripeWebhook', `No user found for customer: ${customerId}`)
      return
    }

    logger.info('StripeWebhook', `Invoice payment succeeded: ${invoice.id} for user: ${userId}`, {
      amount: invoice.amount_paid,
      currency: invoice.currency,
    })
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to process invoice payment', {
      error,
      invoiceId: invoice.id,
    })
    throw error
  }
}

/**
 * Handle failed invoice payment
 */
async function handleInvoicePaymentFailure(invoice: Stripe.Invoice): Promise<void> {
  try {
    const customerId = invoice.customer as string
    const userId = await getUserIdFromCustomerId(customerId)

    if (!userId) {
      logger.warn('StripeWebhook', `No user found for customer: ${customerId}`)
      return
    }

    logger.warn('StripeWebhook', `Invoice payment failed: ${invoice.id} for user: ${userId}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to handle invoice payment failure', {
      error,
      invoiceId: invoice.id,
    })
    throw error
  }
}

/**
 * Handle customer creation
 */
async function handleCustomerCreated(customer: Stripe.Customer): Promise<void> {
  try {
    logger.info('StripeWebhook', `Customer created: ${customer.id}`, {
      email: customer.email,
    })
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to handle customer creation', {
      error,
      customerId: customer.id,
    })
    throw error
  }
}

/**
 * Handle customer update
 */
async function handleCustomerUpdated(customer: Stripe.Customer): Promise<void> {
  try {
    logger.info('StripeWebhook', `Customer updated: ${customer.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to handle customer update', {
      error,
      customerId: customer.id,
    })
    throw error
  }
}

/**
 * Handle customer deletion
 */
async function handleCustomerDeleted(customer: Stripe.Customer): Promise<void> {
  try {
    logger.info('StripeWebhook', `Customer deleted: ${customer.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to handle customer deletion', {
      error,
      customerId: customer.id,
    })
    throw error
  }
}

/**
 * Handle payment method attached
 */
async function handlePaymentMethodAttached(paymentMethod: Stripe.PaymentMethod): Promise<void> {
  try {
    logger.info('StripeWebhook', `Payment method attached: ${paymentMethod.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to handle payment method attachment', {
      error,
      paymentMethodId: paymentMethod.id,
    })
    throw error
  }
}

/**
 * Handle payment method detached
 */
async function handlePaymentMethodDetached(paymentMethod: Stripe.PaymentMethod): Promise<void> {
  try {
    logger.info('StripeWebhook', `Payment method detached: ${paymentMethod.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to handle payment method detachment', {
      error,
      paymentMethodId: paymentMethod.id,
    })
    throw error
  }
}

/**
 * Helper function to get user ID from Stripe customer ID
 */
async function getUserIdFromCustomerId(customerId: string): Promise<string | null> {
  try {
    // This would typically query your user database
    // For now, we'll use the admin user as a placeholder
    return 'admin'
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to get user ID from customer ID', { error, customerId })
    return null
  }
}

/**
 * Map Stripe subscription status to our payment status
 */
function mapStripeStatusToPaymentStatus(stripeStatus: Stripe.Subscription.Status): string {
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
