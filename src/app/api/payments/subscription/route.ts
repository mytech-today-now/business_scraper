/**
 * Subscription Management API Route
 * Handles subscription creation, retrieval, and management
 */

import { NextRequest, NextResponse } from 'next/server'
import { withApiSecurity } from '@/lib/api-security'
import { logger } from '@/utils/logger'
import Stripe from 'stripe'

// Initialize Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2024-06-20',
})

/**
 * GET /api/payments/subscription
 * Get current user's subscription
 */
async function handleGetSubscription(request: NextRequest): Promise<NextResponse> {
  try {
    // TODO: Get user ID from authentication
    const userId = 'temp-user-id' // Replace with actual user authentication

    logger.info('PaymentsAPI', 'Fetching user subscription', { userId })

    // TODO: Implement database lookup for user's Stripe customer ID
    // For now, return no subscription found
    return NextResponse.json(
      {
        success: false,
        error: 'No subscription found',
        message: 'User does not have an active subscription',
      },
      { status: 404 }
    )
  } catch (error) {
    logger.error('PaymentsAPI', 'Failed to fetch subscription', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch subscription',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * POST /api/payments/subscription
 * Create new subscription
 */
async function handleCreateSubscription(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const { planId, paymentMethodId, customerEmail } = body

    if (!planId) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required fields',
          message: 'Plan ID is required',
        },
        { status: 400 }
      )
    }

    logger.info('PaymentsAPI', 'Creating subscription', { planId, customerEmail })

    // Get plan details to find Stripe price ID
    const plansResponse = await fetch(`${request.nextUrl.origin}/api/payments/plans?id=${planId}`)
    const plansData = await plansResponse.json()

    if (!plansData.success) {
      return NextResponse.json(
        {
          success: false,
          error: 'Invalid plan',
          message: 'Selected plan not found',
        },
        { status: 400 }
      )
    }

    const plan = plansData.plan
    const stripePriceId = plan.stripePriceId

    // Create or retrieve customer
    let customer: Stripe.Customer
    try {
      // Try to find existing customer by email
      const existingCustomers = await stripe.customers.list({
        email: customerEmail,
        limit: 1,
      })

      if (existingCustomers.data.length > 0) {
        customer = existingCustomers.data[0]
        logger.info('PaymentsAPI', 'Found existing customer', { customerId: customer.id })
      } else {
        // Create new customer
        customer = await stripe.customers.create({
          email: customerEmail,
          metadata: {
            planId: planId,
            source: 'business_scraper_app',
          },
        })
        logger.info('PaymentsAPI', 'Created new customer', { customerId: customer.id })
      }
    } catch (error) {
      logger.error('PaymentsAPI', 'Failed to create/retrieve customer', error)
      throw new Error('Failed to process customer information')
    }

    // Attach payment method if provided
    if (paymentMethodId) {
      try {
        await stripe.paymentMethods.attach(paymentMethodId, {
          customer: customer.id,
        })

        // Set as default payment method
        await stripe.customers.update(customer.id, {
          invoice_settings: {
            default_payment_method: paymentMethodId,
          },
        })
      } catch (error) {
        logger.error('PaymentsAPI', 'Failed to attach payment method', error)
        throw new Error('Failed to process payment method')
      }
    }

    // Create subscription
    const subscription = await stripe.subscriptions.create({
      customer: customer.id,
      items: [
        {
          price: stripePriceId,
        },
      ],
      payment_behavior: 'default_incomplete',
      payment_settings: { save_default_payment_method: 'on_subscription' },
      expand: ['latest_invoice.payment_intent'],
      metadata: {
        planId: planId,
        userId: 'temp-user-id', // Replace with actual user ID
      },
    })

    logger.info('PaymentsAPI', 'Subscription created', {
      subscriptionId: subscription.id,
      customerId: customer.id,
      planId,
    })

    // TODO: Save subscription to database

    return NextResponse.json({
      success: true,
      subscription: {
        id: subscription.id,
        customerId: customer.id,
        status: subscription.status,
        currentPeriodStart: subscription.current_period_start,
        currentPeriodEnd: subscription.current_period_end,
        planId: planId,
      },
      clientSecret: (subscription.latest_invoice as Stripe.Invoice)?.payment_intent
        ? ((subscription.latest_invoice as Stripe.Invoice).payment_intent as Stripe.PaymentIntent)
            ?.client_secret
        : null,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('PaymentsAPI', 'Failed to create subscription', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to create subscription',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/payments/subscription
 * Cancel subscription
 */
async function handleCancelSubscription(request: NextRequest): Promise<NextResponse> {
  try {
    // TODO: Get user ID from authentication and find their subscription
    const userId = 'temp-user-id'

    logger.info('PaymentsAPI', 'Canceling subscription', { userId })

    // TODO: Implement subscription cancellation
    // 1. Get user's subscription ID from database
    // 2. Cancel subscription in Stripe
    // 3. Update database

    return NextResponse.json(
      {
        success: false,
        error: 'Not implemented',
        message: 'Subscription cancellation not yet implemented',
      },
      { status: 501 }
    )
  } catch (error) {
    logger.error('PaymentsAPI', 'Failed to cancel subscription', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to cancel subscription',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Route handlers
 */
export const GET = withApiSecurity(handleGetSubscription, {
  requireAuth: false, // TODO: Enable when auth is implemented
  rateLimit: 'general',
  logRequests: true,
})

export const POST = withApiSecurity(handleCreateSubscription, {
  requireAuth: false, // TODO: Enable when auth is implemented
  rateLimit: 'general',
  logRequests: true,
})

export const DELETE = withApiSecurity(handleCancelSubscription, {
  requireAuth: false, // TODO: Enable when auth is implemented
  rateLimit: 'general',
  logRequests: true,
})
