/**
 * Billing Portal API Route
 * Creates Stripe billing portal sessions for subscription management
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
 * POST /api/payments/billing-portal
 * Create billing portal session for customer
 */
async function handleCreateBillingPortalSession(request: NextRequest): Promise<NextResponse> {
  try {
    const body = await request.json()
    const { customerId, returnUrl } = body

    if (!customerId) {
      return NextResponse.json(
        {
          success: false,
          error: 'Missing required fields',
          message: 'Customer ID is required'
        },
        { status: 400 }
      )
    }

    logger.info('PaymentsAPI', 'Creating billing portal session', { customerId })

    // Set default return URL if not provided
    const defaultReturnUrl = `${request.nextUrl.origin}/dashboard`
    const portalReturnUrl = returnUrl || defaultReturnUrl

    // Create billing portal session
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: portalReturnUrl,
    })

    logger.info('PaymentsAPI', 'Billing portal session created', { 
      sessionId: portalSession.id,
      customerId,
      returnUrl: portalReturnUrl
    })

    return NextResponse.json({
      success: true,
      url: portalSession.url,
      sessionId: portalSession.id,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    logger.error('PaymentsAPI', 'Failed to create billing portal session', error)
    
    return NextResponse.json(
      {
        success: false,
        error: 'Failed to create billing portal session',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * Route handler
 */
export const POST = withApiSecurity(handleCreateBillingPortalSession, {
  requireAuth: false, // TODO: Enable when auth is implemented
  rateLimit: 'general',
  logRequests: true
})
