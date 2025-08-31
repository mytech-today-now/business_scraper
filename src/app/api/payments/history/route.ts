/**
 * Payment History API Route
 * Handles fetching payment transaction history for users
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
 * GET /api/payments/history
 * Get payment history for current user
 */
async function handleGetPaymentHistory(request: NextRequest): Promise<NextResponse> {
  try {
    // TODO: Get user ID from authentication
    const userId = 'temp-user-id' // Replace with actual user authentication

    const { searchParams } = new URL(request.url)
    const limit = parseInt(searchParams.get('limit') || '10')
    const startingAfter = searchParams.get('starting_after')
    const customerId = searchParams.get('customer_id')

    logger.info('PaymentsAPI', 'Fetching payment history', {
      userId,
      limit,
      startingAfter,
      customerId,
    })

    if (!customerId) {
      // TODO: Look up customer ID from user ID in database
      return NextResponse.json({
        success: true,
        transactions: [],
        hasMore: false,
        count: 0,
        message: 'No customer ID found for user',
        timestamp: new Date().toISOString(),
      })
    }

    // Fetch payment intents for the customer
    const paymentIntentsParams: Stripe.PaymentIntentListParams = {
      customer: customerId,
      limit: Math.min(limit, 100), // Cap at 100
    }

    if (startingAfter) {
      paymentIntentsParams.starting_after = startingAfter
    }

    const paymentIntents = await stripe.paymentIntents.list(paymentIntentsParams)

    // Fetch invoices for the customer
    const invoicesParams: Stripe.InvoiceListParams = {
      customer: customerId,
      limit: Math.min(limit, 100),
    }

    if (startingAfter) {
      invoicesParams.starting_after = startingAfter
    }

    const invoices = await stripe.invoices.list(invoicesParams)

    // Combine and format transactions
    const transactions = [
      ...paymentIntents.data.map(pi => ({
        id: pi.id,
        type: 'payment' as const,
        amount: pi.amount,
        currency: pi.currency,
        status: pi.status,
        description: pi.description || 'Payment',
        created: pi.created,
        metadata: pi.metadata,
        paymentMethod: pi.payment_method_types?.[0] || 'unknown',
      })),
      ...invoices.data.map(invoice => ({
        id: invoice.id,
        type: 'invoice' as const,
        amount: invoice.amount_paid || invoice.amount_due || 0,
        currency: invoice.currency || 'usd',
        status: invoice.status || 'draft',
        description: invoice.description || `Invoice ${invoice.number}`,
        created: invoice.created,
        metadata: invoice.metadata || {},
        paymentMethod: 'subscription',
      })),
    ]

    // Sort by creation date (newest first)
    transactions.sort((a, b) => b.created - a.created)

    // Take only the requested limit
    const limitedTransactions = transactions.slice(0, limit)

    logger.info('PaymentsAPI', 'Payment history retrieved', {
      userId,
      customerId,
      transactionCount: limitedTransactions.length,
    })

    return NextResponse.json({
      success: true,
      transactions: limitedTransactions,
      hasMore: transactions.length > limit,
      count: limitedTransactions.length,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('PaymentsAPI', 'Failed to fetch payment history', error)

    return NextResponse.json(
      {
        success: false,
        error: 'Failed to fetch payment history',
        message: error instanceof Error ? error.message : 'Unknown error',
      },
      { status: 500 }
    )
  }
}

/**
 * Route handler
 */
export const GET = withApiSecurity(handleGetPaymentHistory, {
  requireAuth: false, // TODO: Enable when auth is implemented
  rateLimit: 'general',
  logRequests: true,
})
