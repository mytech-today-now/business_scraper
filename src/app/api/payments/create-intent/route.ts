/**
 * Payment Intent Creation API Endpoint
 * Creates Stripe payment intents with user authentication and comprehensive validation
 */

import { NextRequest, NextResponse } from 'next/server'
import { stripeService } from '@/model/stripeService'
import { userPaymentService } from '@/model/userPaymentService'
import { authenticateUser } from '@/utils/auth'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'
import { withApiSecurity } from '@/lib/api-security'
import { withValidation } from '@/lib/validation-middleware'
import { z } from 'zod'

/**
 * Payment Intent Creation Schema
 * Validates payment intent creation requests
 */
const createPaymentIntentSchema = z.object({
  amountCents: z.number()
    .int('Amount must be an integer')
    .min(50, 'Minimum amount is $0.50')
    .max(10000000, 'Maximum amount is $100,000'),
  
  currency: z.string()
    .length(3, 'Currency must be exactly 3 characters')
    .regex(/^[A-Z]{3}$/, 'Currency must be uppercase ISO 4217 code')
    .default('USD'),
  
  description: z.string()
    .min(1, 'Description is required')
    .max(500, 'Description cannot exceed 500 characters'),
  
  metadata: z.record(z.string())
    .optional()
    .default({}),
  
  setupFutureUsage: z.enum(['on_session', 'off_session'])
    .optional(),
  
  automaticPaymentMethods: z.boolean()
    .default(true),
  
  confirmationMethod: z.enum(['automatic', 'manual'])
    .default('automatic')
}).strict()

/**
 * Validation schema for the API endpoint
 */
const validationSchema = {
  body: [
    { field: 'amountCents', required: true, type: 'number' as const, min: 50, max: 10000000 },
    { field: 'currency', type: 'string' as const, maxLength: 3 },
    { field: 'description', required: true, type: 'string' as const, minLength: 1, maxLength: 500 },
    { field: 'metadata', type: 'object' as const },
    { field: 'setupFutureUsage', type: 'string' as const, allowedValues: ['on_session', 'off_session'] },
    { field: 'automaticPaymentMethods', type: 'boolean' as const },
    { field: 'confirmationMethod', type: 'string' as const, allowedValues: ['automatic', 'manual'] }
  ]
}

/**
 * POST /api/payments/create-intent - Create payment intent
 */
const createPaymentIntentHandler = withApiSecurity(
  withValidation(
    async (request: NextRequest, validatedData: any) => {
      const ip = getClientIP(request)
      
      try {
        // Authenticate user
        const user = await authenticateUser(request)
        if (!user) {
          logger.warn('PaymentAPI', `Unauthorized payment intent creation attempt from IP: ${ip}`)
          return NextResponse.json(
            { error: 'Authentication required' },
            { status: 401 }
          )
        }

        // Parse and validate request body with Zod
        const paymentData = createPaymentIntentSchema.parse(validatedData.body)

        logger.info('PaymentAPI', `Creating payment intent for user: ${user.id}`, {
          amount: paymentData.amountCents,
          currency: paymentData.currency,
          ip
        })

        // Ensure user has Stripe customer
        const stripeCustomerId = await userPaymentService.ensureStripeCustomer(
          user.id,
          user.email,
          user.name
        )

        // Create payment intent with Stripe
        const paymentIntent = await stripeService.createPaymentIntent(
          paymentData.amountCents,
          paymentData.currency,
          {
            customerId: stripeCustomerId,
            description: paymentData.description,
            metadata: {
              userId: user.id,
              userEmail: user.email,
              createdBy: 'business_scraper_app',
              ...paymentData.metadata
            },
            setupFutureUsage: paymentData.setupFutureUsage
          }
        )

        // Record transaction in our system
        await recordPaymentTransaction({
          userId: user.id,
          stripePaymentIntentId: paymentIntent.id,
          amountCents: paymentData.amountCents,
          currency: paymentData.currency,
          status: 'pending',
          description: paymentData.description,
          metadata: paymentData.metadata
        })

        logger.info('PaymentAPI', `Payment intent created successfully: ${paymentIntent.id}`, {
          userId: user.id,
          amount: paymentData.amountCents,
          ip
        })

        // Return client secret for frontend processing
        return NextResponse.json({
          success: true,
          clientSecret: paymentIntent.client_secret,
          paymentIntentId: paymentIntent.id,
          amount: paymentData.amountCents,
          currency: paymentData.currency,
          status: paymentIntent.status
        })

      } catch (error) {
        if (error instanceof z.ZodError) {
          logger.warn('PaymentAPI', 'Payment intent validation failed', {
            errors: error.errors,
            ip
          })
          return NextResponse.json(
            { 
              error: 'Validation failed',
              details: error.errors.map(err => ({
                field: err.path.join('.'),
                message: err.message
              }))
            },
            { status: 400 }
          )
        }

        logger.error('PaymentAPI', 'Failed to create payment intent', {
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined,
          ip
        })

        return NextResponse.json(
          { 
            error: 'Failed to create payment intent',
            message: error instanceof Error ? error.message : 'An unexpected error occurred'
          },
          { status: 500 }
        )
      }
    },
    validationSchema
  ),
  {
    requireAuth: false, // We handle auth manually for better error messages
    rateLimit: 'general',
    logRequests: true
  }
)

/**
 * GET /api/payments/create-intent - Get payment intent status
 */
async function getPaymentIntentHandler(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    // Authenticate user
    const user = await authenticateUser(request)
    if (!user) {
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      )
    }

    const url = new URL(request.url)
    const paymentIntentId = url.searchParams.get('payment_intent_id')

    if (!paymentIntentId) {
      return NextResponse.json(
        { error: 'Payment intent ID is required' },
        { status: 400 }
      )
    }

    // Get payment intent from Stripe
    const stripe = new (await import('stripe')).default(process.env.STRIPE_SECRET_KEY!, {
      apiVersion: '2023-10-16'
    })
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId)

    // Verify the payment intent belongs to the user
    const customerId = paymentIntent.customer as string
    const userProfile = await userPaymentService.getUserPaymentProfile(user.id)
    
    if (!userProfile || userProfile.stripeCustomerId !== customerId) {
      logger.warn('PaymentAPI', `Unauthorized access to payment intent: ${paymentIntentId}`, {
        userId: user.id,
        ip
      })
      return NextResponse.json(
        { error: 'Payment intent not found' },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      paymentIntent: {
        id: paymentIntent.id,
        status: paymentIntent.status,
        amount: paymentIntent.amount,
        currency: paymentIntent.currency,
        clientSecret: paymentIntent.client_secret
      }
    })

  } catch (error) {
    logger.error('PaymentAPI', 'Failed to get payment intent', {
      error: error instanceof Error ? error.message : 'Unknown error',
      ip
    })

    return NextResponse.json(
      { error: 'Failed to retrieve payment intent' },
      { status: 500 }
    )
  }
}

/**
 * Record payment transaction in our system
 */
async function recordPaymentTransaction(transaction: {
  userId: string
  stripePaymentIntentId: string
  amountCents: number
  currency: string
  status: string
  description: string
  metadata?: Record<string, any>
}): Promise<void> {
  try {
    // This would typically save to your database
    // For now, we'll just log it as the storage system is primarily for business data
    logger.info('PaymentTransaction', 'Recording payment transaction', {
      userId: transaction.userId,
      paymentIntentId: transaction.stripePaymentIntentId,
      amount: transaction.amountCents,
      currency: transaction.currency,
      status: transaction.status
    })

    // In a real implementation, you would save this to your payment transactions table
    // await database.paymentTransactions.create(transaction)
  } catch (error) {
    logger.error('PaymentTransaction', 'Failed to record payment transaction', {
      error,
      transaction
    })
    throw error
  }
}

/**
 * Export handlers for different HTTP methods
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  return createPaymentIntentHandler(request)
}

export async function GET(request: NextRequest): Promise<NextResponse> {
  return getPaymentIntentHandler(request)
}

/**
 * Only allow POST and GET methods
 */
export async function OPTIONS(request: NextRequest): Promise<NextResponse> {
  return NextResponse.json(
    { error: 'Method not allowed' },
    { 
      status: 405,
      headers: {
        'Allow': 'POST, GET'
      }
    }
  )
}
