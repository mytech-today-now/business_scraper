# Stripe Payment Integration - AI Implementation Prompts

**Business Scraper App - Complete Payment System Implementation**  
*Version: 1.0.0 | Date: 2025-08-29 | Framework: Next.js 14 + TypeScript*

## Overview

This document contains a series of AI prompts designed for Augment AI running in VS Code to implement a complete Stripe payment system into the Business Scraper App. Each prompt builds upon the previous work and includes detailed step-by-step instructions.

---

## Prompt 1: Project Setup and Dependencies

### Objective
Install and configure all necessary Stripe dependencies and update project configuration files.

### Instructions for AI Assistant

**Step 1: Install Stripe Dependencies**
Execute the following commands in the terminal to install required packages:

```bash
npm install stripe @stripe/stripe-js @stripe/react-stripe-js
npm install --save-dev @types/stripe
npm install crypto-js jsonwebtoken
npm install --save-dev @types/jsonwebtoken
```

**Step 2: Verify Installation**
After installation, check that the following packages appear in `package.json`:
- `stripe`
- `@stripe/stripe-js`
- `@stripe/react-stripe-js`
- `crypto-js`
- `jsonwebtoken`

**Step 3: Update Environment Configuration**
1. Open the file `config/development.env.example`
2. Add the following Stripe configuration variables:

```env
# Stripe Configuration
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Production keys (for deployment)
STRIPE_PUBLISHABLE_KEY_LIVE=pk_live_...
STRIPE_SECRET_KEY_LIVE=sk_live_...
STRIPE_WEBHOOK_SECRET_LIVE=whsec_...

# Payment Configuration
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${STRIPE_PUBLISHABLE_KEY}
PAYMENT_SUCCESS_URL=http://localhost:3000/payment/success
PAYMENT_CANCEL_URL=http://localhost:3000/payment/cancel
```

3. Copy the same configuration to `config/production.env.example` and `config/test.env.example`

**Step 4: Update Configuration Schema**
1. Open `src/lib/config.ts`
2. Locate the `configSchema` object
3. Add the following validation rules:

```typescript
// Add to configSchema
'STRIPE_PUBLISHABLE_KEY': { type: 'string', required: true },
'STRIPE_SECRET_KEY': { type: 'string', required: true },
'STRIPE_WEBHOOK_SECRET': { type: 'string', required: true },
'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY': { type: 'string', required: true },
'PAYMENT_SUCCESS_URL': { type: 'url', required: true },
'PAYMENT_CANCEL_URL': { type: 'url', required: true },
```

4. Update the `AppConfig` interface to include:

```typescript
payments: {
  stripePublishableKey: string
  stripeSecretKey: string
  stripeWebhookSecret: string
  successUrl: string
  cancelUrl: string
}
```

**Validation Steps:**
- Run `npm list` to confirm all packages are installed
- Check that environment files contain Stripe configuration
- Verify config.ts compiles without TypeScript errors
- Test that the application starts without configuration errors

**Next Steps:**
Proceed to Prompt 2 for database schema implementation.

---

## Prompt 2: Database Schema Implementation

### Objective
Create PostgreSQL database tables and indexes to support Stripe payment functionality.

### Instructions for AI Assistant

**Step 1: Create Migration File**
1. Navigate to the `database/migrations/` directory
2. Create a new file named `002_stripe_payment_system.sql`
3. Add the following SQL schema:

```sql
-- Users table updates (add Stripe customer ID if not exists)
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255) UNIQUE;

-- Subscription plans
CREATE TABLE IF NOT EXISTS subscription_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_price_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'usd',
    interval VARCHAR(20) NOT NULL, -- 'month', 'year'
    features JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User subscriptions
CREATE TABLE IF NOT EXISTS user_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    stripe_subscription_id VARCHAR(255) UNIQUE NOT NULL,
    plan_id UUID REFERENCES subscription_plans(id),
    status VARCHAR(50) NOT NULL, -- 'active', 'canceled', 'past_due', etc.
    current_period_start TIMESTAMP,
    current_period_end TIMESTAMP,
    cancel_at_period_end BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Payment transactions
CREATE TABLE IF NOT EXISTS payment_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    stripe_payment_intent_id VARCHAR(255) UNIQUE,
    amount_cents INTEGER NOT NULL,
    currency VARCHAR(3) DEFAULT 'usd',
    status VARCHAR(50) NOT NULL,
    description TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Usage tracking for premium features
CREATE TABLE IF NOT EXISTS feature_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    feature_type VARCHAR(100) NOT NULL, -- 'scraping_request', 'export', 'advanced_search'
    usage_count INTEGER DEFAULT 1,
    date DATE DEFAULT CURRENT_DATE,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON user_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe ON user_subscriptions(stripe_subscription_id);
CREATE INDEX IF NOT EXISTS idx_transactions_user ON payment_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_user_date ON feature_usage(user_id, date);
```

**Step 2: Update IndexedDB Schema**
1. Open `src/model/storage.ts`
2. Locate the database interface definition
3. Add the following to the interface:

```typescript
userProfile: {
  key: string
  value: {
    id: string
    email: string
    name: string
    subscriptionStatus: 'free' | 'premium' | 'enterprise'
    subscriptionPlan?: string
    usageQuotas: {
      scrapingRequests: number
      exports: number
      advancedSearches: number
    }
    createdAt: Date
    updatedAt: Date
  }
}
paymentHistory: {
  key: string
  value: {
    id: string
    amount: number
    currency: string
    status: string
    description: string
    date: Date
  }
}
```

**Step 3: Test Database Migration**
1. Run the migration script to ensure it executes without errors
2. Verify all tables are created with correct structure
3. Check that indexes are properly created

**Validation Steps:**
- Confirm migration file exists and is properly formatted
- Verify database tables are created successfully
- Check that IndexedDB interface compiles without errors
- Test that foreign key relationships work correctly

**Next Steps:**
Proceed to Prompt 3 for Model layer implementation.

---

## Prompt 3: Model Layer Implementation - Part 1 (Stripe Service)

### Objective
Create the core Stripe service class that handles all Stripe API interactions.

### Instructions for AI Assistant

**Step 1: Create Stripe Service File**
1. Create a new file `src/model/stripeService.ts`
2. Implement the following service class:

```typescript
import Stripe from 'stripe'
import { getConfig } from '@/lib/config'
import { logger } from '@/utils/logger'

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
  async createCustomer(email: string, name?: string): Promise<Stripe.Customer> {
    try {
      const customer = await this.stripe.customers.create({
        email,
        name,
        metadata: { source: 'business_scraper_app' }
      })
      logger.info('StripeService', `Customer created: ${customer.id}`)
      return customer
    } catch (error) {
      logger.error('StripeService', 'Failed to create customer', error)
      throw error
    }
  }

  // Subscription Management
  async createSubscription(
    customerId: string,
    priceId: string
  ): Promise<Stripe.Subscription> {
    try {
      const subscription = await this.stripe.subscriptions.create({
        customer: customerId,
        items: [{ price: priceId }],
        payment_behavior: 'default_incomplete',
        payment_settings: { save_default_payment_method: 'on_subscription' },
        expand: ['latest_invoice.payment_intent'],
      })
      return subscription
    } catch (error) {
      logger.error('StripeService', 'Failed to create subscription', error)
      throw error
    }
  }

  // Payment Intent for one-time payments
  async createPaymentIntent(
    amount: number,
    currency: string = 'usd',
    customerId?: string
  ): Promise<Stripe.PaymentIntent> {
    try {
      const paymentIntent = await this.stripe.paymentIntents.create({
        amount,
        currency,
        customer: customerId,
        automatic_payment_methods: { enabled: true },
      })
      return paymentIntent
    } catch (error) {
      logger.error('StripeService', 'Failed to create payment intent', error)
      throw error
    }
  }

  // Webhook signature verification
  verifyWebhookSignature(payload: string, signature: string): Stripe.Event {
    try {
      return this.stripe.webhooks.constructEvent(
        payload,
        signature,
        this.config.payments.stripeWebhookSecret
      )
    } catch (error) {
      logger.error('StripeService', 'Webhook signature verification failed', error)
      throw error
    }
  }
}

export const stripeService = new StripeService()
```

**Step 2: Verify Implementation**
1. Check that all imports resolve correctly
2. Ensure the service compiles without TypeScript errors
3. Verify that the singleton export pattern is used

**Validation Steps:**
- Confirm file is created in correct location
- Check TypeScript compilation passes
- Verify logger and config imports work
- Test that service can be imported in other files

**Next Steps:**
Proceed to Prompt 4 for Payment Models implementation.

---

## Prompt 4: Model Layer Implementation - Part 2 (Payment Models)

### Objective
Create TypeScript models and Zod schemas for all payment-related data structures.

### Instructions for AI Assistant

**Step 1: Create Payment Models File**
1. Create a new file `src/model/paymentModels.ts`
2. Implement the following schemas and types:

```typescript
import { z } from 'zod'

// Subscription Plan Schema
export const SubscriptionPlanSchema = z.object({
  id: z.string().uuid(),
  stripePriceId: z.string(),
  name: z.string(),
  description: z.string().optional(),
  priceCents: z.number().positive(),
  currency: z.string().length(3).default('usd'),
  interval: z.enum(['month', 'year']),
  features: z.record(z.any()).optional(),
  isActive: z.boolean().default(true),
  createdAt: z.date(),
})

export type SubscriptionPlan = z.infer<typeof SubscriptionPlanSchema>

// User Subscription Schema
export const UserSubscriptionSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  stripeSubscriptionId: z.string(),
  planId: z.string().uuid(),
  status: z.enum(['active', 'canceled', 'past_due', 'unpaid', 'incomplete']),
  currentPeriodStart: z.date(),
  currentPeriodEnd: z.date(),
  cancelAtPeriodEnd: z.boolean().default(false),
  createdAt: z.date(),
  updatedAt: z.date(),
})

export type UserSubscription = z.infer<typeof UserSubscriptionSchema>

// Payment Transaction Schema
export const PaymentTransactionSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  stripePaymentIntentId: z.string().optional(),
  amountCents: z.number().positive(),
  currency: z.string().length(3).default('usd'),
  status: z.enum(['succeeded', 'pending', 'failed', 'canceled']),
  description: z.string().optional(),
  metadata: z.record(z.any()).optional(),
  createdAt: z.date(),
})

export type PaymentTransaction = z.infer<typeof PaymentTransactionSchema>

// Feature Usage Schema
export const FeatureUsageSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  featureType: z.enum(['scraping_request', 'export', 'advanced_search', 'premium_industry']),
  usageCount: z.number().positive().default(1),
  date: z.date(),
  metadata: z.record(z.any()).optional(),
  createdAt: z.date(),
})

export type FeatureUsage = z.infer<typeof FeatureUsageSchema>
```

**Step 2: Create Payment Storage Service**
1. Create a new file `src/model/paymentStorage.ts`
2. Implement database operations for payment entities:

```typescript
import { database } from '@/lib/postgresql-database'
import { logger } from '@/utils/logger'
import {
  SubscriptionPlan,
  UserSubscription,
  PaymentTransaction,
  FeatureUsage
} from './paymentModels'

export class PaymentStorage {
  // Subscription Plans
  async createSubscriptionPlan(plan: Omit<SubscriptionPlan, 'id' | 'createdAt'>): Promise<SubscriptionPlan> {
    try {
      const query = `
        INSERT INTO subscription_plans (stripe_price_id, name, description, price_cents, currency, interval, features, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
      `
      const result = await database.query(query, [
        plan.stripePriceId,
        plan.name,
        plan.description,
        plan.priceCents,
        plan.currency,
        plan.interval,
        JSON.stringify(plan.features),
        plan.isActive
      ])
      return result.rows[0]
    } catch (error) {
      logger.error('PaymentStorage', 'Failed to create subscription plan', error)
      throw error
    }
  }

  async getActiveSubscriptionPlans(): Promise<SubscriptionPlan[]> {
    try {
      const query = 'SELECT * FROM subscription_plans WHERE is_active = true ORDER BY price_cents ASC'
      const result = await database.query(query)
      return result.rows
    } catch (error) {
      logger.error('PaymentStorage', 'Failed to get subscription plans', error)
      throw error
    }
  }

  // User Subscriptions
  async createUserSubscription(subscription: Omit<UserSubscription, 'id' | 'createdAt' | 'updatedAt'>): Promise<UserSubscription> {
    try {
      const query = `
        INSERT INTO user_subscriptions (user_id, stripe_subscription_id, plan_id, status, current_period_start, current_period_end, cancel_at_period_end)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `
      const result = await database.query(query, [
        subscription.userId,
        subscription.stripeSubscriptionId,
        subscription.planId,
        subscription.status,
        subscription.currentPeriodStart,
        subscription.currentPeriodEnd,
        subscription.cancelAtPeriodEnd
      ])
      return result.rows[0]
    } catch (error) {
      logger.error('PaymentStorage', 'Failed to create user subscription', error)
      throw error
    }
  }

  async getUserActiveSubscription(userId: string): Promise<UserSubscription | null> {
    try {
      const query = `
        SELECT us.*, sp.name as plan_name, sp.features
        FROM user_subscriptions us
        JOIN subscription_plans sp ON us.plan_id = sp.id
        WHERE us.user_id = $1 AND us.status = 'active'
        ORDER BY us.created_at DESC
        LIMIT 1
      `
      const result = await database.query(query, [userId])
      return result.rows[0] || null
    } catch (error) {
      logger.error('PaymentStorage', 'Failed to get user subscription', error)
      throw error
    }
  }

  // Feature Usage Tracking
  async recordFeatureUsage(usage: Omit<FeatureUsage, 'id' | 'createdAt'>): Promise<void> {
    try {
      const query = `
        INSERT INTO feature_usage (user_id, feature_type, usage_count, date, metadata)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id, feature_type, date)
        DO UPDATE SET usage_count = feature_usage.usage_count + $3
      `
      await database.query(query, [
        usage.userId,
        usage.featureType,
        usage.usageCount,
        usage.date,
        JSON.stringify(usage.metadata)
      ])
    } catch (error) {
      logger.error('PaymentStorage', 'Failed to record feature usage', error)
      throw error
    }
  }

  async getUserFeatureUsage(userId: string, featureType: string, date: Date): Promise<number> {
    try {
      const query = `
        SELECT COALESCE(SUM(usage_count), 0) as total_usage
        FROM feature_usage
        WHERE user_id = $1 AND feature_type = $2 AND date = $3
      `
      const result = await database.query(query, [userId, featureType, date])
      return parseInt(result.rows[0].total_usage)
    } catch (error) {
      logger.error('PaymentStorage', 'Failed to get feature usage', error)
      throw error
    }
  }
}

export const paymentStorage = new PaymentStorage()
```

**Validation Steps:**
- Verify all Zod schemas compile correctly
- Check that TypeScript types are properly exported
- Confirm database operations use correct SQL syntax
- Test that storage service can be imported

**Next Steps:**
Proceed to Prompt 5 for API Layer implementation.

---

## Prompt 5: API Layer Implementation - Webhooks and Endpoints

### Objective
Create API routes for Stripe webhooks and payment processing endpoints.

### Instructions for AI Assistant

**Step 1: Create Stripe Webhooks Handler**
1. Create the directory structure `src/app/api/stripe/webhooks/`
2. Create a new file `src/app/api/stripe/webhooks/route.ts`
3. Implement the webhook handler:

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { stripeService } from '@/model/stripeService'
import { paymentStorage } from '@/model/paymentStorage'
import { logger } from '@/utils/logger'
import Stripe from 'stripe'

export async function POST(request: NextRequest) {
  try {
    const body = await request.text()
    const signature = request.headers.get('stripe-signature')

    if (!signature) {
      return NextResponse.json({ error: 'Missing stripe signature' }, { status: 400 })
    }

    const event = stripeService.verifyWebhookSignature(body, signature)

    logger.info('StripeWebhook', `Processing event: ${event.type}`)

    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
        await handleSubscriptionUpdate(event.data.object as Stripe.Subscription)
        break

      case 'customer.subscription.deleted':
        await handleSubscriptionCancellation(event.data.object as Stripe.Subscription)
        break

      case 'payment_intent.succeeded':
        await handlePaymentSuccess(event.data.object as Stripe.PaymentIntent)
        break

      case 'payment_intent.payment_failed':
        await handlePaymentFailure(event.data.object as Stripe.PaymentIntent)
        break

      default:
        logger.info('StripeWebhook', `Unhandled event type: ${event.type}`)
    }

    return NextResponse.json({ received: true })
  } catch (error) {
    logger.error('StripeWebhook', 'Webhook processing failed', error)
    return NextResponse.json({ error: 'Webhook processing failed' }, { status: 500 })
  }
}

async function handleSubscriptionUpdate(subscription: Stripe.Subscription) {
  try {
    // Update subscription in database
    const query = `
      UPDATE user_subscriptions
      SET status = $1, current_period_start = $2, current_period_end = $3, updated_at = CURRENT_TIMESTAMP
      WHERE stripe_subscription_id = $4
    `
    await database.query(query, [
      subscription.status,
      new Date(subscription.current_period_start * 1000),
      new Date(subscription.current_period_end * 1000),
      subscription.id
    ])

    logger.info('StripeWebhook', `Subscription updated: ${subscription.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to update subscription', error)
    throw error
  }
}

async function handleSubscriptionCancellation(subscription: Stripe.Subscription) {
  try {
    const query = `
      UPDATE user_subscriptions
      SET status = 'canceled', updated_at = CURRENT_TIMESTAMP
      WHERE stripe_subscription_id = $1
    `
    await database.query(query, [subscription.id])

    logger.info('StripeWebhook', `Subscription canceled: ${subscription.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to cancel subscription', error)
    throw error
  }
}

async function handlePaymentSuccess(paymentIntent: Stripe.PaymentIntent) {
  try {
    // Record successful payment
    await paymentStorage.createPaymentTransaction({
      userId: paymentIntent.metadata.userId,
      stripePaymentIntentId: paymentIntent.id,
      amountCents: paymentIntent.amount,
      currency: paymentIntent.currency,
      status: 'succeeded',
      description: paymentIntent.description || 'One-time payment',
      metadata: paymentIntent.metadata
    })

    logger.info('StripeWebhook', `Payment succeeded: ${paymentIntent.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to record payment success', error)
    throw error
  }
}

async function handlePaymentFailure(paymentIntent: Stripe.PaymentIntent) {
  try {
    await paymentStorage.createPaymentTransaction({
      userId: paymentIntent.metadata.userId,
      stripePaymentIntentId: paymentIntent.id,
      amountCents: paymentIntent.amount,
      currency: paymentIntent.currency,
      status: 'failed',
      description: paymentIntent.description || 'Failed payment',
      metadata: paymentIntent.metadata
    })

    logger.info('StripeWebhook', `Payment failed: ${paymentIntent.id}`)
  } catch (error) {
    logger.error('StripeWebhook', 'Failed to record payment failure', error)
    throw error
  }
}
```

**Step 2: Create Payment API Endpoints**
1. Create the directory `src/app/api/payments/`
2. Create a new file `src/app/api/payments/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { stripeService } from '@/model/stripeService'
import { paymentStorage } from '@/model/paymentStorage'
import { withApiSecurity } from '@/lib/api-security'
import { withValidation } from '@/lib/validation-middleware'
import { z } from 'zod'

const CreatePaymentIntentSchema = z.object({
  amount: z.number().positive(),
  currency: z.string().length(3).default('usd'),
  description: z.string().optional(),
})

const CreateSubscriptionSchema = z.object({
  priceId: z.string(),
  customerId: z.string().optional(),
})

export async function POST(request: NextRequest) {
  return withApiSecurity(async () => {
    return withValidation(CreatePaymentIntentSchema, async (data) => {
      try {
        const paymentIntent = await stripeService.createPaymentIntent(
          data.amount,
          data.currency,
          data.customerId
        )

        return NextResponse.json({
          clientSecret: paymentIntent.client_secret,
          paymentIntentId: paymentIntent.id
        })
      } catch (error) {
        logger.error('PaymentAPI', 'Failed to create payment intent', error)
        return NextResponse.json({ error: 'Payment creation failed' }, { status: 500 })
      }
    })(request)
  })(request)
}
```

**Step 3: Create Subscription Management API**
1. Create the directory `src/app/api/subscriptions/`
2. Create a new file `src/app/api/subscriptions/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { stripeService } from '@/model/stripeService'
import { paymentStorage } from '@/model/paymentStorage'

export async function GET(request: NextRequest) {
  try {
    const plans = await paymentStorage.getActiveSubscriptionPlans()
    return NextResponse.json({ plans })
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch plans' }, { status: 500 })
  }
}

export async function POST(request: NextRequest) {
  try {
    const { priceId, customerId } = await request.json()

    const subscription = await stripeService.createSubscription(customerId, priceId)

    return NextResponse.json({
      subscriptionId: subscription.id,
      clientSecret: subscription.latest_invoice?.payment_intent?.client_secret
    })
  } catch (error) {
    return NextResponse.json({ error: 'Subscription creation failed' }, { status: 500 })
  }
}
```

**Validation Steps:**
- Verify all API routes are created in correct directory structure
- Check that webhook signature verification works
- Test that payment intent creation returns proper response
- Confirm subscription endpoints handle errors gracefully

**Next Steps:**
Proceed to Prompt 6 for View Layer implementation.

---

## Prompt 6: View Layer Implementation - Payment Components

### Objective
Create React components for payment forms, subscription plans, and billing management.

### Instructions for AI Assistant

**Step 1: Create Payment Form Component**
1. Create a new file `src/view/components/PaymentForm.tsx`
2. Implement the Stripe Elements payment form:

```typescript
'use client'

import React, { useState } from 'react'
import { loadStripe } from '@stripe/stripe-js'
import {
  Elements,
  CardElement,
  useStripe,
  useElements
} from '@stripe/react-stripe-js'
import { Button } from './ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { useConfig } from '@/controller/ConfigContext'
import { logger } from '@/utils/logger'

const stripePromise = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!)

interface PaymentFormProps {
  amount: number
  currency?: string
  description?: string
  onSuccess: (paymentIntent: any) => void
  onError: (error: string) => void
}

function PaymentFormInner({ amount, currency = 'usd', description, onSuccess, onError }: PaymentFormProps) {
  const stripe = useStripe()
  const elements = useElements()
  const [isProcessing, setIsProcessing] = useState(false)

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()

    if (!stripe || !elements) {
      return
    }

    setIsProcessing(true)

    try {
      // Create payment intent
      const response = await fetch('/api/payments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount, currency, description })
      })

      const { clientSecret } = await response.json()

      // Confirm payment
      const { error, paymentIntent } = await stripe.confirmCardPayment(clientSecret, {
        payment_method: {
          card: elements.getElement(CardElement)!,
        }
      })

      if (error) {
        onError(error.message || 'Payment failed')
      } else if (paymentIntent?.status === 'succeeded') {
        onSuccess(paymentIntent)
      }
    } catch (error) {
      onError('Payment processing failed')
      logger.error('PaymentForm', 'Payment failed', error)
    } finally {
      setIsProcessing(false)
    }
  }

  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle>Payment Details</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="p-4 border rounded-md">
            <CardElement
              options={{
                style: {
                  base: {
                    fontSize: '16px',
                    color: '#424770',
                    '::placeholder': {
                      color: '#aab7c4',
                    },
                  },
                },
              }}
            />
          </div>

          <div className="text-sm text-gray-600">
            Amount: ${(amount / 100).toFixed(2)} {currency.toUpperCase()}
          </div>

          <Button
            type="submit"
            disabled={!stripe || isProcessing}
            className="w-full"
          >
            {isProcessing ? 'Processing...' : `Pay $${(amount / 100).toFixed(2)}`}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

export function PaymentForm(props: PaymentFormProps) {
  return (
    <Elements stripe={stripePromise}>
      <PaymentFormInner {...props} />
    </Elements>
  )
}
```

**Step 2: Create Subscription Plans Component**
1. Create a new file `src/view/components/SubscriptionPlans.tsx`:

```typescript
'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Check, Star } from 'lucide-react'
import { SubscriptionPlan } from '@/model/paymentModels'

interface SubscriptionPlansProps {
  onSelectPlan: (plan: SubscriptionPlan) => void
}

export function SubscriptionPlans({ onSelectPlan }: SubscriptionPlansProps) {
  const [plans, setPlans] = useState<SubscriptionPlan[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchPlans()
  }, [])

  const fetchPlans = async () => {
    try {
      const response = await fetch('/api/subscriptions')
      const { plans } = await response.json()
      setPlans(plans)
    } catch (error) {
      console.error('Failed to fetch plans:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="text-center">Loading plans...</div>
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      {plans.map((plan) => (
        <Card key={plan.id} className={`relative ${plan.name.includes('Pro') ? 'border-blue-500 shadow-lg' : ''}`}>
          {plan.name.includes('Pro') && (
            <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
              <span className="bg-blue-500 text-white px-3 py-1 rounded-full text-sm flex items-center">
                <Star className="w-4 h-4 mr-1" />
                Popular
              </span>
            </div>
          )}

          <CardHeader className="text-center">
            <CardTitle className="text-2xl">{plan.name}</CardTitle>
            <div className="text-3xl font-bold">
              ${(plan.priceCents / 100).toFixed(0)}
              <span className="text-lg font-normal text-gray-600">/{plan.interval}</span>
            </div>
            {plan.description && (
              <p className="text-gray-600">{plan.description}</p>
            )}
          </CardHeader>

          <CardContent>
            <ul className="space-y-3 mb-6">
              {plan.features && Object.entries(plan.features).map(([feature, included]) => (
                <li key={feature} className="flex items-center">
                  <Check className="w-5 h-5 text-green-500 mr-2" />
                  <span className="capitalize">{feature.replace('_', ' ')}</span>
                </li>
              ))}
            </ul>

            <Button
              onClick={() => onSelectPlan(plan)}
              className="w-full"
              variant={plan.name.includes('Pro') ? 'default' : 'outline'}
            >
              Choose {plan.name}
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
```

**Validation Steps:**
- Verify Stripe Elements integration works correctly
- Check that payment form handles loading states properly
- Confirm subscription plans display with correct styling
- Test that error handling works for failed payments

**Next Steps:**
Proceed to Prompt 7 for Controller Layer implementation.

---

## Prompt 7: Controller Layer Implementation - Payment State Management

### Objective
Create React hooks for managing payment state, subscription management, and feature access control.

### Instructions for AI Assistant

**Step 1: Create Payment Controller Hook**
1. Create a new file `src/controller/usePaymentController.ts`
2. Implement the payment state management hook:

```typescript
import { useState, useCallback } from 'react'
import { logger } from '@/utils/logger'
import { SubscriptionPlan, PaymentTransaction } from '@/model/paymentModels'

interface PaymentState {
  isProcessing: boolean
  currentSubscription: any | null
  paymentHistory: PaymentTransaction[]
  error: string | null
}

export function usePaymentController() {
  const [state, setState] = useState<PaymentState>({
    isProcessing: false,
    currentSubscription: null,
    paymentHistory: [],
    error: null
  })

  const processPayment = useCallback(async (amount: number, description?: string) => {
    setState(prev => ({ ...prev, isProcessing: true, error: null }))

    try {
      const response = await fetch('/api/payments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount, description })
      })

      if (!response.ok) {
        throw new Error('Payment failed')
      }

      const result = await response.json()
      return result
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Payment failed'
      setState(prev => ({ ...prev, error: errorMessage }))
      logger.error('PaymentController', 'Payment processing failed', error)
      throw error
    } finally {
      setState(prev => ({ ...prev, isProcessing: false }))
    }
  }, [])

  const createSubscription = useCallback(async (plan: SubscriptionPlan) => {
    setState(prev => ({ ...prev, isProcessing: true, error: null }))

    try {
      const response = await fetch('/api/subscriptions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priceId: plan.stripePriceId })
      })

      if (!response.ok) {
        throw new Error('Subscription creation failed')
      }

      const result = await response.json()
      return result
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Subscription failed'
      setState(prev => ({ ...prev, error: errorMessage }))
      logger.error('PaymentController', 'Subscription creation failed', error)
      throw error
    } finally {
      setState(prev => ({ ...prev, isProcessing: false }))
    }
  }, [])

  const checkFeatureAccess = useCallback(async (featureType: string): Promise<boolean> => {
    try {
      const response = await fetch(`/api/features/access?type=${featureType}`)
      const { hasAccess } = await response.json()
      return hasAccess
    } catch (error) {
      logger.error('PaymentController', 'Feature access check failed', error)
      return false
    }
  }, [])

  const recordFeatureUsage = useCallback(async (featureType: string, metadata?: any) => {
    try {
      await fetch('/api/features/usage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ featureType, metadata })
      })
    } catch (error) {
      logger.error('PaymentController', 'Failed to record feature usage', error)
    }
  }, [])

  return {
    ...state,
    processPayment,
    createSubscription,
    checkFeatureAccess,
    recordFeatureUsage
  }
}
```

**Step 2: Create Feature Access Control Hook**
1. Create a new file `src/controller/useFeatureAccess.ts`:

```typescript
import { useState, useEffect, useCallback } from 'react'
import { usePaymentController } from './usePaymentController'

interface FeatureAccessState {
  canExportAdvanced: boolean
  canUseAdvancedSearch: boolean
  canAccessPremiumIndustries: boolean
  scrapingQuotaRemaining: number
  isLoading: boolean
}

export function useFeatureAccess(userId?: string) {
  const [state, setState] = useState<FeatureAccessState>({
    canExportAdvanced: false,
    canUseAdvancedSearch: false,
    canAccessPremiumIndustries: false,
    scrapingQuotaRemaining: 0,
    isLoading: true
  })

  const { checkFeatureAccess, recordFeatureUsage } = usePaymentController()

  const checkAllFeatures = useCallback(async () => {
    if (!userId) return

    setState(prev => ({ ...prev, isLoading: true }))

    try {
      const [exportAccess, searchAccess, industriesAccess] = await Promise.all([
        checkFeatureAccess('export'),
        checkFeatureAccess('advanced_search'),
        checkFeatureAccess('premium_industry')
      ])

      // Get remaining quota
      const quotaResponse = await fetch(`/api/features/quota?userId=${userId}`)
      const { remaining } = await quotaResponse.json()

      setState({
        canExportAdvanced: exportAccess,
        canUseAdvancedSearch: searchAccess,
        canAccessPremiumIndustries: industriesAccess,
        scrapingQuotaRemaining: remaining,
        isLoading: false
      })
    } catch (error) {
      console.error('Failed to check feature access:', error)
      setState(prev => ({ ...prev, isLoading: false }))
    }
  }, [userId, checkFeatureAccess])

  useEffect(() => {
    checkAllFeatures()
  }, [checkAllFeatures])

  const useFeature = useCallback(async (featureType: string, metadata?: any) => {
    await recordFeatureUsage(featureType, metadata)
    // Refresh feature access after usage
    await checkAllFeatures()
  }, [recordFeatureUsage, checkAllFeatures])

  return {
    ...state,
    useFeature,
    refreshAccess: checkAllFeatures
  }
}
```

**Validation Steps:**
- Verify hooks manage state correctly
- Check that error handling works properly
- Test that feature access checks return correct values
- Confirm usage tracking updates quotas

**Next Steps:**
Proceed to Prompt 8 for Security and Testing implementation.

---

## Prompt 8: Security Implementation and Testing

### Objective
Implement security measures for payment processing and create comprehensive tests for the payment system.

### Instructions for AI Assistant

**Step 1: Create Payment Security Middleware**
1. Create a new file `src/lib/payment-security.ts`
2. Implement security validation functions:

```typescript
import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import crypto from 'crypto'

export function validatePaymentRequest(request: NextRequest): boolean {
  // Validate request origin
  const origin = request.headers.get('origin')
  const allowedOrigins = [
    process.env.NEXT_PUBLIC_APP_URL,
    'https://js.stripe.com'
  ]

  if (origin && !allowedOrigins.includes(origin)) {
    logger.warn('PaymentSecurity', `Invalid origin: ${origin}`)
    return false
  }

  // Validate content type for POST requests
  if (request.method === 'POST') {
    const contentType = request.headers.get('content-type')
    if (!contentType?.includes('application/json')) {
      logger.warn('PaymentSecurity', 'Invalid content type for payment request')
      return false
    }
  }

  return true
}

export function sanitizePaymentData(data: any): any {
  // Remove any potentially dangerous fields
  const sanitized = { ...data }
  delete sanitized.password
  delete sanitized.ssn
  delete sanitized.creditCard

  // Validate amount is positive number
  if (sanitized.amount && (typeof sanitized.amount !== 'number' || sanitized.amount <= 0)) {
    throw new Error('Invalid payment amount')
  }

  return sanitized
}

export function generateIdempotencyKey(): string {
  return crypto.randomUUID()
}

export function validateWebhookTimestamp(timestamp: string): boolean {
  const webhookTimestamp = parseInt(timestamp)
  const currentTime = Math.floor(Date.now() / 1000)
  const timeDifference = Math.abs(currentTime - webhookTimestamp)

  // Reject webhooks older than 5 minutes
  return timeDifference <= 300
}
```

**Step 2: Create Unit Tests for Stripe Service**
1. Create a new file `tests/unit/model/stripeService.test.ts`
2. Implement comprehensive unit tests:

```typescript
import { stripeService } from '@/model/stripeService'
import Stripe from 'stripe'

// Mock Stripe
jest.mock('stripe')
const mockStripe = {
  customers: {
    create: jest.fn(),
  },
  subscriptions: {
    create: jest.fn(),
  },
  paymentIntents: {
    create: jest.fn(),
  },
  webhooks: {
    constructEvent: jest.fn(),
  },
}

describe('StripeService', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(Stripe as jest.MockedClass<typeof Stripe>).mockImplementation(() => mockStripe as any)
  })

  describe('createCustomer', () => {
    it('should create a customer successfully', async () => {
      const mockCustomer = { id: 'cus_test123', email: 'test@example.com' }
      mockStripe.customers.create.mockResolvedValue(mockCustomer)

      const result = await stripeService.createCustomer('test@example.com', 'Test User')

      expect(mockStripe.customers.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        name: 'Test User',
        metadata: { source: 'business_scraper_app' }
      })
      expect(result).toEqual(mockCustomer)
    })

    it('should handle customer creation errors', async () => {
      mockStripe.customers.create.mockRejectedValue(new Error('Stripe error'))

      await expect(stripeService.createCustomer('test@example.com')).rejects.toThrow('Stripe error')
    })
  })

  describe('createPaymentIntent', () => {
    it('should create payment intent successfully', async () => {
      const mockPaymentIntent = { id: 'pi_test123', client_secret: 'pi_test123_secret' }
      mockStripe.paymentIntents.create.mockResolvedValue(mockPaymentIntent)

      const result = await stripeService.createPaymentIntent(2000, 'usd')

      expect(mockStripe.paymentIntents.create).toHaveBeenCalledWith({
        amount: 2000,
        currency: 'usd',
        customer: undefined,
        automatic_payment_methods: { enabled: true },
      })
      expect(result).toEqual(mockPaymentIntent)
    })

    it('should validate payment amount', async () => {
      await expect(stripeService.createPaymentIntent(-100)).rejects.toThrow()
    })
  })

  describe('verifyWebhookSignature', () => {
    it('should verify webhook signature successfully', () => {
      const mockEvent = { type: 'payment_intent.succeeded', data: {} }
      mockStripe.webhooks.constructEvent.mockReturnValue(mockEvent)

      const result = stripeService.verifyWebhookSignature('payload', 'signature')

      expect(mockStripe.webhooks.constructEvent).toHaveBeenCalledWith(
        'payload',
        'signature',
        expect.any(String)
      )
      expect(result).toEqual(mockEvent)
    })

    it('should handle invalid webhook signatures', () => {
      mockStripe.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('Invalid signature')
      })

      expect(() => {
        stripeService.verifyWebhookSignature('payload', 'invalid_signature')
      }).toThrow('Invalid signature')
    })
  })
})
```

**Step 3: Create Integration Tests for Payment API**
1. Create a new file `tests/integration/api/payments.test.ts`:

```typescript
import { NextRequest } from 'next/server'
import { POST } from '@/app/api/payments/route'

describe('/api/payments', () => {
  it('should create payment intent with valid data', async () => {
    const request = new NextRequest('http://localhost:3000/api/payments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: 2000,
        currency: 'usd',
        description: 'Test payment'
      })
    })

    const response = await POST(request)
    const data = await response.json()

    expect(response.status).toBe(200)
    expect(data).toHaveProperty('clientSecret')
    expect(data).toHaveProperty('paymentIntentId')
  })

  it('should reject invalid payment amounts', async () => {
    const request = new NextRequest('http://localhost:3000/api/payments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        amount: -100,
        currency: 'usd'
      })
    })

    const response = await POST(request)
    expect(response.status).toBe(400)
  })
})
```

**Validation Steps:**
- Run all unit tests and ensure they pass
- Verify security middleware blocks invalid requests
- Test webhook signature validation with mock data
- Check that payment API handles edge cases properly

**Next Steps:**
Proceed to Prompt 9 for final integration and deployment.

---

## Prompt 9: Final Integration and Documentation Updates

### Objective
Complete the Stripe integration by updating existing components, adding feature gates, and updating all documentation.

### Instructions for AI Assistant

**Step 1: Update Main App Component for Payment Integration**
1. Open `src/view/components/App.tsx`
2. Add payment-related imports and integrate subscription status:

```typescript
import { usePaymentController } from '@/controller/usePaymentController'
import { useFeatureAccess } from '@/controller/useFeatureAccess'
import { SubscriptionPlans } from './SubscriptionPlans'
import { PaymentForm } from './PaymentForm'

// Add to the main App component
const { currentSubscription, isProcessing } = usePaymentController()
const { canExportAdvanced, canUseAdvancedSearch, scrapingQuotaRemaining } = useFeatureAccess(userId)

// Add subscription status indicator to the header
<div className="subscription-status">
  {currentSubscription ? (
    <span className="text-green-600">Premium Active</span>
  ) : (
    <span className="text-gray-600">Free Plan</span>
  )}
  <span className="ml-2">Quota: {scrapingQuotaRemaining}</span>
</div>
```

**Step 2: Add Feature Gates to Existing Functionality**
1. Open the main scraping component (likely in `src/view/components/`)
2. Add feature access checks before premium operations:

```typescript
// Before advanced export functionality
const handleAdvancedExport = async () => {
  if (!canExportAdvanced) {
    // Show upgrade prompt
    setShowUpgradeModal(true)
    return
  }

  // Record feature usage
  await useFeature('export', { format: 'advanced' })

  // Proceed with export
  // ... existing export logic
}

// Before advanced search
const handleAdvancedSearch = async () => {
  if (!canUseAdvancedSearch) {
    setShowUpgradeModal(true)
    return
  }

  await useFeature('advanced_search')
  // ... existing search logic
}

// Before each scraping request
const handleScrapingRequest = async () => {
  if (scrapingQuotaRemaining <= 0) {
    setShowUpgradeModal(true)
    return
  }

  await useFeature('scraping_request')
  // ... existing scraping logic
}
```

**Step 3: Create Feature Access API Endpoints**
1. Create `src/app/api/features/access/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { paymentStorage } from '@/model/paymentStorage'

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const featureType = searchParams.get('type')
    const userId = searchParams.get('userId') // Get from session/auth

    if (!featureType || !userId) {
      return NextResponse.json({ error: 'Missing parameters' }, { status: 400 })
    }

    // Check user's subscription
    const subscription = await paymentStorage.getUserActiveSubscription(userId)

    let hasAccess = false

    if (subscription && subscription.status === 'active') {
      // Check feature access based on plan
      const planFeatures = subscription.features || {}
      hasAccess = planFeatures[featureType] === true
    } else {
      // Free tier access
      hasAccess = ['basic_export', 'basic_search'].includes(featureType)
    }

    return NextResponse.json({ hasAccess })
  } catch (error) {
    return NextResponse.json({ error: 'Failed to check access' }, { status: 500 })
  }
}
```

2. Create `src/app/api/features/usage/route.ts`:

```typescript
import { NextRequest, NextResponse } from 'next/server'
import { paymentStorage } from '@/model/paymentStorage'

export async function POST(request: NextRequest) {
  try {
    const { featureType, metadata, userId } = await request.json()

    await paymentStorage.recordFeatureUsage({
      userId,
      featureType,
      usageCount: 1,
      date: new Date(),
      metadata
    })

    return NextResponse.json({ success: true })
  } catch (error) {
    return NextResponse.json({ error: 'Failed to record usage' }, { status: 500 })
  }
}
```

**Step 4: Update Documentation Files**
1. Update `README.md` to include payment system information:

```markdown
## Payment System

The Business Scraper App includes a comprehensive Stripe-based payment system with:

- **Subscription Management**: Monthly and yearly plans with different feature tiers
- **Feature Access Control**: Premium features gated behind subscription status
- **Usage Tracking**: Monitor and limit feature usage based on plan
- **Secure Payments**: PCI-compliant payment processing via Stripe

### Payment Features

- **Free Tier**: Basic scraping (limited quota), standard exports
- **Premium Tier**: Advanced exports, increased quotas, premium industries
- **Enterprise Tier**: Unlimited usage, priority support, custom integrations

### Setup

1. Configure Stripe API keys in environment variables
2. Run database migrations for payment tables
3. Configure webhook endpoints in Stripe dashboard
4. Test payment flows with Stripe test cards
```

2. Update `CHANGELOG.md`:

```markdown
## [1.1.0] - 2025-08-29

### Added
- Complete Stripe payment integration
- Subscription management system
- Feature access control and usage tracking
- Payment security middleware
- Comprehensive payment API endpoints
- React components for payment forms and subscription plans
- Unit and integration tests for payment functionality

### Changed
- Updated main app component to include subscription status
- Added feature gates to premium functionality
- Enhanced configuration system for payment settings

### Security
- Implemented PCI-compliant payment processing
- Added webhook signature verification
- Enhanced API security for payment endpoints
```

3. Update `VERSION` file:

```
1.1.0
```

**Step 5: Final Testing and Validation**
1. Run the complete test suite:

```bash
npm test
npm run test:e2e
```

2. Test payment flows with Stripe test cards:
   - Successful payment: 4242424242424242
   - Declined payment: 4000000000000002
   - Requires authentication: 4000002500003155

3. Verify webhook endpoints receive and process events correctly

4. Test feature access controls work as expected

**Validation Steps:**
- All tests pass successfully
- Payment forms render and function correctly
- Subscription plans display properly
- Feature gates prevent unauthorized access
- Documentation is complete and accurate
- Version numbers are updated consistently

**Final Deliverables:**
✅ Complete Stripe payment system integrated
✅ Feature access control implemented
✅ Comprehensive testing suite
✅ Security measures in place
✅ Documentation updated
✅ Ready for production deployment

**Post-Implementation Notes:**
- Configure production Stripe keys before deployment
- Set up monitoring for payment events
- Train support team on subscription management
- Monitor usage patterns and adjust quotas as needed

---

## Summary

This series of AI prompts provides a complete, step-by-step implementation guide for integrating Stripe payments into the Business Scraper App. Each prompt builds upon the previous work and includes detailed validation steps to ensure proper implementation.

The implementation follows the project's MVC architecture, maintains security best practices, and includes comprehensive testing. The result is a production-ready payment system with subscription management, feature access control, and usage tracking.

**Total Implementation Time Estimate:** 8-12 hours for an experienced developer following these prompts sequentially.

**Key Benefits:**
- Monetization through subscription tiers
- Controlled access to premium features
- Scalable usage tracking system
- PCI-compliant payment processing
- Comprehensive error handling and logging

