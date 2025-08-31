/**
 * Payment Validation Schemas
 * Comprehensive Zod validation schemas for payment system components
 * Following existing validation patterns from src/utils/validation.ts
 */

import { z } from 'zod'

// ============================================================================
// VALIDATION CONSTANTS
// ============================================================================

/**
 * UUID validation regex pattern
 */
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

/**
 * Currency code validation regex (ISO 4217)
 */
const CURRENCY_REGEX = /^[A-Z]{3}$/

/**
 * Stripe ID patterns
 */
const STRIPE_PRICE_ID_REGEX = /^price_[a-zA-Z0-9]{24,}$/
const STRIPE_SUBSCRIPTION_ID_REGEX = /^sub_[a-zA-Z0-9]{24,}$/
const STRIPE_PAYMENT_INTENT_ID_REGEX = /^pi_[a-zA-Z0-9]{24,}$/

// ============================================================================
// SUBSCRIPTION PLAN SCHEMA
// ============================================================================

/**
 * Subscription Plan Schema
 * Validates subscription plan data with comprehensive rules
 */
export const subscriptionPlanSchema = z
  .object({
    id: z
      .string()
      .uuid('Invalid UUID format for plan ID')
      .describe('Unique identifier for the subscription plan'),

    stripePriceId: z
      .string()
      .regex(STRIPE_PRICE_ID_REGEX, 'Invalid Stripe price ID format')
      .describe('Stripe price ID for billing integration'),

    name: z
      .string()
      .min(1, 'Plan name is required')
      .max(255, 'Plan name cannot exceed 255 characters')
      .describe('Display name of the subscription plan'),

    description: z.string().optional().describe('Optional description of the plan features'),

    priceCents: z
      .number()
      .int('Price must be an integer')
      .min(0, 'Price cannot be negative')
      .max(10000000, 'Price cannot exceed $100,000')
      .describe('Price in cents (e.g., 2999 for $29.99)'),

    currency: z
      .string()
      .length(3, 'Currency must be exactly 3 characters')
      .regex(CURRENCY_REGEX, 'Currency must be uppercase ISO 4217 code')
      .default('USD')
      .describe('Currency code (ISO 4217)'),

    interval: z
      .enum(['month', 'year'], {
        errorMap: () => ({ message: 'Interval must be either "month" or "year"' }),
      })
      .describe('Billing interval'),

    features: z
      .array(z.string().min(1, 'Feature description cannot be empty'))
      .min(1, 'At least one feature must be specified')
      .describe('List of features included in this plan'),

    isActive: z
      .boolean()
      .default(true)
      .describe('Whether this plan is currently available for subscription'),

    createdAt: z.date().describe('When this plan was created'),
  })
  .strict()

// ============================================================================
// USER SUBSCRIPTION SCHEMA
// ============================================================================

/**
 * User Subscription Schema
 * Validates user subscription data with status and date constraints
 */
export const userSubscriptionSchema = z
  .object({
    id: z
      .string()
      .uuid('Invalid UUID format for subscription ID')
      .describe('Unique identifier for the user subscription'),

    userId: z
      .string()
      .uuid('Invalid UUID format for user ID')
      .describe('ID of the user who owns this subscription'),

    stripeSubscriptionId: z
      .string()
      .regex(STRIPE_SUBSCRIPTION_ID_REGEX, 'Invalid Stripe subscription ID format')
      .describe('Stripe subscription ID for billing integration'),

    planId: z
      .string()
      .uuid('Invalid UUID format for plan ID')
      .describe('ID of the subscription plan'),

    status: z
      .enum(['active', 'canceled', 'past_due', 'unpaid', 'incomplete'], {
        errorMap: () => ({ message: 'Invalid subscription status' }),
      })
      .describe('Current status of the subscription'),

    currentPeriodStart: z.date().describe('Start date of the current billing period'),

    currentPeriodEnd: z.date().describe('End date of the current billing period'),

    cancelAtPeriodEnd: z
      .boolean()
      .default(false)
      .describe('Whether subscription will cancel at the end of current period'),

    createdAt: z.date().describe('When this subscription was created'),

    updatedAt: z.date().describe('When this subscription was last updated'),
  })
  .strict()
  .refine(data => data.currentPeriodEnd > data.currentPeriodStart, {
    message: 'Current period end must be after start date',
    path: ['currentPeriodEnd'],
  })
  .refine(data => data.updatedAt >= data.createdAt, {
    message: 'Updated date must be after or equal to created date',
    path: ['updatedAt'],
  })

// ============================================================================
// PAYMENT TRANSACTION SCHEMA
// ============================================================================

/**
 * Payment Transaction Schema
 * Validates payment transaction data with amount and status rules
 */
export const paymentTransactionSchema = z
  .object({
    id: z
      .string()
      .uuid('Invalid UUID format for transaction ID')
      .describe('Unique identifier for the payment transaction'),

    userId: z
      .string()
      .uuid('Invalid UUID format for user ID')
      .describe('ID of the user who made this payment'),

    stripePaymentIntentId: z
      .string()
      .regex(STRIPE_PAYMENT_INTENT_ID_REGEX, 'Invalid Stripe payment intent ID format')
      .optional()
      .describe('Stripe payment intent ID (if applicable)'),

    amountCents: z
      .number()
      .int('Amount must be an integer')
      .min(0, 'Amount cannot be negative')
      .max(10000000, 'Amount cannot exceed $100,000')
      .describe('Payment amount in cents'),

    currency: z
      .string()
      .length(3, 'Currency must be exactly 3 characters')
      .regex(CURRENCY_REGEX, 'Currency must be uppercase ISO 4217 code')
      .default('USD')
      .describe('Currency code (ISO 4217)'),

    status: z
      .enum(['pending', 'succeeded', 'failed', 'canceled'], {
        errorMap: () => ({ message: 'Invalid payment status' }),
      })
      .describe('Current status of the payment'),

    description: z
      .string()
      .min(1, 'Description is required')
      .max(500, 'Description cannot exceed 500 characters')
      .describe('Description of what this payment is for'),

    metadata: z.record(z.any()).optional().describe('Additional metadata for the payment'),

    createdAt: z.date().describe('When this payment was created'),
  })
  .strict()

// ============================================================================
// FEATURE USAGE SCHEMA
// ============================================================================

/**
 * Feature Usage Schema
 * Validates feature usage tracking data with business logic constraints
 */
export const featureUsageSchema = z
  .object({
    id: z
      .string()
      .uuid('Invalid UUID format for usage ID')
      .describe('Unique identifier for the usage record'),

    userId: z
      .string()
      .uuid('Invalid UUID format for user ID')
      .describe('ID of the user who used this feature'),

    featureType: z
      .enum(['scraping_request', 'export', 'advanced_search', 'api_access'], {
        errorMap: () => ({ message: 'Invalid feature type' }),
      })
      .describe('Type of feature that was used'),

    usageCount: z
      .number()
      .int('Usage count must be an integer')
      .min(1, 'Usage count must be at least 1')
      .default(1)
      .describe('Number of times the feature was used'),

    date: z.date().describe('Date when the feature was used'),

    metadata: z.record(z.any()).optional().describe('Additional metadata about the usage'),

    createdAt: z.date().describe('When this usage record was created'),
  })
  .strict()
  .refine(data => data.date <= data.createdAt, {
    message: 'Usage date cannot be in the future relative to creation time',
    path: ['date'],
  })

// ============================================================================
// EXPORTED SCHEMAS
// ============================================================================

export {
  subscriptionPlanSchema,
  userSubscriptionSchema,
  paymentTransactionSchema,
  featureUsageSchema,
}

// ============================================================================
// TYPE INFERENCE
// ============================================================================

export type SubscriptionPlan = z.infer<typeof subscriptionPlanSchema>
export type UserSubscription = z.infer<typeof userSubscriptionSchema>
export type PaymentTransaction = z.infer<typeof paymentTransactionSchema>
export type FeatureUsage = z.infer<typeof featureUsageSchema>
