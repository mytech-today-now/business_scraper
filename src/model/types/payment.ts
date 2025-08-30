/**
 * Payment Models and Data Structures
 * Comprehensive TypeScript models and Zod schemas for payment-related data
 * with validation and type safety
 */

import { z } from 'zod'

// ============================================================================
// TYPESCRIPT INTERFACES
// ============================================================================

/**
 * Subscription Plan Types
 * Defines available subscription plans with pricing and features
 */
export interface SubscriptionPlan {
  id: string
  stripePriceId: string
  name: string
  description: string
  priceCents: number
  currency: string
  interval: 'month' | 'year'
  features: string[]
  isActive: boolean
  createdAt: Date
}

/**
 * User Subscription Types
 * Tracks user subscription status and billing information
 */
export interface UserSubscription {
  id: string
  userId: string
  stripeSubscriptionId: string
  planId: string
  status: 'active' | 'canceled' | 'past_due' | 'unpaid' | 'incomplete'
  currentPeriodStart: Date
  currentPeriodEnd: Date
  cancelAtPeriodEnd: boolean
  createdAt: Date
  updatedAt: Date
}

/**
 * Payment Transaction Types
 * Records all payment transactions and their status
 */
export interface PaymentTransaction {
  id: string
  userId: string
  stripePaymentIntentId?: string
  amountCents: number
  currency: string
  status: 'pending' | 'succeeded' | 'failed' | 'canceled'
  description: string
  metadata?: Record<string, any>
  createdAt: Date
}

/**
 * Feature Usage Types
 * Tracks user feature usage for billing and analytics
 */
export interface FeatureUsage {
  id: string
  userId: string
  featureType: 'scraping_request' | 'export' | 'advanced_search' | 'api_access'
  usageCount: number
  date: Date
  metadata?: Record<string, any>
  createdAt: Date
}

// ============================================================================
// ZOD VALIDATION SCHEMAS
// ============================================================================

/**
 * Subscription Plan Schema
 * Validates subscription plan data with comprehensive rules
 */
export const SubscriptionPlanSchema = z.object({
  id: z.string().min(1, 'Plan ID is required').max(100, 'Plan ID too long'),
  stripePriceId: z.string().min(1, 'Stripe Price ID is required').max(200, 'Stripe Price ID too long'),
  name: z.string().min(1, 'Plan name is required').max(100, 'Plan name too long'),
  description: z.string().min(1, 'Plan description is required').max(500, 'Plan description too long'),
  priceCents: z.number().int().min(0, 'Price must be non-negative').max(10000000, 'Price too high'),
  currency: z.string().length(3, 'Currency must be 3 characters').regex(/^[A-Z]{3}$/, 'Currency must be uppercase'),
  interval: z.enum(['month', 'year'], { errorMap: () => ({ message: 'Interval must be month or year' }) }),
  features: z.array(z.string().min(1, 'Feature cannot be empty')).min(1, 'At least one feature required'),
  isActive: z.boolean(),
  createdAt: z.date()
})

/**
 * User Subscription Schema
 * Validates user subscription data with status constraints
 */
export const UserSubscriptionSchema = z.object({
  id: z.string().min(1, 'Subscription ID is required').max(100, 'Subscription ID too long'),
  userId: z.string().min(1, 'User ID is required').max(100, 'User ID too long'),
  stripeSubscriptionId: z.string().min(1, 'Stripe Subscription ID is required').max(200, 'Stripe Subscription ID too long'),
  planId: z.string().min(1, 'Plan ID is required').max(100, 'Plan ID too long'),
  status: z.enum(['active', 'canceled', 'past_due', 'unpaid', 'incomplete'], {
    errorMap: () => ({ message: 'Invalid subscription status' })
  }),
  currentPeriodStart: z.date(),
  currentPeriodEnd: z.date(),
  cancelAtPeriodEnd: z.boolean(),
  createdAt: z.date(),
  updatedAt: z.date()
}).refine(
  (data) => data.currentPeriodEnd > data.currentPeriodStart,
  {
    message: 'Current period end must be after start',
    path: ['currentPeriodEnd']
  }
).refine(
  (data) => data.updatedAt >= data.createdAt,
  {
    message: 'Updated date must be after or equal to created date',
    path: ['updatedAt']
  }
)

/**
 * Payment Transaction Schema
 * Validates payment transaction data with amount and status rules
 */
export const PaymentTransactionSchema = z.object({
  id: z.string().min(1, 'Transaction ID is required').max(100, 'Transaction ID too long'),
  userId: z.string().min(1, 'User ID is required').max(100, 'User ID too long'),
  stripePaymentIntentId: z.string().max(200, 'Stripe Payment Intent ID too long').optional(),
  amountCents: z.number().int().min(1, 'Amount must be positive').max(10000000, 'Amount too high'),
  currency: z.string().length(3, 'Currency must be 3 characters').regex(/^[A-Z]{3}$/, 'Currency must be uppercase'),
  status: z.enum(['pending', 'succeeded', 'failed', 'canceled'], {
    errorMap: () => ({ message: 'Invalid payment status' })
  }),
  description: z.string().min(1, 'Description is required').max(500, 'Description too long'),
  metadata: z.record(z.any()).optional(),
  createdAt: z.date()
})

/**
 * Feature Usage Schema
 * Validates feature usage tracking data
 */
export const FeatureUsageSchema = z.object({
  id: z.string().min(1, 'Usage ID is required').max(100, 'Usage ID too long'),
  userId: z.string().min(1, 'User ID is required').max(100, 'User ID too long'),
  featureType: z.enum(['scraping_request', 'export', 'advanced_search', 'api_access'], {
    errorMap: () => ({ message: 'Invalid feature type' })
  }),
  usageCount: z.number().int().min(1, 'Usage count must be positive').max(1000000, 'Usage count too high'),
  date: z.date(),
  metadata: z.record(z.any()).optional(),
  createdAt: z.date()
}).refine(
  (data) => data.date <= data.createdAt,
  {
    message: 'Usage date cannot be in the future relative to creation',
    path: ['date']
  }
)

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

/**
 * Validate subscription plan data
 * @param data - Raw subscription plan data
 * @returns Validation result with parsed data or errors
 */
export function validateSubscriptionPlan(data: unknown): {
  success: boolean
  data?: SubscriptionPlan
  errors?: string[]
} {
  try {
    const parsed = SubscriptionPlanSchema.parse(data)
    return { success: true, data: parsed }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        errors: error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
      }
    }
    return { success: false, errors: ['Unknown validation error'] }
  }
}

/**
 * Validate user subscription data
 * @param data - Raw user subscription data
 * @returns Validation result with parsed data or errors
 */
export function validateUserSubscription(data: unknown): {
  success: boolean
  data?: UserSubscription
  errors?: string[]
} {
  try {
    const parsed = UserSubscriptionSchema.parse(data)
    return { success: true, data: parsed }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        errors: error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
      }
    }
    return { success: false, errors: ['Unknown validation error'] }
  }
}

/**
 * Validate payment transaction data
 * @param data - Raw payment transaction data
 * @returns Validation result with parsed data or errors
 */
export function validatePaymentTransaction(data: unknown): {
  success: boolean
  data?: PaymentTransaction
  errors?: string[]
} {
  try {
    const parsed = PaymentTransactionSchema.parse(data)
    return { success: true, data: parsed }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        errors: error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
      }
    }
    return { success: false, errors: ['Unknown validation error'] }
  }
}

/**
 * Validate feature usage data
 * @param data - Raw feature usage data
 * @returns Validation result with parsed data or errors
 */
export function validateFeatureUsage(data: unknown): {
  success: boolean
  data?: FeatureUsage
  errors?: string[]
} {
  try {
    const parsed = FeatureUsageSchema.parse(data)
    return { success: true, data: parsed }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        errors: error.errors.map(err => `${err.path.join('.')}: ${err.message}`)
      }
    }
    return { success: false, errors: ['Unknown validation error'] }
  }
}

// ============================================================================
// TYPE GUARDS
// ============================================================================

/**
 * Type guard for SubscriptionPlan
 */
export function isSubscriptionPlan(obj: unknown): obj is SubscriptionPlan {
  return validateSubscriptionPlan(obj).success
}

/**
 * Type guard for UserSubscription
 */
export function isUserSubscription(obj: unknown): obj is UserSubscription {
  return validateUserSubscription(obj).success
}

/**
 * Type guard for PaymentTransaction
 */
export function isPaymentTransaction(obj: unknown): obj is PaymentTransaction {
  return validatePaymentTransaction(obj).success
}

/**
 * Type guard for FeatureUsage
 */
export function isFeatureUsage(obj: unknown): obj is FeatureUsage {
  return validateFeatureUsage(obj).success
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Convert price from cents to dollars
 * @param priceCents - Price in cents
 * @returns Price in dollars with 2 decimal places
 */
export function centsTodollars(priceCents: number): number {
  return Math.round(priceCents) / 100
}

/**
 * Convert price from dollars to cents
 * @param priceDollars - Price in dollars
 * @returns Price in cents
 */
export function dollarsToCents(priceDollars: number): number {
  return Math.round(priceDollars * 100)
}

/**
 * Format currency amount for display
 * @param amountCents - Amount in cents
 * @param currency - Currency code (e.g., 'USD')
 * @returns Formatted currency string
 */
export function formatCurrency(amountCents: number, currency: string): string {
  const amount = centsTodollars(amountCents)
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency.toUpperCase(),
  }).format(amount)
}

/**
 * Check if subscription is active and current
 * @param subscription - User subscription data
 * @returns True if subscription is active and within current period
 */
export function isSubscriptionActive(subscription: UserSubscription): boolean {
  const now = new Date()
  return (
    subscription.status === 'active' &&
    subscription.currentPeriodStart <= now &&
    subscription.currentPeriodEnd > now
  )
}

/**
 * Calculate days until subscription expires
 * @param subscription - User subscription data
 * @returns Number of days until expiration, or null if already expired
 */
export function getDaysUntilExpiration(subscription: UserSubscription): number | null {
  const now = new Date()
  const expiration = subscription.currentPeriodEnd

  if (expiration <= now) {
    return null // Already expired
  }

  const diffTime = expiration.getTime() - now.getTime()
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  return diffDays
}

/**
 * Get feature usage summary for a user
 * @param usageRecords - Array of feature usage records
 * @param startDate - Start date for summary period
 * @param endDate - End date for summary period
 * @returns Usage summary by feature type
 */
export function getFeatureUsageSummary(
  usageRecords: FeatureUsage[],
  startDate: Date,
  endDate: Date
): Record<string, number> {
  const summary: Record<string, number> = {}

  usageRecords
    .filter(record => record.date >= startDate && record.date <= endDate)
    .forEach(record => {
      summary[record.featureType] = (summary[record.featureType] || 0) + record.usageCount
    })

  return summary
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Supported currencies for payments
 */
export const SUPPORTED_CURRENCIES = ['USD', 'EUR', 'GBP', 'CAD', 'AUD'] as const

/**
 * Valid subscription statuses
 */
export const SUBSCRIPTION_STATUSES = ['active', 'canceled', 'past_due', 'unpaid', 'incomplete'] as const

/**
 * Valid payment statuses
 */
export const PAYMENT_STATUSES = ['pending', 'succeeded', 'failed', 'canceled'] as const

/**
 * Valid feature types for usage tracking
 */
export const FEATURE_TYPES = ['scraping_request', 'export', 'advanced_search', 'api_access'] as const

/**
 * Valid billing intervals
 */
export const BILLING_INTERVALS = ['month', 'year'] as const
