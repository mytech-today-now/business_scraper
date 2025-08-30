/**
 * Payment API Request and Response Types
 * Comprehensive TypeScript interfaces for payment API interactions
 * with subscription management, payment processing, and feature usage tracking
 */

import { SubscriptionPlan, UserSubscription, PaymentTransaction, FeatureUsage } from './payment'

// ============================================================================
// API REQUEST TYPES
// ============================================================================

/**
 * Request to create a new subscription
 */
export interface CreateSubscriptionRequest {
  /** ID of the subscription plan to subscribe to */
  planId: string
  /** Optional payment method ID from Stripe */
  paymentMethodId?: string
  /** Optional coupon code for discounts */
  couponCode?: string
  /** Optional metadata for the subscription */
  metadata?: Record<string, string>
}

/**
 * Request to create a payment intent
 */
export interface CreatePaymentIntentRequest {
  /** Amount to charge in cents */
  amountCents: number
  /** Currency code (default: 'USD') */
  currency?: string
  /** Description of the payment */
  description: string
  /** Optional metadata for the payment */
  metadata?: Record<string, string>
  /** Optional payment method types to allow */
  paymentMethodTypes?: string[]
}

/**
 * Request to update an existing subscription
 */
export interface UpdateSubscriptionRequest {
  /** New plan ID to switch to */
  planId?: string
  /** Whether to cancel at the end of the current period */
  cancelAtPeriodEnd?: boolean
  /** Optional metadata updates */
  metadata?: Record<string, string>
}

/**
 * Request to cancel a subscription
 */
export interface CancelSubscriptionRequest {
  /** Whether to cancel immediately or at period end */
  immediately?: boolean
  /** Optional reason for cancellation */
  reason?: string
}

/**
 * Request to track feature usage
 */
export interface TrackFeatureUsageRequest {
  /** Type of feature being used */
  featureType: 'scraping_request' | 'export' | 'advanced_search' | 'api_access'
  /** Number of usage units (default: 1) */
  usageCount?: number
  /** Optional metadata for the usage */
  metadata?: Record<string, string>
}

/**
 * Request to get usage analytics
 */
export interface GetUsageAnalyticsRequest {
  /** Start date for analytics period */
  startDate?: string
  /** End date for analytics period */
  endDate?: string
  /** Feature types to include (default: all) */
  featureTypes?: string[]
  /** Grouping period (day, week, month) */
  groupBy?: 'day' | 'week' | 'month'
}

// ============================================================================
// API RESPONSE TYPES
// ============================================================================

/**
 * Response from creating a subscription
 */
export interface CreateSubscriptionResponse {
  /** The created subscription */
  subscription: UserSubscription
  /** Client secret for payment confirmation (if required) */
  clientSecret?: string
  /** Whether additional payment action is required */
  requiresAction: boolean
  /** Payment status */
  paymentStatus: 'succeeded' | 'requires_action' | 'requires_payment_method'
}

/**
 * Response from creating a payment intent
 */
export interface CreatePaymentIntentResponse {
  /** The created payment transaction */
  paymentIntent: PaymentTransaction
  /** Client secret for payment confirmation */
  clientSecret: string
  /** Payment status */
  status: 'requires_payment_method' | 'requires_confirmation' | 'requires_action' | 'processing' | 'succeeded'
}

/**
 * Comprehensive payment status response
 */
export interface PaymentStatusResponse {
  /** Whether user has an active subscription */
  hasActiveSubscription: boolean
  /** Current subscription plan (if any) */
  currentPlan?: SubscriptionPlan
  /** Current subscription details (if any) */
  subscription?: UserSubscription
  /** Recent feature usage records */
  featureUsage: FeatureUsage[]
  /** Usage limits for current plan */
  usageLimits: Record<string, number>
  /** Current usage counts */
  currentUsage: Record<string, number>
  /** Days until subscription expires */
  daysUntilExpiration?: number
  /** Whether user is approaching usage limits */
  approachingLimits: boolean
}

/**
 * Response from updating a subscription
 */
export interface UpdateSubscriptionResponse {
  /** Updated subscription */
  subscription: UserSubscription
  /** Whether the update was successful */
  success: boolean
  /** Any messages about the update */
  message?: string
  /** Whether immediate payment is required */
  requiresPayment?: boolean
  /** Client secret if payment is required */
  clientSecret?: string
}

/**
 * Response from canceling a subscription
 */
export interface CancelSubscriptionResponse {
  /** Updated subscription with cancellation details */
  subscription: UserSubscription
  /** Whether cancellation was successful */
  success: boolean
  /** Cancellation effective date */
  effectiveDate: string
  /** Any refund information */
  refundInfo?: {
    amount: number
    currency: string
    refundId: string
  }
}

/**
 * Response from tracking feature usage
 */
export interface TrackFeatureUsageResponse {
  /** Created usage record */
  usage: FeatureUsage
  /** Updated usage totals */
  totalUsage: Record<string, number>
  /** Remaining usage allowance */
  remainingUsage: Record<string, number>
  /** Whether user has exceeded limits */
  limitExceeded: boolean
  /** Warning if approaching limits */
  limitWarning?: string
}

/**
 * Response from getting usage analytics
 */
export interface GetUsageAnalyticsResponse {
  /** Usage data grouped by time period */
  analytics: Array<{
    period: string
    usage: Record<string, number>
    totalUsage: number
  }>
  /** Summary statistics */
  summary: {
    totalUsage: Record<string, number>
    averageDaily: Record<string, number>
    peakUsage: Record<string, number>
    peakDate: string
  }
  /** Current billing period info */
  billingPeriod: {
    start: string
    end: string
    daysRemaining: number
  }
}

/**
 * Response from getting available plans
 */
export interface GetPlansResponse {
  /** Available subscription plans */
  plans: SubscriptionPlan[]
  /** Current user's plan (if any) */
  currentPlan?: SubscriptionPlan
  /** Recommended plan based on usage */
  recommendedPlan?: SubscriptionPlan
}

/**
 * Response from getting payment history
 */
export interface GetPaymentHistoryResponse {
  /** Payment transaction history */
  transactions: PaymentTransaction[]
  /** Total number of transactions */
  totalCount: number
  /** Pagination info */
  pagination: {
    page: number
    limit: number
    hasMore: boolean
  }
}

// ============================================================================
// ERROR RESPONSE TYPES
// ============================================================================

/**
 * Standard API error response
 */
export interface ApiErrorResponse {
  /** Error code */
  code: string
  /** Human-readable error message */
  message: string
  /** Additional error details */
  details?: Record<string, any>
  /** Request ID for debugging */
  requestId?: string
  /** Timestamp of the error */
  timestamp: string
}

/**
 * Payment-specific error response
 */
export interface PaymentErrorResponse extends ApiErrorResponse {
  /** Payment-specific error type */
  type: 'card_error' | 'validation_error' | 'api_error' | 'authentication_error' | 'rate_limit_error'
  /** Decline code (for card errors) */
  declineCode?: string
  /** Suggested action for the user */
  suggestedAction?: string
}

// ============================================================================
// UTILITY TYPES
// ============================================================================

/**
 * Pagination parameters for list requests
 */
export interface PaginationParams {
  /** Page number (1-based) */
  page?: number
  /** Number of items per page */
  limit?: number
  /** Sort field */
  sortBy?: string
  /** Sort direction */
  sortOrder?: 'asc' | 'desc'
}

/**
 * Date range filter
 */
export interface DateRangeFilter {
  /** Start date (ISO string) */
  startDate?: string
  /** End date (ISO string) */
  endDate?: string
}

/**
 * Generic API response wrapper
 */
export interface ApiResponse<T> {
  /** Response data */
  data: T
  /** Success status */
  success: boolean
  /** Optional message */
  message?: string
  /** Request metadata */
  meta?: {
    requestId: string
    timestamp: string
    version: string
  }
}

/**
 * Webhook event types for payment notifications
 */
export type PaymentWebhookEvent = 
  | 'subscription.created'
  | 'subscription.updated'
  | 'subscription.deleted'
  | 'payment.succeeded'
  | 'payment.failed'
  | 'invoice.payment_succeeded'
  | 'invoice.payment_failed'
  | 'customer.subscription.trial_will_end'
