/**
 * Payment-related TypeScript type definitions
 * Comprehensive types for Stripe integration, user payment profiles, and business rules
 */

import Stripe from 'stripe'

// Core payment types
export type PaymentStatus = 'free' | 'trial' | 'active' | 'past_due' | 'canceled' | 'unpaid'
export type SubscriptionTier = 'free' | 'basic' | 'professional' | 'enterprise'
export type PaymentMethod = 'card' | 'bank_transfer' | 'paypal' | 'crypto'

// User payment profile
export interface UserPaymentProfile {
  userId: string
  stripeCustomerId?: string
  email: string
  name?: string
  subscriptionStatus: PaymentStatus
  subscriptionTier: SubscriptionTier
  subscriptionId?: string
  currentPeriodStart?: Date
  currentPeriodEnd?: Date
  cancelAtPeriodEnd?: boolean
  trialEnd?: Date
  defaultPaymentMethodId?: string
  billingAddress?: BillingAddress
  taxId?: string
  createdAt: Date
  updatedAt: Date
}

// Billing address
export interface BillingAddress {
  line1: string
  line2?: string
  city: string
  state?: string
  postalCode: string
  country: string
}

// Subscription plan configuration
export interface SubscriptionPlan {
  id: string
  name: string
  tier: SubscriptionTier
  stripePriceId: string
  monthlyPrice: number
  yearlyPrice?: number
  features: string[]
  limits: PlanLimits
  isPopular?: boolean
  isActive: boolean
}

// Plan limits and features
export interface PlanLimits {
  maxBusinessRecords: number
  maxExportsPerMonth: number
  maxSearchesPerDay: number
  maxConcurrentScrapes: number
  advancedFilters: boolean
  apiAccess: boolean
  prioritySupport: boolean
  customIntegrations: boolean
  whiteLabel: boolean
}

// Payment transaction record
export interface PaymentTransaction {
  id: string
  userId: string
  stripePaymentIntentId?: string
  stripeInvoiceId?: string
  amount: number
  currency: string
  status: 'pending' | 'succeeded' | 'failed' | 'canceled'
  paymentMethod: PaymentMethod
  description: string
  metadata?: Record<string, string>
  createdAt: Date
  updatedAt: Date
}

// Invoice data
export interface Invoice {
  id: string
  userId: string
  stripeInvoiceId: string
  subscriptionId?: string
  amount: number
  currency: string
  status: 'draft' | 'open' | 'paid' | 'void' | 'uncollectible'
  dueDate?: Date
  paidAt?: Date
  invoiceUrl?: string
  invoicePdf?: string
  lineItems: InvoiceLineItem[]
  createdAt: Date
}

// Invoice line item
export interface InvoiceLineItem {
  id: string
  description: string
  quantity: number
  unitAmount: number
  totalAmount: number
  period?: {
    start: Date
    end: Date
  }
}

// Payment method information
export interface PaymentMethodInfo {
  id: string
  type: PaymentMethod
  card?: {
    brand: string
    last4: string
    expMonth: number
    expYear: number
  }
  isDefault: boolean
  createdAt: Date
}

// Business rules for feature access
export interface FeatureAccessRules {
  tier: SubscriptionTier
  rules: {
    canExportData: boolean
    canUseAdvancedFilters: boolean
    canAccessAPI: boolean
    canUseBulkOperations: boolean
    canUseCustomIntegrations: boolean
    maxDailySearches: number
    maxMonthlyExports: number
    maxBusinessRecords: number
    maxConcurrentScrapes: number
  }
}

// Payment analytics data
export interface PaymentAnalytics {
  userId: string
  period: {
    start: Date
    end: Date
  }
  metrics: {
    totalRevenue: number
    subscriptionRevenue: number
    oneTimePayments: number
    refunds: number
    chargeBacks: number
    mrr: number // Monthly Recurring Revenue
    arr: number // Annual Recurring Revenue
    churnRate: number
    ltv: number // Lifetime Value
  }
  subscriptionMetrics: {
    newSubscriptions: number
    canceledSubscriptions: number
    upgrades: number
    downgrades: number
    reactivations: number
  }
}

// Webhook event types
export type StripeWebhookEvent = 
  | 'customer.created'
  | 'customer.updated'
  | 'customer.deleted'
  | 'customer.subscription.created'
  | 'customer.subscription.updated'
  | 'customer.subscription.deleted'
  | 'invoice.created'
  | 'invoice.payment_succeeded'
  | 'invoice.payment_failed'
  | 'payment_intent.succeeded'
  | 'payment_intent.payment_failed'
  | 'payment_method.attached'
  | 'payment_method.detached'

// Webhook processing result
export interface WebhookProcessingResult {
  eventId: string
  eventType: StripeWebhookEvent
  processed: boolean
  error?: string
  actions: string[]
  timestamp: Date
}

// Payment service configuration
export interface PaymentServiceConfig {
  stripeApiVersion: string
  webhookEndpointSecret: string
  defaultCurrency: string
  trialPeriodDays: number
  gracePeriodDays: number
  retryAttempts: number
  enableAnalytics: boolean
  enableAuditLog: boolean
}

// Audit log entry for compliance
export interface PaymentAuditLog {
  id: string
  userId: string
  action: string
  entityType: 'customer' | 'subscription' | 'payment' | 'invoice'
  entityId: string
  oldValues?: Record<string, any>
  newValues?: Record<string, any>
  metadata?: Record<string, string>
  ipAddress?: string
  userAgent?: string
  timestamp: Date
}

// Error types for payment operations
export class PaymentError extends Error {
  constructor(
    message: string,
    public code: string,
    public stripeError?: Stripe.StripeError
  ) {
    super(message)
    this.name = 'PaymentError'
  }
}

export class SubscriptionError extends Error {
  constructor(
    message: string,
    public code: string,
    public subscriptionId?: string
  ) {
    super(message)
    this.name = 'SubscriptionError'
  }
}

export class ValidationError extends Error {
  constructor(
    message: string,
    public field: string,
    public value?: any
  ) {
    super(message)
    this.name = 'ValidationError'
  }
}

// Service response types
export interface ServiceResponse<T> {
  success: boolean
  data?: T
  error?: string
  code?: string
}

export interface PaginatedResponse<T> {
  data: T[]
  hasMore: boolean
  totalCount?: number
  nextCursor?: string
}

// Feature flag types for payment features
export interface PaymentFeatureFlags {
  enableSubscriptions: boolean
  enableOneTimePayments: boolean
  enableTrials: boolean
  enableProration: boolean
  enableTaxCalculation: boolean
  enableInvoiceGeneration: boolean
  enablePaymentMethodManagement: boolean
  enableAnalytics: boolean
  enableAuditLogging: boolean
}
