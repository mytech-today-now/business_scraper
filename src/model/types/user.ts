/**
 * User Models and Data Structures
 * Comprehensive TypeScript models and Zod schemas for user management
 * with payment integration and usage tracking
 */

import { z } from 'zod'

// ============================================================================
// TYPESCRIPT INTERFACES
// ============================================================================

/**
 * Billing Address Interface
 * Stores user billing information for payment processing
 */
export interface BillingAddress {
  line1: string
  line2?: string
  city: string
  state: string
  postalCode: string
  country: string
}

/**
 * Usage Quotas Interface
 * Tracks user feature usage limits and current consumption
 */
export interface UsageQuotas {
  scrapingRequests: {
    used: number
    limit: number
    resetDate: Date
  }
  exports: {
    used: number
    limit: number
    resetDate: Date
  }
  advancedSearches: {
    used: number
    limit: number
    resetDate: Date
  }
  apiCalls: {
    used: number
    limit: number
    resetDate: Date
  }
}

/**
 * User Interface
 * Complete user model with authentication, payment, and usage tracking
 */
export interface User {
  id: string
  email: string
  name: string
  
  // Authentication fields
  passwordHash?: string
  passwordSalt?: string
  emailVerified: boolean
  emailVerificationToken?: string
  passwordResetToken?: string
  passwordResetExpires?: Date
  
  // Payment-related fields
  stripeCustomerId?: string
  subscriptionStatus: 'free' | 'active' | 'past_due' | 'canceled' | 'incomplete'
  subscriptionPlan?: string
  subscriptionEndsAt?: Date
  paymentMethodLast4?: string
  paymentMethodBrand?: string
  billingAddress?: BillingAddress
  
  // Usage tracking
  usageQuotas: UsageQuotas
  
  // Profile information
  profilePicture?: string
  phoneNumber?: string
  timezone?: string
  language?: string
  
  // Account status
  isActive: boolean
  lastLoginAt?: Date
  loginAttempts: number
  lockedUntil?: Date
  
  // Timestamps
  createdAt: Date
  updatedAt: Date
}

/**
 * User Profile Update Interface
 * Subset of user fields that can be updated by the user
 */
export interface UserProfileUpdate {
  name?: string
  email?: string
  phoneNumber?: string
  timezone?: string
  language?: string
  profilePicture?: string
  billingAddress?: BillingAddress
}

/**
 * User Registration Interface
 * Required fields for user registration
 */
export interface UserRegistration {
  email: string
  name: string
  password: string
  timezone?: string
  language?: string
}

// ============================================================================
// ZOD VALIDATION SCHEMAS
// ============================================================================

/**
 * Billing Address Schema
 * Validates billing address data with comprehensive rules
 */
export const BillingAddressSchema = z.object({
  line1: z.string().min(1, 'Address line 1 is required').max(100, 'Address line 1 too long'),
  line2: z.string().max(100, 'Address line 2 too long').optional(),
  city: z.string().min(1, 'City is required').max(50, 'City name too long'),
  state: z.string().min(1, 'State is required').max(50, 'State name too long'),
  postalCode: z.string().min(1, 'Postal code is required').max(20, 'Postal code too long'),
  country: z.string().length(2, 'Country must be 2-letter code').regex(/^[A-Z]{2}$/, 'Country must be uppercase')
})

/**
 * Usage Quota Item Schema
 * Validates individual quota tracking
 */
const UsageQuotaItemSchema = z.object({
  used: z.number().int().min(0, 'Usage count cannot be negative'),
  limit: z.number().int().min(-1, 'Limit must be -1 (unlimited) or positive'),
  resetDate: z.date()
})

/**
 * Usage Quotas Schema
 * Validates complete usage quota structure
 */
export const UsageQuotasSchema = z.object({
  scrapingRequests: UsageQuotaItemSchema,
  exports: UsageQuotaItemSchema,
  advancedSearches: UsageQuotaItemSchema,
  apiCalls: UsageQuotaItemSchema
})

/**
 * User Schema
 * Validates complete user data with comprehensive rules
 */
export const UserSchema = z.object({
  id: z.string().min(1, 'User ID is required').max(100, 'User ID too long'),
  email: z.string().email('Invalid email format').max(255, 'Email too long'),
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  
  // Authentication fields
  passwordHash: z.string().max(255, 'Password hash too long').optional(),
  passwordSalt: z.string().max(255, 'Password salt too long').optional(),
  emailVerified: z.boolean(),
  emailVerificationToken: z.string().max(255, 'Verification token too long').optional(),
  passwordResetToken: z.string().max(255, 'Reset token too long').optional(),
  passwordResetExpires: z.date().optional(),
  
  // Payment-related fields
  stripeCustomerId: z.string().max(255, 'Stripe customer ID too long').optional(),
  subscriptionStatus: z.enum(['free', 'active', 'past_due', 'canceled', 'incomplete'], {
    errorMap: () => ({ message: 'Invalid subscription status' })
  }),
  subscriptionPlan: z.string().max(100, 'Subscription plan too long').optional(),
  subscriptionEndsAt: z.date().optional(),
  paymentMethodLast4: z.string().length(4, 'Last 4 digits must be exactly 4 characters').regex(/^\d{4}$/, 'Last 4 must be digits').optional(),
  paymentMethodBrand: z.string().max(50, 'Payment method brand too long').optional(),
  billingAddress: BillingAddressSchema.optional(),
  
  // Usage tracking
  usageQuotas: UsageQuotasSchema,
  
  // Profile information
  profilePicture: z.string().url('Invalid profile picture URL').optional(),
  phoneNumber: z.string().max(20, 'Phone number too long').optional(),
  timezone: z.string().max(50, 'Timezone too long').optional(),
  language: z.string().length(2, 'Language must be 2-letter code').optional(),
  
  // Account status
  isActive: z.boolean(),
  lastLoginAt: z.date().optional(),
  loginAttempts: z.number().int().min(0, 'Login attempts cannot be negative').max(100, 'Login attempts too high'),
  lockedUntil: z.date().optional(),
  
  // Timestamps
  createdAt: z.date(),
  updatedAt: z.date()
}).refine(
  (data) => data.updatedAt >= data.createdAt,
  {
    message: 'Updated date must be after or equal to created date',
    path: ['updatedAt']
  }
).refine(
  (data) => !data.passwordResetExpires || data.passwordResetExpires > new Date(),
  {
    message: 'Password reset expiration must be in the future',
    path: ['passwordResetExpires']
  }
)

/**
 * User Profile Update Schema
 * Validates user profile update data
 */
export const UserProfileUpdateSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name too long').optional(),
  email: z.string().email('Invalid email format').max(255, 'Email too long').optional(),
  phoneNumber: z.string().max(20, 'Phone number too long').optional(),
  timezone: z.string().max(50, 'Timezone too long').optional(),
  language: z.string().length(2, 'Language must be 2-letter code').optional(),
  profilePicture: z.string().url('Invalid profile picture URL').optional(),
  billingAddress: BillingAddressSchema.optional()
})

/**
 * User Registration Schema
 * Validates user registration data
 */
export const UserRegistrationSchema = z.object({
  email: z.string().email('Invalid email format').max(255, 'Email too long'),
  name: z.string().min(1, 'Name is required').max(100, 'Name too long'),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128, 'Password too long'),
  timezone: z.string().max(50, 'Timezone too long').optional(),
  language: z.string().length(2, 'Language must be 2-letter code').optional()
})

// ============================================================================
// VALIDATION FUNCTIONS
// ============================================================================

/**
 * Validate user data
 * @param data - Raw user data
 * @returns Validation result with parsed data or errors
 */
export function validateUser(data: unknown): {
  success: boolean
  data?: User
  errors?: string[]
} {
  try {
    const parsed = UserSchema.parse(data)
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
 * Validate user profile update data
 * @param data - Raw user profile update data
 * @returns Validation result with parsed data or errors
 */
export function validateUserProfileUpdate(data: unknown): {
  success: boolean
  data?: UserProfileUpdate
  errors?: string[]
} {
  try {
    const parsed = UserProfileUpdateSchema.parse(data)
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
 * Validate user registration data
 * @param data - Raw user registration data
 * @returns Validation result with parsed data or errors
 */
export function validateUserRegistration(data: unknown): {
  success: boolean
  data?: UserRegistration
  errors?: string[]
} {
  try {
    const parsed = UserRegistrationSchema.parse(data)
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
 * Type guard for User
 */
export function isUser(obj: unknown): obj is User {
  return validateUser(obj).success
}

/**
 * Type guard for BillingAddress
 */
export function isBillingAddress(obj: unknown): obj is BillingAddress {
  try {
    BillingAddressSchema.parse(obj)
    return true
  } catch {
    return false
  }
}

/**
 * Type guard for UsageQuotas
 */
export function isUsageQuotas(obj: unknown): obj is UsageQuotas {
  try {
    UsageQuotasSchema.parse(obj)
    return true
  } catch {
    return false
  }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Create default usage quotas for a subscription plan
 * @param planType - Subscription plan type
 * @returns Default usage quotas for the plan
 */
export function createDefaultUsageQuotas(planType: string = 'free'): UsageQuotas {
  const resetDate = new Date()
  resetDate.setMonth(resetDate.getMonth() + 1)

  const quotaMap: Record<string, Record<string, number>> = {
    free: { scrapingRequests: 10, exports: 5, advancedSearches: 0, apiCalls: 0 },
    basic: { scrapingRequests: 100, exports: 50, advancedSearches: 10, apiCalls: 0 },
    pro: { scrapingRequests: 1000, exports: 500, advancedSearches: 100, apiCalls: 50 },
    enterprise: { scrapingRequests: -1, exports: -1, advancedSearches: -1, apiCalls: -1 }
  }

  const quotas = quotaMap[planType] || quotaMap.free

  return {
    scrapingRequests: { used: 0, limit: quotas.scrapingRequests, resetDate },
    exports: { used: 0, limit: quotas.exports, resetDate },
    advancedSearches: { used: 0, limit: quotas.advancedSearches, resetDate },
    apiCalls: { used: 0, limit: quotas.apiCalls, resetDate }
  }
}

/**
 * Check if user has exceeded usage quota for a feature
 * @param quotas - User's usage quotas
 * @param featureType - Type of feature to check
 * @returns True if quota is exceeded
 */
export function isQuotaExceeded(quotas: UsageQuotas, featureType: keyof UsageQuotas): boolean {
  const quota = quotas[featureType]
  if (quota.limit === -1) return false // Unlimited
  return quota.used >= quota.limit
}

/**
 * Get usage percentage for a feature
 * @param quotas - User's usage quotas
 * @param featureType - Type of feature to check
 * @returns Usage percentage (0-100) or -1 for unlimited
 */
export function getUsagePercentage(quotas: UsageQuotas, featureType: keyof UsageQuotas): number {
  const quota = quotas[featureType]
  if (quota.limit === -1) return -1 // Unlimited
  if (quota.limit === 0) return 100 // No quota allowed
  return Math.min((quota.used / quota.limit) * 100, 100)
}

/**
 * Check if user account is locked
 * @param user - User data
 * @returns True if account is currently locked
 */
export function isAccountLocked(user: User): boolean {
  if (!user.lockedUntil) return false
  return user.lockedUntil > new Date()
}

/**
 * Check if user has active subscription
 * @param user - User data
 * @returns True if user has active subscription
 */
export function hasActiveSubscription(user: User): boolean {
  return user.subscriptionStatus === 'active' &&
         (!user.subscriptionEndsAt || user.subscriptionEndsAt > new Date())
}

/**
 * Get user display name
 * @param user - User data
 * @returns Display name (name or email if name not available)
 */
export function getUserDisplayName(user: User): string {
  return user.name || user.email
}

/**
 * Reset usage quotas for new billing period
 * @param quotas - Current usage quotas
 * @param planType - Subscription plan type
 * @returns Updated quotas with reset usage counts
 */
export function resetUsageQuotas(quotas: UsageQuotas, planType: string = 'free'): UsageQuotas {
  const newQuotas = createDefaultUsageQuotas(planType)

  // Keep the same reset dates but update limits and reset usage
  return {
    scrapingRequests: { ...newQuotas.scrapingRequests, resetDate: quotas.scrapingRequests.resetDate },
    exports: { ...newQuotas.exports, resetDate: quotas.exports.resetDate },
    advancedSearches: { ...newQuotas.advancedSearches, resetDate: quotas.advancedSearches.resetDate },
    apiCalls: { ...newQuotas.apiCalls, resetDate: quotas.apiCalls.resetDate }
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * Valid subscription statuses
 */
export const USER_SUBSCRIPTION_STATUSES = ['free', 'active', 'past_due', 'canceled', 'incomplete'] as const

/**
 * Valid quota feature types
 */
export const QUOTA_FEATURE_TYPES = ['scrapingRequests', 'exports', 'advancedSearches', 'apiCalls'] as const

/**
 * Default plan quotas
 */
export const DEFAULT_PLAN_QUOTAS = {
  free: { scrapingRequests: 10, exports: 5, advancedSearches: 0, apiCalls: 0 },
  basic: { scrapingRequests: 100, exports: 50, advancedSearches: 10, apiCalls: 0 },
  pro: { scrapingRequests: 1000, exports: 500, advancedSearches: 100, apiCalls: 50 },
  enterprise: { scrapingRequests: -1, exports: -1, advancedSearches: -1, apiCalls: -1 }
} as const
