/**
 * Feature Access Controller
 * Manages user permissions based on subscription plans and usage limits
 */

import { paymentController } from './paymentController'
import { logger } from '@/utils/logger'
import { UserSubscription, isSubscriptionActive } from '@/model/types/payment'

/**
 * Feature limits configuration for each subscription tier
 */
interface FeatureLimits {
  scraping_request: number
  export: number
  advanced_search: number
  api_access: number
}

/**
 * Plan-based feature limits
 * -1 indicates unlimited access
 */
const FEATURE_LIMITS: Record<string, FeatureLimits> = {
  free: {
    scraping_request: 10,
    export: 5,
    advanced_search: 0,
    api_access: 0,
  },
  basic: {
    scraping_request: 100,
    export: 50,
    advanced_search: 10,
    api_access: 0,
  },
  pro: {
    scraping_request: 1000,
    export: 500,
    advanced_search: 100,
    api_access: 50,
  },
  enterprise: {
    scraping_request: -1, // unlimited
    export: -1,
    advanced_search: -1,
    api_access: -1,
  },
}

/**
 * Feature access denial reasons
 */
export type AccessDenialReason =
  | 'subscription_required'
  | 'usage_limit_exceeded'
  | 'plan_restriction'
  | 'account_suspended'
  | 'feature_disabled'

/**
 * Feature access result
 */
export interface FeatureAccessResult {
  hasAccess: boolean
  reason?: AccessDenialReason
  currentUsage?: number
  usageLimit?: number
  resetDate?: Date
  upgradeRequired?: {
    minimumPlan: string
    upgradeUrl: string
  }
}

/**
 * Feature Access Controller Class
 * Handles feature access validation and usage tracking
 */
export class FeatureAccessController {
  private usageCache: Map<string, Map<string, number>> = new Map()
  private lastCacheUpdate: Map<string, Date> = new Map()
  private readonly CACHE_TTL = 5 * 60 * 1000 // 5 minutes

  constructor() {
    // Listen to payment controller events
    paymentController.on('subscription:loaded', this.onSubscriptionLoaded.bind(this))
    paymentController.on('usage:recorded', this.onUsageRecorded.bind(this))
  }

  /**
   * Check if user can access a feature
   */
  async canAccessFeature(featureType: string): Promise<FeatureAccessResult> {
    try {
      const user = paymentController.getCurrentUser()
      if (!user) {
        return {
          hasAccess: false,
          reason: 'subscription_required',
        }
      }

      // Check subscription-based access
      const subscriptionAccess = await this.checkSubscriptionAccess(featureType)
      if (!subscriptionAccess.hasAccess) {
        this.emitAccessDenied(featureType, subscriptionAccess.reason!)
        return subscriptionAccess
      }

      // Check usage limits
      const usageAccess = await this.checkUsageLimit(featureType)
      if (!usageAccess.hasAccess) {
        this.emitAccessDenied(featureType, usageAccess.reason!)
        return usageAccess
      }

      return { hasAccess: true }
    } catch (error) {
      logger.error('FeatureAccessController', 'Failed to check feature access', error)
      return {
        hasAccess: false,
        reason: 'feature_disabled',
      }
    }
  }

  /**
   * Check subscription-based access
   */
  private async checkSubscriptionAccess(featureType: string): Promise<FeatureAccessResult> {
    const subscription = paymentController.getUserSubscription()
    const planType = this.getPlanType(subscription)

    // Check if feature is available in current plan
    const limit = FEATURE_LIMITS[planType]?.[featureType as keyof FeatureLimits]

    if (limit === undefined) {
      return {
        hasAccess: false,
        reason: 'feature_disabled',
      }
    }

    if (limit === 0) {
      return {
        hasAccess: false,
        reason: 'plan_restriction',
        upgradeRequired: {
          minimumPlan: this.getMinimumPlanForFeature(featureType),
          upgradeUrl: '/upgrade',
        },
      }
    }

    return { hasAccess: true }
  }

  /**
   * Check usage limits
   */
  async checkUsageLimit(featureType: string): Promise<FeatureAccessResult> {
    const subscription = paymentController.getUserSubscription()
    const planType = this.getPlanType(subscription)
    const limit = FEATURE_LIMITS[planType]?.[featureType as keyof FeatureLimits]

    // Unlimited access
    if (limit === -1) {
      return { hasAccess: true }
    }

    // No access
    if (limit === 0) {
      return {
        hasAccess: false,
        reason: 'plan_restriction',
      }
    }

    // Check current usage
    const currentUsage = await this.getCurrentUsage(featureType)
    const hasUsageRemaining = currentUsage < limit

    if (!hasUsageRemaining) {
      return {
        hasAccess: false,
        reason: 'usage_limit_exceeded',
        currentUsage,
        usageLimit: limit,
        resetDate: this.getUsageResetDate(),
      }
    }

    return {
      hasAccess: true,
      currentUsage,
      usageLimit: limit,
    }
  }

  /**
   * Get current usage for a feature
   */
  private async getCurrentUsage(featureType: string): Promise<number> {
    const user = paymentController.getCurrentUser()
    if (!user) return 0

    const userId = user.id
    const cacheKey = `${userId}:${featureType}`

    // Check cache first
    const cachedUsage = this.usageCache.get(userId)?.get(featureType)
    const lastUpdate = this.lastCacheUpdate.get(cacheKey)

    if (
      cachedUsage !== undefined &&
      lastUpdate &&
      Date.now() - lastUpdate.getTime() < this.CACHE_TTL
    ) {
      return cachedUsage
    }

    // Mock usage data until userPaymentService is implemented
    const usage = await this.getMockCurrentUsage(userId, featureType)

    // Update cache
    if (!this.usageCache.has(userId)) {
      this.usageCache.set(userId, new Map())
    }
    this.usageCache.get(userId)!.set(featureType, usage)
    this.lastCacheUpdate.set(cacheKey, new Date())

    return usage
  }

  /**
   * Get plan type from subscription
   */
  private getPlanType(subscription: UserSubscription | null): string {
    if (!subscription || !isSubscriptionActive(subscription)) {
      return 'free'
    }

    // Extract plan type from subscription data
    const planId = subscription.planId
    if (FEATURE_LIMITS[planId]) {
      return planId
    }

    // Default to free if plan not recognized
    return 'free'
  }

  /**
   * Get minimum plan required for a feature
   */
  private getMinimumPlanForFeature(featureType: string): string {
    const plans = ['basic', 'pro', 'enterprise']

    for (const plan of plans) {
      const limit = FEATURE_LIMITS[plan]?.[featureType as keyof FeatureLimits]
      if (limit && limit > 0) {
        return plan
      }
    }

    return 'basic'
  }

  /**
   * Get usage reset date (start of next month)
   */
  private getUsageResetDate(): Date {
    const now = new Date()
    const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1)
    return nextMonth
  }

  /**
   * Emit access denied event
   */
  private emitAccessDenied(featureType: string, reason: AccessDenialReason): void {
    paymentController.emit('access:denied', { featureType, reason })
    logger.info(
      'FeatureAccessController',
      `Access denied for feature: ${featureType}, reason: ${reason}`
    )
  }

  /**
   * Get feature limits for current user
   */
  async getFeatureLimits(): Promise<FeatureLimits> {
    const subscription = paymentController.getUserSubscription()
    const planType = this.getPlanType(subscription)
    return { ...FEATURE_LIMITS[planType] } || { ...FEATURE_LIMITS.free }
  }

  /**
   * Get usage summary for current user
   */
  async getUsageSummary(): Promise<Record<string, { used: number; limit: number }>> {
    const user = paymentController.getCurrentUser()
    if (!user) {
      return {}
    }

    const limits = await this.getFeatureLimits()
    const summary: Record<string, { used: number; limit: number }> = {}

    for (const [featureType, limit] of Object.entries(limits)) {
      const used = await this.getCurrentUsage(featureType)
      summary[featureType] = { used, limit }
    }

    return summary
  }

  /**
   * Clear usage cache for a user
   */
  clearUsageCache(userId?: string): void {
    if (userId) {
      this.usageCache.delete(userId)
      // Clear related cache timestamps
      for (const [key] of this.lastCacheUpdate) {
        if (key.startsWith(`${userId}:`)) {
          this.lastCacheUpdate.delete(key)
        }
      }
    } else {
      this.usageCache.clear()
      this.lastCacheUpdate.clear()
    }
  }

  // ============================================================================
  // EVENT HANDLERS
  // ============================================================================

  private onSubscriptionLoaded(subscription: UserSubscription | null): void {
    // Clear cache when subscription changes
    const user = paymentController.getCurrentUser()
    if (user) {
      this.clearUsageCache(user.id)
    }
  }

  private onUsageRecorded(data: { featureType: string; metadata?: any }): void {
    // Invalidate cache for the feature that was used
    const user = paymentController.getCurrentUser()
    if (user) {
      const cacheKey = `${user.id}:${data.featureType}`
      this.lastCacheUpdate.delete(cacheKey)
    }
  }

  // ============================================================================
  // MOCK METHODS (TO BE REPLACED WITH REAL SERVICES)
  // ============================================================================

  private async getMockCurrentUsage(userId: string, featureType: string): Promise<number> {
    // Mock usage data - return random usage for demonstration
    const mockUsage: Record<string, number> = {
      scraping_request: Math.floor(Math.random() * 5),
      export: Math.floor(Math.random() * 3),
      advanced_search: Math.floor(Math.random() * 2),
      api_access: 0,
    }

    return mockUsage[featureType] || 0
  }
}

// Export singleton instance
export const featureAccessController = new FeatureAccessController()
