/**
 * Payment Validation Service
 * Implements business rules engine and feature access control
 */

import { userPaymentService } from './userPaymentService'
import { logger } from '@/utils/logger'
import {
  UserPaymentProfile,
  SubscriptionTier,
  PaymentStatus,
  FeatureAccessRules,
  SubscriptionPlan,
  PlanLimits,
  ServiceResponse,
  ValidationError,
} from '@/types/payment'

export class PaymentValidationService {
  // Default subscription plans configuration
  private readonly subscriptionPlans: SubscriptionPlan[] = [
    {
      id: 'free',
      name: 'Free Plan',
      tier: 'free',
      stripePriceId: '',
      monthlyPrice: 0,
      features: ['Basic scraping', 'Up to 100 records', '1 export per month'],
      limits: {
        maxBusinessRecords: 100,
        maxExportsPerMonth: 1,
        maxSearchesPerDay: 10,
        maxConcurrentScrapes: 1,
        advancedFilters: false,
        apiAccess: false,
        prioritySupport: false,
        customIntegrations: false,
        whiteLabel: false,
      },
      isActive: true,
    },
    {
      id: 'basic',
      name: 'Basic Plan',
      tier: 'basic',
      stripePriceId: 'price_basic_monthly',
      monthlyPrice: 2900, // $29.00
      yearlyPrice: 29000, // $290.00 (save 2 months)
      features: [
        'Advanced scraping',
        'Up to 1,000 records',
        '10 exports per month',
        'Basic filters',
      ],
      limits: {
        maxBusinessRecords: 1000,
        maxExportsPerMonth: 10,
        maxSearchesPerDay: 50,
        maxConcurrentScrapes: 2,
        advancedFilters: true,
        apiAccess: false,
        prioritySupport: false,
        customIntegrations: false,
        whiteLabel: false,
      },
      isPopular: true,
      isActive: true,
    },
    {
      id: 'professional',
      name: 'Professional Plan',
      tier: 'professional',
      stripePriceId: 'price_professional_monthly',
      monthlyPrice: 9900, // $99.00
      yearlyPrice: 99000, // $990.00 (save 2 months)
      features: [
        'Premium scraping',
        'Up to 10,000 records',
        'Unlimited exports',
        'Advanced filters',
        'API access',
      ],
      limits: {
        maxBusinessRecords: 10000,
        maxExportsPerMonth: -1, // Unlimited
        maxSearchesPerDay: 200,
        maxConcurrentScrapes: 5,
        advancedFilters: true,
        apiAccess: true,
        prioritySupport: true,
        customIntegrations: false,
        whiteLabel: false,
      },
      isActive: true,
    },
    {
      id: 'enterprise',
      name: 'Enterprise Plan',
      tier: 'enterprise',
      stripePriceId: 'price_enterprise_monthly',
      monthlyPrice: 29900, // $299.00
      yearlyPrice: 299000, // $2,990.00 (save 2 months)
      features: [
        'Enterprise scraping',
        'Unlimited records',
        'Unlimited exports',
        'All features',
        'White label',
        'Custom integrations',
      ],
      limits: {
        maxBusinessRecords: -1, // Unlimited
        maxExportsPerMonth: -1, // Unlimited
        maxSearchesPerDay: -1, // Unlimited
        maxConcurrentScrapes: 10,
        advancedFilters: true,
        apiAccess: true,
        prioritySupport: true,
        customIntegrations: true,
        whiteLabel: true,
      },
      isActive: true,
    },
  ]

  /**
   * Validate if user can access a specific feature
   */
  async canAccessFeature(userId: string, feature: string): Promise<ServiceResponse<boolean>> {
    try {
      const profile = await userPaymentService.getUserPaymentProfile(userId)
      if (!profile) {
        return {
          success: false,
          error: 'User payment profile not found',
          code: 'PROFILE_NOT_FOUND',
        }
      }

      const rules = this.getFeatureAccessRules(profile.subscriptionTier)
      const hasAccess = this.checkFeatureAccess(feature, rules)

      logger.info(
        'PaymentValidationService',
        `Feature access check for user ${userId}, feature: ${feature}, access: ${hasAccess}`
      )
      return { success: true, data: hasAccess }
    } catch (error) {
      logger.error(
        'PaymentValidationService',
        `Failed to check feature access for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'FEATURE_ACCESS_CHECK_FAILED',
      }
    }
  }

  /**
   * Validate if user can perform an action based on usage limits
   */
  async validateUsageLimit(
    userId: string,
    action: 'export' | 'search' | 'scrape' | 'record_storage',
    currentUsage: number
  ): Promise<ServiceResponse<boolean>> {
    try {
      const profile = await userPaymentService.getUserPaymentProfile(userId)
      if (!profile) {
        return {
          success: false,
          error: 'User payment profile not found',
          code: 'PROFILE_NOT_FOUND',
        }
      }

      const rules = this.getFeatureAccessRules(profile.subscriptionTier)
      const isWithinLimit = this.checkUsageLimit(action, currentUsage, rules)

      if (!isWithinLimit) {
        const limitInfo = this.getLimitInfo(action, rules)
        return {
          success: false,
          error: `Usage limit exceeded. Current: ${currentUsage}, Limit: ${limitInfo}`,
          code: 'USAGE_LIMIT_EXCEEDED',
        }
      }

      return { success: true, data: true }
    } catch (error) {
      logger.error(
        'PaymentValidationService',
        `Failed to validate usage limit for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'USAGE_LIMIT_CHECK_FAILED',
      }
    }
  }

  /**
   * Get feature access rules for a subscription tier
   */
  getFeatureAccessRules(tier: SubscriptionTier): FeatureAccessRules {
    const plan = this.subscriptionPlans.find(p => p.tier === tier)
    if (!plan) {
      // Default to free plan rules
      return this.getFeatureAccessRules('free')
    }

    return {
      tier,
      rules: {
        canExportData: plan.limits.maxExportsPerMonth !== 0,
        canUseAdvancedFilters: plan.limits.advancedFilters,
        canAccessAPI: plan.limits.apiAccess,
        canUseBulkOperations: tier !== 'free',
        canUseCustomIntegrations: plan.limits.customIntegrations,
        maxDailySearches: plan.limits.maxSearchesPerDay,
        maxMonthlyExports: plan.limits.maxExportsPerMonth,
        maxBusinessRecords: plan.limits.maxBusinessRecords,
        maxConcurrentScrapes: plan.limits.maxConcurrentScrapes,
      },
    }
  }

  /**
   * Validate subscription status
   */
  async validateSubscriptionStatus(userId: string): Promise<ServiceResponse<boolean>> {
    try {
      const profile = await userPaymentService.getUserPaymentProfile(userId)
      if (!profile) {
        return {
          success: false,
          error: 'User payment profile not found',
          code: 'PROFILE_NOT_FOUND',
        }
      }

      const isValid = this.isSubscriptionValid(profile)

      if (!isValid) {
        return {
          success: false,
          error: `Subscription is not valid. Status: ${profile.subscriptionStatus}`,
          code: 'INVALID_SUBSCRIPTION',
        }
      }

      return { success: true, data: true }
    } catch (error) {
      logger.error(
        'PaymentValidationService',
        `Failed to validate subscription for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'SUBSCRIPTION_VALIDATION_FAILED',
      }
    }
  }

  /**
   * Get subscription plan by tier
   */
  getSubscriptionPlan(tier: SubscriptionTier): SubscriptionPlan | null {
    return this.subscriptionPlans.find(plan => plan.tier === tier) || null
  }

  /**
   * Get all available subscription plans
   */
  getAvailableSubscriptionPlans(): SubscriptionPlan[] {
    return this.subscriptionPlans.filter(plan => plan.isActive)
  }

  /**
   * Validate payment data
   */
  validatePaymentData(data: any): ServiceResponse<boolean> {
    try {
      const errors: string[] = []

      // Validate required fields
      if (!data.amount || typeof data.amount !== 'number' || data.amount <= 0) {
        errors.push('Amount must be a positive number')
      }

      if (!data.currency || typeof data.currency !== 'string') {
        errors.push('Currency is required')
      }

      if (data.email && !this.isValidEmail(data.email)) {
        errors.push('Invalid email format')
      }

      if (errors.length > 0) {
        return {
          success: false,
          error: errors.join(', '),
          code: 'VALIDATION_FAILED',
        }
      }

      return { success: true, data: true }
    } catch (error) {
      logger.error('PaymentValidationService', 'Failed to validate payment data', error)
      return {
        success: false,
        error: 'Payment data validation failed',
        code: 'PAYMENT_DATA_VALIDATION_FAILED',
      }
    }
  }

  /**
   * Check if user can upgrade/downgrade to a specific tier
   */
  async canChangeTier(
    userId: string,
    newTier: SubscriptionTier
  ): Promise<ServiceResponse<boolean>> {
    try {
      const profile = await userPaymentService.getUserPaymentProfile(userId)
      if (!profile) {
        return {
          success: false,
          error: 'User payment profile not found',
          code: 'PROFILE_NOT_FOUND',
        }
      }

      const currentPlan = this.getSubscriptionPlan(profile.subscriptionTier)
      const newPlan = this.getSubscriptionPlan(newTier)

      if (!newPlan) {
        return { success: false, error: 'Invalid subscription tier', code: 'INVALID_TIER' }
      }

      // Check if it's a valid transition
      const canChange = this.isValidTierTransition(profile.subscriptionTier, newTier)

      if (!canChange) {
        return {
          success: false,
          error: `Cannot change from ${profile.subscriptionTier} to ${newTier}`,
          code: 'INVALID_TIER_TRANSITION',
        }
      }

      return { success: true, data: true }
    } catch (error) {
      logger.error(
        'PaymentValidationService',
        `Failed to validate tier change for user: ${userId}`,
        error
      )
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        code: 'TIER_CHANGE_VALIDATION_FAILED',
      }
    }
  }

  // Private helper methods

  private checkFeatureAccess(feature: string, rules: FeatureAccessRules): boolean {
    switch (feature) {
      case 'export_data':
        return rules.rules.canExportData
      case 'advanced_filters':
        return rules.rules.canUseAdvancedFilters
      case 'api_access':
        return rules.rules.canAccessAPI
      case 'bulk_operations':
        return rules.rules.canUseBulkOperations
      case 'custom_integrations':
        return rules.rules.canUseCustomIntegrations
      default:
        return false
    }
  }

  private checkUsageLimit(
    action: string,
    currentUsage: number,
    rules: FeatureAccessRules
  ): boolean {
    switch (action) {
      case 'export':
        return rules.rules.maxMonthlyExports === -1 || currentUsage < rules.rules.maxMonthlyExports
      case 'search':
        return rules.rules.maxDailySearches === -1 || currentUsage < rules.rules.maxDailySearches
      case 'record_storage':
        return (
          rules.rules.maxBusinessRecords === -1 || currentUsage < rules.rules.maxBusinessRecords
        )
      case 'scrape':
        return (
          rules.rules.maxConcurrentScrapes === -1 || currentUsage < rules.rules.maxConcurrentScrapes
        )
      default:
        return false
    }
  }

  private getLimitInfo(action: string, rules: FeatureAccessRules): string {
    switch (action) {
      case 'export':
        return rules.rules.maxMonthlyExports === -1
          ? 'Unlimited'
          : rules.rules.maxMonthlyExports.toString()
      case 'search':
        return rules.rules.maxDailySearches === -1
          ? 'Unlimited'
          : rules.rules.maxDailySearches.toString()
      case 'record_storage':
        return rules.rules.maxBusinessRecords === -1
          ? 'Unlimited'
          : rules.rules.maxBusinessRecords.toString()
      case 'scrape':
        return rules.rules.maxConcurrentScrapes === -1
          ? 'Unlimited'
          : rules.rules.maxConcurrentScrapes.toString()
      default:
        return 'Unknown'
    }
  }

  private isSubscriptionValid(profile: UserPaymentProfile): boolean {
    const validStatuses: PaymentStatus[] = ['free', 'trial', 'active']

    if (!validStatuses.includes(profile.subscriptionStatus)) {
      return false
    }

    // Check if trial has expired
    if (profile.subscriptionStatus === 'trial' && profile.trialEnd) {
      return new Date() < profile.trialEnd
    }

    // Check if subscription has expired
    if (profile.subscriptionStatus === 'active' && profile.currentPeriodEnd) {
      return new Date() < profile.currentPeriodEnd
    }

    return true
  }

  private isValidTierTransition(currentTier: SubscriptionTier, newTier: SubscriptionTier): boolean {
    // Define valid transitions
    const validTransitions: Record<SubscriptionTier, SubscriptionTier[]> = {
      free: ['basic', 'professional', 'enterprise'],
      basic: ['free', 'professional', 'enterprise'],
      professional: ['free', 'basic', 'enterprise'],
      enterprise: ['free', 'basic', 'professional'],
    }

    return validTransitions[currentTier]?.includes(newTier) || false
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  }
}

// Singleton instance
export const paymentValidationService = new PaymentValidationService()
