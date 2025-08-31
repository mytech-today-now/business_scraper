/**
 * @jest-environment jsdom
 */

import {
  PaymentValidationService,
  paymentValidationService,
} from '@/model/paymentValidationService'
import { userPaymentService } from '@/model/userPaymentService'
import { UserPaymentProfile, SubscriptionTier, PaymentStatus } from '@/types/payment'

// Mock dependencies
jest.mock('@/model/userPaymentService')
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}))

const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>

describe('PaymentValidationService', () => {
  let service: PaymentValidationService

  beforeEach(() => {
    jest.clearAllMocks()
    service = new PaymentValidationService()
  })

  describe('canAccessFeature', () => {
    it('should allow export_data for basic tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.canAccessFeature('user123', 'export_data')

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should deny advanced_filters for free tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.canAccessFeature('user123', 'advanced_filters')

      expect(result.success).toBe(true)
      expect(result.data).toBe(false)
    })

    it('should allow api_access for professional tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'professional',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.canAccessFeature('user123', 'api_access')

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should handle missing user profile', async () => {
      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(null)

      const result = await service.canAccessFeature('user123', 'export_data')

      expect(result.success).toBe(false)
      expect(result.code).toBe('PROFILE_NOT_FOUND')
    })
  })

  describe('validateUsageLimit', () => {
    it('should allow export within limit for basic tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateUsageLimit('user123', 'export', 5)

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should deny export over limit for basic tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateUsageLimit('user123', 'export', 15)

      expect(result.success).toBe(false)
      expect(result.code).toBe('USAGE_LIMIT_EXCEEDED')
    })

    it('should allow unlimited exports for professional tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'professional',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateUsageLimit('user123', 'export', 1000)

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should deny search over limit for free tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateUsageLimit('user123', 'search', 15)

      expect(result.success).toBe(false)
      expect(result.code).toBe('USAGE_LIMIT_EXCEEDED')
    })
  })

  describe('validateSubscriptionStatus', () => {
    it('should validate active subscription', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        currentPeriodEnd: new Date(Date.now() + 86400000), // Tomorrow
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateSubscriptionStatus('user123')

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should validate trial subscription within period', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'trial',
        subscriptionTier: 'basic',
        trialEnd: new Date(Date.now() + 86400000), // Tomorrow
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateSubscriptionStatus('user123')

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should invalidate expired trial', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'trial',
        subscriptionTier: 'basic',
        trialEnd: new Date(Date.now() - 86400000), // Yesterday
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateSubscriptionStatus('user123')

      expect(result.success).toBe(false)
      expect(result.code).toBe('INVALID_SUBSCRIPTION')
    })

    it('should invalidate canceled subscription', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'canceled',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.validateSubscriptionStatus('user123')

      expect(result.success).toBe(false)
      expect(result.code).toBe('INVALID_SUBSCRIPTION')
    })
  })

  describe('getFeatureAccessRules', () => {
    it('should return correct rules for free tier', () => {
      const rules = service.getFeatureAccessRules('free')

      expect(rules.tier).toBe('free')
      expect(rules.rules.canExportData).toBe(false)
      expect(rules.rules.canUseAdvancedFilters).toBe(false)
      expect(rules.rules.canAccessAPI).toBe(false)
      expect(rules.rules.maxBusinessRecords).toBe(100)
      expect(rules.rules.maxDailySearches).toBe(10)
    })

    it('should return correct rules for basic tier', () => {
      const rules = service.getFeatureAccessRules('basic')

      expect(rules.tier).toBe('basic')
      expect(rules.rules.canExportData).toBe(true)
      expect(rules.rules.canUseAdvancedFilters).toBe(true)
      expect(rules.rules.canAccessAPI).toBe(false)
      expect(rules.rules.maxBusinessRecords).toBe(1000)
      expect(rules.rules.maxDailySearches).toBe(50)
      expect(rules.rules.maxMonthlyExports).toBe(10)
    })

    it('should return correct rules for professional tier', () => {
      const rules = service.getFeatureAccessRules('professional')

      expect(rules.tier).toBe('professional')
      expect(rules.rules.canExportData).toBe(true)
      expect(rules.rules.canUseAdvancedFilters).toBe(true)
      expect(rules.rules.canAccessAPI).toBe(true)
      expect(rules.rules.maxBusinessRecords).toBe(10000)
      expect(rules.rules.maxDailySearches).toBe(200)
      expect(rules.rules.maxMonthlyExports).toBe(-1) // Unlimited
    })

    it('should return correct rules for enterprise tier', () => {
      const rules = service.getFeatureAccessRules('enterprise')

      expect(rules.tier).toBe('enterprise')
      expect(rules.rules.canExportData).toBe(true)
      expect(rules.rules.canUseAdvancedFilters).toBe(true)
      expect(rules.rules.canAccessAPI).toBe(true)
      expect(rules.rules.canUseCustomIntegrations).toBe(true)
      expect(rules.rules.maxBusinessRecords).toBe(-1) // Unlimited
      expect(rules.rules.maxDailySearches).toBe(-1) // Unlimited
      expect(rules.rules.maxMonthlyExports).toBe(-1) // Unlimited
    })
  })

  describe('getSubscriptionPlan', () => {
    it('should return correct plan for basic tier', () => {
      const plan = service.getSubscriptionPlan('basic')

      expect(plan).toBeDefined()
      expect(plan?.tier).toBe('basic')
      expect(plan?.name).toBe('Basic Plan')
      expect(plan?.monthlyPrice).toBe(2900)
      expect(plan?.isPopular).toBe(true)
    })

    it('should return null for invalid tier', () => {
      const plan = service.getSubscriptionPlan('invalid' as SubscriptionTier)

      expect(plan).toBeNull()
    })
  })

  describe('validatePaymentData', () => {
    it('should validate correct payment data', () => {
      const paymentData = {
        amount: 2000,
        currency: 'usd',
        email: 'test@example.com',
      }

      const result = service.validatePaymentData(paymentData)

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should reject invalid amount', () => {
      const paymentData = {
        amount: -100,
        currency: 'usd',
      }

      const result = service.validatePaymentData(paymentData)

      expect(result.success).toBe(false)
      expect(result.error).toContain('Amount must be a positive number')
    })

    it('should reject missing currency', () => {
      const paymentData = {
        amount: 2000,
      }

      const result = service.validatePaymentData(paymentData)

      expect(result.success).toBe(false)
      expect(result.error).toContain('Currency is required')
    })

    it('should reject invalid email format', () => {
      const paymentData = {
        amount: 2000,
        currency: 'usd',
        email: 'invalid-email',
      }

      const result = service.validatePaymentData(paymentData)

      expect(result.success).toBe(false)
      expect(result.error).toContain('Invalid email format')
    })
  })

  describe('canChangeTier', () => {
    it('should allow upgrade from free to basic', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.canChangeTier('user123', 'basic')

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should allow downgrade from professional to basic', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'professional',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.canChangeTier('user123', 'basic')

      expect(result.success).toBe(true)
      expect(result.data).toBe(true)
    })

    it('should handle missing user profile', async () => {
      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(null)

      const result = await service.canChangeTier('user123', 'basic')

      expect(result.success).toBe(false)
      expect(result.code).toBe('PROFILE_NOT_FOUND')
    })

    it('should reject invalid tier', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockProfile)

      const result = await service.canChangeTier('user123', 'invalid' as SubscriptionTier)

      expect(result.success).toBe(false)
      expect(result.code).toBe('INVALID_TIER')
    })
  })
})
