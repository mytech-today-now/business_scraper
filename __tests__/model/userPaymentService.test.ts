/**
 * @jest-environment jsdom
 */

import { UserPaymentService, userPaymentService } from '@/model/userPaymentService'
import { stripeService } from '@/model/stripeService'
import { storage } from '@/model/storage'
import { UserPaymentProfile, PaymentError, SubscriptionError } from '@/types/payment'
import Stripe from 'stripe'

// Mock dependencies
jest.mock('@/model/stripeService')
jest.mock('@/model/storage')
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
  }
}))

const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockStorage = storage as jest.Mocked<typeof storage>

describe('UserPaymentService', () => {
  let service: UserPaymentService

  beforeEach(() => {
    jest.clearAllMocks()
    service = new UserPaymentService()
  })

  describe('ensureStripeCustomer', () => {
    it('should return existing customer ID if user already has one', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        stripeCustomerId: 'cus_existing123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      const mockCustomer = { id: 'cus_existing123' } as Stripe.Customer

      mockStorage.getItem.mockResolvedValue(mockProfile)
      mockStripeService.getCustomer.mockResolvedValue(mockCustomer)

      const result = await service.ensureStripeCustomer('user123', 'test@example.com')

      expect(result).toBe('cus_existing123')
      expect(mockStripeService.createCustomer).not.toHaveBeenCalled()
    })

    it('should create new customer if user does not have one', async () => {
      const mockCustomer = { id: 'cus_new123' } as Stripe.Customer

      mockStorage.getItem.mockResolvedValue(null)
      mockStripeService.createCustomer.mockResolvedValue(mockCustomer)
      mockStorage.setItem.mockResolvedValue(undefined)

      const result = await service.ensureStripeCustomer('user123', 'test@example.com', 'Test User')

      expect(result).toBe('cus_new123')
      expect(mockStripeService.createCustomer).toHaveBeenCalledWith('test@example.com', 'Test User', {
        userId: 'user123',
        createdBy: 'business_scraper_app'
      })
    })

    it('should create new customer if existing customer not found in Stripe', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        stripeCustomerId: 'cus_deleted123',
        email: 'test@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      const mockNewCustomer = { id: 'cus_new123' } as Stripe.Customer

      mockStorage.getItem.mockResolvedValue(mockProfile)
      mockStripeService.getCustomer.mockResolvedValue(null)
      mockStripeService.createCustomer.mockResolvedValue(mockNewCustomer)
      mockStorage.setItem.mockResolvedValue(undefined)

      const result = await service.ensureStripeCustomer('user123', 'test@example.com')

      expect(result).toBe('cus_new123')
      expect(mockStripeService.createCustomer).toHaveBeenCalled()
    })

    it('should handle errors during customer creation', async () => {
      mockStorage.getItem.mockResolvedValue(null)
      mockStripeService.createCustomer.mockRejectedValue(new Error('Stripe error'))

      await expect(service.ensureStripeCustomer('user123', 'test@example.com')).rejects.toThrow(PaymentError)
    })
  })

  describe('getUserPaymentProfile', () => {
    it('should return user payment profile', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      mockStorage.getItem.mockResolvedValue(mockProfile)

      const result = await service.getUserPaymentProfile('user123')

      expect(result).toEqual(mockProfile)
      expect(mockStorage.getItem).toHaveBeenCalledWith('userPaymentProfiles', 'user123')
    })

    it('should return null if profile not found', async () => {
      mockStorage.getItem.mockResolvedValue(null)

      const result = await service.getUserPaymentProfile('user123')

      expect(result).toBeNull()
    })

    it('should handle storage errors', async () => {
      mockStorage.getItem.mockRejectedValue(new Error('Storage error'))

      const result = await service.getUserPaymentProfile('user123')

      expect(result).toBeNull()
    })
  })

  describe('updateUserPaymentProfile', () => {
    it('should update existing profile', async () => {
      const existingProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'old@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date('2023-01-01'),
        updatedAt: new Date('2023-01-01')
      }

      const updates = {
        email: 'new@example.com',
        subscriptionStatus: 'active' as const,
        subscriptionTier: 'basic' as const
      }

      mockStorage.getItem.mockResolvedValue(existingProfile)
      mockStorage.setItem.mockResolvedValue(undefined)

      const result = await service.updateUserPaymentProfile('user123', updates)

      expect(result.email).toBe('new@example.com')
      expect(result.subscriptionStatus).toBe('active')
      expect(result.subscriptionTier).toBe('basic')
      expect(result.createdAt).toEqual(existingProfile.createdAt)
      expect(result.updatedAt).toBeInstanceOf(Date)
    })

    it('should create new profile if none exists', async () => {
      const updates = {
        email: 'new@example.com',
        subscriptionStatus: 'active' as const,
        subscriptionTier: 'basic' as const
      }

      mockStorage.getItem.mockResolvedValue(null)
      mockStorage.setItem.mockResolvedValue(undefined)

      const result = await service.updateUserPaymentProfile('user123', updates)

      expect(result.userId).toBe('user123')
      expect(result.email).toBe('new@example.com')
      expect(result.subscriptionStatus).toBe('active')
      expect(result.subscriptionTier).toBe('basic')
    })
  })

  describe('createSubscription', () => {
    it('should create subscription successfully', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        stripeCustomerId: 'cus_test123',
        email: 'test@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      const mockSubscription = {
        id: 'sub_test123',
        status: 'active',
        current_period_start: 1640995200, // 2022-01-01
        current_period_end: 1643673600,   // 2022-02-01
        cancel_at_period_end: false
      } as Stripe.Subscription

      mockStorage.getItem.mockResolvedValue(mockProfile)
      mockStripeService.createSubscription.mockResolvedValue(mockSubscription)
      mockStorage.setItem.mockResolvedValue(undefined)

      const result = await service.createSubscription('user123', 'price_test123')

      expect(result.success).toBe(true)
      expect(result.data).toEqual(mockSubscription)
      expect(mockStripeService.createSubscription).toHaveBeenCalledWith('cus_test123', 'price_test123', {
        trialPeriodDays: undefined,
        metadata: { userId: 'user123' }
      })
    })

    it('should handle missing Stripe customer', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      mockStorage.getItem.mockResolvedValue(mockProfile)

      const result = await service.createSubscription('user123', 'price_test123')

      expect(result.success).toBe(false)
      expect(result.code).toBe('NO_STRIPE_CUSTOMER')
    })
  })

  describe('cancelSubscription', () => {
    it('should cancel subscription successfully', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        subscriptionId: 'sub_test123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      const mockSubscription = {
        id: 'sub_test123',
        status: 'canceled',
        cancel_at_period_end: true
      } as Stripe.Subscription

      mockStorage.getItem.mockResolvedValue(mockProfile)
      mockStripeService.cancelSubscription.mockResolvedValue(mockSubscription)
      mockStorage.setItem.mockResolvedValue(undefined)

      const result = await service.cancelSubscription('user123', true)

      expect(result.success).toBe(true)
      expect(result.data).toEqual(mockSubscription)
    })

    it('should handle missing subscription', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        email: 'test@example.com',
        subscriptionStatus: 'free',
        subscriptionTier: 'free',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      mockStorage.getItem.mockResolvedValue(mockProfile)

      const result = await service.cancelSubscription('user123')

      expect(result.success).toBe(false)
      expect(result.code).toBe('NO_ACTIVE_SUBSCRIPTION')
    })
  })

  describe('getUserPaymentMethods', () => {
    it('should return payment methods for user', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        stripeCustomerId: 'cus_test123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      const mockPaymentMethods = [
        {
          id: 'pm_test123',
          type: 'card',
          card: {
            brand: 'visa',
            last4: '4242',
            exp_month: 12,
            exp_year: 2025
          },
          created: 1640995200
        }
      ] as Stripe.PaymentMethod[]

      mockStorage.getItem.mockResolvedValue(mockProfile)
      mockStripeService.listPaymentMethods.mockResolvedValue(mockPaymentMethods)

      const result = await service.getUserPaymentMethods('user123')

      expect(result).toHaveLength(1)
      expect(result[0].id).toBe('pm_test123')
      expect(result[0].card?.brand).toBe('visa')
      expect(result[0].card?.last4).toBe('4242')
    })

    it('should return empty array if no Stripe customer', async () => {
      mockStorage.getItem.mockResolvedValue(null)

      const result = await service.getUserPaymentMethods('user123')

      expect(result).toEqual([])
    })
  })

  describe('syncWithStripe', () => {
    it('should sync user data with Stripe successfully', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        stripeCustomerId: 'cus_test123',
        subscriptionId: 'sub_test123',
        email: 'old@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      const mockCustomer = {
        id: 'cus_test123',
        email: 'new@example.com',
        name: 'Updated Name'
      } as Stripe.Customer

      const mockSubscription = {
        id: 'sub_test123',
        status: 'active',
        current_period_start: 1640995200,
        current_period_end: 1643673600,
        cancel_at_period_end: false
      } as Stripe.Subscription

      mockStorage.getItem.mockResolvedValue(mockProfile)
      mockStripeService.getCustomer.mockResolvedValue(mockCustomer)
      mockStripeService.getSubscription.mockResolvedValue(mockSubscription)
      mockStorage.setItem.mockResolvedValue(undefined)

      const result = await service.syncWithStripe('user123')

      expect(result.success).toBe(true)
      expect(result.data?.email).toBe('new@example.com')
      expect(result.data?.name).toBe('Updated Name')
    })

    it('should handle missing Stripe customer', async () => {
      const mockProfile: UserPaymentProfile = {
        userId: 'user123',
        stripeCustomerId: 'cus_test123',
        email: 'test@example.com',
        subscriptionStatus: 'active',
        subscriptionTier: 'basic',
        createdAt: new Date(),
        updatedAt: new Date()
      }

      mockStorage.getItem.mockResolvedValue(mockProfile)
      mockStripeService.getCustomer.mockResolvedValue(null)

      const result = await service.syncWithStripe('user123')

      expect(result.success).toBe(false)
      expect(result.code).toBe('STRIPE_CUSTOMER_NOT_FOUND')
    })
  })
})
