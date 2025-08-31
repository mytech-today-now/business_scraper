/**
 * Unit Tests for User Onboarding Service
 * Comprehensive testing of user onboarding flow, payment setup, and quota initialization
 */

import { userOnboardingService } from '@/model/userOnboardingService'
import { userPaymentService } from '@/model/userPaymentService'
import { storage } from '@/model/storage'
import { UserRegistration, User, createDefaultUsageQuotas } from '@/model/types/user'
import { hashPassword } from '@/lib/security'

// Mock dependencies
jest.mock('@/model/userPaymentService')
jest.mock('@/model/storage')
jest.mock('@/lib/security')
jest.mock('@/utils/logger')

const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>
const mockStorage = storage as jest.Mocked<typeof storage>
const mockHashPassword = hashPassword as jest.MockedFunction<typeof hashPassword>

describe('UserOnboardingService', () => {
  beforeEach(() => {
    jest.clearAllMocks()

    // Setup default mocks
    mockHashPassword.mockReturnValue({
      hash: 'hashed-password',
      salt: 'salt-value',
    })

    mockUserPaymentService.ensureStripeCustomer.mockResolvedValue('cus_123')
    mockStorage.setItem.mockResolvedValue()
    mockStorage.getItem.mockResolvedValue(null)
    mockStorage.getAllItems.mockResolvedValue([])
  })

  describe('completeOnboarding', () => {
    const validRegistration: UserRegistration = {
      email: 'test@example.com',
      name: 'Test User',
      password: 'securePassword123',
      timezone: 'America/New_York',
      language: 'en',
    }

    test('should complete onboarding successfully without subscription', async () => {
      const result = await userOnboardingService.completeOnboarding(validRegistration)

      expect(result).toBeDefined()
      expect(result.email).toBe(validRegistration.email)
      expect(result.name).toBe(validRegistration.name)
      expect(result.subscriptionStatus).toBe('free')
      expect(result.emailVerified).toBe(false)
      expect(result.isActive).toBe(true)
      expect(result.usageQuotas).toEqual(createDefaultUsageQuotas('free'))

      // Verify password was hashed
      expect(mockHashPassword).toHaveBeenCalledWith(validRegistration.password)
      expect(result.passwordHash).toBe('hashed-password')
      expect(result.passwordSalt).toBe('salt-value')

      // Verify Stripe customer was created
      expect(mockUserPaymentService.ensureStripeCustomer).toHaveBeenCalledWith(
        result.id,
        validRegistration.email,
        validRegistration.name
      )

      // Verify user was saved to storage
      expect(mockStorage.setItem).toHaveBeenCalledWith('users', result.id, result)
    })

    test('should complete onboarding with subscription plan', async () => {
      const result = await userOnboardingService.completeOnboarding(validRegistration, 'pro-plan')

      expect(result.subscriptionStatus).toBe('active')
      expect(result.subscriptionPlan).toBe('pro-plan')
      expect(result.subscriptionEndsAt).toBeDefined()
    })

    test('should handle payment profile initialization failure gracefully', async () => {
      mockUserPaymentService.ensureStripeCustomer.mockRejectedValue(new Error('Stripe error'))

      const result = await userOnboardingService.completeOnboarding(validRegistration)

      // Should still complete onboarding despite payment failure
      expect(result).toBeDefined()
      expect(result.email).toBe(validRegistration.email)
    })

    test('should reject invalid registration data', async () => {
      const invalidRegistration = {
        email: 'invalid-email',
        name: '',
        password: '123',
      } as UserRegistration

      await expect(userOnboardingService.completeOnboarding(invalidRegistration)).rejects.toThrow(
        'Invalid user data'
      )
    })

    test('should set default timezone and language', async () => {
      const registrationWithoutOptionals: UserRegistration = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'securePassword123',
      }

      const result = await userOnboardingService.completeOnboarding(registrationWithoutOptionals)

      expect(result.timezone).toBeDefined()
      expect(result.language).toBe('en')
    })

    test('should generate unique user ID and verification token', async () => {
      const result1 = await userOnboardingService.completeOnboarding(validRegistration)
      const result2 = await userOnboardingService.completeOnboarding({
        ...validRegistration,
        email: 'test2@example.com',
      })

      expect(result1.id).not.toBe(result2.id)
      expect(result1.emailVerificationToken).not.toBe(result2.emailVerificationToken)
      expect(result1.emailVerificationToken).toBeDefined()
      expect(result2.emailVerificationToken).toBeDefined()
    })
  })

  describe('getUserById', () => {
    test('should return user when found', async () => {
      const mockUser: User = {
        id: 'user-123',
        email: 'test@example.com',
        name: 'Test User',
        emailVerified: true,
        subscriptionStatus: 'free',
        usageQuotas: createDefaultUsageQuotas('free'),
        isActive: true,
        loginAttempts: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      mockStorage.getItem.mockResolvedValue(mockUser)

      const result = await userOnboardingService.getUserById('user-123')

      expect(result).toEqual(mockUser)
      expect(mockStorage.getItem).toHaveBeenCalledWith('users', 'user-123')
    })

    test('should return null when user not found', async () => {
      mockStorage.getItem.mockResolvedValue(null)

      const result = await userOnboardingService.getUserById('nonexistent')

      expect(result).toBeNull()
    })

    test('should handle storage errors gracefully', async () => {
      mockStorage.getItem.mockRejectedValue(new Error('Storage error'))

      const result = await userOnboardingService.getUserById('user-123')

      expect(result).toBeNull()
    })
  })

  describe('getUserByEmail', () => {
    test('should return user when found by email', async () => {
      const mockUsers: User[] = [
        {
          id: 'user-1',
          email: 'user1@example.com',
          name: 'User 1',
          emailVerified: true,
          subscriptionStatus: 'free',
          usageQuotas: createDefaultUsageQuotas('free'),
          isActive: true,
          loginAttempts: 0,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'user-2',
          email: 'user2@example.com',
          name: 'User 2',
          emailVerified: true,
          subscriptionStatus: 'active',
          usageQuotas: createDefaultUsageQuotas('pro'),
          isActive: true,
          loginAttempts: 0,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ]

      mockStorage.getAllItems.mockResolvedValue(mockUsers)

      const result = await userOnboardingService.getUserByEmail('user2@example.com')

      expect(result).toEqual(mockUsers[1])
    })

    test('should return null when email not found', async () => {
      mockStorage.getAllItems.mockResolvedValue([])

      const result = await userOnboardingService.getUserByEmail('notfound@example.com')

      expect(result).toBeNull()
    })

    test('should handle storage errors gracefully', async () => {
      mockStorage.getAllItems.mockRejectedValue(new Error('Storage error'))

      const result = await userOnboardingService.getUserByEmail('test@example.com')

      expect(result).toBeNull()
    })
  })

  describe('verifyEmail', () => {
    const mockUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      name: 'Test User',
      emailVerified: false,
      emailVerificationToken: 'verification-token',
      subscriptionStatus: 'free',
      usageQuotas: createDefaultUsageQuotas('free'),
      isActive: true,
      loginAttempts: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    }

    test('should verify email with correct token', async () => {
      mockStorage.getItem.mockResolvedValue(mockUser)

      const result = await userOnboardingService.verifyEmail('user-123', 'verification-token')

      expect(result).toBe(true)
      expect(mockStorage.setItem).toHaveBeenCalledWith(
        'users',
        'user-123',
        expect.objectContaining({
          emailVerified: true,
          emailVerificationToken: undefined,
        })
      )
    })

    test('should reject verification with incorrect token', async () => {
      mockStorage.getItem.mockResolvedValue(mockUser)

      const result = await userOnboardingService.verifyEmail('user-123', 'wrong-token')

      expect(result).toBe(false)
      expect(mockStorage.setItem).not.toHaveBeenCalled()
    })

    test('should reject verification for nonexistent user', async () => {
      mockStorage.getItem.mockResolvedValue(null)

      const result = await userOnboardingService.verifyEmail('nonexistent', 'any-token')

      expect(result).toBe(false)
    })

    test('should handle storage errors gracefully', async () => {
      mockStorage.getItem.mockRejectedValue(new Error('Storage error'))

      const result = await userOnboardingService.verifyEmail('user-123', 'verification-token')

      expect(result).toBe(false)
    })
  })

  describe('Error Handling', () => {
    test('should handle user creation failure', async () => {
      mockStorage.setItem.mockRejectedValue(new Error('Storage full'))

      await expect(
        userOnboardingService.completeOnboarding({
          email: 'test@example.com',
          name: 'Test User',
          password: 'securePassword123',
        })
      ).rejects.toThrow('Storage full')
    })

    test('should handle password hashing failure', async () => {
      mockHashPassword.mockImplementation(() => {
        throw new Error('Hashing failed')
      })

      await expect(
        userOnboardingService.completeOnboarding({
          email: 'test@example.com',
          name: 'Test User',
          password: 'securePassword123',
        })
      ).rejects.toThrow('Hashing failed')
    })
  })

  describe('Integration with Usage Quotas', () => {
    test('should initialize correct quotas for different plans', async () => {
      const registration: UserRegistration = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'securePassword123',
      }

      // Test free plan (default)
      const freeUser = await userOnboardingService.completeOnboarding(registration)
      expect(freeUser.usageQuotas.scrapingRequests.limit).toBe(10)

      // Test with pro plan
      const proUser = await userOnboardingService.completeOnboarding(
        { ...registration, email: 'pro@example.com' },
        'pro'
      )
      expect(proUser.usageQuotas.scrapingRequests.limit).toBe(1000)
    })

    test('should set quota reset dates in the future', async () => {
      const result = await userOnboardingService.completeOnboarding({
        email: 'test@example.com',
        name: 'Test User',
        password: 'securePassword123',
      })

      const now = new Date()
      expect(result.usageQuotas.scrapingRequests.resetDate.getTime()).toBeGreaterThan(now.getTime())
      expect(result.usageQuotas.exports.resetDate.getTime()).toBeGreaterThan(now.getTime())
    })
  })
})
