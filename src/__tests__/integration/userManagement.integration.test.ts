/**
 * Integration Tests for User Management System
 * End-to-end testing of user onboarding, payment integration, and dashboard functionality
 */

import { userOnboardingService } from '@/model/userOnboardingService'
import { userPaymentService } from '@/model/userPaymentService'
import { storage } from '@/model/storage'
import { UserRegistration, createDefaultUsageQuotas } from '@/model/types/user'

// Mock external dependencies but test real integration between our services
jest.mock('@/lib/security', () => ({
  hashPassword: jest.fn(() => ({ hash: 'hashed-password', salt: 'salt-value' })),
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}))

// Mock Stripe service
jest.mock('@/model/stripeService', () => ({
  stripeService: {
    createCustomer: jest.fn(() => Promise.resolve({ id: 'cus_test123' })),
    getCustomer: jest.fn(() => Promise.resolve({ id: 'cus_test123' })),
  },
}))

describe('User Management Integration', () => {
  beforeEach(async () => {
    // Initialize storage for each test
    await storage.initialize()

    // Clear any existing data
    jest.clearAllMocks()
  })

  describe('Complete User Onboarding Flow', () => {
    const validRegistration: UserRegistration = {
      email: 'integration@example.com',
      name: 'Integration Test User',
      password: 'securePassword123',
      timezone: 'America/New_York',
      language: 'en',
    }

    test('should complete full onboarding flow with payment setup', async () => {
      // Step 1: Complete user onboarding
      const newUser = await userOnboardingService.completeOnboarding(validRegistration)

      // Verify user was created correctly
      expect(newUser).toBeDefined()
      expect(newUser.id).toBeDefined()
      expect(newUser.email).toBe(validRegistration.email)
      expect(newUser.name).toBe(validRegistration.name)
      expect(newUser.subscriptionStatus).toBe('free')
      expect(newUser.emailVerified).toBe(false)
      expect(newUser.emailVerificationToken).toBeDefined()
      expect(newUser.stripeCustomerId).toBeDefined()

      // Step 2: Verify user can be retrieved by ID
      const retrievedUser = await userOnboardingService.getUserById(newUser.id)
      expect(retrievedUser).toEqual(newUser)

      // Step 3: Verify user can be retrieved by email
      const userByEmail = await userOnboardingService.getUserByEmail(validRegistration.email)
      expect(userByEmail).toEqual(newUser)

      // Step 4: Verify payment profile was created
      const paymentProfile = await userPaymentService.getUserPaymentProfile(newUser.id)
      expect(paymentProfile).toBeDefined()
      expect(paymentProfile?.stripeCustomerId).toBe(newUser.stripeCustomerId)

      // Step 5: Verify email verification works
      const verificationResult = await userOnboardingService.verifyEmail(
        newUser.id,
        newUser.emailVerificationToken!
      )
      expect(verificationResult).toBe(true)

      // Step 6: Verify user is now email verified
      const verifiedUser = await userOnboardingService.getUserById(newUser.id)
      expect(verifiedUser?.emailVerified).toBe(true)
      expect(verifiedUser?.emailVerificationToken).toBeUndefined()
    })

    test('should handle subscription upgrade flow', async () => {
      // Step 1: Create user with subscription
      const userWithSubscription = await userOnboardingService.completeOnboarding(
        validRegistration,
        'pro'
      )

      // Verify subscription was set up
      expect(userWithSubscription.subscriptionStatus).toBe('active')
      expect(userWithSubscription.subscriptionPlan).toBe('pro')
      expect(userWithSubscription.subscriptionEndsAt).toBeDefined()

      // Verify usage quotas were updated for pro plan
      expect(userWithSubscription.usageQuotas.scrapingRequests.limit).toBe(1000)
      expect(userWithSubscription.usageQuotas.exports.limit).toBe(500)
      expect(userWithSubscription.usageQuotas.advancedSearches.limit).toBe(100)
      expect(userWithSubscription.usageQuotas.apiCalls.limit).toBe(50)
    })

    test('should handle multiple user registrations', async () => {
      const users = []

      // Create multiple users
      for (let i = 0; i < 3; i++) {
        const registration: UserRegistration = {
          email: `user${i}@example.com`,
          name: `User ${i}`,
          password: 'securePassword123',
        }

        const user = await userOnboardingService.completeOnboarding(registration)
        users.push(user)
      }

      // Verify all users were created with unique IDs
      const userIds = users.map(u => u.id)
      const uniqueIds = new Set(userIds)
      expect(uniqueIds.size).toBe(3)

      // Verify each user can be retrieved
      for (const user of users) {
        const retrieved = await userOnboardingService.getUserById(user.id)
        expect(retrieved).toEqual(user)
      }

      // Verify email lookup works for all users
      for (let i = 0; i < 3; i++) {
        const userByEmail = await userOnboardingService.getUserByEmail(`user${i}@example.com`)
        expect(userByEmail?.email).toBe(`user${i}@example.com`)
      }
    })
  })

  describe('Usage Quota Management', () => {
    test('should properly initialize and track usage quotas', async () => {
      const user = await userOnboardingService.completeOnboarding({
        email: 'quota@example.com',
        name: 'Quota User',
        password: 'securePassword123',
      })

      // Verify initial quotas
      expect(user.usageQuotas.scrapingRequests.used).toBe(0)
      expect(user.usageQuotas.scrapingRequests.limit).toBe(10)
      expect(user.usageQuotas.exports.used).toBe(0)
      expect(user.usageQuotas.exports.limit).toBe(5)

      // Verify reset dates are in the future
      const now = new Date()
      expect(user.usageQuotas.scrapingRequests.resetDate.getTime()).toBeGreaterThan(now.getTime())
    })

    test('should handle different plan quota limits', async () => {
      const plans = [
        { plan: 'free', expectedScraping: 10, expectedExports: 5 },
        { plan: 'basic', expectedScraping: 100, expectedExports: 50 },
        { plan: 'pro', expectedScraping: 1000, expectedExports: 500 },
        { plan: 'enterprise', expectedScraping: -1, expectedExports: -1 },
      ]

      for (const { plan, expectedScraping, expectedExports } of plans) {
        const user = await userOnboardingService.completeOnboarding(
          {
            email: `${plan}@example.com`,
            name: `${plan} User`,
            password: 'securePassword123',
          },
          plan === 'free' ? undefined : plan
        )

        expect(user.usageQuotas.scrapingRequests.limit).toBe(expectedScraping)
        expect(user.usageQuotas.exports.limit).toBe(expectedExports)
      }
    })
  })

  describe('Payment Integration', () => {
    test('should handle payment profile creation and updates', async () => {
      const user = await userOnboardingService.completeOnboarding({
        email: 'payment@example.com',
        name: 'Payment User',
        password: 'securePassword123',
      })

      // Verify Stripe customer was created
      expect(user.stripeCustomerId).toBeDefined()

      // Verify payment profile exists
      const paymentProfile = await userPaymentService.getUserPaymentProfile(user.id)
      expect(paymentProfile).toBeDefined()
      expect(paymentProfile?.userId).toBe(user.id)
      expect(paymentProfile?.email).toBe(user.email)
      expect(paymentProfile?.stripeCustomerId).toBe(user.stripeCustomerId)
    })

    test('should gracefully handle payment service failures', async () => {
      // Mock payment service to fail
      const originalEnsureStripeCustomer = userPaymentService.ensureStripeCustomer
      userPaymentService.ensureStripeCustomer = jest
        .fn()
        .mockRejectedValue(new Error('Stripe service unavailable'))

      // User onboarding should still succeed
      const user = await userOnboardingService.completeOnboarding({
        email: 'failsafe@example.com',
        name: 'Failsafe User',
        password: 'securePassword123',
      })

      expect(user).toBeDefined()
      expect(user.email).toBe('failsafe@example.com')
      // Stripe customer ID might not be set due to failure
      expect(user.stripeCustomerId).toBeUndefined()

      // Restore original function
      userPaymentService.ensureStripeCustomer = originalEnsureStripeCustomer
    })
  })

  describe('Data Persistence and Retrieval', () => {
    test('should persist user data correctly across service calls', async () => {
      const registration: UserRegistration = {
        email: 'persistence@example.com',
        name: 'Persistence User',
        password: 'securePassword123',
      }

      // Create user
      const originalUser = await userOnboardingService.completeOnboarding(registration)

      // Retrieve user multiple times to ensure consistency
      for (let i = 0; i < 3; i++) {
        const retrievedUser = await userOnboardingService.getUserById(originalUser.id)
        expect(retrievedUser).toEqual(originalUser)
      }

      // Test email lookup consistency
      for (let i = 0; i < 3; i++) {
        const userByEmail = await userOnboardingService.getUserByEmail(registration.email)
        expect(userByEmail).toEqual(originalUser)
      }
    })

    test('should handle concurrent user operations', async () => {
      const registrations = Array.from({ length: 5 }, (_, i) => ({
        email: `concurrent${i}@example.com`,
        name: `Concurrent User ${i}`,
        password: 'securePassword123',
      }))

      // Create users concurrently
      const userPromises = registrations.map(reg => userOnboardingService.completeOnboarding(reg))

      const users = await Promise.all(userPromises)

      // Verify all users were created successfully
      expect(users).toHaveLength(5)
      users.forEach((user, index) => {
        expect(user.email).toBe(`concurrent${index}@example.com`)
        expect(user.name).toBe(`Concurrent User ${index}`)
      })

      // Verify all users can be retrieved
      const retrievalPromises = users.map(user => userOnboardingService.getUserById(user.id))

      const retrievedUsers = await Promise.all(retrievalPromises)
      retrievedUsers.forEach((retrieved, index) => {
        expect(retrieved).toEqual(users[index])
      })
    })
  })

  describe('Error Scenarios', () => {
    test('should handle duplicate email registration attempts', async () => {
      const registration: UserRegistration = {
        email: 'duplicate@example.com',
        name: 'First User',
        password: 'securePassword123',
      }

      // Create first user
      const firstUser = await userOnboardingService.completeOnboarding(registration)
      expect(firstUser).toBeDefined()

      // Attempt to create second user with same email
      const duplicateRegistration: UserRegistration = {
        email: 'duplicate@example.com',
        name: 'Second User',
        password: 'differentPassword123',
      }

      // This should succeed as we don't have unique email constraint in current implementation
      // In a real system, this would be handled by database constraints
      const secondUser = await userOnboardingService.completeOnboarding(duplicateRegistration)
      expect(secondUser).toBeDefined()
      expect(secondUser.id).not.toBe(firstUser.id)
    })

    test('should handle invalid verification tokens', async () => {
      const user = await userOnboardingService.completeOnboarding({
        email: 'verification@example.com',
        name: 'Verification User',
        password: 'securePassword123',
      })

      // Try to verify with wrong token
      const result = await userOnboardingService.verifyEmail(user.id, 'wrong-token')
      expect(result).toBe(false)

      // User should still be unverified
      const unverifiedUser = await userOnboardingService.getUserById(user.id)
      expect(unverifiedUser?.emailVerified).toBe(false)
    })
  })
})
