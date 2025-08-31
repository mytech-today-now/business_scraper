/**
 * Unit Tests for User Model Types
 * Comprehensive testing of user interfaces, validation, and utility functions
 */

import {
  User,
  BillingAddress,
  UsageQuotas,
  UserRegistration,
  UserProfileUpdate,
  validateUser,
  validateUserRegistration,
  validateUserProfileUpdate,
  isUser,
  isBillingAddress,
  isUsageQuotas,
  createDefaultUsageQuotas,
  isQuotaExceeded,
  getUsagePercentage,
  isAccountLocked,
  hasActiveSubscription,
  getUserDisplayName,
  resetUsageQuotas,
} from '@/model/types/user'

describe('User Model Types', () => {
  describe('User Interface Validation', () => {
    const validUser: User = {
      id: 'user-123',
      email: 'test@example.com',
      name: 'Test User',
      emailVerified: true,
      subscriptionStatus: 'free',
      usageQuotas: createDefaultUsageQuotas('free'),
      isActive: true,
      loginAttempts: 0,
      createdAt: new Date('2024-01-01'),
      updatedAt: new Date('2024-01-01'),
    }

    test('should validate a complete valid user', () => {
      const result = validateUser(validUser)
      expect(result.success).toBe(true)
      expect(result.data).toEqual(validUser)
      expect(result.errors).toBeUndefined()
    })

    test('should reject user with invalid email', () => {
      const invalidUser = { ...validUser, email: 'invalid-email' }
      const result = validateUser(invalidUser)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('email: Invalid email format')
    })

    test('should reject user with missing required fields', () => {
      const incompleteUser = { email: 'test@example.com' }
      const result = validateUser(incompleteUser)
      expect(result.success).toBe(false)
      expect(result.errors?.length).toBeGreaterThan(0)
    })

    test('should reject user with invalid subscription status', () => {
      const invalidUser = { ...validUser, subscriptionStatus: 'invalid' as any }
      const result = validateUser(invalidUser)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('subscriptionStatus: Invalid subscription status')
    })

    test('should validate user with optional fields', () => {
      const userWithOptionals: User = {
        ...validUser,
        stripeCustomerId: 'cus_123',
        subscriptionPlan: 'pro',
        subscriptionEndsAt: new Date('2024-12-31'),
        paymentMethodLast4: '1234',
        paymentMethodBrand: 'visa',
        billingAddress: {
          line1: '123 Main St',
          city: 'Anytown',
          state: 'CA',
          postalCode: '12345',
          country: 'US',
        },
        profilePicture: 'https://example.com/avatar.jpg',
        phoneNumber: '+1234567890',
        timezone: 'America/New_York',
        language: 'en',
        lastLoginAt: new Date('2024-01-15'),
      }

      const result = validateUser(userWithOptionals)
      expect(result.success).toBe(true)
    })
  })

  describe('BillingAddress Validation', () => {
    const validAddress: BillingAddress = {
      line1: '123 Main St',
      city: 'Anytown',
      state: 'CA',
      postalCode: '12345',
      country: 'US',
    }

    test('should validate complete billing address', () => {
      expect(isBillingAddress(validAddress)).toBe(true)
    })

    test('should reject address with missing required fields', () => {
      const incompleteAddress = { line1: '123 Main St' }
      expect(isBillingAddress(incompleteAddress)).toBe(false)
    })

    test('should reject address with invalid country code', () => {
      const invalidAddress = { ...validAddress, country: 'USA' }
      expect(isBillingAddress(invalidAddress)).toBe(false)
    })

    test('should accept address with optional line2', () => {
      const addressWithLine2 = { ...validAddress, line2: 'Apt 4B' }
      expect(isBillingAddress(addressWithLine2)).toBe(true)
    })
  })

  describe('UsageQuotas Validation', () => {
    const validQuotas: UsageQuotas = createDefaultUsageQuotas('free')

    test('should validate usage quotas', () => {
      expect(isUsageQuotas(validQuotas)).toBe(true)
    })

    test('should reject quotas with negative usage', () => {
      const invalidQuotas = {
        ...validQuotas,
        scrapingRequests: { ...validQuotas.scrapingRequests, used: -1 },
      }
      expect(isUsageQuotas(invalidQuotas)).toBe(false)
    })

    test('should accept unlimited quotas', () => {
      const unlimitedQuotas = {
        ...validQuotas,
        scrapingRequests: { ...validQuotas.scrapingRequests, limit: -1 },
      }
      expect(isUsageQuotas(unlimitedQuotas)).toBe(true)
    })
  })

  describe('UserRegistration Validation', () => {
    const validRegistration: UserRegistration = {
      email: 'newuser@example.com',
      name: 'New User',
      password: 'securePassword123',
    }

    test('should validate user registration', () => {
      const result = validateUserRegistration(validRegistration)
      expect(result.success).toBe(true)
      expect(result.data).toEqual(validRegistration)
    })

    test('should reject registration with weak password', () => {
      const weakPassword = { ...validRegistration, password: '123' }
      const result = validateUserRegistration(weakPassword)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('password: Password must be at least 8 characters')
    })

    test('should reject registration with invalid email', () => {
      const invalidEmail = { ...validRegistration, email: 'not-an-email' }
      const result = validateUserRegistration(invalidEmail)
      expect(result.success).toBe(false)
      expect(result.errors).toContain('email: Invalid email format')
    })

    test('should accept registration with optional fields', () => {
      const withOptionals = {
        ...validRegistration,
        timezone: 'America/New_York',
        language: 'en',
      }
      const result = validateUserRegistration(withOptionals)
      expect(result.success).toBe(true)
    })
  })

  describe('UserProfileUpdate Validation', () => {
    test('should validate profile update with partial data', () => {
      const update: UserProfileUpdate = {
        name: 'Updated Name',
        phoneNumber: '+1234567890',
      }
      const result = validateUserProfileUpdate(update)
      expect(result.success).toBe(true)
    })

    test('should reject update with invalid email', () => {
      const invalidUpdate = { email: 'invalid-email' }
      const result = validateUserProfileUpdate(invalidUpdate)
      expect(result.success).toBe(false)
    })

    test('should accept empty update object', () => {
      const result = validateUserProfileUpdate({})
      expect(result.success).toBe(true)
    })
  })

  describe('Utility Functions', () => {
    describe('createDefaultUsageQuotas', () => {
      test('should create free plan quotas', () => {
        const quotas = createDefaultUsageQuotas('free')
        expect(quotas.scrapingRequests.limit).toBe(10)
        expect(quotas.exports.limit).toBe(5)
        expect(quotas.advancedSearches.limit).toBe(0)
        expect(quotas.apiCalls.limit).toBe(0)
      })

      test('should create pro plan quotas', () => {
        const quotas = createDefaultUsageQuotas('pro')
        expect(quotas.scrapingRequests.limit).toBe(1000)
        expect(quotas.exports.limit).toBe(500)
        expect(quotas.advancedSearches.limit).toBe(100)
        expect(quotas.apiCalls.limit).toBe(50)
      })

      test('should create enterprise plan quotas', () => {
        const quotas = createDefaultUsageQuotas('enterprise')
        expect(quotas.scrapingRequests.limit).toBe(-1)
        expect(quotas.exports.limit).toBe(-1)
        expect(quotas.advancedSearches.limit).toBe(-1)
        expect(quotas.apiCalls.limit).toBe(-1)
      })

      test('should default to free plan for unknown plan', () => {
        const quotas = createDefaultUsageQuotas('unknown')
        expect(quotas.scrapingRequests.limit).toBe(10)
      })
    })

    describe('isQuotaExceeded', () => {
      const quotas = createDefaultUsageQuotas('free')

      test('should return false when under limit', () => {
        const underLimit = { ...quotas, scrapingRequests: { ...quotas.scrapingRequests, used: 5 } }
        expect(isQuotaExceeded(underLimit, 'scrapingRequests')).toBe(false)
      })

      test('should return true when at limit', () => {
        const atLimit = { ...quotas, scrapingRequests: { ...quotas.scrapingRequests, used: 10 } }
        expect(isQuotaExceeded(atLimit, 'scrapingRequests')).toBe(true)
      })

      test('should return false for unlimited quota', () => {
        const unlimited = {
          ...quotas,
          scrapingRequests: { ...quotas.scrapingRequests, limit: -1, used: 1000 },
        }
        expect(isQuotaExceeded(unlimited, 'scrapingRequests')).toBe(false)
      })
    })

    describe('getUsagePercentage', () => {
      const quotas = createDefaultUsageQuotas('free')

      test('should calculate correct percentage', () => {
        const halfUsed = { ...quotas, scrapingRequests: { ...quotas.scrapingRequests, used: 5 } }
        expect(getUsagePercentage(halfUsed, 'scrapingRequests')).toBe(50)
      })

      test('should return -1 for unlimited quota', () => {
        const unlimited = { ...quotas, scrapingRequests: { ...quotas.scrapingRequests, limit: -1 } }
        expect(getUsagePercentage(unlimited, 'scrapingRequests')).toBe(-1)
      })

      test('should cap at 100%', () => {
        const overLimit = { ...quotas, scrapingRequests: { ...quotas.scrapingRequests, used: 15 } }
        expect(getUsagePercentage(overLimit, 'scrapingRequests')).toBe(100)
      })
    })

    describe('isAccountLocked', () => {
      const baseUser: User = {
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

      test('should return false for unlocked account', () => {
        expect(isAccountLocked(baseUser)).toBe(false)
      })

      test('should return true for locked account', () => {
        const lockedUser = { ...baseUser, lockedUntil: new Date(Date.now() + 3600000) }
        expect(isAccountLocked(lockedUser)).toBe(true)
      })

      test('should return false for expired lock', () => {
        const expiredLock = { ...baseUser, lockedUntil: new Date(Date.now() - 3600000) }
        expect(isAccountLocked(expiredLock)).toBe(false)
      })
    })

    describe('hasActiveSubscription', () => {
      const baseUser: User = {
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

      test('should return false for free user', () => {
        expect(hasActiveSubscription(baseUser)).toBe(false)
      })

      test('should return true for active subscription', () => {
        const activeUser = {
          ...baseUser,
          subscriptionStatus: 'active' as const,
          subscriptionEndsAt: new Date(Date.now() + 86400000),
        }
        expect(hasActiveSubscription(activeUser)).toBe(true)
      })

      test('should return false for expired subscription', () => {
        const expiredUser = {
          ...baseUser,
          subscriptionStatus: 'active' as const,
          subscriptionEndsAt: new Date(Date.now() - 86400000),
        }
        expect(hasActiveSubscription(expiredUser)).toBe(false)
      })
    })

    describe('getUserDisplayName', () => {
      test('should return name when available', () => {
        const user = {
          name: 'John Doe',
          email: 'john@example.com',
        } as User
        expect(getUserDisplayName(user)).toBe('John Doe')
      })

      test('should return email when name is empty', () => {
        const user = {
          name: '',
          email: 'john@example.com',
        } as User
        expect(getUserDisplayName(user)).toBe('john@example.com')
      })
    })
  })

  describe('Type Guards', () => {
    test('isUser should correctly identify valid user objects', () => {
      const validUser: User = {
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

      expect(isUser(validUser)).toBe(true)
      expect(isUser({})).toBe(false)
      expect(isUser(null)).toBe(false)
      expect(isUser('not a user')).toBe(false)
    })
  })
})
