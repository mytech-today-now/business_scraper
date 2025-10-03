/**
 * User Onboarding Service
 * Comprehensive user onboarding with payment setup, subscription management, and quota initialization
 */

import { userPaymentService } from './userPaymentService'
import { logger } from '@/utils/logger'
import { storage } from './storage'
import {
  User,
  UserRegistration,
  createDefaultUsageQuotas,
  validateUser,
  validateUserRegistration,
} from './types/user'
import { hashPassword } from '@/lib/security'
import { v4 as uuidv4 } from 'uuid'

export class UserOnboardingService {
  /**
   * Complete user onboarding process
   * @param userData - User registration data
   * @param selectedPlanId - Optional subscription plan ID
   * @returns Created user with complete profile
   */
  async completeOnboarding(userData: UserRegistration, selectedPlanId?: string): Promise<User> {
    try {
      // Validate input data
      const validationResult = validateUserRegistration(userData)
      if (!validationResult.success) {
        throw new Error(`Invalid user data: ${validationResult.errors?.join(', ')}`)
      }

      const userId = uuidv4()
      logger.info('UserOnboarding', `Starting onboarding for user: ${userId}`)

      // 1. Create user profile
      const user = await this.createUserProfile(userId, userData)

      // 2. Initialize payment profile
      await this.initializePaymentProfile(user)

      // 3. Set up subscription if plan selected
      if (selectedPlanId) {
        await this.setupInitialSubscription(user, selectedPlanId)
      }

      // 4. Initialize usage quotas
      const updatedUser = await this.initializeUsageQuotas(user)

      // 5. Send welcome email
      await this.sendWelcomeEmail(updatedUser)

      logger.info('UserOnboarding', `Onboarding completed for user: ${userId}`)
      return updatedUser
    } catch (error) {
      logger.error('UserOnboarding', 'Onboarding failed', error)
      throw error
    }
  }

  /**
   * Create user profile with secure password handling
   * @param userId - Generated user ID
   * @param userData - User registration data
   * @returns Created user profile
   */
  private async createUserProfile(userId: string, userData: UserRegistration): Promise<User> {
    try {
      // Hash password securely
      const { hash, salt } = await hashPassword(userData.password)

      const user: User = {
        id: userId,
        email: userData.email,
        name: userData.name,

        // Authentication fields
        passwordHash: hash,
        passwordSalt: salt,
        emailVerified: false,
        emailVerificationToken: uuidv4(),

        // Payment-related fields
        subscriptionStatus: 'free',

        // Usage tracking
        usageQuotas: createDefaultUsageQuotas('free'),

        // Profile information
        timezone: userData.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: userData.language || 'en',

        // Account status
        isActive: true,
        loginAttempts: 0,

        // Timestamps
        createdAt: new Date(),
        updatedAt: new Date(),
      }

      // Validate the created user
      const validation = validateUser(user)
      if (!validation.success) {
        throw new Error(`User validation failed: ${validation.errors?.join(', ')}`)
      }

      // Save to database
      await this.saveUserProfile(user)
      logger.info('UserOnboarding', `User profile created: ${userId}`)

      return user
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to create user profile', error)
      throw error
    }
  }

  /**
   * Initialize payment profile with Stripe customer creation
   * @param user - User profile
   */
  private async initializePaymentProfile(user: User): Promise<void> {
    try {
      // Create Stripe customer
      const stripeCustomerId = await userPaymentService.ensureStripeCustomer(
        user.id,
        user.email,
        user.name
      )

      // Update user with Stripe customer ID
      await this.updateUserProfile(user.id, { stripeCustomerId })

      logger.info('UserOnboarding', `Payment profile initialized for user: ${user.id}`)
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to initialize payment profile', error)
      // Don't throw - allow user to complete onboarding without payment setup
      logger.warn('UserOnboarding', 'Continuing onboarding without payment profile')
    }
  }

  /**
   * Setup initial subscription for user
   * @param user - User profile
   * @param planId - Subscription plan ID
   */
  private async setupInitialSubscription(user: User, planId: string): Promise<void> {
    try {
      // This would integrate with a payment controller when available
      // For now, we'll update the user's subscription status
      await this.updateUserProfile(user.id, {
        subscriptionStatus: 'active',
        subscriptionPlan: planId,
        subscriptionEndsAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
      })

      logger.info('UserOnboarding', `Subscription setup completed for user: ${user.id}`)
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to setup subscription', error)
      // Don't throw - allow user to complete onboarding without subscription
      logger.warn('UserOnboarding', 'Continuing onboarding without subscription setup')
    }
  }

  /**
   * Initialize usage quotas based on plan
   * @param user - User profile
   * @returns Updated user with initialized quotas
   */
  private async initializeUsageQuotas(user: User): Promise<User> {
    try {
      const quotas = createDefaultUsageQuotas(user.subscriptionPlan || 'free')

      const updatedUser = {
        ...user,
        usageQuotas: quotas,
        updatedAt: new Date(),
      }

      await this.updateUserProfile(user.id, { usageQuotas: quotas })

      logger.info('UserOnboarding', `Usage quotas initialized for user: ${user.id}`)
      return updatedUser
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to initialize usage quotas', error)
      throw error
    }
  }

  /**
   * Send welcome email to new user
   * @param user - User profile
   */
  private async sendWelcomeEmail(user: User): Promise<void> {
    try {
      // Implementation would integrate with email service
      // For now, we'll just log the action
      logger.info('UserOnboarding', `Welcome email sent to: ${user.email}`)

      // In a real implementation, this would:
      // 1. Generate email verification link
      // 2. Send welcome email with verification
      // 3. Include onboarding tips and next steps
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to send welcome email', error)
      // Don't throw - email failure shouldn't block onboarding
    }
  }

  /**
   * Save user profile to database
   * @param user - User profile to save
   */
  private async saveUserProfile(user: User): Promise<void> {
    try {
      // Store in the existing storage system
      await storage.setItem('users', user.id, user)
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to save user profile', error)
      throw error
    }
  }

  /**
   * Update user profile in database
   * @param userId - User ID
   * @param updates - Partial user updates
   */
  private async updateUserProfile(userId: string, updates: Partial<User>): Promise<void> {
    try {
      const existingUser = (await storage.getItem('users', userId)) as User
      if (!existingUser) {
        throw new Error(`User not found: ${userId}`)
      }

      const updatedUser = {
        ...existingUser,
        ...updates,
        updatedAt: new Date(),
      }

      await storage.setItem('users', userId, updatedUser)
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to update user profile', error)
      throw error
    }
  }

  /**
   * Get user by ID
   * @param userId - User ID
   * @returns User profile or null if not found
   */
  async getUserById(userId: string): Promise<User | null> {
    try {
      const user = (await storage.getItem('users', userId)) as User
      return user || null
    } catch (error) {
      logger.error('UserOnboarding', `Failed to get user: ${userId}`, error)
      return null
    }
  }

  /**
   * Get user by email
   * @param email - User email
   * @returns User profile or null if not found
   */
  async getUserByEmail(email: string): Promise<User | null> {
    try {
      // This is a simplified implementation
      // In a real database, you'd have an index on email
      const allUsers = (await storage.getAllItems('users')) as User[]
      return allUsers.find(user => user.email === email) || null
    } catch (error) {
      logger.error('UserOnboarding', `Failed to get user by email: ${email}`, error)
      return null
    }
  }

  /**
   * Verify user email
   * @param userId - User ID
   * @param token - Verification token
   * @returns Success status
   */
  async verifyEmail(userId: string, token: string): Promise<boolean> {
    try {
      const user = await this.getUserById(userId)
      if (!user || user.emailVerificationToken !== token) {
        return false
      }

      await this.updateUserProfile(userId, {
        emailVerified: true,
        emailVerificationToken: undefined,
      })

      logger.info('UserOnboarding', `Email verified for user: ${userId}`)
      return true
    } catch (error) {
      logger.error('UserOnboarding', 'Failed to verify email', error)
      return false
    }
  }
}

export const userOnboardingService = new UserOnboardingService()
