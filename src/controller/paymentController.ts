/**
 * Payment Controller
 * Comprehensive payment state management, feature access control, and subscription lifecycle management
 */

import { EventEmitter } from 'events'
import { logger } from '@/utils/logger'
import {
  SubscriptionPlan,
  UserSubscription,
  PaymentTransaction,
  FeatureUsage,
  isSubscriptionActive
} from '@/model/types/payment'

/**
 * Payment Controller Events
 */
export interface PaymentControllerEvents {
  'payment:initialized': () => void
  'payment:processing': () => void
  'payment:success': () => void
  'payment:error': (error: Error) => void
  'plans:loaded': (plans: SubscriptionPlan[]) => void
  'user:set': (user: any) => void
  'subscription:loaded': (subscription: UserSubscription | null) => void
  'subscription:created': (subscription: any) => void
  'subscription:canceled': () => void
  'usage:recorded': (data: { featureType: string; metadata?: any }) => void
  'access:denied': (data: { featureType: string; reason: string }) => void
}

/**
 * Payment Controller Class
 * Manages payment state, subscriptions, and feature access
 */
export class PaymentController extends EventEmitter {
  private currentUser: any = null
  private subscriptionPlans: SubscriptionPlan[] = []
  private userSubscription: UserSubscription | null = null
  private paymentStatus: 'idle' | 'processing' | 'success' | 'error' = 'idle'
  private isInitialized = false

  constructor() {
    super()
    this.setMaxListeners(50) // Allow more listeners for complex UI components
  }

  /**
   * Initialize payment system
   */
  async initializePaymentSystem(): Promise<void> {
    try {
      if (this.isInitialized) {
        logger.info('PaymentController', 'Payment system already initialized')
        return
      }

      await this.loadSubscriptionPlans()
      this.isInitialized = true
      this.emit('payment:initialized')
      logger.info('PaymentController', 'Payment system initialized successfully')
    } catch (error) {
      logger.error('PaymentController', 'Failed to initialize payment system', error)
      this.emit('payment:error', error as Error)
      throw error
    }
  }

  /**
   * Load available subscription plans
   */
  async loadSubscriptionPlans(): Promise<SubscriptionPlan[]> {
    try {
      // For now, return mock plans until userPaymentService is implemented
      this.subscriptionPlans = await this.getMockSubscriptionPlans()
      this.emit('plans:loaded', this.subscriptionPlans)
      logger.info('PaymentController', `Loaded ${this.subscriptionPlans.length} subscription plans`)
      return this.subscriptionPlans
    } catch (error) {
      logger.error('PaymentController', 'Failed to load subscription plans', error)
      throw error
    }
  }

  /**
   * Set current user and load their payment data
   */
  async setCurrentUser(user: any): Promise<void> {
    try {
      if (!user || !user.id) {
        throw new Error('Invalid user object provided')
      }

      this.currentUser = user
      await this.loadUserPaymentData()
      this.emit('user:set', user)
      logger.info('PaymentController', `Set current user: ${user.id}`)
    } catch (error) {
      logger.error('PaymentController', 'Failed to set current user', error)
      throw error
    }
  }

  /**
   * Load user's payment data
   */
  async loadUserPaymentData(): Promise<void> {
    if (!this.currentUser) {
      logger.warn('PaymentController', 'No current user set for loading payment data')
      return
    }

    try {
      // For now, return mock subscription until userPaymentService is implemented
      this.userSubscription = await this.getMockUserSubscription(this.currentUser.id)
      this.emit('subscription:loaded', this.userSubscription)
      logger.info('PaymentController', `Loaded payment data for user: ${this.currentUser.id}`)
    } catch (error) {
      logger.error('PaymentController', 'Failed to load user payment data', error)
      throw error
    }
  }

  /**
   * Create subscription
   */
  async createSubscription(planId: string, paymentMethodId?: string): Promise<any> {
    if (!this.currentUser) {
      throw new Error('No user set')
    }

    this.paymentStatus = 'processing'
    this.emit('payment:processing')

    try {
      // Find the plan
      const plan = this.subscriptionPlans.find(p => p.id === planId)
      if (!plan) {
        throw new Error(`Plan not found: ${planId}`)
      }

      logger.info('PaymentController', `Creating subscription for user ${this.currentUser.id} with plan ${planId}`)

      // Mock subscription creation until services are implemented
      const mockSubscription = await this.createMockSubscription(this.currentUser.id, planId)

      // Update local state
      await this.loadUserPaymentData()

      this.paymentStatus = 'success'
      this.emit('subscription:created', mockSubscription)
      this.emit('payment:success')

      logger.info('PaymentController', `Successfully created subscription: ${mockSubscription.id}`)
      return mockSubscription
    } catch (error) {
      this.paymentStatus = 'error'
      this.emit('payment:error', error as Error)
      logger.error('PaymentController', 'Failed to create subscription', error)
      throw error
    }
  }

  /**
   * Cancel subscription
   */
  async cancelSubscription(): Promise<void> {
    if (!this.userSubscription) {
      throw new Error('No active subscription to cancel')
    }

    try {
      logger.info('PaymentController', `Canceling subscription: ${this.userSubscription.id}`)

      // Mock cancellation until userPaymentService is implemented
      await this.cancelMockSubscription(this.userSubscription.id)
      
      await this.loadUserPaymentData()
      this.emit('subscription:canceled')
      
      logger.info('PaymentController', 'Successfully canceled subscription')
    } catch (error) {
      logger.error('PaymentController', 'Failed to cancel subscription', error)
      throw error
    }
  }

  /**
   * Check feature access
   */
  async checkFeatureAccess(featureType: string): Promise<boolean> {
    if (!this.currentUser) {
      logger.warn('PaymentController', 'No user set for feature access check')
      return false
    }

    try {
      // Mock feature access check until userPaymentService is implemented
      const hasAccess = await this.mockCheckFeatureAccess(this.currentUser.id, featureType)
      
      if (!hasAccess) {
        this.emit('access:denied', { featureType, reason: 'subscription_required' })
      }

      return hasAccess
    } catch (error) {
      logger.error('PaymentController', 'Failed to check feature access', error)
      return false
    }
  }

  /**
   * Record feature usage
   */
  async recordFeatureUsage(featureType: string, metadata?: any): Promise<void> {
    if (!this.currentUser) {
      logger.warn('PaymentController', 'No user set for recording feature usage')
      return
    }

    try {
      // Mock usage recording until userPaymentService is implemented
      await this.mockRecordFeatureUsage(this.currentUser.id, featureType, metadata)
      
      this.emit('usage:recorded', { featureType, metadata })
      logger.debug('PaymentController', `Recorded feature usage: ${featureType} for user ${this.currentUser.id}`)
    } catch (error) {
      logger.error('PaymentController', 'Failed to record feature usage', error)
      throw error
    }
  }

  // ============================================================================
  // GETTERS
  // ============================================================================

  /**
   * Get subscription plans
   */
  getSubscriptionPlans(): SubscriptionPlan[] {
    return [...this.subscriptionPlans]
  }

  /**
   * Get user subscription
   */
  getUserSubscription(): UserSubscription | null {
    return this.userSubscription ? { ...this.userSubscription } : null
  }

  /**
   * Get payment status
   */
  getPaymentStatus(): string {
    return this.paymentStatus
  }

  /**
   * Check if user has active subscription
   */
  hasActiveSubscription(): boolean {
    return this.userSubscription ? isSubscriptionActive(this.userSubscription) : false
  }

  /**
   * Get current user
   */
  getCurrentUser(): any {
    return this.currentUser ? { ...this.currentUser } : null
  }

  /**
   * Check if payment system is initialized
   */
  isPaymentSystemInitialized(): boolean {
    return this.isInitialized
  }

  // ============================================================================
  // MOCK METHODS (TO BE REPLACED WITH REAL SERVICES)
  // ============================================================================

  private async getMockSubscriptionPlans(): Promise<SubscriptionPlan[]> {
    // Mock data until userPaymentService is implemented
    return [
      {
        id: 'free',
        stripePriceId: 'price_free',
        name: 'Free',
        description: 'Basic features for getting started',
        priceCents: 0,
        currency: 'USD',
        interval: 'month',
        features: ['10 scraping requests', '5 exports', 'Basic support'],
        isActive: true,
        createdAt: new Date()
      },
      {
        id: 'basic',
        stripePriceId: 'price_basic',
        name: 'Basic',
        description: 'Perfect for small businesses',
        priceCents: 2900,
        currency: 'USD',
        interval: 'month',
        features: ['100 scraping requests', '50 exports', '10 advanced searches', 'Email support'],
        isActive: true,
        createdAt: new Date()
      },
      {
        id: 'pro',
        stripePriceId: 'price_pro',
        name: 'Pro',
        description: 'Advanced features for growing businesses',
        priceCents: 9900,
        currency: 'USD',
        interval: 'month',
        features: ['1000 scraping requests', '500 exports', '100 advanced searches', '50 API calls', 'Priority support'],
        isActive: true,
        createdAt: new Date()
      }
    ]
  }

  private async getMockUserSubscription(userId: string): Promise<UserSubscription | null> {
    // Mock user subscription - return null for free tier
    return null
  }

  private async createMockSubscription(userId: string, planId: string): Promise<any> {
    // Mock subscription creation
    return {
      id: `sub_${Date.now()}`,
      userId,
      planId,
      status: 'active',
      createdAt: new Date()
    }
  }

  private async cancelMockSubscription(subscriptionId: string): Promise<void> {
    // Mock subscription cancellation
    logger.info('PaymentController', `Mock cancellation of subscription: ${subscriptionId}`)
  }

  private async mockCheckFeatureAccess(userId: string, featureType: string): Promise<boolean> {
    // Mock feature access check - allow all for now
    return true
  }

  private async mockRecordFeatureUsage(userId: string, featureType: string, metadata?: any): Promise<void> {
    // Mock usage recording
    logger.debug('PaymentController', `Mock usage recording: ${featureType} for user ${userId}`, metadata)
  }
}

// Export singleton instance
export const paymentController = new PaymentController()
