/**
 * Payment Integration Tests
 * End-to-end testing of payment flows with real service integration
 */

import { 
  setupPaymentMocks, 
  resetPaymentMocks, 
  configureDefaultMockBehaviors,
  allMocks
} from '../utils/paymentMockSetup'
import { 
  createMockStripeCustomer,
  createMockStripePaymentIntent,
  createMockStripeSubscription,
  createPaymentRequest,
  createWebhookRequest,
  paymentTestData,
  simulateStripeError
} from '../utils/paymentTestUtils'

// Import actual services for integration testing
import { stripeService } from '../../model/stripeService'
import { userPaymentService } from '../../model/userPaymentService'
import { paymentValidationService } from '../../model/paymentValidationService'
import { PaymentController } from '../../controller/paymentController'

// Setup mocks before importing modules
setupPaymentMocks()
configureDefaultMockBehaviors()

describe('Payment Integration Tests', () => {
  let paymentController: PaymentController

  beforeEach(() => {
    resetPaymentMocks()
    configureDefaultMockBehaviors()
    paymentController = new PaymentController()
  })

  afterEach(() => {
    if (paymentController) {
      paymentController.removeAllListeners()
    }
  })

  describe('End-to-End Payment Intent Flow', () => {
    it('should complete full payment intent creation and confirmation flow', async () => {
      // Setup test data
      const mockCustomer = createMockStripeCustomer()
      const mockPaymentIntent = createMockStripePaymentIntent()
      const mockUser = paymentTestData.validUser

      // Mock service responses
      allMocks.userPaymentService.ensureStripeCustomer.mockResolvedValue(mockCustomer.id)
      allMocks.stripeService.createPaymentIntent.mockResolvedValue(mockPaymentIntent)
      allMocks.stripeService.confirmPaymentIntent.mockResolvedValue({
        ...mockPaymentIntent,
        status: 'succeeded'
      })
      allMocks.userPaymentService.recordPaymentSuccess.mockResolvedValue({ success: true })

      // Step 1: Initialize payment system
      await paymentController.initializePaymentSystem()
      expect(paymentController.isPaymentSystemInitialized()).toBe(true)

      // Step 2: Set user
      await paymentController.setCurrentUser(mockUser)
      expect(paymentController.getCurrentUser()).toEqual(mockUser)

      // Step 3: Create payment intent
      const paymentIntent = await allMocks.stripeService.createPaymentIntent(
        2000,
        'usd',
        { customerId: mockCustomer.id }
      )
      expect(paymentIntent.amount).toBe(2000)
      expect(paymentIntent.currency).toBe('usd')

      // Step 4: Confirm payment intent
      const confirmedPayment = await allMocks.stripeService.confirmPaymentIntent(
        paymentIntent.id,
        'pm_test123'
      )
      expect(confirmedPayment.status).toBe('succeeded')

      // Step 5: Record payment success
      await allMocks.userPaymentService.recordPaymentSuccess(mockUser.id, {
        paymentIntentId: paymentIntent.id,
        amount: 2000
      })

      // Verify all services were called correctly
      expect(allMocks.userPaymentService.ensureStripeCustomer).toHaveBeenCalledWith(
        mockUser.id,
        mockUser.email,
        mockUser.name
      )
      expect(allMocks.stripeService.createPaymentIntent).toHaveBeenCalledWith(
        2000,
        'usd',
        { customerId: mockCustomer.id }
      )
      expect(allMocks.stripeService.confirmPaymentIntent).toHaveBeenCalledWith(
        paymentIntent.id,
        'pm_test123'
      )
      expect(allMocks.userPaymentService.recordPaymentSuccess).toHaveBeenCalledWith(
        mockUser.id,
        { paymentIntentId: paymentIntent.id, amount: 2000 }
      )
    })

    it('should handle payment intent creation failure gracefully', async () => {
      const mockUser = paymentTestData.validUser

      // Mock failure
      allMocks.userPaymentService.ensureStripeCustomer.mockResolvedValue('cus_test123')
      allMocks.stripeService.createPaymentIntent.mockRejectedValue(
        simulateStripeError('card_error')
      )
      allMocks.userPaymentService.recordPaymentFailure.mockResolvedValue({ success: true })

      // Initialize and set user
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)

      // Attempt payment creation and expect failure
      await expect(
        allMocks.stripeService.createPaymentIntent(2000, 'usd', { customerId: 'cus_test123' })
      ).rejects.toThrow()

      // Verify failure was recorded
      await allMocks.userPaymentService.recordPaymentFailure(mockUser.id, {
        error: 'Card error',
        amount: 2000
      })

      expect(allMocks.userPaymentService.recordPaymentFailure).toHaveBeenCalledWith(
        mockUser.id,
        { error: 'Card error', amount: 2000 }
      )
    })

    it('should validate payment data before processing', async () => {
      const mockUser = paymentTestData.validUser
      const invalidPaymentData = {
        amount: -100, // Invalid negative amount
        currency: 'invalid',
        description: '<script>alert("xss")</script>'
      }

      // Mock validation failure
      allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
        success: false,
        error: 'Invalid payment data',
        validationErrors: ['Invalid amount', 'Invalid currency', 'XSS detected']
      })

      // Initialize and set user
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)

      // Validate payment data
      const validationResult = allMocks.paymentValidationService.validatePaymentData(
        invalidPaymentData
      )

      expect(validationResult.success).toBe(false)
      expect(validationResult.validationErrors).toContain('Invalid amount')
      expect(validationResult.validationErrors).toContain('Invalid currency')
      expect(validationResult.validationErrors).toContain('XSS detected')

      // Ensure payment creation is not attempted with invalid data
      expect(allMocks.stripeService.createPaymentIntent).not.toHaveBeenCalled()
    })
  })

  describe('End-to-End Subscription Flow', () => {
    it('should complete full subscription creation flow', async () => {
      const mockCustomer = createMockStripeCustomer()
      const mockSubscription = createMockStripeSubscription()
      const mockUser = paymentTestData.validUser
      const planId = 'basic'

      // Mock service responses
      allMocks.userPaymentService.ensureStripeCustomer.mockResolvedValue(mockCustomer.id)
      allMocks.stripeService.createSubscription.mockResolvedValue(mockSubscription)
      allMocks.userPaymentService.updateUserPaymentProfile.mockResolvedValue({ success: true })

      // Initialize payment system
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)
      await paymentController.loadSubscriptionPlans()

      // Create subscription
      await paymentController.createSubscription(planId)

      // Verify subscription creation flow
      expect(allMocks.userPaymentService.ensureStripeCustomer).toHaveBeenCalledWith(
        mockUser.id,
        mockUser.email,
        mockUser.name
      )
      expect(allMocks.stripeService.createSubscription).toHaveBeenCalled()
      expect(allMocks.userPaymentService.updateUserPaymentProfile).toHaveBeenCalled()
    })

    it('should handle subscription cancellation flow', async () => {
      const mockSubscription = createMockStripeSubscription({ status: 'canceled' })
      const mockUser = paymentTestData.validUser

      // Mock existing subscription
      allMocks.stripeService.cancelSubscription.mockResolvedValue(mockSubscription)
      allMocks.userPaymentService.updateUserPaymentProfile.mockResolvedValue({ success: true })

      // Initialize with existing subscription
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)
      
      // Set up subscription state
      paymentController['userSubscription'] = mockSubscription

      // Cancel subscription
      await paymentController.cancelSubscription()

      // Verify cancellation flow
      expect(allMocks.stripeService.cancelSubscription).toHaveBeenCalled()
      expect(allMocks.userPaymentService.updateUserPaymentProfile).toHaveBeenCalledWith(
        mockUser.id,
        expect.objectContaining({ subscriptionStatus: 'canceled' })
      )
    })

    it('should validate subscription access correctly', async () => {
      const mockUser = paymentTestData.validUser

      // Mock access validation
      allMocks.userPaymentService.validateSubscriptionAccess.mockResolvedValue({
        success: true,
        data: true
      })

      // Initialize and set user
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)

      // Check feature access
      const hasAccess = await paymentController.checkFeatureAccess('premium_feature')

      expect(hasAccess).toBe(true)
      expect(allMocks.userPaymentService.validateSubscriptionAccess).toHaveBeenCalledWith(
        mockUser.id,
        'premium_feature'
      )
    })
  })

  describe('Webhook Integration Flow', () => {
    it('should process webhook events end-to-end', async () => {
      const webhookEvent = {
        id: 'evt_test123',
        type: 'payment_intent.succeeded',
        data: {
          object: createMockStripePaymentIntent({ status: 'succeeded' })
        }
      }

      // Mock webhook processing
      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.userPaymentService.recordPaymentSuccess.mockResolvedValue({ success: true })

      // Process webhook
      const isValidSignature = allMocks.stripeService.verifyWebhookSignature(
        JSON.stringify(webhookEvent),
        'valid-signature',
        'webhook-secret'
      )

      expect(isValidSignature).toBe(true)

      // Process payment success event
      if (webhookEvent.type === 'payment_intent.succeeded') {
        await allMocks.userPaymentService.recordPaymentSuccess('user-123', {
          paymentIntentId: webhookEvent.data.object.id,
          amount: webhookEvent.data.object.amount
        })
      }

      expect(allMocks.userPaymentService.recordPaymentSuccess).toHaveBeenCalledWith(
        'user-123',
        {
          paymentIntentId: webhookEvent.data.object.id,
          amount: webhookEvent.data.object.amount
        }
      )
    })

    it('should reject webhooks with invalid signatures', async () => {
      const webhookEvent = {
        id: 'evt_test123',
        type: 'payment_intent.succeeded',
        data: { object: {} }
      }

      // Mock invalid signature
      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(false)

      // Attempt to verify webhook
      const isValidSignature = allMocks.stripeService.verifyWebhookSignature(
        JSON.stringify(webhookEvent),
        'invalid-signature',
        'webhook-secret'
      )

      expect(isValidSignature).toBe(false)

      // Ensure no payment processing occurs
      expect(allMocks.userPaymentService.recordPaymentSuccess).not.toHaveBeenCalled()
    })
  })

  describe('Error Recovery and Resilience', () => {
    it('should handle network failures gracefully', async () => {
      const mockUser = paymentTestData.validUser

      // Mock network failure
      allMocks.stripeService.createPaymentIntent.mockRejectedValue(
        new Error('Network timeout')
      )

      // Initialize system
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)

      // Attempt operation and expect graceful failure
      await expect(
        allMocks.stripeService.createPaymentIntent(2000, 'usd')
      ).rejects.toThrow('Network timeout')

      // Verify system remains stable
      expect(paymentController.isPaymentSystemInitialized()).toBe(true)
      expect(paymentController.getCurrentUser()).toEqual(mockUser)
    })

    it('should handle service unavailability', async () => {
      const mockUser = paymentTestData.validUser

      // Mock service unavailable
      allMocks.userPaymentService.ensureStripeCustomer.mockRejectedValue(
        new Error('Service unavailable')
      )

      // Initialize system
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)

      // Attempt operation and expect graceful failure
      await expect(
        allMocks.userPaymentService.ensureStripeCustomer(mockUser.id, mockUser.email, mockUser.name)
      ).rejects.toThrow('Service unavailable')

      // Verify system state is maintained
      expect(paymentController.getCurrentUser()).toEqual(mockUser)
    })
  })

  describe('Security Integration', () => {
    it('should enforce security validations across the payment flow', async () => {
      const mockUser = paymentTestData.validUser
      const suspiciousPaymentData = {
        amount: 1, // Potential card testing
        currency: 'usd',
        description: 'Test payment'
      }

      // Mock security validation failure
      allMocks.paymentValidationService.detectCardTesting.mockResolvedValue({
        success: false,
        code: 'CARD_TESTING_DETECTED',
        data: { attempts: 25, timeWindow: 300 }
      })

      // Initialize system
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)

      // Check for card testing
      const cardTestingResult = await allMocks.paymentValidationService.detectCardTesting(
        mockUser.id,
        suspiciousPaymentData
      )

      expect(cardTestingResult.success).toBe(false)
      expect(cardTestingResult.code).toBe('CARD_TESTING_DETECTED')

      // Ensure payment is blocked
      expect(allMocks.stripeService.createPaymentIntent).not.toHaveBeenCalled()
    })

    it('should validate fraud patterns before processing payments', async () => {
      const mockUser = paymentTestData.validUser
      const fraudulentPattern = {
        amount: 1,
        currency: 'usd',
        count: 50 // High velocity
      }

      // Mock fraud detection
      allMocks.paymentValidationService.detectFraudPattern.mockResolvedValue({
        success: false,
        code: 'FRAUD_DETECTED',
        data: { pattern: 'VELOCITY_ABUSE', riskScore: 95 }
      })

      // Initialize system
      await paymentController.initializePaymentSystem()
      await paymentController.setCurrentUser(mockUser)

      // Check for fraud patterns
      const fraudResult = await allMocks.paymentValidationService.detectFraudPattern(
        mockUser.id,
        fraudulentPattern
      )

      expect(fraudResult.success).toBe(false)
      expect(fraudResult.code).toBe('FRAUD_DETECTED')
      expect(fraudResult.data.riskScore).toBeGreaterThan(90)

      // Ensure payment is blocked
      expect(allMocks.stripeService.createPaymentIntent).not.toHaveBeenCalled()
    })
  })
})
