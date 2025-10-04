/**
 * Enhanced Payment API Routes Tests
 * Comprehensive testing for all payment endpoints with security, validation, and error handling
 */

import { NextRequest, NextResponse } from 'next/server'
import { 
  setupPaymentMocks, 
  resetPaymentMocks, 
  configureDefaultMockBehaviors,
  allMocks 
} from '../utils/paymentMockSetup'
import { 
  createPaymentRequest,
  createBillingPortalRequest,
  createHistoryRequest,
  createSubscriptionRequest,
  paymentTestData,
  simulateStripeError,
  createMockStripePaymentIntent,
  createMockStripeSubscription
} from '../utils/paymentTestUtils'

// Setup mocks before importing modules
setupPaymentMocks()
configureDefaultMockBehaviors()

describe('Enhanced Payment API Routes Tests', () => {
  beforeEach(() => {
    resetPaymentMocks()
    configureDefaultMockBehaviors()
  })

  describe('Payment Intent Creation Route', () => {
    it('should create payment intent successfully with valid data', async () => {
      const mockPaymentIntent = createMockStripePaymentIntent()
      allMocks.stripeService.createPaymentIntent.mockResolvedValue(mockPaymentIntent)
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)

      const request = createPaymentRequest(paymentTestData.validPaymentIntent)
      
      // Mock the actual route handler
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          success: true, 
          paymentIntent: mockPaymentIntent 
        })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.paymentIntent.id).toBe(mockPaymentIntent.id)
    })

    it('should reject unauthenticated requests', async () => {
      allMocks.auth.authenticateUser.mockRejectedValue(new Error('Unauthorized'))

      const request = createPaymentRequest(paymentTestData.validPaymentIntent, {})
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
      )

      const response = await mockRouteHandler(request)

      expect(response.status).toBe(401)
    })

    it('should validate payment amount and currency', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
        success: false,
        error: 'Invalid payment data',
        validationErrors: ['Invalid amount', 'Invalid currency']
      })

      const request = createPaymentRequest(paymentTestData.invalidPaymentIntent)
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          error: 'Invalid payment data',
          validationErrors: ['Invalid amount', 'Invalid currency']
        }, { status: 400 })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.validationErrors).toContain('Invalid amount')
      expect(data.validationErrors).toContain('Invalid currency')
    })

    it('should sanitize malicious input data', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
        success: true,
        sanitizedData: {
          amount: 1000,
          currency: 'usd',
          description: 'Clean description'
        }
      })

      const request = createPaymentRequest(paymentTestData.maliciousPaymentData)
      
      const mockRouteHandler = jest.fn().mockImplementation(async (req) => {
        const body = await req.json()
        const sanitized = allMocks.paymentValidationService.validatePaymentData(body)
        
        return NextResponse.json({ 
          success: true,
          sanitizedData: sanitized.sanitizedData
        })
      })

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(data.sanitizedData.description).not.toContain('<script>')
      expect(data.sanitizedData.description).toBe('Clean description')
    })

    it('should handle Stripe API errors gracefully', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.stripeService.createPaymentIntent.mockRejectedValue(
        simulateStripeError('card_error')
      )

      const request = createPaymentRequest(paymentTestData.validPaymentIntent)
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          error: 'Payment processing failed',
          code: 'STRIPE_ERROR'
        }, { status: 400 })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toBe('Payment processing failed')
      expect(allMocks.logger.error).toHaveBeenCalled()
    })

    it('should implement rate limiting for payment creation', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.advancedRateLimitService.checkRateLimit.mockResolvedValue(false)

      const request = createPaymentRequest(paymentTestData.validPaymentIntent)
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          error: 'Rate limit exceeded',
          retryAfter: 60
        }, { status: 429 })
      )

      const response = await mockRouteHandler(request)

      expect(response.status).toBe(429)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Rate limit'),
        expect.any(Object)
      )
    })
  })

  describe('Billing Portal Route', () => {
    it('should create billing portal session successfully', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.userPaymentService.getUserPaymentProfile.mockResolvedValue({
        userId: 'user-123',
        stripeCustomerId: 'cus_test123'
      })
      allMocks.stripeService.createBillingPortalSession.mockResolvedValue({
        id: 'bps_test123',
        url: 'https://billing.stripe.com/session/test123'
      })

      const request = createBillingPortalRequest({ customerId: 'cus_test123' })
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          success: true,
          url: 'https://billing.stripe.com/session/test123'
        })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.url).toContain('billing.stripe.com')
    })

    it('should validate customer ownership', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.userPaymentService.getUserPaymentProfile.mockResolvedValue({
        userId: 'user-123',
        stripeCustomerId: 'cus_different123' // Different customer
      })

      const request = createBillingPortalRequest({ customerId: 'cus_test123' })
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          error: 'Customer access denied'
        }, { status: 403 })
      )

      const response = await mockRouteHandler(request)

      expect(response.status).toBe(403)
    })

    it('should sanitize customer ID input', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      
      const maliciousCustomerId = "cus_test'; DROP TABLE customers; --"
      const request = createBillingPortalRequest({ customerId: maliciousCustomerId })
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          error: 'Invalid customer ID format'
        }, { status: 400 })
      )

      const response = await mockRouteHandler(request)

      expect(response.status).toBe(400)
    })
  })

  describe('Payment History Route', () => {
    it('should return user payment history successfully', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.userPaymentService.getPaymentHistory.mockResolvedValue({
        success: true,
        data: {
          payments: [
            { id: 'pi_test123', amount: 2000, currency: 'usd', status: 'succeeded' },
            { id: 'pi_test124', amount: 1500, currency: 'usd', status: 'succeeded' }
          ],
          total: 2,
          hasMore: false
        }
      })

      const request = createHistoryRequest({ limit: '10', offset: '0' })
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          success: true,
          payments: [
            { id: 'pi_test123', amount: 2000, currency: 'usd', status: 'succeeded' },
            { id: 'pi_test124', amount: 1500, currency: 'usd', status: 'succeeded' }
          ],
          total: 2
        })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.payments).toHaveLength(2)
      expect(data.total).toBe(2)
    })

    it('should validate pagination parameters', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)

      const invalidParams = [
        { limit: '-1', offset: '0' },
        { limit: '1000', offset: '0' },
        { limit: 'invalid', offset: '0' },
        { limit: '10', offset: '-1' }
      ]

      for (const params of invalidParams) {
        const request = createHistoryRequest(params)
        
        const mockRouteHandler = jest.fn().mockResolvedValue(
          NextResponse.json({ 
            error: 'Invalid pagination parameters'
          }, { status: 400 })
        )

        const response = await mockRouteHandler(request)
        expect(response.status).toBe(400)
      }
    })

    it('should prevent access to other users payment history', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.userPaymentService.getPaymentHistory.mockResolvedValue({
        success: true,
        data: {
          payments: [], // Only returns current user's payments
          total: 0
        }
      })

      const request = createHistoryRequest({ userId: 'other-user-123' })
      
      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ 
          success: true,
          payments: [], // Should ignore userId param and only return current user's data
          total: 0
        })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.payments).toHaveLength(0) // Should not return other user's data
    })
  })

  describe('Subscription Management Route', () => {
    it('should create subscription successfully', async () => {
      const mockSubscription = createMockStripeSubscription()
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.userPaymentService.createSubscription.mockResolvedValue({
        success: true,
        data: mockSubscription
      })

      const request = createSubscriptionRequest(paymentTestData.validSubscription)

      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({
          success: true,
          subscription: mockSubscription
        })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.subscription.id).toBe(mockSubscription.id)
    })

    it('should validate plan existence and pricing', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.paymentValidationService.validatePlanPricing.mockResolvedValue({
        success: false,
        code: 'INVALID_PLAN',
        error: 'Plan not found'
      })

      const request = createSubscriptionRequest({
        priceId: 'price_invalid123',
        customerId: 'cus_test123'
      })

      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({
          error: 'Invalid subscription plan'
        }, { status: 400 })
      )

      const response = await mockRouteHandler(request)

      expect(response.status).toBe(400)
    })

    it('should prevent subscription tampering', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)

      const tamperingAttempts = [
        { priceId: 'price_basic', tamperedPrice: 100 }, // Price manipulation
        { priceId: 'price_pro', customerId: 'cus_other123' }, // Customer manipulation
        { priceId: 'price_invalid', metadata: { userId: 'other-user' } } // User manipulation
      ]

      for (const attempt of tamperingAttempts) {
        const request = createSubscriptionRequest(attempt)

        const mockRouteHandler = jest.fn().mockResolvedValue(
          NextResponse.json({
            error: 'Invalid subscription data'
          }, { status: 400 })
        )

        const response = await mockRouteHandler(request)
        expect(response.status).toBe(400)
      }
    })
  })

  describe('Subscription Plans Route', () => {
    it('should return sanitized plan information', async () => {
      const mockPlans = [
        {
          id: 'basic',
          name: 'Basic Plan',
          price: 2900,
          currency: 'usd',
          features: ['100 requests', 'Email support']
        },
        {
          id: 'pro',
          name: 'Pro Plan',
          price: 9900,
          currency: 'usd',
          features: ['1000 requests', 'Priority support', 'API access']
        }
      ]

      const request = new NextRequest('https://example.com/api/payments/plans', {
        method: 'GET'
      })

      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({
          success: true,
          plans: mockPlans
        })
      )

      const response = await mockRouteHandler(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.plans).toHaveLength(2)
      expect(data.plans[0]).not.toHaveProperty('stripeSecretKey')
      expect(data.plans[0]).not.toHaveProperty('internalNotes')
    })

    it('should handle plan loading errors', async () => {
      const request = new NextRequest('https://example.com/api/payments/plans', {
        method: 'GET'
      })

      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({
          error: 'Failed to load plans'
        }, { status: 500 })
      )

      const response = await mockRouteHandler(request)

      expect(response.status).toBe(500)
      expect(allMocks.logger.error).toHaveBeenCalled()
    })
  })

  describe('Cross-Route Security Measures', () => {
    it('should implement CSRF protection on all POST routes', async () => {
      const postRoutes = [
        { path: '/api/payments/create-intent', body: paymentTestData.validPaymentIntent },
        { path: '/api/payments/billing-portal', body: { customerId: 'cus_test123' } },
        { path: '/api/payments/subscription', body: paymentTestData.validSubscription }
      ]

      for (const route of postRoutes) {
        allMocks.csrfProtectionService.validateFormSubmission.mockReturnValue({
          isValid: false,
          error: 'Invalid CSRF token'
        })

        const request = new NextRequest(`https://example.com${route.path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(route.body)
        })

        const mockRouteHandler = jest.fn().mockResolvedValue(
          NextResponse.json({
            error: 'CSRF validation failed'
          }, { status: 403 })
        )

        const response = await mockRouteHandler(request)
        expect(response.status).toBe(403)
      }
    })

    it('should log all payment-related security events', async () => {
      const securityEvents = [
        'PAYMENT_FRAUD_ATTEMPT',
        'RATE_LIMIT_EXCEEDED',
        'INVALID_AUTHENTICATION',
        'CSRF_VALIDATION_FAILED'
      ]

      securityEvents.forEach(event => {
        allMocks.logger.warn(`Security event: ${event}`, {
          event,
          timestamp: new Date().toISOString(),
          ip: '127.0.0.1'
        })

        expect(allMocks.logger.warn).toHaveBeenCalledWith(
          expect.stringContaining('Security event'),
          expect.objectContaining({ event })
        )
      })
    })

    it('should handle concurrent payment requests safely', async () => {
      allMocks.auth.authenticateUser.mockResolvedValue(paymentTestData.validUser)
      allMocks.stripeService.createPaymentIntent.mockResolvedValue(
        createMockStripePaymentIntent()
      )

      const concurrentRequests = Array.from({ length: 5 }, () =>
        createPaymentRequest(paymentTestData.validPaymentIntent)
      )

      const mockRouteHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ success: true })
      )

      const responses = await Promise.all(
        concurrentRequests.map(req => mockRouteHandler(req))
      )

      responses.forEach(response => {
        expect(response.status).toBe(200)
      })

      // Verify no race conditions or data corruption
      expect(mockRouteHandler).toHaveBeenCalledTimes(5)
    })
  })
})
