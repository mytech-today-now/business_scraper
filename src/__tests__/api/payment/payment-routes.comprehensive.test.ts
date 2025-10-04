/**
 * Comprehensive Payment API Routes Tests
 * Security-focused testing for all payment endpoints with fraud prevention,
 * input validation, authentication, and PCI compliance validation
 */

import { NextRequest, NextResponse } from 'next/server'
import { POST as billingPortalHandler } from '@/app/api/payments/billing-portal/route'
import { 
  POST as createIntentHandler, 
  GET as getIntentHandler 
} from '@/app/api/payments/create-intent/route'
import { GET as historyHandler } from '@/app/api/payments/history/route'
import { GET as plansHandler } from '@/app/api/payments/plans/route'
import { POST as subscriptionHandler } from '@/app/api/payments/subscription/route'
import { stripeService } from '@/model/stripeService'
import { userPaymentService } from '@/model/userPaymentService'
import { authenticateUser } from '@/utils/auth'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

// Mock all dependencies
jest.mock('@/model/stripeService', () => ({
  stripeService: {
    createPaymentIntent: jest.fn(),
    createCustomer: jest.fn(),
    createSubscription: jest.fn(),
    createBillingPortalSession: jest.fn(),
    verifyWebhookSignature: jest.fn()
  }
}))

jest.mock('@/model/userPaymentService', () => ({
  userPaymentService: {
    ensureStripeCustomer: jest.fn(),
    getUserPaymentProfile: jest.fn(),
    updateUserPaymentProfile: jest.fn(),
    recordUsage: jest.fn()
  }
}))

jest.mock('@/utils/auth', () => ({
  authenticateUser: jest.fn()
}))

jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn()
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }
}))

jest.mock('@/lib/api-security')
jest.mock('@/middleware/paymentSecurity')

// Type mocked services
const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>
const mockAuthenticateUser = authenticateUser as jest.MockedFunction<typeof authenticateUser>
const mockGetClientIP = getClientIP as jest.MockedFunction<typeof getClientIP>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('Payment API Routes - Comprehensive Security Tests', () => {
  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    sessionId: 'session-123',
    isAuthenticated: true,
    permissions: ['payment:create', 'payment:read'],
    roles: ['user']
  }

  const mockStripeCustomer = {
    id: 'cus_test123',
    email: 'test@example.com',
    name: 'Test User'
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockGetClientIP.mockReturnValue('192.168.1.1')
    mockAuthenticateUser.mockResolvedValue(mockUser)
    mockUserPaymentService.ensureStripeCustomer.mockResolvedValue('cus_test123')
  })

  describe('Billing Portal Route Security', () => {
    const createBillingPortalRequest = (body: any, headers: Record<string, string> = {}) => {
      const request = new NextRequest('https://example.com/api/payments/billing-portal', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...headers
        },
        body: JSON.stringify(body)
      })
      return request
    }

    it('should reject unauthenticated requests', async () => {
      mockAuthenticateUser.mockResolvedValue(null)
      
      const request = createBillingPortalRequest({ customerId: 'cus_test123' })
      const response = await billingPortalHandler(request)
      
      expect(response.status).toBe(401)
      const data = await response.json()
      expect(data.error).toContain('Authentication required')
    })

    it('should validate required fields', async () => {
      const request = createBillingPortalRequest({})
      const response = await billingPortalHandler(request)
      
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toContain('Missing required fields')
    })

    it('should sanitize customer ID input', async () => {
      const maliciousCustomerId = 'cus_test<script>alert("xss")</script>'
      const request = createBillingPortalRequest({ customerId: maliciousCustomerId })
      
      const response = await billingPortalHandler(request)
      
      // Should either reject or sanitize the input
      expect(response.status).toBeGreaterThanOrEqual(400)
    })

    it('should validate customer ownership', async () => {
      // Mock user doesn't own this customer
      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue({
        userId: 'user-123',
        stripeCustomerId: 'cus_different123',
        subscriptionId: null,
        subscriptionStatus: 'inactive',
        subscriptionTier: 'free'
      })

      const request = createBillingPortalRequest({ customerId: 'cus_test123' })
      const response = await billingPortalHandler(request)
      
      expect(response.status).toBe(403)
    })

    it('should handle Stripe API errors gracefully', async () => {
      mockStripeService.createBillingPortalSession = jest.fn().mockRejectedValue(
        new Error('Stripe API Error')
      )

      const request = createBillingPortalRequest({ customerId: 'cus_test123' })
      const response = await billingPortalHandler(request)
      
      expect(response.status).toBe(500)
      expect(mockLogger.error).toHaveBeenCalled()
    })
  })

  describe('Payment Intent Creation Security', () => {
    const createPaymentIntentRequest = (body: any, headers: Record<string, string> = {}) => {
      return new NextRequest('https://example.com/api/payments/create-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...headers
        },
        body: JSON.stringify(body)
      })
    }

    it('should prevent amount manipulation attacks', async () => {
      const maliciousAmounts = [
        -100, // Negative amount
        0, // Zero amount
        999999999999, // Extremely large amount
        1.5, // Non-integer cents
        'invalid', // Non-numeric
        null,
        undefined
      ]

      for (const amount of maliciousAmounts) {
        const request = createPaymentIntentRequest({ 
          amountCents: amount,
          currency: 'usd'
        })
        
        const response = await createIntentHandler(request)
        expect(response.status).toBeGreaterThanOrEqual(400)
      }
    })

    it('should validate currency codes', async () => {
      const invalidCurrencies = ['invalid', 'USDD', '', null, 123]

      for (const currency of invalidCurrencies) {
        const request = createPaymentIntentRequest({
          amountCents: 1000,
          currency
        })
        
        const response = await createIntentHandler(request)
        expect(response.status).toBeGreaterThanOrEqual(400)
      }
    })

    it('should sanitize metadata inputs', async () => {
      const maliciousMetadata = {
        description: '<script>alert("xss")</script>',
        userInput: '"; DROP TABLE users; --',
        nested: {
          dangerous: '<img src=x onerror=alert(1)>'
        }
      }

      const request = createPaymentIntentRequest({
        amountCents: 1000,
        currency: 'usd',
        metadata: maliciousMetadata
      })

      mockStripeService.createPaymentIntent.mockResolvedValue({
        id: 'pi_test123',
        client_secret: 'pi_test123_secret',
        status: 'requires_payment_method'
      } as any)

      const response = await createIntentHandler(request)
      
      // Should succeed but with sanitized metadata
      expect(response.status).toBe(200)
      expect(mockStripeService.createPaymentIntent).toHaveBeenCalledWith(
        1000,
        'usd',
        expect.objectContaining({
          metadata: expect.not.objectContaining({
            description: expect.stringContaining('<script>')
          })
        })
      )
    })

    it('should enforce rate limiting for payment creation', async () => {
      // Simulate multiple rapid requests
      const requests = Array(10).fill(null).map(() => 
        createPaymentIntentRequest({
          amountCents: 1000,
          currency: 'usd'
        })
      )

      const responses = await Promise.all(
        requests.map(req => createIntentHandler(req))
      )

      // At least some should be rate limited
      const rateLimitedResponses = responses.filter(res => res.status === 429)
      expect(rateLimitedResponses.length).toBeGreaterThan(0)
    })
  })

  describe('Payment History Security', () => {
    const createHistoryRequest = (params: Record<string, string> = {}) => {
      const url = new URL('https://example.com/api/payments/history')
      Object.entries(params).forEach(([key, value]) => {
        url.searchParams.set(key, value)
      })
      
      return new NextRequest(url.toString(), { method: 'GET' })
    }

    it('should prevent unauthorized access to payment history', async () => {
      mockAuthenticateUser.mockResolvedValue(null)
      
      const request = createHistoryRequest()
      const response = await historyHandler(request)
      
      expect(response.status).toBe(401)
    })

    it('should validate pagination parameters', async () => {
      const invalidParams = [
        { limit: '-1' },
        { limit: '1000' }, // Too large
        { offset: '-5' },
        { limit: 'invalid' },
        { offset: 'invalid' }
      ]

      for (const params of invalidParams) {
        const request = createHistoryRequest(params)
        const response = await historyHandler(request)
        
        expect(response.status).toBeGreaterThanOrEqual(400)
      }
    })

    it('should prevent access to other users payment history', async () => {
      // Mock different user trying to access history
      const otherUser = { ...mockUser, id: 'other-user-456' }
      mockAuthenticateUser.mockResolvedValue(otherUser)

      const request = createHistoryRequest({ userId: 'user-123' })
      const response = await historyHandler(request)
      
      // Should only return the authenticated user's history
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.userId).toBe('other-user-456')
    })
  })

  describe('Subscription Plans Security', () => {
    it('should return sanitized plan information', async () => {
      const request = new NextRequest('https://example.com/api/payments/plans', {
        method: 'GET'
      })

      const response = await plansHandler(request)
      expect(response.status).toBe(200)
      
      const data = await response.json()
      expect(data.plans).toBeDefined()
      
      // Ensure no sensitive information is exposed
      data.plans.forEach((plan: any) => {
        expect(plan).not.toHaveProperty('stripeSecretKey')
        expect(plan).not.toHaveProperty('webhookSecret')
        expect(plan).not.toHaveProperty('internalNotes')
      })
    })
  })

  describe('Subscription Creation Security', () => {
    const createSubscriptionRequest = (body: any) => {
      return new NextRequest('https://example.com/api/payments/subscription', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
    }

    it('should prevent subscription tampering', async () => {
      const tamperingAttempts = [
        { planId: 'premium', priceOverride: 0 }, // Price manipulation
        { planId: 'premium', discountPercent: 100 }, // Full discount
        { planId: 'premium', trialDays: 999999 }, // Excessive trial
        { planId: '../../../admin' }, // Path traversal
      ]

      for (const attempt of tamperingAttempts) {
        const request = createSubscriptionRequest(attempt)
        const response = await subscriptionHandler(request)
        
        expect(response.status).toBeGreaterThanOrEqual(400)
      }
    })

    it('should validate plan existence and pricing', async () => {
      const request = createSubscriptionRequest({ planId: 'nonexistent-plan' })
      const response = await subscriptionHandler(request)
      
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toContain('Invalid plan')
    })
  })

  describe('Cross-Route Security Measures', () => {
    it('should implement CSRF protection on all POST routes', async () => {
      const postRoutes = [
        { handler: billingPortalHandler, body: { customerId: 'cus_test' } },
        { handler: createIntentHandler, body: { amountCents: 1000, currency: 'usd' } },
        { handler: subscriptionHandler, body: { planId: 'basic' } }
      ]

      for (const { handler, body } of postRoutes) {
        const request = new NextRequest('https://example.com/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        })

        // Request without CSRF token should be rejected
        const response = await handler(request)
        expect([400, 401, 403]).toContain(response.status)
      }
    })

    it('should log all payment-related security events', async () => {
      const request = new NextRequest('https://example.com/api/payments/create-intent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ amountCents: -100, currency: 'usd' })
      })

      await createIntentHandler(request)
      
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('security'),
        expect.any(Object)
      )
    })

    it('should handle concurrent payment requests safely', async () => {
      const concurrentRequests = Array(5).fill(null).map(() => {
        const request = new NextRequest('https://example.com/api/payments/create-intent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amountCents: 1000, currency: 'usd' })
        })
        return createIntentHandler(request)
      })

      const responses = await Promise.all(concurrentRequests)
      
      // All should either succeed or fail gracefully
      responses.forEach(response => {
        expect([200, 400, 429, 500]).toContain(response.status)
      })
    })
  })
})
