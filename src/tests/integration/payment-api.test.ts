/**
 * Integration Tests for Payment API Endpoints
 * Tests for Stripe webhook handler and payment intent creation API
 */

import { NextRequest } from 'next/server'
import { POST as webhookHandler } from '@/app/api/webhooks/stripe/route'
import {
  POST as createPaymentIntentHandler,
  GET as getPaymentIntentHandler,
} from '@/app/api/payments/create-intent/route'
import { stripeService } from '@/model/stripeService'
import { userPaymentService } from '@/model/userPaymentService'
import { authenticateUser } from '@/utils/auth'

// Mock dependencies
jest.mock('@/model/stripeService')
jest.mock('@/model/userPaymentService')
jest.mock('@/utils/auth')
jest.mock('@/utils/logger')
jest.mock('@/lib/security')

const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>
const mockAuthenticateUser = authenticateUser as jest.MockedFunction<typeof authenticateUser>

describe('Payment API Integration Tests', () => {
  const mockUser = {
    id: 'admin',
    email: 'admin@test.com',
    name: 'Admin User',
    sessionId: 'session-123',
    isAuthenticated: true,
    permissions: ['read', 'write', 'admin'],
    roles: ['admin'],
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Stripe Webhook Handler', () => {
    const createMockRequest = (body: string, signature?: string) => {
      const headers = new Headers()
      if (signature) {
        headers.set('stripe-signature', signature)
      }

      return {
        text: jest.fn().mockResolvedValue(body),
        headers: {
          get: jest.fn().mockImplementation((name: string) => headers.get(name)),
        },
      } as unknown as NextRequest
    }

    it('should process valid webhook with signature', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'customer.subscription.created',
        created: Date.now() / 1000,
        data: {
          object: {
            id: 'sub_123',
            customer: 'cus_123',
            status: 'active',
            current_period_start: Date.now() / 1000,
            current_period_end: Date.now() / 1000 + 86400,
            cancel_at_period_end: false,
          },
        },
      }

      mockStripeService.verifyWebhookSignature.mockReturnValue(mockEvent as any)
      mockUserPaymentService.updateUserPaymentProfile.mockResolvedValue({} as any)

      const request = createMockRequest('webhook-body', 'valid-signature')
      const response = await webhookHandler(request)

      expect(response.status).toBe(200)
      expect(mockStripeService.verifyWebhookSignature).toHaveBeenCalledWith(
        'webhook-body',
        'valid-signature'
      )
    })

    it('should reject webhook without signature', async () => {
      const request = createMockRequest('webhook-body')
      const response = await webhookHandler(request)

      expect(response.status).toBe(400)
      const responseData = await response.json()
      expect(responseData.error).toBe('Missing signature')
    })

    it('should reject webhook with invalid signature', async () => {
      mockStripeService.verifyWebhookSignature.mockImplementation(() => {
        throw new Error('Invalid signature')
      })

      const request = createMockRequest('webhook-body', 'invalid-signature')
      const response = await webhookHandler(request)

      expect(response.status).toBe(400)
      const responseData = await response.json()
      expect(responseData.error).toBe('Invalid signature')
    })

    it('should handle subscription update events', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'customer.subscription.updated',
        created: Date.now() / 1000,
        data: {
          object: {
            id: 'sub_123',
            customer: 'cus_123',
            status: 'active',
            current_period_start: Date.now() / 1000,
            current_period_end: Date.now() / 1000 + 86400,
            cancel_at_period_end: false,
          },
        },
      }

      mockStripeService.verifyWebhookSignature.mockReturnValue(mockEvent as any)
      mockUserPaymentService.updateUserPaymentProfile.mockResolvedValue({} as any)

      const request = createMockRequest('webhook-body', 'valid-signature')
      const response = await webhookHandler(request)

      expect(response.status).toBe(200)
      expect(mockUserPaymentService.updateUserPaymentProfile).toHaveBeenCalled()
    })

    it('should handle payment success events', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'payment_intent.succeeded',
        created: Date.now() / 1000,
        data: {
          object: {
            id: 'pi_123',
            customer: 'cus_123',
            amount: 2999,
            currency: 'usd',
          },
        },
      }

      mockStripeService.verifyWebhookSignature.mockReturnValue(mockEvent as any)

      const request = createMockRequest('webhook-body', 'valid-signature')
      const response = await webhookHandler(request)

      expect(response.status).toBe(200)
    })

    it('should handle unhandled event types gracefully', async () => {
      const mockEvent = {
        id: 'evt_123',
        type: 'unknown.event.type',
        created: Date.now() / 1000,
        data: { object: {} },
      }

      mockStripeService.verifyWebhookSignature.mockReturnValue(mockEvent as any)

      const request = createMockRequest('webhook-body', 'valid-signature')
      const response = await webhookHandler(request)

      expect(response.status).toBe(200)
    })
  })

  describe('Payment Intent Creation API', () => {
    const createMockRequest = (body: any, method: string = 'POST') => {
      const headers = new Headers()
      headers.set('content-type', 'application/json')

      return {
        method,
        json: jest.fn().mockResolvedValue(body),
        headers: {
          get: jest.fn().mockImplementation((name: string) => headers.get(name)),
        },
        cookies: {
          get: jest.fn().mockReturnValue({ value: 'session-123' }),
        },
        nextUrl: {
          pathname: '/api/payments/create-intent',
        },
      } as unknown as NextRequest
    }

    it('should create payment intent for authenticated user', async () => {
      const requestBody = {
        amountCents: 2999,
        currency: 'USD',
        description: 'Test payment',
        metadata: { test: 'data' },
      }

      const mockPaymentIntent = {
        id: 'pi_123',
        client_secret: 'pi_123_secret',
        status: 'requires_payment_method',
        amount: 2999,
        currency: 'usd',
      }

      mockAuthenticateUser.mockResolvedValue(mockUser)
      mockUserPaymentService.ensureStripeCustomer.mockResolvedValue('cus_123')
      mockStripeService.createPaymentIntent.mockResolvedValue(mockPaymentIntent as any)

      const request = createMockRequest(requestBody)
      const response = await createPaymentIntentHandler(request)

      expect(response.status).toBe(200)
      const responseData = await response.json()
      expect(responseData.success).toBe(true)
      expect(responseData.clientSecret).toBe('pi_123_secret')
      expect(responseData.paymentIntentId).toBe('pi_123')
    })

    it('should reject unauthenticated requests', async () => {
      const requestBody = {
        amountCents: 2999,
        currency: 'USD',
        description: 'Test payment',
      }

      mockAuthenticateUser.mockResolvedValue(null)

      const request = createMockRequest(requestBody)
      const response = await createPaymentIntentHandler(request)

      expect(response.status).toBe(401)
      const responseData = await response.json()
      expect(responseData.error).toBe('Authentication required')
    })

    it('should validate request body', async () => {
      const requestBody = {
        amountCents: -100, // Invalid amount
        currency: 'USD',
        description: 'Test payment',
      }

      mockAuthenticateUser.mockResolvedValue(mockUser)

      const request = createMockRequest(requestBody)
      const response = await createPaymentIntentHandler(request)

      expect(response.status).toBe(400)
      const responseData = await response.json()
      expect(responseData.error).toBe('Validation failed')
    })

    it('should handle Stripe errors gracefully', async () => {
      const requestBody = {
        amountCents: 2999,
        currency: 'USD',
        description: 'Test payment',
      }

      mockAuthenticateUser.mockResolvedValue(mockUser)
      mockUserPaymentService.ensureStripeCustomer.mockResolvedValue('cus_123')
      mockStripeService.createPaymentIntent.mockRejectedValue(new Error('Stripe error'))

      const request = createMockRequest(requestBody)
      const response = await createPaymentIntentHandler(request)

      expect(response.status).toBe(500)
      const responseData = await response.json()
      expect(responseData.error).toBe('Failed to create payment intent')
    })
  })

  describe('Payment Intent Retrieval API', () => {
    const createMockGetRequest = (paymentIntentId?: string) => {
      const url = new URL('http://localhost:3000/api/payments/create-intent')
      if (paymentIntentId) {
        url.searchParams.set('payment_intent_id', paymentIntentId)
      }

      return {
        method: 'GET',
        url: url.toString(),
        cookies: {
          get: jest.fn().mockReturnValue({ value: 'session-123' }),
        },
      } as unknown as NextRequest
    }

    it('should retrieve payment intent for authenticated user', async () => {
      const mockPaymentIntent = {
        id: 'pi_123',
        status: 'succeeded',
        amount: 2999,
        currency: 'usd',
        customer: 'cus_123',
        client_secret: 'pi_123_secret',
      }

      const mockUserProfile = {
        stripeCustomerId: 'cus_123',
      }

      mockAuthenticateUser.mockResolvedValue(mockUser)
      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockUserProfile as any)

      // Mock Stripe API call
      const mockStripe = {
        paymentIntents: {
          retrieve: jest.fn().mockResolvedValue(mockPaymentIntent),
        },
      }

      // Mock the dynamic import
      jest.doMock('stripe', () => ({
        default: jest.fn().mockImplementation(() => mockStripe),
      }))

      const request = createMockGetRequest('pi_123')
      const response = await getPaymentIntentHandler(request)

      expect(response.status).toBe(200)
      const responseData = await response.json()
      expect(responseData.success).toBe(true)
      expect(responseData.paymentIntent.id).toBe('pi_123')
    })

    it('should reject request without payment intent ID', async () => {
      mockAuthenticateUser.mockResolvedValue(mockUser)

      const request = createMockGetRequest()
      const response = await getPaymentIntentHandler(request)

      expect(response.status).toBe(400)
      const responseData = await response.json()
      expect(responseData.error).toBe('Payment intent ID is required')
    })

    it('should reject unauthorized access to payment intent', async () => {
      const mockPaymentIntent = {
        id: 'pi_123',
        customer: 'cus_different',
      }

      const mockUserProfile = {
        stripeCustomerId: 'cus_123',
      }

      mockAuthenticateUser.mockResolvedValue(mockUser)
      mockUserPaymentService.getUserPaymentProfile.mockResolvedValue(mockUserProfile as any)

      // Mock Stripe API call
      const mockStripe = {
        paymentIntents: {
          retrieve: jest.fn().mockResolvedValue(mockPaymentIntent),
        },
      }

      jest.doMock('stripe', () => ({
        default: jest.fn().mockImplementation(() => mockStripe),
      }))

      const request = createMockGetRequest('pi_123')
      const response = await getPaymentIntentHandler(request)

      expect(response.status).toBe(404)
      const responseData = await response.json()
      expect(responseData.error).toBe('Payment intent not found')
    })
  })
})
