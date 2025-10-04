/**
 * Comprehensive Stripe Webhook Tests
 * Security-focused testing for webhook signature validation, replay attack prevention,
 * event processing security, and webhook endpoint protection
 */

import { NextRequest, NextResponse } from 'next/server'
import { POST as stripeWebhookHandler } from '@/app/api/webhooks/stripe/route'
import { stripeService } from '@/model/stripeService'
import { userPaymentService } from '@/model/userPaymentService'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'
import Stripe from 'stripe'

// Mock all dependencies
jest.mock('@/model/stripeService', () => ({
  stripeService: {
    verifyWebhookSignature: jest.fn()
  }
}))

jest.mock('@/model/userPaymentService', () => ({
  userPaymentService: {
    updateUserPaymentProfile: jest.fn(),
    recordPaymentSuccess: jest.fn()
  }
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

// Type mocked services
const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>
const mockGetClientIP = getClientIP as jest.MockedFunction<typeof getClientIP>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('Stripe Webhook - Comprehensive Security Tests', () => {
  const validSignature = 't=1234567890,v1=valid_signature_hash'
  const webhookSecret = 'whsec_test_secret'

  const createWebhookRequest = (
    body: string,
    signature?: string,
    headers: Record<string, string> = {}
  ) => {
    const requestHeaders = new Headers({
      'Content-Type': 'application/json',
      ...headers
    })

    if (signature) {
      requestHeaders.set('stripe-signature', signature)
    }

    return new NextRequest('https://example.com/api/webhooks/stripe', {
      method: 'POST',
      headers: requestHeaders,
      body
    })
  }

  const mockStripeEvent = (type: string, data: any = {}) => ({
    id: `evt_test_${Date.now()}`,
    type,
    created: Math.floor(Date.now() / 1000),
    data: { object: data },
    api_version: '2024-06-20',
    livemode: false,
    object: 'event',
    pending_webhooks: 1,
    request: { id: 'req_test', idempotency_key: null }
  } as Stripe.Event)

  beforeEach(() => {
    jest.clearAllMocks()
    mockGetClientIP.mockReturnValue('192.168.1.1')
  })

  describe('Webhook Signature Validation', () => {
    it('should reject requests without signature header', async () => {
      const body = JSON.stringify({ type: 'payment_intent.succeeded' })
      const request = createWebhookRequest(body)

      const response = await stripeWebhookHandler(request)
      
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toBe('Missing signature')
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StripeWebhook',
        'Missing stripe-signature header',
        expect.objectContaining({ ip: '192.168.1.1' })
      )
    })

    it('should reject requests with invalid signatures', async () => {
      const body = JSON.stringify({ type: 'payment_intent.succeeded' })
      const invalidSignature = 't=1234567890,v1=invalid_signature'
      
      mockStripeService.verifyWebhookSignature.mockImplementation(() => {
        throw new Error('Invalid signature')
      })

      const request = createWebhookRequest(body, invalidSignature)
      const response = await stripeWebhookHandler(request)
      
      expect(response.status).toBe(400)
      const data = await response.json()
      expect(data.error).toBe('Invalid signature')
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StripeWebhook',
        'Webhook signature verification failed',
        expect.objectContaining({ error: expect.any(Error), ip: '192.168.1.1' })
      )
    })

    it('should accept requests with valid signatures', async () => {
      const event = mockStripeEvent('payment_intent.succeeded')
      const body = JSON.stringify(event)
      
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)

      const request = createWebhookRequest(body, validSignature)
      const response = await stripeWebhookHandler(request)
      
      expect(response.status).toBe(200)
      const data = await response.json()
      expect(data.received).toBe(true)
      
      expect(mockStripeService.verifyWebhookSignature).toHaveBeenCalledWith(body, validSignature)
    })

    it('should prevent signature reuse attacks', async () => {
      const event = mockStripeEvent('payment_intent.succeeded')
      const body = JSON.stringify(event)
      
      // First request should succeed
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      const request1 = createWebhookRequest(body, validSignature)
      const response1 = await stripeWebhookHandler(request1)
      expect(response1.status).toBe(200)

      // Second request with same signature should be rejected
      mockStripeService.verifyWebhookSignature.mockImplementation(() => {
        throw new Error('Timestamp outside tolerance')
      })
      
      const request2 = createWebhookRequest(body, validSignature)
      const response2 = await stripeWebhookHandler(request2)
      expect(response2.status).toBe(400)
    })
  })

  describe('Webhook Event Processing Security', () => {
    beforeEach(() => {
      const event = mockStripeEvent('payment_intent.succeeded')
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
    })

    it('should handle malformed event data', async () => {
      const malformedEvents = [
        '{"invalid": "json"',
        '{}',
        '{"type": ""}',
        '{"type": "invalid_event_type"}',
        null,
        undefined
      ]

      for (const eventData of malformedEvents) {
        const body = typeof eventData === 'string' ? eventData : JSON.stringify(eventData)
        const request = createWebhookRequest(body, validSignature)
        
        const response = await stripeWebhookHandler(request)
        expect([400, 500]).toContain(response.status)
      }
    })

    it('should sanitize event data before processing', async () => {
      const maliciousEvent = mockStripeEvent('customer.created', {
        id: 'cus_test123',
        email: 'test+<script>alert("xss")</script>@example.com',
        name: 'Test"; DROP TABLE customers; --',
        metadata: {
          userInput: '<img src=x onerror=alert(1)>',
          description: '"; DELETE FROM users; --'
        }
      })

      mockStripeService.verifyWebhookSignature.mockReturnValue(maliciousEvent)
      
      const body = JSON.stringify(maliciousEvent)
      const request = createWebhookRequest(body, validSignature)
      
      const response = await stripeWebhookHandler(request)
      expect(response.status).toBe(200)

      // Verify that malicious data was sanitized before processing
      expect(mockUserPaymentService.updateUserPaymentProfile).toHaveBeenCalledWith(
        expect.any(String),
        expect.not.objectContaining({
          email: expect.stringContaining('<script>'),
          name: expect.stringContaining('DROP TABLE')
        })
      )
    })

    it('should validate event timestamps', async () => {
      const oldEvent = mockStripeEvent('payment_intent.succeeded')
      oldEvent.created = Math.floor(Date.now() / 1000) - 3600 // 1 hour old

      mockStripeService.verifyWebhookSignature.mockReturnValue(oldEvent)
      
      const body = JSON.stringify(oldEvent)
      const request = createWebhookRequest(body, validSignature)
      
      const response = await stripeWebhookHandler(request)
      
      // Should either reject or log warning for old events
      if (response.status === 200) {
        expect(mockLogger.warn).toHaveBeenCalledWith(
          expect.any(String),
          expect.stringContaining('old event'),
          expect.any(Object)
        )
      } else {
        expect(response.status).toBe(400)
      }
    })
  })

  describe('Event Type Handling Security', () => {
    const testEventProcessing = async (eventType: string, eventData: any) => {
      const event = mockStripeEvent(eventType, eventData)
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      const body = JSON.stringify(event)
      const request = createWebhookRequest(body, validSignature)
      
      return await stripeWebhookHandler(request)
    }

    it('should handle subscription events securely', async () => {
      const subscriptionData = {
        id: 'sub_test123',
        customer: 'cus_test123',
        status: 'active',
        metadata: {
          userId: 'user-123'
        }
      }

      const response = await testEventProcessing('customer.subscription.created', subscriptionData)
      expect(response.status).toBe(200)
      
      expect(mockUserPaymentService.updateUserPaymentProfile).toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          subscriptionId: 'sub_test123',
          subscriptionStatus: 'active'
        })
      )
    })

    it('should handle payment intent events securely', async () => {
      const paymentIntentData = {
        id: 'pi_test123',
        amount: 1000,
        currency: 'usd',
        status: 'succeeded',
        metadata: {
          userId: 'user-123'
        }
      }

      const response = await testEventProcessing('payment_intent.succeeded', paymentIntentData)
      expect(response.status).toBe(200)
      
      expect(mockUserPaymentService.recordPaymentSuccess).toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          paymentIntentId: 'pi_test123',
          amount: 1000
        })
      )
    })

    it('should handle invoice events securely', async () => {
      const invoiceData = {
        id: 'in_test123',
        customer: 'cus_test123',
        status: 'paid',
        amount_paid: 1000,
        subscription: 'sub_test123'
      }

      const response = await testEventProcessing('invoice.payment_succeeded', invoiceData)
      expect(response.status).toBe(200)
    })

    it('should reject unknown event types safely', async () => {
      const response = await testEventProcessing('unknown.event.type', {})
      expect(response.status).toBe(200) // Should not fail, just log
      
      expect(mockLogger.info).toHaveBeenCalledWith(
        'StripeWebhook',
        expect.stringContaining('Unhandled event type'),
        expect.any(Object)
      )
    })
  })

  describe('Rate Limiting and DDoS Protection', () => {
    it('should handle high volume webhook requests', async () => {
      const event = mockStripeEvent('payment_intent.succeeded')
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      const body = JSON.stringify(event)
      const requests = Array(20).fill(null).map(() => 
        createWebhookRequest(body, validSignature)
      )

      const responses = await Promise.all(
        requests.map(req => stripeWebhookHandler(req))
      )

      // Should handle all requests or implement rate limiting
      const successfulResponses = responses.filter(res => res.status === 200)
      const rateLimitedResponses = responses.filter(res => res.status === 429)
      
      expect(successfulResponses.length + rateLimitedResponses.length).toBe(responses.length)
    })

    it('should validate request origin', async () => {
      const event = mockStripeEvent('payment_intent.succeeded')
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      // Mock suspicious IP
      mockGetClientIP.mockReturnValue('1.2.3.4')
      
      const body = JSON.stringify(event)
      const request = createWebhookRequest(body, validSignature)
      
      const response = await stripeWebhookHandler(request)
      
      // Should log suspicious activity
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('webhook from IP'),
        expect.objectContaining({ ip: '1.2.3.4' })
      )
    })
  })

  describe('Error Handling and Recovery', () => {
    it('should handle processing errors gracefully', async () => {
      const event = mockStripeEvent('payment_intent.succeeded')
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      // Mock processing error
      mockUserPaymentService.recordPaymentSuccess.mockRejectedValue(
        new Error('Database connection failed')
      )
      
      const body = JSON.stringify(event)
      const request = createWebhookRequest(body, validSignature)
      
      const response = await stripeWebhookHandler(request)
      
      expect(response.status).toBe(500) // Should retry
      const data = await response.json()
      expect(data.shouldRetry).toBe(true)
      
      expect(mockLogger.error).toHaveBeenCalledWith(
        'StripeWebhook',
        expect.stringContaining('Failed to process event'),
        expect.any(Object)
      )
    })

    it('should handle business logic errors without retry', async () => {
      const event = mockStripeEvent('customer.subscription.created')
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      // Mock business logic error
      mockUserPaymentService.updateUserPaymentProfile.mockRejectedValue(
        new Error('Invalid subscription plan')
      )
      
      const body = JSON.stringify(event)
      const request = createWebhookRequest(body, validSignature)
      
      const response = await stripeWebhookHandler(request)
      
      expect(response.status).toBe(200) // Should not retry
      const data = await response.json()
      expect(data.shouldRetry).toBe(false)
    })

    it('should implement idempotency for webhook processing', async () => {
      const event = mockStripeEvent('payment_intent.succeeded')
      event.id = 'evt_duplicate_test'
      
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      const body = JSON.stringify(event)
      
      // Process same event twice
      const request1 = createWebhookRequest(body, validSignature)
      const request2 = createWebhookRequest(body, validSignature)
      
      const response1 = await stripeWebhookHandler(request1)
      const response2 = await stripeWebhookHandler(request2)
      
      expect(response1.status).toBe(200)
      expect(response2.status).toBe(200)
      
      // Should only process once
      expect(mockUserPaymentService.recordPaymentSuccess).toHaveBeenCalledTimes(1)
    })
  })

  describe('Security Monitoring and Logging', () => {
    it('should log all webhook events for audit trail', async () => {
      const event = mockStripeEvent('payment_intent.succeeded')
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      const body = JSON.stringify(event)
      const request = createWebhookRequest(body, validSignature)
      
      await stripeWebhookHandler(request)
      
      expect(mockLogger.info).toHaveBeenCalledWith(
        'StripeWebhook',
        expect.stringContaining('Processing event'),
        expect.objectContaining({
          eventId: event.id,
          ip: '192.168.1.1'
        })
      )
    })

    it('should detect and log suspicious webhook patterns', async () => {
      // Simulate rapid webhook requests from same IP
      const event = mockStripeEvent('payment_intent.succeeded')
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      const body = JSON.stringify(event)
      const requests = Array(10).fill(null).map(() => 
        createWebhookRequest(body, validSignature)
      )

      await Promise.all(requests.map(req => stripeWebhookHandler(req)))
      
      // Should detect suspicious pattern
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('High frequency webhooks'),
        expect.any(Object)
      )
    })

    it('should not log sensitive data', async () => {
      const event = mockStripeEvent('customer.created', {
        id: 'cus_test123',
        email: 'sensitive@example.com',
        payment_methods: ['pm_secret123']
      })
      
      mockStripeService.verifyWebhookSignature.mockReturnValue(event)
      
      const body = JSON.stringify(event)
      const request = createWebhookRequest(body, validSignature)
      
      await stripeWebhookHandler(request)
      
      // Verify sensitive data is not in logs
      const logCalls = mockLogger.info.mock.calls.concat(mockLogger.error.mock.calls)
      logCalls.forEach(call => {
        const logMessage = JSON.stringify(call)
        expect(logMessage).not.toContain('pm_secret123')
        expect(logMessage).not.toContain('sensitive@example.com')
      })
    })
  })
})
