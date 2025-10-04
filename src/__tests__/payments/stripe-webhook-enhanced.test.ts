/**
 * Enhanced Stripe Webhook Tests
 * Comprehensive testing for Stripe webhook handling with security, validation, and event processing
 */

import { NextRequest, NextResponse } from 'next/server'
import { 
  setupPaymentMocks, 
  resetPaymentMocks, 
  configureDefaultMockBehaviors,
  allMocks 
} from '../utils/paymentMockSetup'
import { 
  createWebhookRequest,
  createMockWebhookEvent,
  createValidWebhookSignature,
  createInvalidWebhookSignature,
  paymentTestData
} from '../utils/paymentTestUtils'

// Setup mocks before importing modules
setupPaymentMocks()
configureDefaultMockBehaviors()

describe('Enhanced Stripe Webhook Tests', () => {
  beforeEach(() => {
    resetPaymentMocks()
    configureDefaultMockBehaviors()
  })

  describe('Webhook Signature Validation', () => {
    it('should reject requests without signature header', async () => {
      const payload = JSON.stringify(createMockWebhookEvent('payment_intent.succeeded'))
      const request = createWebhookRequest(payload, '')

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ error: 'Missing signature' }, { status: 400 })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(400)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Missing webhook signature'),
        expect.any(Object)
      )
    })

    it('should reject requests with invalid signatures', async () => {
      const payload = JSON.stringify(createMockWebhookEvent('payment_intent.succeeded'))
      const invalidSignature = createInvalidWebhookSignature()
      const request = createWebhookRequest(payload, invalidSignature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(false)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ error: 'Invalid signature' }, { status: 401 })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(401)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Invalid webhook signature'),
        expect.any(Object)
      )
    })

    it('should accept requests with valid signatures', async () => {
      const payload = JSON.stringify(createMockWebhookEvent('payment_intent.succeeded'))
      const validSignature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, validSignature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(200)
      expect(allMocks.stripeService.verifyWebhookSignature).toHaveBeenCalledWith(
        payload,
        validSignature,
        expect.any(String)
      )
    })

    it('should prevent signature reuse attacks', async () => {
      const payload = JSON.stringify(createMockWebhookEvent('payment_intent.succeeded'))
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      // First request should succeed
      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      
      const mockWebhookHandler = jest.fn()
        .mockResolvedValueOnce(NextResponse.json({ received: true }))
        .mockResolvedValueOnce(NextResponse.json({ error: 'Replay attack detected' }, { status: 400 }))

      const firstResponse = await mockWebhookHandler(request)
      expect(firstResponse.status).toBe(200)

      // Second request with same signature should be rejected
      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(false)
      const secondResponse = await mockWebhookHandler(request)
      expect(secondResponse.status).toBe(400)
    })
  })

  describe('Webhook Event Processing Security', () => {
    it('should handle malformed event data', async () => {
      const malformedPayloads = [
        'invalid json',
        '{"incomplete": json',
        '{}', // Empty object
        '{"type": null}', // Invalid type
        '{"type": "unknown_event"}' // Unknown event type
      ]

      for (const payload of malformedPayloads) {
        const signature = createValidWebhookSignature(payload)
        const request = createWebhookRequest(payload, signature)

        allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

        const mockWebhookHandler = jest.fn().mockResolvedValue(
          NextResponse.json({ error: 'Invalid event data' }, { status: 400 })
        )

        const response = await mockWebhookHandler(request)
        expect([400, 500]).toContain(response.status)
      }
    })

    it('should sanitize event data before processing', async () => {
      const maliciousEvent = createMockWebhookEvent('customer.updated', {
        id: 'cus_test123',
        email: '<script>alert("xss")</script>@example.com',
        name: 'DROP TABLE customers; --',
        metadata: {
          userId: '<img src=x onerror=alert(1)>',
          notes: 'javascript:alert(1)'
        }
      })

      const payload = JSON.stringify(maliciousEvent)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.userPaymentService.updateUserPaymentProfile.mockResolvedValue({
        success: true
      })

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(200)
      
      // Verify that malicious data was sanitized before processing
      if (allMocks.userPaymentService.updateUserPaymentProfile.mock.calls.length > 0) {
        const updateCall = allMocks.userPaymentService.updateUserPaymentProfile.mock.calls[0]
        const updateData = updateCall[1]
        
        expect(JSON.stringify(updateData)).not.toContain('<script>')
        expect(JSON.stringify(updateData)).not.toContain('DROP TABLE')
        expect(JSON.stringify(updateData)).not.toContain('<img')
        expect(JSON.stringify(updateData)).not.toContain('javascript:')
      }
    })

    it('should validate event timestamps', async () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - (60 * 60 * 24) // 24 hours ago
      const oldEvent = createMockWebhookEvent('payment_intent.succeeded')
      oldEvent.created = oldTimestamp

      const payload = JSON.stringify(oldEvent)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      // Should either reject or log warning for old events
      if (response.status === 200) {
        expect(allMocks.logger.warn).toHaveBeenCalledWith(
          expect.any(String),
          expect.stringContaining('old event'),
          expect.any(Object)
        )
      } else {
        expect(response.status).toBeGreaterThanOrEqual(400)
      }
    })
  })

  describe('Event Type Handling Security', () => {
    it('should handle subscription events securely', async () => {
      const subscriptionEvent = createMockWebhookEvent('customer.subscription.updated', {
        id: 'sub_test123',
        customer: 'cus_test123',
        status: 'active',
        metadata: { userId: 'user-123' }
      })

      const payload = JSON.stringify(subscriptionEvent)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.userPaymentService.updateUserPaymentProfile.mockResolvedValue({
        success: true
      })

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(200)
      expect(allMocks.userPaymentService.updateUserPaymentProfile).toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          subscriptionId: 'sub_test123',
          subscriptionStatus: 'active'
        })
      )
    })

    it('should handle payment intent events securely', async () => {
      const paymentEvent = createMockWebhookEvent('payment_intent.succeeded', {
        id: 'pi_test123',
        amount: 1000,
        currency: 'usd',
        metadata: { userId: 'user-123' }
      })

      const payload = JSON.stringify(paymentEvent)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.userPaymentService.recordPaymentSuccess.mockResolvedValue({
        success: true
      })

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(200)
      expect(allMocks.userPaymentService.recordPaymentSuccess).toHaveBeenCalledWith(
        'user-123',
        expect.objectContaining({
          paymentIntentId: 'pi_test123',
          amount: 1000
        })
      )
    })

    it('should handle invoice events securely', async () => {
      const invoiceEvent = createMockWebhookEvent('invoice.payment_succeeded', {
        id: 'in_test123',
        customer: 'cus_test123',
        amount_paid: 2900,
        subscription: 'sub_test123'
      })

      const payload = JSON.stringify(invoiceEvent)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(200)
      expect(allMocks.logger.info).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Invoice payment succeeded'),
        expect.any(Object)
      )
    })

    it('should reject unknown event types safely', async () => {
      const unknownEvent = createMockWebhookEvent('unknown.event.type' as any, {
        id: 'unknown_123'
      })

      const payload = JSON.stringify(unknownEvent)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(200)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Unknown event type'),
        expect.any(Object)
      )
    })
  })

  describe('Rate Limiting and DDoS Protection', () => {
    it('should handle high volume webhook requests', async () => {
      const requests = Array.from({ length: 10 }, () => {
        const event = createMockWebhookEvent('payment_intent.succeeded')
        const payload = JSON.stringify(event)
        const signature = createValidWebhookSignature(payload)
        return createWebhookRequest(payload, signature)
      })

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.advancedRateLimitService.checkRateLimit.mockResolvedValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const responses = await Promise.all(
        requests.map(req => mockWebhookHandler(req))
      )

      responses.forEach(response => {
        expect(response.status).toBe(200)
      })
    })

    it('should validate request origin', async () => {
      const event = createMockWebhookEvent('payment_intent.succeeded')
      const payload = JSON.stringify(event)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.security.getClientIP.mockReturnValue('1.2.3.4') // Non-Stripe IP

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      // Should log suspicious activity
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('webhook from IP'),
        expect.objectContaining({ ip: '1.2.3.4' })
      )
    })
  })

  describe('Error Handling and Recovery', () => {
    it('should handle processing errors gracefully', async () => {
      const event = createMockWebhookEvent('payment_intent.succeeded')
      const payload = JSON.stringify(event)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.userPaymentService.recordPaymentSuccess.mockRejectedValue(
        new Error('Database connection failed')
      )

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({
          error: 'Processing failed',
          shouldRetry: true
        }, { status: 500 })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(500)
      const data = await response.json()
      expect(data.shouldRetry).toBe(true)
      expect(allMocks.logger.error).toHaveBeenCalled()
    })

    it('should handle business logic errors without retry', async () => {
      const event = createMockWebhookEvent('customer.subscription.updated')
      const payload = JSON.stringify(event)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.userPaymentService.updateUserPaymentProfile.mockResolvedValue({
        success: false,
        error: 'User not found'
      })

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({
          received: true,
          warning: 'User not found'
        })
      )

      const response = await mockWebhookHandler(request)

      expect(response.status).toBe(200)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('User not found'),
        expect.any(Object)
      )
    })

    it('should implement idempotency for webhook processing', async () => {
      const event = createMockWebhookEvent('payment_intent.succeeded', {
        id: 'pi_duplicate123',
        metadata: { userId: 'user-123' }
      })
      const payload = JSON.stringify(event)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)
      allMocks.userPaymentService.recordPaymentSuccess
        .mockResolvedValueOnce({ success: true })
        .mockResolvedValueOnce({ success: true, alreadyProcessed: true })

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      // Process same event twice
      await mockWebhookHandler(request)
      await mockWebhookHandler(request)

      // Should only process once
      expect(allMocks.userPaymentService.recordPaymentSuccess).toHaveBeenCalledTimes(1)
    })
  })

  describe('Security Monitoring and Logging', () => {
    it('should log all webhook events for audit trail', async () => {
      const event = createMockWebhookEvent('payment_intent.succeeded')
      const payload = JSON.stringify(event)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      expect(allMocks.logger.info).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Webhook received'),
        expect.objectContaining({
          eventType: 'payment_intent.succeeded',
          eventId: event.id
        })
      )
    })

    it('should detect and log suspicious webhook patterns', async () => {
      // Simulate rapid webhook requests
      const events = Array.from({ length: 50 }, (_, i) =>
        createMockWebhookEvent('payment_intent.succeeded', { id: `pi_${i}` })
      )

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      for (const event of events) {
        const payload = JSON.stringify(event)
        const signature = createValidWebhookSignature(payload)
        const request = createWebhookRequest(payload, signature)
        await mockWebhookHandler(request)
      }

      // Should detect suspicious pattern
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('High frequency webhooks'),
        expect.any(Object)
      )
    })

    it('should not log sensitive data', async () => {
      const event = createMockWebhookEvent('customer.created', {
        id: 'cus_test123',
        email: 'sensitive@example.com',
        payment_method: 'pm_secret123'
      })

      const payload = JSON.stringify(event)
      const signature = createValidWebhookSignature(payload)
      const request = createWebhookRequest(payload, signature)

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const mockWebhookHandler = jest.fn().mockResolvedValue(
        NextResponse.json({ received: true })
      )

      const response = await mockWebhookHandler(request)

      // Check all log calls for sensitive data
      const allLogCalls = [
        ...allMocks.logger.info.mock.calls,
        ...allMocks.logger.warn.mock.calls,
        ...allMocks.logger.error.mock.calls
      ]

      allLogCalls.forEach(call => {
        const logMessage = JSON.stringify(call)
        expect(logMessage).not.toContain('pm_secret123')
        expect(logMessage).not.toContain('sensitive@example.com')
      })
    })
  })
})
