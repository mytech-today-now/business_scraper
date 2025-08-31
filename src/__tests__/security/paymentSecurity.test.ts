/**
 * Payment Security Middleware Tests
 * Comprehensive security validation tests for payment processing
 */

import { NextRequest, NextResponse } from 'next/server'
import {
  paymentRateLimit,
  validateWebhookSignature,
  sanitizePaymentData,
  validatePaymentCSRFToken,
  validateWebhookIP,
  withPaymentSecurity,
  withStripeWebhookSecurity,
} from '@/middleware/paymentSecurity'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { csrfProtectionService } from '@/lib/csrfProtection'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'

// Mock dependencies
jest.mock('@/lib/advancedRateLimit')
jest.mock('@/lib/csrfProtection')
jest.mock('@/lib/security')
jest.mock('@/utils/logger')

const mockAdvancedRateLimitService = advancedRateLimitService as jest.Mocked<
  typeof advancedRateLimitService
>
const mockCsrfProtectionService = csrfProtectionService as jest.Mocked<typeof csrfProtectionService>
const mockGetClientIP = getClientIP as jest.MockedFunction<typeof getClientIP>
const mockLogger = logger as jest.Mocked<typeof logger>

describe('Payment Security Middleware', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockGetClientIP.mockReturnValue('192.168.1.1')
  })

  describe('paymentRateLimit', () => {
    it('should allow requests within rate limit', async () => {
      mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(true)

      const request = new NextRequest('https://example.com/api/payment')
      const result = await paymentRateLimit(request, 'payment')

      expect(result).toBeNull()
      expect(mockAdvancedRateLimitService.checkRateLimit).toHaveBeenCalledWith(
        'payment_payment',
        '192.168.1.1',
        10,
        900000
      )
    })

    it('should block requests exceeding rate limit', async () => {
      mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(false)

      const request = new NextRequest('https://example.com/api/payment')
      const result = await paymentRateLimit(request, 'payment')

      expect(result).toBeInstanceOf(NextResponse)
      expect(result?.status).toBe(429)

      const responseData = await result?.json()
      expect(responseData.error).toBe('Too many payment requests, please try again later')
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentSecurity',
        'Payment rate limit exceeded for payment from IP: 192.168.1.1'
      )
    })

    it('should handle rate limit service errors gracefully', async () => {
      mockAdvancedRateLimitService.checkRateLimit.mockRejectedValue(new Error('Service error'))

      const request = new NextRequest('https://example.com/api/payment')
      const result = await paymentRateLimit(request, 'payment')

      expect(result).toBeNull() // Should allow request on service failure
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentSecurity',
        'Rate limit check failed',
        expect.any(Error)
      )
    })

    it('should use different limits for different types', async () => {
      mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(true)

      const request = new NextRequest('https://example.com/api/webhook')
      await paymentRateLimit(request, 'webhook')

      expect(mockAdvancedRateLimitService.checkRateLimit).toHaveBeenCalledWith(
        'payment_webhook',
        '192.168.1.1',
        100,
        60000
      )
    })
  })

  describe('validateWebhookSignature', () => {
    const testSecret = 'whsec_test123'
    const testPayload = '{"test": "data"}'

    it('should validate correct webhook signature', () => {
      const crypto = require('crypto')
      const expectedSignature = crypto
        .createHmac('sha256', testSecret)
        .update(testPayload, 'utf8')
        .digest('hex')

      const result = validateWebhookSignature(testPayload, expectedSignature, testSecret)
      expect(result).toBe(true)
    })

    it('should reject invalid webhook signature', () => {
      const result = validateWebhookSignature(testPayload, 'invalid_signature', testSecret)
      expect(result).toBe(false)
    })

    it('should handle Stripe signature format with v1= prefix', () => {
      const crypto = require('crypto')
      const expectedSignature = crypto
        .createHmac('sha256', testSecret)
        .update(testPayload, 'utf8')
        .digest('hex')

      const result = validateWebhookSignature(testPayload, `v1=${expectedSignature}`, testSecret)
      expect(result).toBe(true)
    })

    it('should handle missing parameters', () => {
      expect(validateWebhookSignature('', 'sig', testSecret)).toBe(false)
      expect(validateWebhookSignature(testPayload, '', testSecret)).toBe(false)
      expect(validateWebhookSignature(testPayload, 'sig', '')).toBe(false)

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentSecurity',
        'Missing required parameters for webhook signature validation'
      )
    })

    it('should handle signature validation errors', () => {
      // Test with malformed signature
      const result = validateWebhookSignature(testPayload, 'malformed_hex', testSecret)
      expect(result).toBe(false)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentSecurity',
        'Webhook signature validation failed',
        expect.any(Error)
      )
    })
  })

  describe('sanitizePaymentData', () => {
    it('should remove sensitive payment fields', () => {
      const sensitiveData = {
        name: 'John Doe',
        email: 'john@example.com',
        card_number: '4242424242424242',
        cvv: '123',
        ssn: '123-45-6789',
        bank_account: '123456789',
        safe_field: 'keep this',
      }

      const sanitized = sanitizePaymentData(sensitiveData)

      expect(sanitized).toEqual({
        name: 'John Doe',
        email: 'john@example.com',
        safe_field: 'keep this',
      })
      expect(sanitized.card_number).toBeUndefined()
      expect(sanitized.cvv).toBeUndefined()
      expect(sanitized.ssn).toBeUndefined()
      expect(sanitized.bank_account).toBeUndefined()
    })

    it('should handle nested objects', () => {
      const nestedData = {
        user: {
          name: 'John Doe',
          payment: {
            card_number: '4242424242424242',
            cvv: '123',
          },
        },
        transaction: {
          amount: 1000,
          routing_number: '123456789',
        },
      }

      const sanitized = sanitizePaymentData(nestedData)

      expect(sanitized.user.name).toBe('John Doe')
      expect(sanitized.user.payment.card_number).toBeUndefined()
      expect(sanitized.user.payment.cvv).toBeUndefined()
      expect(sanitized.transaction.amount).toBe(1000)
      expect(sanitized.transaction.routing_number).toBeUndefined()
    })

    it('should handle arrays', () => {
      const arrayData = [
        { name: 'Item 1', card_number: '4242424242424242' },
        { name: 'Item 2', cvv: '123' },
      ]

      const sanitized = sanitizePaymentData(arrayData)

      expect(sanitized).toHaveLength(2)
      expect(sanitized[0].name).toBe('Item 1')
      expect(sanitized[0].card_number).toBeUndefined()
      expect(sanitized[1].name).toBe('Item 2')
      expect(sanitized[1].cvv).toBeUndefined()
    })

    it('should handle non-object inputs', () => {
      expect(sanitizePaymentData(null)).toBeNull()
      expect(sanitizePaymentData(undefined)).toBeUndefined()
      expect(sanitizePaymentData('string')).toBe('string')
      expect(sanitizePaymentData(123)).toBe(123)
    })
  })

  describe('validatePaymentCSRFToken', () => {
    it('should validate CSRF token successfully', () => {
      const request = new NextRequest('https://example.com/api/payment', {
        method: 'POST',
        headers: { Cookie: 'session-id=test-session' },
      })

      mockCsrfProtectionService.validateFormSubmission.mockReturnValue({
        isValid: true,
      })

      const result = validatePaymentCSRFToken(request)

      expect(result).toBe(true)
      expect(mockCsrfProtectionService.validateFormSubmission).toHaveBeenCalledWith(
        request,
        'test-session'
      )
    })

    it('should reject invalid CSRF token', () => {
      const request = new NextRequest('https://example.com/api/payment', {
        method: 'POST',
        headers: { Cookie: 'session-id=test-session' },
      })

      mockCsrfProtectionService.validateFormSubmission.mockReturnValue({
        isValid: false,
        error: 'Invalid token',
      })

      const result = validatePaymentCSRFToken(request)

      expect(result).toBe(false)
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentSecurity',
        'CSRF validation failed: Invalid token'
      )
    })

    it('should handle missing session ID', () => {
      const request = new NextRequest('https://example.com/api/payment', {
        method: 'POST',
      })

      const result = validatePaymentCSRFToken(request)

      expect(result).toBe(false)
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentSecurity',
        'No session ID found for CSRF validation'
      )
    })

    it('should handle CSRF validation errors', () => {
      const request = new NextRequest('https://example.com/api/payment', {
        method: 'POST',
        headers: { Cookie: 'session-id=test-session' },
      })

      mockCsrfProtectionService.validateFormSubmission.mockImplementation(() => {
        throw new Error('CSRF service error')
      })

      const result = validatePaymentCSRFToken(request)

      expect(result).toBe(false)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentSecurity',
        'CSRF token validation failed',
        expect.any(Error)
      )
    })
  })

  describe('validateWebhookIP', () => {
    it('should allow requests from Stripe IPs', () => {
      mockGetClientIP.mockReturnValue('54.187.174.169') // Known Stripe IP

      const request = new NextRequest('https://example.com/api/webhook')
      const result = validateWebhookIP(request)

      expect(result).toBe(true)
    })

    it('should block requests from unauthorized IPs', () => {
      mockGetClientIP.mockReturnValue('192.168.1.100') // Not a Stripe IP

      const request = new NextRequest('https://example.com/api/webhook')
      const result = validateWebhookIP(request)

      expect(result).toBe(false)
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentSecurity',
        'Webhook request from unauthorized IP: 192.168.1.100'
      )
    })

    it('should handle missing client IP', () => {
      mockGetClientIP.mockReturnValue('')

      const request = new NextRequest('https://example.com/api/webhook')
      const result = validateWebhookIP(request)

      expect(result).toBe(false)
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentSecurity',
        'No client IP found for webhook validation'
      )
    })

    it('should handle IP validation errors', () => {
      mockGetClientIP.mockImplementation(() => {
        throw new Error('IP service error')
      })

      const request = new NextRequest('https://example.com/api/webhook')
      const result = validateWebhookIP(request)

      expect(result).toBe(false)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentSecurity',
        'Webhook IP validation failed',
        expect.any(Error)
      )
    })
  })

  describe('withPaymentSecurity', () => {
    const mockHandler = jest.fn().mockResolvedValue(NextResponse.json({ success: true }))

    beforeEach(() => {
      mockHandler.mockClear()
      mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(true)
      mockCsrfProtectionService.validateFormSubmission.mockReturnValue({
        isValid: true,
      })
    })

    it('should apply all security checks for POST requests', async () => {
      const securedHandler = withPaymentSecurity(mockHandler, {
        requireCSRF: true,
        rateLimitType: 'payment',
      })

      const request = new NextRequest('https://example.com/api/payment', {
        method: 'POST',
        headers: { Cookie: 'session-id=test-session' },
      })

      const response = await securedHandler(request)

      expect(mockAdvancedRateLimitService.checkRateLimit).toHaveBeenCalled()
      expect(mockCsrfProtectionService.validateFormSubmission).toHaveBeenCalled()
      expect(mockHandler).toHaveBeenCalled()
      expect(response.status).toBe(200)
    })

    it('should block requests that fail rate limiting', async () => {
      mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(false)

      const securedHandler = withPaymentSecurity(mockHandler)
      const request = new NextRequest('https://example.com/api/payment')

      const response = await securedHandler(request)

      expect(response.status).toBe(429)
      expect(mockHandler).not.toHaveBeenCalled()
    })

    it('should block requests that fail CSRF validation', async () => {
      mockCsrfProtectionService.validateFormSubmission.mockReturnValue({
        isValid: false,
        error: 'Invalid token',
      })

      const securedHandler = withPaymentSecurity(mockHandler, {
        requireCSRF: true,
      })

      const request = new NextRequest('https://example.com/api/payment', {
        method: 'POST',
        headers: { Cookie: 'session-id=test-session' },
      })

      const response = await securedHandler(request)

      expect(response.status).toBe(403)
      expect(mockHandler).not.toHaveBeenCalled()
    })

    it('should skip CSRF for GET requests', async () => {
      const securedHandler = withPaymentSecurity(mockHandler, {
        requireCSRF: true,
      })

      const request = new NextRequest('https://example.com/api/payment', {
        method: 'GET',
      })

      await securedHandler(request)

      expect(mockCsrfProtectionService.validateFormSubmission).not.toHaveBeenCalled()
      expect(mockHandler).toHaveBeenCalled()
    })

    it('should handle middleware errors gracefully', async () => {
      mockHandler.mockRejectedValue(new Error('Handler error'))

      const securedHandler = withPaymentSecurity(mockHandler)
      const request = new NextRequest('https://example.com/api/payment')

      const response = await securedHandler(request)

      expect(response.status).toBe(500)
      expect(mockLogger.error).toHaveBeenCalledWith(
        'PaymentSecurity',
        expect.stringContaining('Payment security middleware error'),
        expect.any(Error)
      )
    })
  })

  describe('withStripeWebhookSecurity', () => {
    const mockHandler = jest.fn().mockResolvedValue(NextResponse.json({ received: true }))
    const webhookSecret = 'whsec_test123'

    beforeEach(() => {
      mockHandler.mockClear()
      mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(true)
      mockGetClientIP.mockReturnValue('54.187.174.169') // Stripe IP
    })

    it('should validate webhook signature and allow valid requests', async () => {
      const payload = '{"test": "data"}'
      const crypto = require('crypto')
      const signature = crypto
        .createHmac('sha256', webhookSecret)
        .update(payload, 'utf8')
        .digest('hex')

      const securedHandler = withStripeWebhookSecurity(mockHandler, webhookSecret)
      const request = new NextRequest('https://example.com/api/webhook', {
        method: 'POST',
        headers: {
          'stripe-signature': signature,
        },
        body: payload,
      })

      const response = await securedHandler(request)

      expect(response.status).toBe(200)
      expect(mockHandler).toHaveBeenCalled()
    })

    it('should reject requests with invalid signatures', async () => {
      const securedHandler = withStripeWebhookSecurity(mockHandler, webhookSecret)
      const request = new NextRequest('https://example.com/api/webhook', {
        method: 'POST',
        headers: {
          'stripe-signature': 'invalid_signature',
        },
        body: '{"test": "data"}',
      })

      const response = await securedHandler(request)

      expect(response.status).toBe(401)
      expect(mockHandler).not.toHaveBeenCalled()
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'PaymentSecurity',
        'Invalid Stripe webhook signature'
      )
    })

    it('should reject requests without signature header', async () => {
      const securedHandler = withStripeWebhookSecurity(mockHandler, webhookSecret)
      const request = new NextRequest('https://example.com/api/webhook', {
        method: 'POST',
        body: '{"test": "data"}',
      })

      const response = await securedHandler(request)

      expect(response.status).toBe(401)
      expect(mockHandler).not.toHaveBeenCalled()
    })
  })
})
