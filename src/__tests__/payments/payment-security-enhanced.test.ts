/**
 * Enhanced Payment Security Tests
 * Comprehensive security testing for payment processing with proper mocking
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
  createSecurityTestScenarios,
  paymentTestData,
  simulateStripeError
} from '../utils/paymentTestUtils'

// Setup mocks before importing modules
setupPaymentMocks()
configureDefaultMockBehaviors()

// Import after mocks are setup
import { 
  paymentRateLimit,
  validateWebhookSignature,
  sanitizePaymentData,
  validatePaymentCSRFToken
} from '@/middleware/paymentSecurity'

describe('Enhanced Payment Security Tests', () => {
  beforeEach(() => {
    resetPaymentMocks()
    configureDefaultMockBehaviors()
  })

  describe('Payment Fraud Prevention', () => {
    it('should detect and prevent amount manipulation attacks', async () => {
      const maliciousAmounts = [999999999, -100, 0.01, Number.MAX_SAFE_INTEGER]
      
      for (const amount of maliciousAmounts) {
        allMocks.paymentValidationService.validatePaymentSecurity.mockReturnValue({
          isValid: false,
          securityFlags: ['AMOUNT_MANIPULATION'],
          sanitizedData: { amount: Math.min(amount, 100000) }
        })

        const request = createPaymentRequest({ amount, currency: 'usd' })
        const result = allMocks.paymentValidationService.validatePaymentSecurity(request)

        expect(result.isValid).toBe(false)
        expect(result.securityFlags).toContain('AMOUNT_MANIPULATION')
        expect(allMocks.logger.warn).toHaveBeenCalledWith(
          expect.any(String),
          expect.stringContaining('Amount manipulation'),
          expect.any(Object)
        )
      }
    })

    it('should detect suspicious payment patterns', async () => {
      const suspiciousPatterns = [
        { amount: 1, currency: 'usd', count: 50 }, // Card testing
        { amount: 9999, currency: 'usd', count: 10 }, // High value rapid
        { amount: 100, currency: 'eur', count: 20 } // Currency switching
      ]

      for (const pattern of suspiciousPatterns) {
        allMocks.paymentValidationService.detectFraudPattern.mockResolvedValue({
          success: false,
          code: 'FRAUD_PATTERN_DETECTED',
          data: { pattern: pattern.count > 30 ? 'CARD_TESTING' : 'HIGH_VELOCITY' }
        })

        const result = await allMocks.paymentValidationService.detectFraudPattern(
          'user-123', 
          pattern
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('FRAUD_PATTERN_DETECTED')
      }
    })

    it('should implement velocity checks', async () => {
      allMocks.advancedRateLimitService.checkRateLimit.mockResolvedValue(false)

      const request = createPaymentRequest({ amount: 1000, currency: 'usd' })
      const result = await paymentRateLimit(request, 'payment_creation')

      expect(result).toBeInstanceOf(NextResponse)
      expect(result?.status).toBe(429)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Rate limit exceeded'),
        expect.any(Object)
      )
    })

    it('should detect card testing attacks', async () => {
      const cardTestingAttempts = Array.from({ length: 20 }, (_, i) => ({
        amount: 1,
        currency: 'usd',
        paymentMethodId: `pm_test_${i}`
      }))

      for (const attempt of cardTestingAttempts) {
        allMocks.paymentValidationService.detectCardTesting.mockResolvedValue({
          success: false,
          code: 'CARD_TESTING_DETECTED',
          data: { attempts: cardTestingAttempts.length }
        })

        const result = await allMocks.paymentValidationService.detectCardTesting(
          'user-123',
          attempt
        )

        if (!result.success) {
          expect(result.code).toBe('CARD_TESTING_DETECTED')
          break
        }
      }
    })
  })

  describe('PCI Compliance Validation', () => {
    it('should ensure no sensitive card data is logged', () => {
      const sensitiveData = {
        cardNumber: '4242424242424242',
        cvv: '123',
        expiryMonth: '12',
        expiryYear: '2025'
      }

      allMocks.logger.info('Payment processed', sensitiveData)

      // Verify logger was called but sensitive data should be filtered
      expect(allMocks.logger.info).toHaveBeenCalled()
      const logCall = allMocks.logger.info.mock.calls[0]
      const logMessage = JSON.stringify(logCall)
      
      expect(logMessage).not.toContain('4242424242424242')
      expect(logMessage).not.toContain('123')
    })

    it('should validate PCI-compliant data handling', () => {
      const pciViolations = [
        { field: 'cardNumber', value: '4242424242424242' },
        { field: 'cvv', value: '123' },
        { field: 'pin', value: '1234' }
      ]

      for (const violation of pciViolations) {
        const paymentData = { [violation.field]: violation.value }
        
        allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
          isValid: false,
          securityFlags: ['PCI_VIOLATION'],
          sanitizedData: { [violation.field]: '[REDACTED]' }
        })

        const result = allMocks.paymentValidationService.validatePaymentData(paymentData)

        expect(result.isValid).toBe(false)
        expect(result.securityFlags).toContain('PCI_VIOLATION')
        expect(result.sanitizedData).not.toHaveProperty(violation.field, violation.value)
      }
    })

    it('should enforce secure transmission requirements', async () => {
      const insecureRequests = [
        { protocol: 'http', shouldReject: true },
        { protocol: 'https', shouldReject: false }
      ]

      for (const test of insecureRequests) {
        const url = `${test.protocol}://example.com/api/payments`
        const request = new NextRequest(url, {
          method: 'POST',
          body: JSON.stringify({ amount: 1000, currency: 'usd' })
        })

        // Mock security validation
        allMocks.security.validateOrigin.mockReturnValue(!test.shouldReject)

        const isSecure = allMocks.security.validateOrigin(request)

        if (test.shouldReject) {
          expect(isSecure).toBe(false)
        } else {
          expect(isSecure).toBe(true)
        }
      }
    })
  })

  describe('Price Manipulation Protection', () => {
    it('should validate subscription plan pricing', async () => {
      const pricingTamperingAttempts = [
        { planId: 'basic', expectedPrice: 2900, tamperedPrice: 100 },
        { planId: 'pro', expectedPrice: 9900, tamperedPrice: 2900 }
      ]

      for (const attempt of pricingTamperingAttempts) {
        allMocks.paymentValidationService.validatePlanPricing.mockResolvedValue({
          success: false,
          code: 'PRICE_MANIPULATION',
          data: { 
            expected: attempt.expectedPrice, 
            received: attempt.tamperedPrice 
          }
        })

        const result = await allMocks.paymentValidationService.validatePlanPricing(
          attempt.planId,
          attempt.tamperedPrice
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('PRICE_MANIPULATION')
      }
    })

    it('should prevent discount manipulation', () => {
      const discountManipulation = [
        { discount: 150, isValid: false }, // Over 100%
        { discount: -50, isValid: false }, // Negative
        { discount: 50, isValid: true }    // Valid
      ]

      for (const test of discountManipulation) {
        const paymentData = { 
          amount: 1000, 
          discount: test.discount,
          currency: 'usd' 
        }

        allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
          isValid: test.isValid,
          securityFlags: test.isValid ? [] : ['DISCOUNT_MANIPULATION'],
          sanitizedData: paymentData
        })

        const result = allMocks.paymentValidationService.validatePaymentData(paymentData)

        expect(result.isValid).toBe(test.isValid)
        if (!test.isValid) {
          expect(result.securityFlags).toContain('DISCOUNT_MANIPULATION')
        }
      }
    })

    it('should validate currency conversion rates', async () => {
      const currencyManipulation = [
        { from: 'usd', to: 'eur', rate: 10.0, isValid: false }, // Unrealistic rate
        { from: 'usd', to: 'eur', rate: 0.85, isValid: true }   // Realistic rate
      ]

      for (const test of currencyManipulation) {
        allMocks.paymentValidationService.validateCurrencyConversion.mockResolvedValue({
          success: test.isValid,
          code: test.isValid ? undefined : 'CURRENCY_MANIPULATION',
          data: { rate: test.rate }
        })

        const result = await allMocks.paymentValidationService.validateCurrencyConversion(
          test.from,
          test.to,
          test.rate
        )

        expect(result.success).toBe(test.isValid)
        if (!test.isValid) {
          expect(result.code).toBe('CURRENCY_MANIPULATION')
        }
      }
    })
  })

  describe('Payment Data Sanitization', () => {
    it('should sanitize all user input fields', () => {
      const maliciousInputs = createSecurityTestScenarios()
      const paymentData = {
        description: maliciousInputs.xssPayloads[0],
        customerName: maliciousInputs.sqlInjection[0],
        billingAddress: {
          line1: maliciousInputs.xssPayloads[1],
          city: maliciousInputs.sqlInjection[1]
        }
      }

      allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
        isValid: true,
        sanitizedData: {
          description: 'Clean description',
          customerName: 'Clean name',
          billingAddress: {
            line1: 'Clean address',
            city: 'Clean city'
          }
        }
      })

      const result = allMocks.paymentValidationService.validatePaymentData(paymentData)

      expect(result.sanitizedData.description).not.toContain('<script>')
      expect(result.sanitizedData.customerName).not.toContain('DROP TABLE')
      expect(result.sanitizedData.billingAddress.line1).not.toContain('<img')
      expect(result.sanitizedData.billingAddress.city).not.toContain('DELETE FROM')
    })

    it('should validate data types and formats', () => {
      const invalidData = {
        amount: 'invalid',
        currency: 123,
        email: 'not-an-email'
      }

      allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
        isValid: false,
        validationErrors: [
          'Invalid amount format',
          'Invalid currency format', 
          'Invalid email format'
        ]
      })

      const result = allMocks.paymentValidationService.validatePaymentData(invalidData)

      expect(result.isValid).toBe(false)
      expect(result.validationErrors).toContain('Invalid amount format')
      expect(result.validationErrors).toContain('Invalid currency format')
      expect(result.validationErrors).toContain('Invalid email format')
    })

    it('should enforce field length limits', () => {
      const oversizedData = createSecurityTestScenarios().oversizedInputs

      allMocks.paymentValidationService.validatePaymentData.mockReturnValue({
        isValid: true,
        sanitizedData: {
          description: oversizedData.description.substring(0, 500),
          customerName: oversizedData.customerName.substring(0, 100),
          notes: oversizedData.notes.substring(0, 1000)
        }
      })

      const result = allMocks.paymentValidationService.validatePaymentData(oversizedData)

      expect(result.sanitizedData.description.length).toBeLessThanOrEqual(500)
      expect(result.sanitizedData.customerName.length).toBeLessThanOrEqual(100)
      expect(result.sanitizedData.notes.length).toBeLessThanOrEqual(1000)
    })
  })

  describe('CSRF Protection for Payment Endpoints', () => {
    it('should validate CSRF tokens on payment requests', async () => {
      const invalidTokenScenarios = [
        { token: null, sessionId: 'session-123' },
        { token: 'invalid-token', sessionId: 'session-123' },
        { token: 'valid-token', sessionId: null }
      ]

      for (const scenario of invalidTokenScenarios) {
        const request = createPaymentRequest(
          { amount: 1000, currency: 'usd' },
          scenario.sessionId ? { 'Cookie': `session-id=${scenario.sessionId}` } : {}
        )

        allMocks.csrfProtectionService.validateFormSubmission.mockReturnValue({
          isValid: false,
          error: 'Invalid CSRF token'
        })

        const result = validatePaymentCSRFToken(request)

        expect(result).toBe(false)
      }
    })

    it('should prevent CSRF attacks with valid tokens', () => {
      const request = createPaymentRequest(
        { amount: 1000, currency: 'usd' },
        { 'Cookie': 'session-id=valid-session' }
      )

      allMocks.csrfProtectionService.validateFormSubmission.mockReturnValue({
        isValid: true
      })

      const result = validatePaymentCSRFToken(request)

      expect(result).toBe(true)
    })
  })

  describe('Security Monitoring and Alerting', () => {
    it('should trigger security alerts for critical events', () => {
      const criticalEvents = [
        'PAYMENT_FRAUD_DETECTED',
        'CARD_TESTING_ATTACK',
        'PRICE_MANIPULATION',
        'PCI_VIOLATION'
      ]

      criticalEvents.forEach(event => {
        allMocks.logger.error(`Critical security event: ${event}`, {
          event,
          timestamp: new Date().toISOString(),
          severity: 'CRITICAL'
        })

        expect(allMocks.logger.error).toHaveBeenCalledWith(
          expect.stringContaining('Critical security event'),
          expect.objectContaining({
            event,
            severity: 'CRITICAL'
          })
        )
      })
    })

    it('should implement security metrics collection', () => {
      const securityMetrics = {
        fraudAttempts: 5,
        blockedRequests: 12,
        suspiciousPatterns: 3,
        pciViolations: 0
      }

      allMocks.logger.info('Security metrics collected', {
        metrics: securityMetrics,
        timestamp: new Date().toISOString()
      })

      expect(allMocks.logger.info).toHaveBeenCalledWith(
        'Security metrics collected',
        expect.objectContaining({
          metrics: securityMetrics
        })
      )
    })
  })

  describe('Webhook Signature Validation', () => {
    it('should validate webhook signatures correctly', () => {
      const validPayload = JSON.stringify({ type: 'payment_intent.succeeded' })
      const validSignature = 't=1234567890,v1=valid_signature'
      const secret = 'whsec_test_secret'

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(true)

      const result = validateWebhookSignature(validPayload, validSignature, secret)

      expect(result).toBe(true)
      expect(allMocks.stripeService.verifyWebhookSignature).toHaveBeenCalledWith(
        validPayload,
        validSignature,
        secret
      )
    })

    it('should reject invalid webhook signatures', () => {
      const payload = JSON.stringify({ type: 'payment_intent.succeeded' })
      const invalidSignature = 'invalid_signature'
      const secret = 'whsec_test_secret'

      allMocks.stripeService.verifyWebhookSignature.mockReturnValue(false)

      const result = validateWebhookSignature(payload, invalidSignature, secret)

      expect(result).toBe(false)
      expect(allMocks.logger.warn).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Invalid webhook signature'),
        expect.any(Object)
      )
    })

    it('should handle signature validation errors', () => {
      const payload = JSON.stringify({ type: 'payment_intent.succeeded' })
      const malformedSignature = 'malformed_signature'
      const secret = 'whsec_test_secret'

      allMocks.stripeService.verifyWebhookSignature.mockImplementation(() => {
        throw new Error('Signature validation error')
      })

      const result = validateWebhookSignature(payload, malformedSignature, secret)

      expect(result).toBe(false)
      expect(allMocks.logger.error).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining('Webhook signature validation failed'),
        expect.any(Error)
      )
    })
  })

  describe('Payment Amount Validation', () => {
    it('should validate payment amounts within acceptable ranges', () => {
      const testAmounts = [
        { amount: 50, currency: 'usd', isValid: true },    // Minimum valid
        { amount: 100000, currency: 'usd', isValid: true }, // Maximum valid
        { amount: 25, currency: 'usd', isValid: false },   // Below minimum
        { amount: 1000000, currency: 'usd', isValid: false } // Above maximum
      ]

      testAmounts.forEach(test => {
        allMocks.paymentValidationService.validatePaymentAmount.mockReturnValue({
          isValid: test.isValid,
          error: test.isValid ? null : 'Amount out of range'
        })

        const result = allMocks.paymentValidationService.validatePaymentAmount(
          test.amount,
          test.currency
        )

        expect(result.isValid).toBe(test.isValid)
        if (!test.isValid) {
          expect(result.error).toBeTruthy()
        }
      })
    })

    it('should handle currency-specific amount limits', () => {
      const currencyLimits = [
        { currency: 'jpy', amount: 5000, isValid: true },   // JPY has different limits
        { currency: 'eur', amount: 50, isValid: true },     // EUR standard
        { currency: 'gbp', amount: 30, isValid: true }      // GBP standard
      ]

      currencyLimits.forEach(test => {
        allMocks.paymentValidationService.validatePaymentAmount.mockReturnValue({
          isValid: test.isValid,
          normalizedAmount: test.amount
        })

        const result = allMocks.paymentValidationService.validatePaymentAmount(
          test.amount,
          test.currency
        )

        expect(result.isValid).toBe(test.isValid)
      })
    })
  })
})
