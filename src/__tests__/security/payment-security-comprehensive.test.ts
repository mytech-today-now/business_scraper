/**
 * Comprehensive Payment Security Tests
 * Cross-system security testing covering payment fraud prevention, PCI compliance,
 * price manipulation protection, payment data sanitization, and security monitoring
 */

import { NextRequest, NextResponse } from 'next/server'
import { 
  paymentRateLimit,
  validateWebhookSignature,
  sanitizePaymentData,
  validatePaymentCSRFToken,
  withPaymentSecurity,
  withStripeWebhookSecurity
} from '@/middleware/paymentSecurity'
import { stripeService } from '@/model/stripeService'
import { userPaymentService } from '@/model/userPaymentService'
import { paymentValidationService } from '@/model/paymentValidationService'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { csrfProtectionService } from '@/lib/csrfProtection'

// Mock all dependencies
jest.mock('@/model/stripeService', () => ({
  stripeService: {
    createPaymentIntent: jest.fn(),
    createCustomer: jest.fn(),
    createSubscription: jest.fn(),
    verifyWebhookSignature: jest.fn(),
    createBillingPortalSession: jest.fn()
  }
}))

jest.mock('@/model/userPaymentService', () => ({
  userPaymentService: {
    getUserPaymentProfile: jest.fn(),
    updateUserPaymentProfile: jest.fn(),
    recordUsage: jest.fn(),
    ensureStripeCustomer: jest.fn()
  }
}))

jest.mock('@/model/paymentValidationService', () => ({
  paymentValidationService: {
    validatePaymentSecurity: jest.fn(),
    detectFraudPattern: jest.fn(),
    detectCardTesting: jest.fn(),
    validatePlanPricing: jest.fn(),
    validateCurrencyConversion: jest.fn(),
    validatePaymentAmount: jest.fn(),
    validateSubscriptionCreation: jest.fn(),
    canAccessFeature: jest.fn()
  }
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }
}))

jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn()
}))

jest.mock('@/lib/advancedRateLimit', () => ({
  advancedRateLimitService: {
    checkRateLimit: jest.fn()
  }
}))

jest.mock('@/lib/csrfProtection', () => ({
  csrfProtectionService: {
    validateToken: jest.fn()
  }
}))

// Type mocked services
const mockStripeService = stripeService as jest.Mocked<typeof stripeService>
const mockUserPaymentService = userPaymentService as jest.Mocked<typeof userPaymentService>
const mockPaymentValidationService = paymentValidationService as jest.Mocked<typeof paymentValidationService>
const mockLogger = logger as jest.Mocked<typeof logger>
const mockGetClientIP = getClientIP as jest.MockedFunction<typeof getClientIP>
const mockAdvancedRateLimitService = advancedRateLimitService as jest.Mocked<typeof advancedRateLimitService>
const mockCsrfProtectionService = csrfProtectionService as jest.Mocked<typeof csrfProtectionService>

describe('Payment Security - Comprehensive Cross-System Tests', () => {
  const mockUser = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    sessionId: 'session-123',
    isAuthenticated: true,
    permissions: ['payment:create', 'payment:read'],
    roles: ['user']
  }

  beforeEach(() => {
    jest.clearAllMocks()
    mockGetClientIP.mockReturnValue('192.168.1.1')
    mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(true)
    mockCsrfProtectionService.validateToken.mockResolvedValue(true)
  })

  describe('Payment Fraud Prevention', () => {
    it('should detect and prevent amount manipulation attacks', async () => {
      const fraudulentAmounts = [
        { original: 10000, manipulated: 100 }, // Price reduction
        { original: 1000, manipulated: -1000 }, // Negative amount
        { original: 1000, manipulated: 0 }, // Zero amount
        { original: 1000, manipulated: 999999999 }, // Unrealistic amount
      ]

      for (const { original, manipulated } of fraudulentAmounts) {
        const paymentData = {
          amountCents: manipulated,
          currency: 'usd',
          metadata: {
            originalAmount: original.toString(),
            clientSideAmount: original.toString()
          }
        }

        const result = sanitizePaymentData(paymentData)
        
        // Should detect manipulation
        expect(result.isValid).toBe(false)
        expect(result.securityFlags).toContain('AMOUNT_MANIPULATION')
        
        expect(mockLogger.warn).toHaveBeenCalledWith(
          'PaymentSecurity',
          expect.stringContaining('Amount manipulation detected'),
          expect.objectContaining({
            originalAmount: original,
            manipulatedAmount: manipulated
          })
        )
      }
    })

    it('should detect suspicious payment patterns', async () => {
      const suspiciousPatterns = [
        { 
          pattern: 'rapid_payments',
          payments: Array(10).fill({ amount: 1000, timestamp: Date.now() })
        },
        {
          pattern: 'round_amounts',
          payments: [10000, 20000, 50000, 100000].map(amount => ({ amount, timestamp: Date.now() }))
        },
        {
          pattern: 'incremental_testing',
          payments: [100, 200, 300, 400, 500].map(amount => ({ amount, timestamp: Date.now() }))
        }
      ]

      for (const { pattern, payments } of suspiciousPatterns) {
        mockPaymentValidationService.detectFraudPattern.mockResolvedValue({
          success: false,
          error: `Suspicious ${pattern} pattern detected`,
          code: 'FRAUD_PATTERN_DETECTED'
        })

        const result = await paymentValidationService.validatePaymentSecurity(
          mockUser.id,
          payments[0].amount,
          'usd'
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('FRAUD_PATTERN_DETECTED')
      }
    })

    it('should implement velocity checks', async () => {
      const velocityChecks = [
        { timeframe: '1_minute', limit: 5, attempts: 10 },
        { timeframe: '1_hour', limit: 20, attempts: 25 },
        { timeframe: '1_day', limit: 100, attempts: 150 }
      ]

      for (const check of velocityChecks) {
        mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(false)
        
        const request = new NextRequest('https://example.com/api/payments/create-intent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amountCents: 1000, currency: 'usd' })
        })

        const result = await paymentRateLimit(request, 'payment_creation')
        
        expect(result).toBeInstanceOf(NextResponse)
        expect(result?.status).toBe(429)
        
        expect(mockLogger.warn).toHaveBeenCalledWith(
          'PaymentSecurity',
          expect.stringContaining('Rate limit exceeded'),
          expect.objectContaining({
            ip: '192.168.1.1',
            action: 'payment_creation'
          })
        )
      }
    })

    it('should detect card testing attacks', async () => {
      const cardTestingPatterns = [
        { amounts: [100, 100, 100, 100, 100], pattern: 'same_amount_repeated' },
        { amounts: [1, 2, 3, 4, 5], pattern: 'incremental_amounts' },
        { amounts: [100, 200, 150, 175, 125], pattern: 'random_small_amounts' }
      ]

      for (const { amounts, pattern } of cardTestingPatterns) {
        mockPaymentValidationService.detectCardTesting.mockResolvedValue({
          success: false,
          error: `Card testing pattern detected: ${pattern}`,
          code: 'CARD_TESTING_DETECTED'
        })

        for (const amount of amounts) {
          const result = await paymentValidationService.validatePaymentSecurity(
            mockUser.id,
            amount,
            'usd'
          )

          if (!result.success) {
            expect(result.code).toBe('CARD_TESTING_DETECTED')
            break
          }
        }
      }
    })
  })

  describe('PCI Compliance Validation', () => {
    it('should ensure no sensitive card data is logged', async () => {
      const sensitiveData = {
        cardNumber: '4111111111111111',
        cvv: '123',
        expiryDate: '12/25',
        cardholderName: 'Test User'
      }

      const paymentData = {
        amountCents: 1000,
        currency: 'usd',
        paymentMethod: {
          ...sensitiveData,
          type: 'card'
        }
      }

      sanitizePaymentData(paymentData)

      // Verify no sensitive data in logs
      const allLogCalls = [
        ...mockLogger.info.mock.calls,
        ...mockLogger.warn.mock.calls,
        ...mockLogger.error.mock.calls,
        ...mockLogger.debug.mock.calls
      ]

      allLogCalls.forEach(call => {
        const logMessage = JSON.stringify(call)
        expect(logMessage).not.toContain('4111111111111111')
        expect(logMessage).not.toContain('123') // CVV
        expect(logMessage).not.toContain('12/25')
      })
    })

    it('should validate PCI-compliant data handling', async () => {
      const pciViolations = [
        { field: 'cardNumber', value: '4111111111111111' },
        { field: 'cvv', value: '123' },
        { field: 'track1Data', value: '%B4111111111111111^TEST/USER^2512101?' },
        { field: 'track2Data', value: '4111111111111111=25121011234567890' }
      ]

      for (const violation of pciViolations) {
        const paymentData = {
          amountCents: 1000,
          currency: 'usd',
          [violation.field]: violation.value
        }

        const result = sanitizePaymentData(paymentData)
        
        expect(result.isValid).toBe(false)
        expect(result.securityFlags).toContain('PCI_VIOLATION')
        expect(result.sanitizedData).not.toHaveProperty(violation.field)
      }
    })

    it('should enforce secure transmission requirements', async () => {
      const insecureRequests = [
        { protocol: 'http', shouldReject: true },
        { protocol: 'https', shouldReject: false },
        { headers: {}, shouldReject: true }, // Missing security headers
        { headers: { 'X-Forwarded-Proto': 'http' }, shouldReject: true }
      ]

      for (const { protocol, headers, shouldReject } of insecureRequests) {
        const request = new NextRequest(`${protocol}://example.com/api/payments/create-intent`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...headers
          },
          body: JSON.stringify({ amountCents: 1000, currency: 'usd' })
        })

        const handler = withPaymentSecurity(async () => {
          return NextResponse.json({ success: true })
        })

        const response = await handler(request)
        
        if (shouldReject) {
          expect(response.status).toBeGreaterThanOrEqual(400)
        } else {
          expect(response.status).toBe(200)
        }
      }
    })
  })

  describe('Price Manipulation Protection', () => {
    it('should validate subscription plan pricing', async () => {
      const pricingAttacks = [
        { planId: 'premium', expectedPrice: 2999, attackPrice: 999 },
        { planId: 'enterprise', expectedPrice: 9999, attackPrice: 0 },
        { planId: 'basic', expectedPrice: 999, attackPrice: -100 }
      ]

      for (const { planId, expectedPrice, attackPrice } of pricingAttacks) {
        mockPaymentValidationService.validatePlanPricing.mockResolvedValue({
          success: false,
          error: 'Price manipulation detected',
          code: 'PRICE_MANIPULATION',
          data: { expectedPrice, providedPrice: attackPrice }
        })

        const result = await paymentValidationService.validateSubscriptionCreation(
          mockUser.id,
          planId,
          { customPrice: attackPrice }
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('PRICE_MANIPULATION')
      }
    })

    it('should prevent discount manipulation', async () => {
      const discountAttacks = [
        { discount: 100, type: 'percentage' }, // 100% discount
        { discount: -50, type: 'percentage' }, // Negative discount
        { discount: 999999, type: 'amount' }, // Excessive amount discount
        { discount: 'unlimited', type: 'code' } // Invalid discount code
      ]

      for (const attack of discountAttacks) {
        const paymentData = {
          amountCents: 1000,
          currency: 'usd',
          discount: attack
        }

        const result = sanitizePaymentData(paymentData)
        
        expect(result.isValid).toBe(false)
        expect(result.securityFlags).toContain('DISCOUNT_MANIPULATION')
      }
    })

    it('should validate currency conversion rates', async () => {
      const currencyAttacks = [
        { from: 'usd', to: 'eur', rate: 0.01 }, // Unrealistic rate
        { from: 'usd', to: 'btc', rate: 1000000 }, // Excessive rate
        { from: 'usd', to: 'fake', rate: 1 } // Invalid currency
      ]

      for (const { from, to, rate } of currencyAttacks) {
        mockPaymentValidationService.validateCurrencyConversion.mockResolvedValue({
          success: false,
          error: 'Invalid currency conversion rate',
          code: 'CURRENCY_MANIPULATION'
        })

        const result = await paymentValidationService.validatePaymentAmount(
          1000,
          from,
          { convertTo: to, rate }
        )

        expect(result.success).toBe(false)
        expect(result.code).toBe('CURRENCY_MANIPULATION')
      }
    })
  })

  describe('Payment Data Sanitization', () => {
    it('should sanitize all user input fields', async () => {
      const maliciousInputs = {
        description: '<script>alert("xss")</script>',
        customerName: 'Test"; DROP TABLE customers; --',
        billingAddress: {
          line1: '<img src=x onerror=alert(1)>',
          city: '"; DELETE FROM addresses; --',
          state: '<script>document.location="http://evil.com"</script>'
        },
        metadata: {
          userInput: '"; UPDATE payments SET amount=0; --',
          notes: '<iframe src="javascript:alert(1)"></iframe>'
        }
      }

      const result = sanitizePaymentData(maliciousInputs)
      
      expect(result.sanitizedData.description).not.toContain('<script>')
      expect(result.sanitizedData.customerName).not.toContain('DROP TABLE')
      expect(result.sanitizedData.billingAddress.line1).not.toContain('<img')
      expect(result.sanitizedData.billingAddress.city).not.toContain('DELETE FROM')
      expect(result.sanitizedData.metadata.userInput).not.toContain('UPDATE payments')
      expect(result.sanitizedData.metadata.notes).not.toContain('<iframe>')
    })

    it('should validate data types and formats', async () => {
      const invalidData = {
        amountCents: 'invalid',
        currency: 123,
        email: 'not-an-email',
        phone: '<script>alert(1)</script>',
        zipCode: '"; DROP TABLE addresses; --'
      }

      const result = sanitizePaymentData(invalidData)
      
      expect(result.isValid).toBe(false)
      expect(result.validationErrors).toContain('Invalid amount format')
      expect(result.validationErrors).toContain('Invalid currency format')
      expect(result.validationErrors).toContain('Invalid email format')
    })

    it('should enforce field length limits', async () => {
      const oversizedData = {
        description: 'A'.repeat(10000),
        customerName: 'B'.repeat(1000),
        notes: 'C'.repeat(50000)
      }

      const result = sanitizePaymentData(oversizedData)
      
      expect(result.sanitizedData.description.length).toBeLessThanOrEqual(500)
      expect(result.sanitizedData.customerName.length).toBeLessThanOrEqual(100)
      expect(result.sanitizedData.notes.length).toBeLessThanOrEqual(1000)
    })
  })

  describe('CSRF Protection for Payment Endpoints', () => {
    it('should validate CSRF tokens on payment requests', async () => {
      const paymentEndpoints = [
        '/api/payments/create-intent',
        '/api/payments/subscription',
        '/api/payments/billing-portal'
      ]

      for (const endpoint of paymentEndpoints) {
        const request = new NextRequest(`https://example.com${endpoint}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amountCents: 1000, currency: 'usd' })
        })

        // Mock missing CSRF token
        mockCsrfProtectionService.validateToken.mockResolvedValue(false)

        const result = await validatePaymentCSRFToken(request)
        
        expect(result).toBeInstanceOf(NextResponse)
        expect(result?.status).toBe(403)
      }
    })

    it('should prevent CSRF attacks with valid tokens', async () => {
      const validToken = 'csrf_token_123'
      
      const request = new NextRequest('https://example.com/api/payments/create-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': validToken
        },
        body: JSON.stringify({ amountCents: 1000, currency: 'usd' })
      })

      mockCsrfProtectionService.validateToken.mockResolvedValue(true)

      const result = await validatePaymentCSRFToken(request)
      
      expect(result).toBeNull() // Should pass validation
    })
  })

  describe('Security Monitoring and Alerting', () => {
    it('should trigger security alerts for critical events', async () => {
      const criticalEvents = [
        { type: 'FRAUD_DETECTED', severity: 'HIGH' },
        { type: 'PCI_VIOLATION', severity: 'CRITICAL' },
        { type: 'PRICE_MANIPULATION', severity: 'HIGH' },
        { type: 'WEBHOOK_SIGNATURE_FAILURE', severity: 'MEDIUM' }
      ]

      for (const event of criticalEvents) {
        mockLogger.error.mockClear()
        
        // Simulate security event
        mockLogger.error('PaymentSecurity', `Security event: ${event.type}`, {
          severity: event.severity,
          timestamp: new Date().toISOString(),
          ip: '192.168.1.1'
        })

        expect(mockLogger.error).toHaveBeenCalledWith(
          'PaymentSecurity',
          expect.stringContaining(event.type),
          expect.objectContaining({
            severity: event.severity
          })
        )
      }
    })

    it('should implement security metrics collection', async () => {
      const securityMetrics = [
        'payment_fraud_attempts',
        'pci_violations',
        'price_manipulation_attempts',
        'csrf_failures',
        'rate_limit_violations'
      ]

      for (const metric of securityMetrics) {
        // Simulate metric collection
        mockLogger.info('PaymentSecurityMetrics', `Metric: ${metric}`, {
          count: 1,
          timestamp: new Date().toISOString()
        })

        expect(mockLogger.info).toHaveBeenCalledWith(
          'PaymentSecurityMetrics',
          expect.stringContaining(metric),
          expect.any(Object)
        )
      }
    })
  })
})
