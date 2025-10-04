/**
 * Payment Mock Setup
 * Centralized mock configuration for all payment-related tests
 */

import { jest } from '@jest/globals'

// Mock configuration object
export const mockConfig = {
  payments: {
    stripeSecretKey: 'sk_test_mock_key',
    stripePublishableKey: 'pk_test_mock_key',
    stripeWebhookSecret: 'whsec_test_mock_secret'
  },
  app: {
    url: 'https://test.example.com'
  }
}

// Mock Stripe Service
export const mockStripeService = {
  createCustomer: jest.fn(),
  getCustomer: jest.fn(),
  updateCustomer: jest.fn(),
  createPaymentIntent: jest.fn(),
  getPaymentIntent: jest.fn(),
  confirmPaymentIntent: jest.fn(),
  createSubscription: jest.fn(),
  getSubscription: jest.fn(),
  updateSubscription: jest.fn(),
  cancelSubscription: jest.fn(),
  createBillingPortalSession: jest.fn(),
  verifyWebhookSignature: jest.fn(),
  processWebhookEvent: jest.fn(),
  refundPayment: jest.fn(),
  listPaymentMethods: jest.fn(),
  attachPaymentMethod: jest.fn(),
  detachPaymentMethod: jest.fn()
}

// Mock User Payment Service
export const mockUserPaymentService = {
  ensureStripeCustomer: jest.fn(),
  getUserPaymentProfile: jest.fn(),
  updateUserPaymentProfile: jest.fn(),
  createSubscription: jest.fn(),
  cancelSubscription: jest.fn(),
  recordPaymentSuccess: jest.fn(),
  recordPaymentFailure: jest.fn(),
  recordUsage: jest.fn(),
  getPaymentHistory: jest.fn(),
  setDefaultPaymentMethod: jest.fn(),
  validateSubscriptionAccess: jest.fn()
}

// Mock Payment Validation Service
export const mockPaymentValidationService = {
  validatePaymentData: jest.fn(),
  validateSubscriptionStatus: jest.fn(),
  validatePaymentSecurity: jest.fn(),
  detectFraudPattern: jest.fn(),
  detectCardTesting: jest.fn(),
  validatePlanPricing: jest.fn(),
  validateCurrencyConversion: jest.fn(),
  sanitizePaymentInput: jest.fn(),
  validatePaymentAmount: jest.fn(),
  validateCurrency: jest.fn(),
  isValidEmail: jest.fn()
}

// Mock Advanced Rate Limit Service
export const mockAdvancedRateLimitService = {
  checkRateLimit: jest.fn(),
  recordRequest: jest.fn(),
  getRemainingRequests: jest.fn(),
  resetRateLimit: jest.fn()
}

// Mock CSRF Protection Service
export const mockCsrfProtectionService = {
  generateToken: jest.fn(),
  validateToken: jest.fn(),
  validateFormSubmission: jest.fn(),
  getTokenFromRequest: jest.fn()
}

// Mock Logger
export const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn()
}

// Mock Auth
export const mockAuth = {
  authenticateUser: jest.fn(),
  getCurrentUser: jest.fn(),
  validateSession: jest.fn()
}

// Mock Security
export const mockSecurity = {
  getClientIP: jest.fn(),
  validateOrigin: jest.fn(),
  sanitizeInput: jest.fn()
}

// Setup all mocks
export const setupPaymentMocks = () => {
  // Mock config
  jest.doMock('@/lib/config', () => ({
    getConfig: jest.fn(() => mockConfig)
  }))

  // Mock Stripe service
  jest.doMock('@/model/stripeService', () => ({
    stripeService: mockStripeService,
    StripeService: jest.fn(() => mockStripeService)
  }))

  // Mock user payment service
  jest.doMock('@/model/userPaymentService', () => ({
    userPaymentService: mockUserPaymentService,
    UserPaymentService: jest.fn(() => mockUserPaymentService)
  }))

  // Mock payment validation service
  jest.doMock('@/model/paymentValidationService', () => ({
    paymentValidationService: mockPaymentValidationService,
    PaymentValidationService: jest.fn(() => mockPaymentValidationService)
  }))

  // Mock advanced rate limit service
  jest.doMock('@/lib/advancedRateLimit', () => ({
    advancedRateLimitService: mockAdvancedRateLimitService
  }))

  // Mock CSRF protection service
  jest.doMock('@/lib/csrfProtection', () => ({
    csrfProtectionService: mockCsrfProtectionService
  }))

  // Mock logger
  jest.doMock('@/utils/logger', () => ({
    logger: mockLogger
  }))

  // Mock auth
  jest.doMock('@/utils/auth', () => mockAuth)

  // Mock security
  jest.doMock('@/lib/security', () => mockSecurity)

  // Mock Next.js
  jest.doMock('next/server', () => ({
    NextRequest: jest.fn(),
    NextResponse: {
      json: jest.fn((data, init) => ({
        json: jest.fn(() => Promise.resolve(data)),
        status: init?.status || 200,
        headers: new Map()
      })),
      redirect: jest.fn((url, status) => ({
        status: status || 302,
        headers: new Map([['Location', url]])
      }))
    }
  }))
}

// Reset all mocks
export const resetPaymentMocks = () => {
  Object.values(mockStripeService).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
  
  Object.values(mockUserPaymentService).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
  
  Object.values(mockPaymentValidationService).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
  
  Object.values(mockAdvancedRateLimitService).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
  
  Object.values(mockCsrfProtectionService).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
  
  Object.values(mockLogger).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
  
  Object.values(mockAuth).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
  
  Object.values(mockSecurity).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset()
    }
  })
}

// Configure default mock behaviors
export const configureDefaultMockBehaviors = () => {
  // Stripe service defaults
  mockStripeService.createCustomer.mockResolvedValue({ id: 'cus_test123', email: 'test@example.com' })
  mockStripeService.createPaymentIntent.mockResolvedValue({ id: 'pi_test123', client_secret: 'pi_test123_secret' })
  mockStripeService.createSubscription.mockResolvedValue({ id: 'sub_test123', status: 'active' })
  mockStripeService.verifyWebhookSignature.mockReturnValue(true)
  
  // User payment service defaults
  mockUserPaymentService.ensureStripeCustomer.mockResolvedValue('cus_test123')
  mockUserPaymentService.getUserPaymentProfile.mockResolvedValue({
    userId: 'user-123',
    stripeCustomerId: 'cus_test123',
    subscriptionStatus: 'active'
  })
  
  // Payment validation service defaults
  mockPaymentValidationService.validatePaymentData.mockReturnValue({ success: true, data: true })
  mockPaymentValidationService.validateSubscriptionStatus.mockResolvedValue({ success: true, data: true })
  
  // Rate limit service defaults
  mockAdvancedRateLimitService.checkRateLimit.mockResolvedValue(true)
  
  // CSRF service defaults
  mockCsrfProtectionService.validateFormSubmission.mockReturnValue({ isValid: true })
  
  // Auth defaults
  mockAuth.authenticateUser.mockResolvedValue({ id: 'user-123', email: 'test@example.com' })
  
  // Security defaults
  mockSecurity.getClientIP.mockReturnValue('127.0.0.1')
}

// Export all mocks for easy access
export const allMocks = {
  stripeService: mockStripeService,
  userPaymentService: mockUserPaymentService,
  paymentValidationService: mockPaymentValidationService,
  advancedRateLimitService: mockAdvancedRateLimitService,
  csrfProtectionService: mockCsrfProtectionService,
  logger: mockLogger,
  auth: mockAuth,
  security: mockSecurity
}
