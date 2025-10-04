/**
 * Payment Testing Utilities
 * Comprehensive utilities for payment testing including mocks, fixtures, and helpers
 */

import { NextRequest } from 'next/server'
import Stripe from 'stripe'

// Mock Stripe objects
export const createMockStripeCustomer = (overrides: Partial<Stripe.Customer> = {}): Stripe.Customer => ({
  id: 'cus_test123',
  object: 'customer',
  created: Date.now() / 1000,
  email: 'test@example.com',
  livemode: false,
  metadata: {},
  ...overrides
} as Stripe.Customer)

export const createMockStripePaymentIntent = (overrides: Partial<Stripe.PaymentIntent> = {}): Stripe.PaymentIntent => ({
  id: 'pi_test123',
  object: 'payment_intent',
  amount: 2000,
  currency: 'usd',
  status: 'requires_payment_method',
  created: Date.now() / 1000,
  livemode: false,
  metadata: {},
  client_secret: 'pi_test123_secret_test',
  ...overrides
} as Stripe.PaymentIntent)

export const createMockStripeSubscription = (overrides: Partial<Stripe.Subscription> = {}): Stripe.Subscription => ({
  id: 'sub_test123',
  object: 'subscription',
  created: Date.now() / 1000,
  current_period_start: Date.now() / 1000,
  current_period_end: (Date.now() / 1000) + (30 * 24 * 60 * 60),
  customer: 'cus_test123',
  status: 'active',
  items: {
    object: 'list',
    data: [{
      id: 'si_test123',
      object: 'subscription_item',
      created: Date.now() / 1000,
      metadata: {},
      price: {
        id: 'price_test123',
        object: 'price',
        active: true,
        currency: 'usd',
        unit_amount: 2900,
        recurring: { interval: 'month' },
        created: Date.now() / 1000,
        livemode: false,
        metadata: {},
        nickname: null,
        product: 'prod_test123',
        type: 'recurring'
      } as Stripe.Price,
      quantity: 1,
      subscription: 'sub_test123'
    } as Stripe.SubscriptionItem]
  },
  livemode: false,
  metadata: {},
  ...overrides
} as Stripe.Subscription)

export const createMockWebhookEvent = (type: string, data: any = {}): Stripe.Event => ({
  id: 'evt_test123',
  object: 'event',
  api_version: '2024-06-20',
  created: Date.now() / 1000,
  data: {
    object: data,
    previous_attributes: {}
  },
  livemode: false,
  pending_webhooks: 1,
  request: {
    id: 'req_test123',
    idempotency_key: null
  },
  type: type as Stripe.Event.Type
} as Stripe.Event)

// Request builders
export const createPaymentRequest = (body: any = {}, headers: Record<string, string> = {}): NextRequest => {
  return new NextRequest('https://example.com/api/payments/create-intent', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token',
      ...headers
    },
    body: JSON.stringify(body)
  })
}

export const createWebhookRequest = (
  payload: string, 
  signature: string = 'test-signature',
  headers: Record<string, string> = {}
): NextRequest => {
  return new NextRequest('https://example.com/api/webhooks/stripe', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'stripe-signature': signature,
      ...headers
    },
    body: payload
  })
}

export const createBillingPortalRequest = (body: any = {}, headers: Record<string, string> = {}): NextRequest => {
  return new NextRequest('https://example.com/api/payments/billing-portal', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token',
      ...headers
    },
    body: JSON.stringify(body)
  })
}

export const createHistoryRequest = (params: Record<string, string> = {}, headers: Record<string, string> = {}): NextRequest => {
  const url = new URL('https://example.com/api/payments/history')
  Object.entries(params).forEach(([key, value]) => {
    url.searchParams.set(key, value)
  })
  
  return new NextRequest(url.toString(), {
    method: 'GET',
    headers: {
      'Authorization': 'Bearer test-token',
      ...headers
    }
  })
}

export const createSubscriptionRequest = (body: any = {}, headers: Record<string, string> = {}): NextRequest => {
  return new NextRequest('https://example.com/api/payments/subscription', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token',
      ...headers
    },
    body: JSON.stringify(body)
  })
}

// Mock service responses
export const mockServiceResponse = <T>(data: T, success: boolean = true) => ({
  success,
  data: success ? data : undefined,
  error: success ? undefined : 'Mock error',
  code: success ? undefined : 'MOCK_ERROR'
})

// Test data fixtures
export const paymentTestData = {
  validPaymentIntent: {
    amount: 2000,
    currency: 'usd',
    description: 'Test payment'
  },
  invalidPaymentIntent: {
    amount: -100,
    currency: 'invalid',
    description: '<script>alert("xss")</script>'
  },
  validSubscription: {
    priceId: 'price_test123',
    customerId: 'cus_test123'
  },
  maliciousPaymentData: {
    amount: 999999999,
    currency: 'usd',
    description: '<script>alert("xss")</script>',
    metadata: {
      userId: 'DROP TABLE users;',
      source: '<img src=x onerror=alert(1)>'
    }
  },
  validUser: {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User'
  },
  validCustomer: {
    id: 'cus_test123',
    email: 'test@example.com',
    name: 'Test Customer'
  }
}

// Security test helpers
export const createSecurityTestScenarios = () => ({
  sqlInjection: [
    "'; DROP TABLE users; --",
    "1' OR '1'='1",
    "admin'--",
    "' UNION SELECT * FROM users --"
  ],
  xssPayloads: [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<svg onload=alert(1)>'
  ],
  oversizedInputs: {
    description: 'A'.repeat(10000),
    customerName: 'B'.repeat(1000),
    notes: 'C'.repeat(50000)
  },
  invalidAmounts: [
    -100,
    0,
    999999999,
    'invalid',
    null,
    undefined
  ],
  invalidCurrencies: [
    'INVALID',
    'xxx',
    '',
    null,
    undefined,
    123
  ]
})

// Rate limiting test helpers
export const createRateLimitTestRequests = (count: number, endpoint: string = '/api/payments/create-intent') => {
  return Array.from({ length: count }, (_, i) => 
    createPaymentRequest({ amount: 1000 + i, currency: 'usd' })
  )
}

// Webhook signature helpers
export const createValidWebhookSignature = (payload: string, secret: string = 'test-secret'): string => {
  // Mock signature - in real tests this would use actual Stripe signature generation
  return `t=${Date.now()},v1=test-signature-${payload.length}`
}

export const createInvalidWebhookSignature = (): string => {
  return 'invalid-signature'
}

// Error simulation helpers
export const simulateStripeError = (type: 'card_error' | 'invalid_request_error' | 'api_error' = 'card_error') => {
  const error = new Error('Stripe error') as any
  error.type = type
  error.code = 'card_declined'
  error.decline_code = 'generic_decline'
  return error
}

export const simulateNetworkError = () => {
  const error = new Error('Network error') as any
  error.code = 'ECONNREFUSED'
  return error
}

// Cleanup helpers
export const cleanupMocks = () => {
  jest.clearAllMocks()
}

export const resetMockTimers = () => {
  jest.clearAllTimers()
  jest.useRealTimers()
}
