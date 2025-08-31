/**
 * Payment Security Middleware
 * Comprehensive security measures for payment processing including PCI compliance,
 * rate limiting, webhook validation, CSRF protection, and data sanitization
 */

import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { csrfProtectionService } from '@/lib/csrfProtection'

// Payment-specific rate limiting configuration
export interface PaymentRateLimitConfig {
  windowMs: number
  maxRequests: number
  skipSuccessfulRequests?: boolean
  skipFailedRequests?: boolean
}

// Default payment rate limits
const PAYMENT_RATE_LIMITS: Record<string, PaymentRateLimitConfig> = {
  payment: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
  webhook: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100,
    skipSuccessfulRequests: true,
    skipFailedRequests: false,
  },
  subscription: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 5,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
}

// Stripe webhook IPs (updated list)
const STRIPE_WEBHOOK_IPS = [
  '54.187.174.169',
  '54.187.205.235',
  '54.187.216.72',
  '54.241.31.99',
  '54.241.31.102',
  '54.241.34.107',
]

// Sensitive payment fields that should be sanitized
const SENSITIVE_PAYMENT_FIELDS = [
  'card_number',
  'cardNumber',
  'cvv',
  'cvc',
  'ssn',
  'social_security_number',
  'bank_account',
  'bankAccount',
  'routing_number',
  'routingNumber',
  'account_number',
  'accountNumber',
  'pin',
  'password',
]

/**
 * Payment rate limiting middleware
 */
export async function paymentRateLimit(
  request: NextRequest,
  limitType: keyof typeof PAYMENT_RATE_LIMITS = 'payment'
): Promise<NextResponse | null> {
  const ip = getClientIP(request)
  const config = PAYMENT_RATE_LIMITS[limitType]

  try {
    const isAllowed = await advancedRateLimitService.checkRateLimit(
      `payment_${limitType}`,
      ip,
      config.maxRequests,
      config.windowMs
    )

    if (!isAllowed) {
      logger.warn('PaymentSecurity', `Payment rate limit exceeded for ${limitType} from IP: ${ip}`)

      return NextResponse.json(
        {
          error: 'Too many payment requests, please try again later',
          retryAfter: Math.ceil(config.windowMs / 1000),
        },
        {
          status: 429,
          headers: {
            'Retry-After': String(Math.ceil(config.windowMs / 1000)),
            'X-RateLimit-Limit': String(config.maxRequests),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': String(Date.now() + config.windowMs),
          },
        }
      )
    }

    return null
  } catch (error) {
    logger.error('PaymentSecurity', 'Rate limit check failed', error)
    // Allow request to proceed on rate limit service failure
    return null
  }
}

/**
 * Validate webhook signature using HMAC-SHA256
 */
export function validateWebhookSignature(
  payload: string,
  signature: string,
  secret: string
): boolean {
  try {
    if (!payload || !signature || !secret) {
      logger.warn('PaymentSecurity', 'Missing required parameters for webhook signature validation')
      return false
    }

    // Remove 'v1=' prefix if present (Stripe format)
    const cleanSignature = signature.replace(/^v1=/, '')

    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload, 'utf8')
      .digest('hex')

    // Use timing-safe comparison to prevent timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(cleanSignature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    )
  } catch (error) {
    logger.error('PaymentSecurity', 'Webhook signature validation failed', error)
    return false
  }
}

/**
 * Sanitize payment data by removing sensitive fields
 */
export function sanitizePaymentData(data: any): any {
  if (!data || typeof data !== 'object') {
    return data
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizePaymentData(item))
  }

  const sanitized = { ...data }

  // Remove sensitive fields
  SENSITIVE_PAYMENT_FIELDS.forEach(field => {
    if (sanitized[field]) {
      delete sanitized[field]
    }
  })

  // Recursively sanitize nested objects
  Object.keys(sanitized).forEach(key => {
    if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizePaymentData(sanitized[key])
    }
  })

  return sanitized
}

/**
 * Validate CSRF token for payment forms
 */
export function validatePaymentCSRFToken(request: NextRequest): boolean {
  try {
    const sessionId = request.cookies.get('session-id')?.value

    if (!sessionId) {
      logger.warn('PaymentSecurity', 'No session ID found for CSRF validation')
      return false
    }

    const result = csrfProtectionService.validateFormSubmission(request, sessionId)

    if (!result.isValid) {
      logger.warn('PaymentSecurity', `CSRF validation failed: ${result.error}`)
      return false
    }

    return true
  } catch (error) {
    logger.error('PaymentSecurity', 'CSRF token validation failed', error)
    return false
  }
}

/**
 * Validate webhook IP address against Stripe's known IPs
 */
export function validateWebhookIP(request: NextRequest): boolean {
  try {
    const clientIP = getClientIP(request)

    if (!clientIP) {
      logger.warn('PaymentSecurity', 'No client IP found for webhook validation')
      return false
    }

    // Check if IP is in the allowed list
    const isAllowed = STRIPE_WEBHOOK_IPS.includes(clientIP)

    if (!isAllowed) {
      logger.warn('PaymentSecurity', `Webhook request from unauthorized IP: ${clientIP}`)
    }

    return isAllowed
  } catch (error) {
    logger.error('PaymentSecurity', 'Webhook IP validation failed', error)
    return false
  }
}

/**
 * Comprehensive payment security middleware wrapper
 */
export function withPaymentSecurity(
  handler: (request: NextRequest) => Promise<NextResponse>,
  options: {
    requireCSRF?: boolean
    rateLimitType?: keyof typeof PAYMENT_RATE_LIMITS
    validateWebhook?: boolean
    sanitizeRequest?: boolean
    sanitizeResponse?: boolean
  } = {}
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const {
      requireCSRF = true,
      rateLimitType = 'payment',
      validateWebhook = false,
      sanitizeRequest = true,
      sanitizeResponse = true,
    } = options

    const ip = getClientIP(request)
    const pathname = request.nextUrl.pathname
    const method = request.method

    try {
      // Apply rate limiting
      const rateLimitResponse = await paymentRateLimit(request, rateLimitType)
      if (rateLimitResponse) {
        return rateLimitResponse
      }

      // Validate webhook IP if required
      if (validateWebhook && !validateWebhookIP(request)) {
        return NextResponse.json({ error: 'Unauthorized webhook source' }, { status: 403 })
      }

      // Validate CSRF token for state-changing requests
      if (requireCSRF && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        if (!validatePaymentCSRFToken(request)) {
          return NextResponse.json({ error: 'Invalid CSRF token' }, { status: 403 })
        }
      }

      // Sanitize request data if required
      if (sanitizeRequest && request.body) {
        try {
          const body = await request.json()
          const sanitizedBody = sanitizePaymentData(body)

          // Create new request with sanitized body
          const sanitizedRequest = new NextRequest(request.url, {
            method: request.method,
            headers: request.headers,
            body: JSON.stringify(sanitizedBody),
          })

          request = sanitizedRequest
        } catch (error) {
          // If body parsing fails, continue with original request
          logger.debug('PaymentSecurity', 'Could not parse request body for sanitization')
        }
      }

      // Execute the handler
      const response = await handler(request)

      // Sanitize response data if required
      if (sanitizeResponse) {
        try {
          const responseData = await response.json()
          const sanitizedData = sanitizePaymentData(responseData)

          return NextResponse.json(sanitizedData, {
            status: response.status,
            headers: response.headers,
          })
        } catch (error) {
          // If response parsing fails, return original response
          return response
        }
      }

      return response
    } catch (error) {
      logger.error('PaymentSecurity', `Payment security middleware error for ${pathname}`, error)

      return NextResponse.json({ error: 'Payment processing error' }, { status: 500 })
    }
  }
}

/**
 * Specific middleware for Stripe webhooks
 */
export function withStripeWebhookSecurity(
  handler: (request: NextRequest) => Promise<NextResponse>,
  webhookSecret: string
) {
  return withPaymentSecurity(
    async (request: NextRequest) => {
      // Validate webhook signature
      const signature = request.headers.get('stripe-signature')
      const payload = await request.text()

      if (!signature || !validateWebhookSignature(payload, signature, webhookSecret)) {
        logger.warn('PaymentSecurity', 'Invalid Stripe webhook signature')
        return NextResponse.json({ error: 'Invalid webhook signature' }, { status: 401 })
      }

      // Create new request with the payload for the handler
      const webhookRequest = new NextRequest(request.url, {
        method: request.method,
        headers: request.headers,
        body: payload,
      })

      return handler(webhookRequest)
    },
    {
      requireCSRF: false,
      rateLimitType: 'webhook',
      validateWebhook: true,
      sanitizeRequest: false,
      sanitizeResponse: false,
    }
  )
}
