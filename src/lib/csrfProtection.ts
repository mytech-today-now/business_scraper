/**
 * Enhanced CSRF Protection System
 * Implements comprehensive CSRF protection with token refresh, double-submit cookies,
 * and form integration
 */

import { NextRequest, NextResponse } from 'next/server'
import { getSession, generateSecureToken } from './security'
import { logger } from '@/utils/logger'
import { validateTemporaryCSRFToken } from '@/app/api/csrf/route'

// Edge Runtime compatibility check
const isEdgeRuntime = (typeof globalThis !== 'undefined' && 'EdgeRuntime' in globalThis) ||
  (typeof process !== 'undefined' && process.env.NEXT_RUNTIME === 'edge')

// Web Crypto API compatibility
const webCrypto = globalThis.crypto

/**
 * Timing-safe string comparison for Edge Runtime with enhanced security
 */
function timingSafeEqual(a: string, b: string): boolean {
  // Prevent timing attacks by ensuring consistent execution time
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false
  }

  // Always perform comparison on fixed-length strings to prevent length-based timing attacks
  const maxLength = Math.max(a.length, b.length, 32) // Minimum 32 chars for consistent timing
  const paddedA = a.padEnd(maxLength, '\0')
  const paddedB = b.padEnd(maxLength, '\0')

  let result = 0
  // Always compare the full padded length to maintain constant time
  for (let i = 0; i < maxLength; i++) {
    result |= paddedA.charCodeAt(i) ^ paddedB.charCodeAt(i)
  }

  // Additional check to ensure original lengths match (prevents padding bypass)
  result |= a.length ^ b.length

  return result === 0
}

export interface CSRFTokenInfo {
  token: string
  expiresAt: number
  issuedAt: number
}

export interface CSRFValidationResult {
  isValid: boolean
  error?: string
  needsRefresh?: boolean
  securityViolation?: boolean
  originValidated?: boolean
}

/**
 * CSRF Protection Service
 */
export class CSRFProtectionService {
  private tokenStore = new Map<string, CSRFTokenInfo>()
  private temporaryTokens = new Map<string, CSRFTokenInfo>()
  private readonly tokenExpiry = 60 * 60 * 1000 // 1 hour
  private readonly refreshThreshold = 15 * 60 * 1000 // 15 minutes
  private readonly allowedOrigins: string[]
  private readonly maxTokensPerSession = 5 // Prevent token accumulation
  private readonly cleanupInterval = 5 * 60 * 1000 // 5 minutes

  constructor() {
    // Initialize allowed origins from environment variables
    this.allowedOrigins = [
      process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
      process.env.NEXT_PUBLIC_DOMAIN || 'localhost:3000',
      ...(process.env.CSRF_ALLOWED_ORIGINS?.split(',') || [])
    ].filter(Boolean)

    // Start periodic cleanup in non-edge environments
    if (!isEdgeRuntime) {
      this.startPeriodicCleanup()
    }
  }

  /**
   * Start periodic cleanup of expired tokens
   */
  private startPeriodicCleanup(): void {
    setInterval(() => {
      this.cleanupExpiredTokens()
    }, this.cleanupInterval)
  }

  /**
   * Securely store token with additional metadata
   */
  private secureStoreToken(sessionId: string, tokenInfo: CSRFTokenInfo): void {
    // Prevent token accumulation attacks
    if (this.tokenStore.size > 1000) {
      logger.warn('CSRF', 'Token store size limit reached, forcing cleanup')
      this.cleanupExpiredTokens()
    }

    // Store the token
    this.tokenStore.set(sessionId, tokenInfo)

    // Log for security monitoring
    logger.info('CSRF', `Stored CSRF token for session: ${sessionId}`, {
      expiresAt: tokenInfo.expiresAt,
      issuedAt: tokenInfo.issuedAt
    })
  }

  /**
   * Securely retrieve token with validation
   */
  private secureRetrieveToken(sessionId: string): CSRFTokenInfo | null {
    const tokenInfo = this.tokenStore.get(sessionId)

    if (!tokenInfo) {
      return null
    }

    // Check if token is expired
    if (Date.now() > tokenInfo.expiresAt) {
      this.tokenStore.delete(sessionId)
      logger.info('CSRF', `Removed expired token for session: ${sessionId}`)
      return null
    }

    return tokenInfo
  }

  /**
   * Validate origin and referer headers for CSRF protection
   */
  private validateOriginHeaders(request: NextRequest): { isValid: boolean; error?: string } {
    const origin = request.headers.get('origin')
    const referer = request.headers.get('referer')
    const host = request.headers.get('host')

    // For same-origin requests, origin might be null
    if (!origin && !referer) {
      // Allow requests without origin/referer only for GET requests or if explicitly configured
      if (request.method === 'GET') {
        return { isValid: true }
      }
      return {
        isValid: false,
        error: 'Missing origin and referer headers for state-changing request'
      }
    }

    // Validate origin header
    if (origin) {
      const isOriginAllowed = this.allowedOrigins.some(allowedOrigin => {
        try {
          const originUrl = new URL(origin)
          const allowedUrl = new URL(allowedOrigin.startsWith('http') ? allowedOrigin : `https://${allowedOrigin}`)
          return originUrl.origin === allowedUrl.origin
        } catch {
          return origin === allowedOrigin
        }
      })

      if (!isOriginAllowed) {
        logger.warn('CSRF', `Invalid origin header: ${origin}`)
        return {
          isValid: false,
          error: `Origin ${origin} not allowed`
        }
      }
    }

    // Validate referer header as fallback
    if (!origin && referer) {
      try {
        const refererUrl = new URL(referer)
        const isRefererAllowed = this.allowedOrigins.some(allowedOrigin => {
          try {
            const allowedUrl = new URL(allowedOrigin.startsWith('http') ? allowedOrigin : `https://${allowedOrigin}`)
            return refererUrl.origin === allowedUrl.origin
          } catch {
            return refererUrl.hostname === allowedOrigin
          }
        })

        if (!isRefererAllowed) {
          logger.warn('CSRF', `Invalid referer header: ${referer}`)
          return {
            isValid: false,
            error: `Referer ${referer} not allowed`
          }
        }
      } catch {
        return {
          isValid: false,
          error: 'Invalid referer header format'
        }
      }
    }

    return { isValid: true }
  }

  /**
   * Generate a new CSRF token for a session with enhanced security
   */
  generateCSRFToken(sessionId: string): CSRFTokenInfo {
    // Input validation
    if (!sessionId || typeof sessionId !== 'string') {
      throw new Error('Invalid session ID provided')
    }

    // Generate cryptographically secure token
    const token = generateSecureToken(32)
    const now = Date.now()

    const tokenInfo: CSRFTokenInfo = {
      token,
      expiresAt: now + this.tokenExpiry,
      issuedAt: now,
    }

    // Use secure storage method
    this.secureStoreToken(sessionId, tokenInfo)

    logger.info('CSRF', `Generated new CSRF token for session: ${sessionId}`)

    return tokenInfo
  }

  /**
   * Validate CSRF token with comprehensive checks including origin validation
   */
  validateCSRFToken(
    sessionId: string,
    providedToken: string,
    request?: NextRequest
  ): CSRFValidationResult {
    // Input validation to prevent timing attacks
    if (typeof sessionId !== 'string' || typeof providedToken !== 'string') {
      return {
        isValid: false,
        error: 'Invalid input parameters',
        securityViolation: true
      }
    }

    // Validate origin headers first if request is provided
    let originValidated = false
    if (request) {
      const originValidation = this.validateOriginHeaders(request)
      if (!originValidation.isValid) {
        logger.warn('CSRF', `Origin validation failed: ${originValidation.error}`)
        return {
          isValid: false,
          error: originValidation.error,
          securityViolation: true,
          originValidated: false
        }
      }
      originValidated = true
    }

    // Check if session exists
    const session = getSession(sessionId)
    if (!session || !session.isValid) {
      return {
        isValid: false,
        error: 'Invalid session',
        securityViolation: true
      }
    }

    // Get stored token info using secure retrieval
    const tokenInfo = this.secureRetrieveToken(sessionId)
    if (!tokenInfo) {
      return {
        isValid: false,
        error: 'No CSRF token found for session',
        needsRefresh: true
      }
    }

    // Check token expiry with secure timing
    const currentTime = Date.now()
    const isExpired = currentTime > tokenInfo.expiresAt
    if (isExpired) {
      this.tokenStore.delete(sessionId)
      return {
        isValid: false,
        error: 'CSRF token expired',
        needsRefresh: true,
        originValidated
      }
    }

    // Validate token using enhanced timing-safe comparison
    try {
      // Perform timing-safe comparison
      const isTokenValid = timingSafeEqual(tokenInfo.token, providedToken)

      // Double-submit cookie validation if request is provided
      let isCookieValid = true
      if (request) {
        const cookieToken = request.cookies.get('csrf-token')?.value
        if (cookieToken) {
          isCookieValid = timingSafeEqual(cookieToken, providedToken)
          if (!isCookieValid) {
            logger.warn('CSRF', `CSRF cookie mismatch for session: ${sessionId}`)
          }
        }
      }

      // Combine all validation results
      const isValid = isTokenValid && isCookieValid

      if (!isValid) {
        logger.warn('CSRF', `CSRF token validation failed for session: ${sessionId}`)
        return {
          isValid: false,
          error: 'Invalid CSRF token',
          securityViolation: true,
          originValidated
        }
      }

      // Check if token needs refresh (approaching expiry)
      const needsRefresh = tokenInfo.expiresAt - currentTime < this.refreshThreshold

      logger.info('CSRF', `CSRF token validated successfully for session: ${sessionId}`)
      return {
        isValid: true,
        needsRefresh,
        originValidated
      }
    } catch (error) {
      logger.error('CSRF', 'Error validating CSRF token', error)
      return {
        isValid: false,
        error: 'Token validation error',
        securityViolation: true,
        originValidated
      }
    }
  }

  /**
   * Validate temporary CSRF token for unauthenticated requests (e.g., login)
   */
  validateTemporaryCSRFToken(token: string, tokenId: string, request: NextRequest): CSRFValidationResult {
    const ip = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown'

    const validation = validateTemporaryCSRFToken(tokenId, token, ip)

    if (!validation.isValid) {
      logger.warn('CSRF', `Temporary CSRF token validation failed: ${validation.error}`)
      return {
        isValid: false,
        error: validation.error || 'Invalid temporary CSRF token',
        needsRefresh: true,
      }
    }

    logger.info('CSRF', `Temporary CSRF token validated successfully for IP: ${ip}`)
    return {
      isValid: true,
    }
  }

  /**
   * Refresh CSRF token if needed with secure retrieval
   */
  refreshTokenIfNeeded(sessionId: string): CSRFTokenInfo | null {
    const tokenInfo = this.secureRetrieveToken(sessionId)
    if (!tokenInfo) {
      return null
    }

    const needsRefresh = tokenInfo.expiresAt - Date.now() < this.refreshThreshold
    if (needsRefresh) {
      logger.info('CSRF', `Refreshing CSRF token for session: ${sessionId}`)
      return this.generateCSRFToken(sessionId)
    }

    return tokenInfo
  }

  /**
   * Rotate CSRF token on authentication events
   */
  rotateTokenOnAuthentication(sessionId: string): CSRFTokenInfo {
    // Invalidate old token
    this.invalidateCSRFToken(sessionId)

    // Generate new token
    const newToken = this.generateCSRFToken(sessionId)

    logger.info('CSRF', `Rotated CSRF token on authentication for session: ${sessionId}`)
    return newToken
  }

  /**
   * Force token rotation for security events
   */
  forceTokenRotation(sessionId: string, reason: string): CSRFTokenInfo {
    logger.warn('CSRF', `Forcing token rotation for session ${sessionId}: ${reason}`)

    // Invalidate old token
    this.invalidateCSRFToken(sessionId)

    // Generate new token with extended expiry for security
    const token = generateSecureToken(32)
    const now = Date.now()

    const tokenInfo: CSRFTokenInfo = {
      token,
      expiresAt: now + this.tokenExpiry,
      issuedAt: now,
    }

    this.tokenStore.set(sessionId, tokenInfo)

    return tokenInfo
  }

  /**
   * Get current CSRF token for a session with secure retrieval
   */
  getCSRFToken(sessionId: string): CSRFTokenInfo | null {
    return this.secureRetrieveToken(sessionId)
  }

  /**
   * Invalidate CSRF token for a session
   */
  invalidateCSRFToken(sessionId: string): void {
    this.tokenStore.delete(sessionId)
    logger.info('CSRF', `Invalidated CSRF token for session: ${sessionId}`)
  }

  /**
   * Clean up expired tokens
   */
  cleanupExpiredTokens(): void {
    const now = Date.now()
    let cleanedCount = 0

    for (const [sessionId, tokenInfo] of Array.from(this.tokenStore.entries())) {
      if (now > tokenInfo.expiresAt) {
        this.tokenStore.delete(sessionId)
        cleanedCount++
      }
    }

    if (cleanedCount > 0) {
      logger.info('CSRF', `Cleaned up ${cleanedCount} expired CSRF tokens`)
    }
  }

  /**
   * Add CSRF protection headers to response with enhanced security
   */
  addCSRFHeaders(response: NextResponse, sessionId: string): NextResponse {
    const tokenInfo = this.getCSRFToken(sessionId)
    if (tokenInfo) {
      // Calculate remaining time for cookie expiry
      const remainingTime = Math.max(0, Math.floor((tokenInfo.expiresAt - Date.now()) / 1000))

      if (remainingTime > 0) {
        // Set CSRF token as a secure cookie (double-submit pattern)
        response.cookies.set('csrf-token', tokenInfo.token, {
          httpOnly: false, // Needs to be accessible to JavaScript for AJAX requests
          secure: process.env.NODE_ENV === 'production', // HTTPS only in production
          sameSite: 'strict', // Strict SameSite policy for CSRF protection
          maxAge: remainingTime,
          path: '/', // Ensure cookie is available site-wide
          domain: process.env.NODE_ENV === 'production' ? process.env.COOKIE_DOMAIN : undefined
        })

        // Add CSRF token to response headers for AJAX requests
        response.headers.set('X-CSRF-Token', tokenInfo.token)
        response.headers.set('X-CSRF-Expires', String(tokenInfo.expiresAt))

        // Add security headers
        response.headers.set('X-Content-Type-Options', 'nosniff')
        response.headers.set('X-Frame-Options', 'DENY')
        response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
      } else {
        // Token expired, remove the cookie
        response.cookies.delete('csrf-token')
        logger.warn('CSRF', `Expired token not set in headers for session: ${sessionId}`)
      }
    }

    return response
  }

  /**
   * Generate CSRF token for forms (HTML meta tag format)
   */
  generateFormCSRFToken(sessionId: string): string {
    const tokenInfo = this.getCSRFToken(sessionId) || this.generateCSRFToken(sessionId)
    return tokenInfo.token
  }

  /**
   * Get current token count for monitoring
   */
  getTokenCount(): number {
    return this.tokenStore.size + this.temporaryTokens.size
  }

  /**
   * Validate form submission with CSRF protection
   */
  validateFormSubmission(request: NextRequest, sessionId: string): CSRFValidationResult {
    // Check for CSRF token in various locations
    const headerToken = request.headers.get('x-csrf-token')

    const csrfToken = headerToken

    // If it's a form submission, we might need to parse the body
    // For now, we'll rely on the header token
    if (!csrfToken) {
      return {
        isValid: false,
        error: 'CSRF token not provided',
      }
    }

    return this.validateCSRFToken(sessionId, csrfToken, request)
  }

  /**
   * Create CSRF-protected form HTML
   */
  createCSRFFormField(sessionId: string): string {
    const token = this.generateFormCSRFToken(sessionId)
    return `<input type="hidden" name="csrf_token" value="${token}" />`
  }

  /**
   * Get CSRF token for JavaScript usage
   */
  getTokenForJavaScript(sessionId: string): { token: string; expiresAt: number } | null {
    const tokenInfo = this.getCSRFToken(sessionId)
    if (!tokenInfo) {
      return null
    }

    return {
      token: tokenInfo.token,
      expiresAt: tokenInfo.expiresAt,
    }
  }
}

/**
 * Default CSRF protection service instance
 */
export const csrfProtectionService = new CSRFProtectionService()

// Note: Token cleanup is now handled by API routes instead of setInterval
// for Edge Runtime compatibility. See /api/cleanup/csrf-tokens route.

/**
 * Middleware helper for CSRF protection
 */
export function validateCSRFMiddleware(request: NextRequest): NextResponse | null {
  const pathname = request.nextUrl.pathname
  const method = request.method

  // Only check CSRF for state-changing requests to API endpoints
  if (!pathname.startsWith('/api/') || !['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    return null
  }

  // Skip CSRF for public routes
  const publicRoutes = ['/api/health', '/api/auth', '/api/csrf']
  if (publicRoutes.some(route => pathname.startsWith(route))) {
    return null
  }

  const sessionId = request.cookies.get('session-id')?.value
  const csrfToken = request.headers.get('x-csrf-token')

  if (!csrfToken) {
    return new NextResponse(JSON.stringify({ error: 'CSRF token required' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // Handle temporary CSRF tokens for login requests (when no session exists)
  if (!sessionId && pathname === '/api/auth' && method === 'POST') {
    const tokenId = request.headers.get('x-csrf-token-id')

    if (!tokenId) {
      return new NextResponse(JSON.stringify({ error: 'CSRF token ID required for login' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const validation = csrfProtectionService.validateTemporaryCSRFToken(csrfToken, tokenId, request)
    if (!validation.isValid) {
      return new NextResponse(
        JSON.stringify({
          error: validation.error || 'CSRF validation failed',
          needsRefresh: validation.needsRefresh,
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }

    // Temporary token is valid, allow the request to proceed
    return null
  }

  // For all other requests, require a session
  if (!sessionId) {
    return new NextResponse(JSON.stringify({ error: 'Session required for CSRF protection' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // Validate regular session-based CSRF token
  const validation = csrfProtectionService.validateCSRFToken(sessionId, csrfToken, request)
  if (!validation.isValid) {
    return new NextResponse(
      JSON.stringify({
        error: validation.error || 'CSRF validation failed',
        needsRefresh: validation.needsRefresh,
      }),
      {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }
    )
  }

  return null
}
