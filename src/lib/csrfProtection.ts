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
 * Timing-safe string comparison for Edge Runtime
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

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
}

/**
 * CSRF Protection Service
 */
export class CSRFProtectionService {
  private tokenStore = new Map<string, CSRFTokenInfo>()
  private temporaryTokens = new Map<string, CSRFTokenInfo>()
  private readonly tokenExpiry = 60 * 60 * 1000 // 1 hour
  private readonly refreshThreshold = 15 * 60 * 1000 // 15 minutes

  /**
   * Generate a new CSRF token for a session
   */
  generateCSRFToken(sessionId: string): CSRFTokenInfo {
    const token = generateSecureToken(32)
    const now = Date.now()

    const tokenInfo: CSRFTokenInfo = {
      token,
      expiresAt: now + this.tokenExpiry,
      issuedAt: now,
    }

    this.tokenStore.set(sessionId, tokenInfo)
    logger.info('CSRF', `Generated new CSRF token for session: ${sessionId}`)

    return tokenInfo
  }

  /**
   * Validate CSRF token with comprehensive checks
   */
  validateCSRFToken(
    sessionId: string,
    providedToken: string,
    request?: NextRequest
  ): CSRFValidationResult {
    // Check if session exists
    const session = getSession(sessionId)
    if (!session || !session.isValid) {
      return {
        isValid: false,
        error: 'Invalid session',
      }
    }

    // Get stored token info
    const tokenInfo = this.tokenStore.get(sessionId)
    if (!tokenInfo) {
      return {
        isValid: false,
        error: 'No CSRF token found for session',
      }
    }

    // Check token expiry
    if (Date.now() > tokenInfo.expiresAt) {
      this.tokenStore.delete(sessionId)
      return {
        isValid: false,
        error: 'CSRF token expired',
        needsRefresh: true,
      }
    }

    // Validate token using timing-safe comparison
    try {
      const isValid = timingSafeEqual(tokenInfo.token, providedToken)

      if (!isValid) {
        logger.warn('CSRF', `Invalid CSRF token provided for session: ${sessionId}`)
        return {
          isValid: false,
          error: 'Invalid CSRF token',
        }
      }

      // Check if token needs refresh (approaching expiry)
      const needsRefresh = tokenInfo.expiresAt - Date.now() < this.refreshThreshold

      // Double-submit cookie validation if request is provided
      if (request) {
        const cookieToken = request.cookies.get('csrf-token')?.value
        if (cookieToken && cookieToken !== providedToken) {
          logger.warn('CSRF', `CSRF cookie mismatch for session: ${sessionId}`)
          return {
            isValid: false,
            error: 'CSRF token mismatch',
          }
        }
      }

      return {
        isValid: true,
        needsRefresh,
      }
    } catch (error) {
      logger.error('CSRF', 'Error validating CSRF token', error)
      return {
        isValid: false,
        error: 'Token validation error',
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
   * Refresh CSRF token if needed
   */
  refreshTokenIfNeeded(sessionId: string): CSRFTokenInfo | null {
    const tokenInfo = this.tokenStore.get(sessionId)
    if (!tokenInfo) {
      return null
    }

    const needsRefresh = tokenInfo.expiresAt - Date.now() < this.refreshThreshold
    if (needsRefresh) {
      return this.generateCSRFToken(sessionId)
    }

    return tokenInfo
  }

  /**
   * Get current CSRF token for a session
   */
  getCSRFToken(sessionId: string): CSRFTokenInfo | null {
    return this.tokenStore.get(sessionId) || null
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
   * Add CSRF protection headers to response
   */
  addCSRFHeaders(response: NextResponse, sessionId: string): NextResponse {
    const tokenInfo = this.getCSRFToken(sessionId)
    if (tokenInfo) {
      // Set CSRF token as a secure cookie (double-submit pattern)
      response.cookies.set('csrf-token', tokenInfo.token, {
        httpOnly: false, // Needs to be accessible to JavaScript
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: Math.floor((tokenInfo.expiresAt - Date.now()) / 1000),
      })

      // Add CSRF token to response headers for AJAX requests
      response.headers.set('X-CSRF-Token', tokenInfo.token)
      response.headers.set('X-CSRF-Expires', String(tokenInfo.expiresAt))
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
