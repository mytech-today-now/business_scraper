/**
 * Next.js middleware for security, authentication, and rate limiting
 * Edge Runtime Compatible Version
 *
 * This middleware has been refactored to work with Next.js Edge Runtime:
 * - Uses Web Crypto API instead of Node.js crypto
 * - Removes setInterval usage for cleanup operations
 * - Optimized for edge environments
 */

import { NextRequest, NextResponse } from 'next/server'
import {
  defaultSecurityConfig,
  checkRateLimit,
  getClientIP,
  getSession,
  isLockedOut,
} from '@/lib/security'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { validateCSRFMiddleware, csrfProtectionService } from '@/lib/csrfProtection'
import { securityMonitoringService } from '@/lib/securityMonitoring'
import { enhancedSecurityMonitoringService } from '@/lib/enhanced-security-monitoring'
import { getCSPHeader, generateCSPNonce } from '@/lib/cspConfig'
import { hardenedSecurityConfig } from '@/lib/hardened-security-config'
import { logger } from '@/utils/logger'
import { performCleanupIfNeeded } from '@/lib/edgeRuntimeCleanup'

/**
 * Generate a UUID using Web Crypto API (Edge Runtime compatible)
 */
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
    const r = (Math.random() * 16) | 0
    const v = c === 'x' ? r : (r & 0x3) | 0x8
    return v.toString(16)
  })
}

// Public routes that don't require authentication
const publicRoutes = ['/api/health', '/api/csrf', '/api/auth', '/api/ping', '/api/csp-report', '/api/stream-search', '/login', '/favicon.ico', '/_next', '/static', '/manifest.json', '/sw.js']

// API routes that require rate limiting with their types
const rateLimitedRoutes: Record<string, 'general' | 'scraping' | 'auth' | 'upload' | 'export'> = {
  '/api/scrape': 'scraping',
  '/api/search': 'scraping',
  '/api/stream-search': 'scraping', // Streaming search endpoint
  '/api/geocode': 'general',
  '/api/auth': 'auth',
  '/api/data-management': 'general',
  '/api/config': 'general',
  '/api/upload': 'upload',
  '/api/export': 'export',
}

// Routes that require burst protection
const burstProtectedRoutes = ['/api/auth', '/api/scrape', '/api/upload']

/**
 * Check if a route is public (doesn't require authentication)
 */
function isPublicRoute(pathname: string): boolean {
  return publicRoutes.some(route => pathname.startsWith(route))
}

/**
 * Get rate limit type for route
 */
function getRateLimitType(
  pathname: string
): 'general' | 'scraping' | 'auth' | 'upload' | 'export' | null {
  for (const [route, type] of Object.entries(rateLimitedRoutes)) {
    if (pathname.startsWith(route)) {
      return type
    }
  }
  return null
}

/**
 * Check if route requires burst protection
 */
function requiresBurstProtection(pathname: string): boolean {
  return burstProtectedRoutes.some(route => pathname.startsWith(route))
}

/**
 * Add enhanced security headers to response
 */
function addSecurityHeaders(response: NextResponse): NextResponse {
  if (!defaultSecurityConfig.enableSecurityHeaders) {
    return response
  }

  const isDevelopment = process.env.NODE_ENV === 'development'

  // Log environment detection for debugging
  logger.debug('Middleware', `Environment detection: NODE_ENV=${process.env.NODE_ENV}, isDevelopment=${isDevelopment}`)

  // Always use permissive CSP in development to avoid blocking legitimate development tools
  if (isDevelopment) {
    // In development, use a very permissive CSP to avoid blocking legitimate development tools
    // Remove any nonce-based directives to ensure 'unsafe-inline' works properly
    const devCSP =
      "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://js.stripe.com https://vercel.live https://checkout.stripe.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self' ws: wss: https:; worker-src 'self' blob:; manifest-src 'self'; frame-src 'self' https://js.stripe.com https://checkout.stripe.com;"

    logger.debug('Middleware', `Setting development CSP: ${devCSP}`)
    response.headers.set('Content-Security-Policy', devCSP)

    // Ensure no nonce headers are set in development
    response.headers.delete('X-CSP-Nonce')

    // Log final headers for debugging
    logger.debug('Middleware', `Final CSP header: ${response.headers.get('Content-Security-Policy')}`)
  } else {
    // Generate nonce for CSP in production
    const nonce = generateCSPNonce()

    // Get enhanced Content Security Policy from centralized config
    const csp = getCSPHeader(nonce)
    logger.debug('Middleware', `Setting production CSP with nonce: ${csp}`)
    response.headers.set('Content-Security-Policy', csp)

    // Add nonce to response for use in templates
    if (nonce) {
      response.headers.set('X-CSP-Nonce', nonce)
    }
  }



  // Frame protection
  response.headers.set('X-Frame-Options', 'DENY')

  // MIME type sniffing protection
  response.headers.set('X-Content-Type-Options', 'nosniff')

  // Referrer policy
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')

  // Feature policy / Permissions policy
  // Note: Removed 'ambient-light-sensor' as it's not supported by modern browsers
  const permissionsPolicy = [
    'camera=()',
    'microphone=()',
    'geolocation=()',
    'payment=*',
    'usb=()',
    'magnetometer=()',
    'gyroscope=()',
    'accelerometer=()',
    'autoplay=()',
    'encrypted-media=()',
    'fullscreen=(self)',
    'picture-in-picture=()',
  ].join(', ')

  response.headers.set('Permissions-Policy', permissionsPolicy)

  // XSS protection (legacy but still useful)
  response.headers.set('X-XSS-Protection', '1; mode=block')

  // Cross-Origin policies
  // COEP disabled to allow Stripe.js loading
  // response.headers.set('Cross-Origin-Embedder-Policy', 'require-corp')
  response.headers.set('Cross-Origin-Opener-Policy', 'same-origin')
  response.headers.set('Cross-Origin-Resource-Policy', 'same-origin')

  // HSTS (only in production)
  if (process.env.NODE_ENV === 'production') {
    response.headers.set(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains; preload'
    )
  }

  // Cache control for sensitive pages (exclude SSE endpoints)
  const url = response.url || ''
  const isSSEEndpoint = url.includes('/api/stream-search') || url.includes('/api/stream')

  if ((url.includes('/login') || url.includes('/api/')) && !isSSEEndpoint) {
    response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
    response.headers.set('Pragma', 'no-cache')
    response.headers.set('Expires', '0')
  }

  // Special headers for Server-Sent Events endpoints
  if (isSSEEndpoint) {
    response.headers.set('Cache-Control', 'no-cache, no-transform')
    response.headers.set('Connection', 'keep-alive')
    response.headers.set('X-Accel-Buffering', 'no') // Disable nginx buffering for SSE
  }

  // Remove server information
  response.headers.delete('Server')
  response.headers.delete('X-Powered-By')
  response.headers.delete('X-AspNet-Version')
  response.headers.delete('X-AspNetMvc-Version')

  // Add security monitoring headers
  response.headers.set('X-Request-ID', generateUUID())
  response.headers.set('X-Security-Policy', 'enforced')

  return response
}

/**
 * Handle advanced rate limiting
 */
function handleRateLimit(request: NextRequest): NextResponse | null {
  const pathname = request.nextUrl.pathname
  const ip = getClientIP(request)

  // Skip rate limiting for public routes
  if (isPublicRoute(pathname)) {
    return null
  }

  // Check if user is locked out (legacy security check)
  if (isLockedOut(ip)) {
    return new NextResponse(
      JSON.stringify({
        error: 'Account temporarily locked due to too many failed attempts',
        retryAfter: Math.ceil(defaultSecurityConfig.lockoutDuration / 1000),
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(Math.ceil(defaultSecurityConfig.lockoutDuration / 1000)),
          'X-RateLimit-Limit': '0',
          'X-RateLimit-Remaining': '0',
        },
      }
    )
  }

  // Check burst protection first
  if (requiresBurstProtection(pathname)) {
    const burstResult = advancedRateLimitService.checkBurstRateLimit(`ip:${ip}`)
    if (!burstResult.allowed) {
      return new NextResponse(
        JSON.stringify({
          error: 'Too many requests in a short time. Please slow down.',
          retryAfter: burstResult.retryAfter || 60,
        }),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(burstResult.retryAfter || 60),
            'X-RateLimit-Limit': '20',
            'X-RateLimit-Remaining': String(burstResult.remaining),
            'X-RateLimit-Reset': String(burstResult.resetTime),
          },
        }
      )
    }
  }

  // Check endpoint-specific rate limits
  const rateLimitType = getRateLimitType(pathname)
  if (rateLimitType) {
    const rateLimitResult = advancedRateLimitService.checkApiRateLimit(request, rateLimitType)

    if (!rateLimitResult.allowed) {
      return new NextResponse(
        JSON.stringify({
          error: `Rate limit exceeded for ${rateLimitType} endpoints. Please slow down.`,
          retryAfter:
            rateLimitResult.retryAfter || Math.ceil(defaultSecurityConfig.rateLimitWindow / 1000),
          type: rateLimitType,
        }),
        {
          status: 429,
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': String(
              rateLimitResult.retryAfter || Math.ceil(defaultSecurityConfig.rateLimitWindow / 1000)
            ),
            'X-RateLimit-Limit': getMaxRequestsForType(rateLimitType),
            'X-RateLimit-Remaining': String(rateLimitResult.remaining),
            'X-RateLimit-Reset': String(rateLimitResult.resetTime),
            'X-RateLimit-Type': rateLimitType,
          },
        }
      )
    }
  }

  return null
}

/**
 * Get max requests for rate limit type
 */
function getMaxRequestsForType(type: string): string {
  const limits: Record<string, string> = {
    general: '100',
    scraping: '10',
    auth: '5',
    upload: '20',
    export: '50',
  }
  return limits[type] || '100'
}

/**
 * Handle authentication
 */
function handleAuthentication(request: NextRequest): NextResponse | null {
  const pathname = request.nextUrl.pathname

  // Skip authentication for public routes
  if (isPublicRoute(pathname)) {
    return null
  }

  // Skip authentication for API routes that handle their own auth
  // Note: /api/auth and /api/csrf should be excluded since they create/manage sessions
  if (pathname.startsWith('/api/') && !pathname.startsWith('/api/protected/')) {
    return null
  }

  // Skip authentication if not enabled
  if (!defaultSecurityConfig.enableAuth) {
    return null
  }

  // Check for session cookie
  const sessionId = request.cookies.get('session-id')?.value

  if (!sessionId) {
    // Redirect to login for browser requests, but avoid redirect loops
    if (request.headers.get('accept')?.includes('text/html') && !pathname.startsWith('/login')) {
      return NextResponse.redirect(new URL('/login', request.url))
    }

    // Return 401 for API requests
    return new NextResponse(JSON.stringify({ error: 'Authentication required' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // Validate session
  const session = getSession(sessionId)

  if (!session || !session.isValid) {
    // Clear invalid session cookie
    const response = request.headers.get('accept')?.includes('text/html') && !pathname.startsWith('/login')
      ? NextResponse.redirect(new URL('/login', request.url))
      : new NextResponse(JSON.stringify({ error: 'Invalid session' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        })

    response.cookies.delete('session-id')
    return response
  }

  return null
}

/**
 * Handle CSRF protection for state-changing requests
 */
function handleCSRF(request: NextRequest): NextResponse | null {
  const pathname = request.nextUrl.pathname

  // Skip CSRF if authentication is disabled
  if (!defaultSecurityConfig.enableAuth) {
    return null
  }

  // Skip CSRF protection for public routes that don't need it
  if (isPublicRoute(pathname)) {
    return null
  }

  // Only apply CSRF to state-changing requests (POST, PUT, DELETE, PATCH)
  const needsCSRF = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method) &&
    pathname.startsWith('/api/') &&
    !pathname.startsWith('/api/auth') && // Auth endpoint handles its own CSRF
    !pathname.startsWith('/api/csrf')   // CSRF endpoint doesn't need CSRF protection

  if (!needsCSRF) {
    return null
  }

  // Use the enhanced CSRF protection middleware
  return validateCSRFMiddleware(request)
}

/**
 * Main middleware function
 */
export async function middleware(request: NextRequest) {
  // Perform cleanup if needed (Edge Runtime compatible)
  await performCleanupIfNeeded()

  // Track request signature for pattern analysis
  securityMonitoringService.trackRequestSignature(request)

  // Enhanced threat analysis using the new security monitoring service
  const enhancedThreats = enhancedSecurityMonitoringService.analyzeRequest(request)
  if (enhancedThreats.length > 0) {
    // Log enhanced threats
    const highSeverityThreats = enhancedThreats.filter(
      threat => threat.severity === 'high' || threat.severity === 'critical'
    )

    if (highSeverityThreats.length > 0) {
      // Log the security event
      enhancedSecurityMonitoringService.logSecurityEvent(
        'threat_detected',
        'critical',
        request,
        { threats: highSeverityThreats },
        true
      )

      // Block high severity threats
      return new NextResponse(
        JSON.stringify({
          error: 'Request blocked due to security policy violation',
          threatCount: highSeverityThreats.length,
          requestId: generateUUID()
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      )
    }
  }

  // Handle rate limiting first
  const rateLimitResponse = handleRateLimit(request)
  if (rateLimitResponse) {
    // Log rate limit event
    securityMonitoringService.logSecurityEvent(
      'rate_limit_exceeded',
      'medium',
      request,
      { message: 'Rate limit exceeded' },
      true
    )
    return addSecurityHeaders(rateLimitResponse)
  }

  // Handle authentication
  const authResponse = handleAuthentication(request)
  if (authResponse) {
    return addSecurityHeaders(authResponse)
  }

  // Handle CSRF protection
  const csrfResponse = handleCSRF(request)
  if (csrfResponse) {
    // Log CSRF violation
    securityMonitoringService.logSecurityEvent(
      'invalid_csrf_token',
      'high',
      request,
      { message: 'CSRF token validation failed' },
      true
    )
    return addSecurityHeaders(csrfResponse)
  }

  // Continue with the request
  const response = NextResponse.next()

  // Add CSRF headers if session exists
  const sessionId = request.cookies.get('session-id')?.value
  if (sessionId) {
    csrfProtectionService.addCSRFHeaders(response, sessionId)
  }

  // Add security headers to all responses
  return addSecurityHeaders(response)
}

/**
 * Configure which routes the middleware should run on
 * Explicitly configured for Edge Runtime compatibility
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - favicon.png (favicon PNG file)
     * - manifest.json (PWA manifest)
     * - sw.js (service worker)
     * But include API routes that need middleware protection
     */
    '/((?!_next/static|_next/image|favicon\\.ico|favicon\\.png|manifest\\.json|sw\\.js).*)',
  ],
  // Explicitly specify Edge Runtime for better performance and compatibility
  runtime: 'experimental-edge',
}
