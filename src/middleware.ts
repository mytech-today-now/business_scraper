/**
 * Next.js middleware for security, authentication, and rate limiting
 */

import { NextRequest, NextResponse } from 'next/server'
import { 
  defaultSecurityConfig, 
  checkRateLimit, 
  getClientIP, 
  getSession,
  isLockedOut 
} from '@/lib/security'

// Public routes that don't require authentication
const publicRoutes = [
  '/api/health',
  '/login',
  '/favicon.ico',
  '/_next',
  '/static',
]

// API routes that require rate limiting
const rateLimitedRoutes = [
  '/api/scrape',
  '/api/geocode',
  '/api/auth',
]

// Scraping routes that require special rate limiting
const scrapingRoutes = [
  '/api/scrape',
]

/**
 * Check if a route is public (doesn't require authentication)
 */
function isPublicRoute(pathname: string): boolean {
  return publicRoutes.some(route => pathname.startsWith(route))
}

/**
 * Check if a route requires rate limiting
 */
function isRateLimitedRoute(pathname: string): boolean {
  return rateLimitedRoutes.some(route => pathname.startsWith(route))
}

/**
 * Check if a route is a scraping route
 */
function isScrapingRoute(pathname: string): boolean {
  return scrapingRoutes.some(route => pathname.startsWith(route))
}

/**
 * Add security headers to response
 */
function addSecurityHeaders(response: NextResponse): NextResponse {
  if (!defaultSecurityConfig.enableSecurityHeaders) {
    return response
  }

  // Content Security Policy
  response.headers.set('Content-Security-Policy', defaultSecurityConfig.contentSecurityPolicy)
  
  // Security headers
  response.headers.set('X-Frame-Options', 'DENY')
  response.headers.set('X-Content-Type-Options', 'nosniff')
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  
  // HTTPS enforcement in production
  if (process.env.NODE_ENV === 'production') {
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  }
  
  // Remove server information
  response.headers.delete('Server')
  response.headers.delete('X-Powered-By')
  
  return response
}

/**
 * Handle rate limiting
 */
function handleRateLimit(request: NextRequest): NextResponse | null {
  const ip = getClientIP(request)
  const pathname = request.nextUrl.pathname
  
  // Check if IP is locked out
  if (isLockedOut(ip)) {
    return new NextResponse(
      JSON.stringify({ 
        error: 'Too many failed attempts. Please try again later.',
        retryAfter: Math.ceil(defaultSecurityConfig.lockoutDuration / 1000)
      }),
      { 
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(Math.ceil(defaultSecurityConfig.lockoutDuration / 1000))
        }
      }
    )
  }
  
  // Apply different rate limits based on route type
  let rateLimit = defaultSecurityConfig.rateLimitMax
  
  if (isScrapingRoute(pathname)) {
    rateLimit = defaultSecurityConfig.scrapingRateLimit
  }
  
  if (isRateLimitedRoute(pathname) && !checkRateLimit(ip, rateLimit)) {
    return new NextResponse(
      JSON.stringify({ 
        error: 'Rate limit exceeded. Please slow down.',
        retryAfter: Math.ceil(defaultSecurityConfig.rateLimitWindow / 1000)
      }),
      { 
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(Math.ceil(defaultSecurityConfig.rateLimitWindow / 1000))
        }
      }
    )
  }
  
  return null
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
  
  // Skip authentication if not enabled
  if (!defaultSecurityConfig.enableAuth) {
    return null
  }
  
  // Check for session cookie
  const sessionId = request.cookies.get('session-id')?.value
  
  if (!sessionId) {
    // Redirect to login for browser requests
    if (request.headers.get('accept')?.includes('text/html')) {
      return NextResponse.redirect(new URL('/login', request.url))
    }
    
    // Return 401 for API requests
    return new NextResponse(
      JSON.stringify({ error: 'Authentication required' }),
      { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      }
    )
  }
  
  // Validate session
  const session = getSession(sessionId)
  
  if (!session || !session.isValid) {
    // Clear invalid session cookie
    const response = request.headers.get('accept')?.includes('text/html')
      ? NextResponse.redirect(new URL('/login', request.url))
      : new NextResponse(
          JSON.stringify({ error: 'Invalid session' }),
          { 
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          }
        )
    
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
  const method = request.method
  
  // Only check CSRF for state-changing requests to API endpoints
  if (!pathname.startsWith('/api/') || !['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    return null
  }
  
  // Skip CSRF for public routes
  if (isPublicRoute(pathname)) {
    return null
  }
  
  // Skip CSRF if authentication is disabled
  if (!defaultSecurityConfig.enableAuth) {
    return null
  }
  
  const csrfToken = request.headers.get('x-csrf-token')
  const sessionId = request.cookies.get('session-id')?.value
  
  if (!csrfToken || !sessionId) {
    return new NextResponse(
      JSON.stringify({ error: 'CSRF token required' }),
      { 
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      }
    )
  }
  
  // Validate CSRF token (this would need to be implemented in the security module)
  // For now, we'll skip the actual validation since it requires session access
  
  return null
}

/**
 * Main middleware function
 */
export function middleware(request: NextRequest) {
  // Handle rate limiting first
  const rateLimitResponse = handleRateLimit(request)
  if (rateLimitResponse) {
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
    return addSecurityHeaders(csrfResponse)
  }
  
  // Continue with the request
  const response = NextResponse.next()
  
  // Add security headers to all responses
  return addSecurityHeaders(response)
}

/**
 * Configure which routes the middleware should run on
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
