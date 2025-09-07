#!/usr/bin/env node

/**
 * Test public route logic
 */

// Public routes that don't require authentication
const publicRoutes = ['/api/health', '/api/csrf', '/api/auth', '/login', '/favicon.ico', '/_next', '/static', '/manifest.json', '/sw.js']

/**
 * Check if a route is public (doesn't require authentication)
 */
function isPublicRoute(pathname) {
  return publicRoutes.some(route => pathname.startsWith(route))
}

// Test cases
const testPaths = [
  '/api/auth',
  '/api/csrf',
  '/api/health',
  '/api/protected/something',
  '/login',
  '/dashboard',
  '/_next/static/something',
  '/favicon.ico'
]

console.log('=== Public Route Test ===')
console.log('Public Routes:', publicRoutes)
console.log('')

testPaths.forEach(path => {
  const isPublic = isPublicRoute(path)
  console.log(`${path}: ${isPublic ? '✅ PUBLIC' : '❌ PROTECTED'}`)
})

console.log('')
console.log('=== API Route Logic Test ===')
testPaths.forEach(path => {
  const isPublic = isPublicRoute(path)
  const isApiRoute = path.startsWith('/api/')
  const isProtectedApi = path.startsWith('/api/protected/')
  const shouldSkipAuth = isPublic || (isApiRoute && !isProtectedApi)
  
  console.log(`${path}:`)
  console.log(`  - isPublic: ${isPublic}`)
  console.log(`  - isApiRoute: ${isApiRoute}`)
  console.log(`  - isProtectedApi: ${isProtectedApi}`)
  console.log(`  - shouldSkipAuth: ${shouldSkipAuth}`)
  console.log('')
})
