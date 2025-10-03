/**
 * CORS Test Utilities
 * Dedicated utilities for testing CORS functionality in the business_scraper application
 */

import { NextRequest } from 'next/server'

export interface CORSTestOptions {
  origin?: string
  method?: string
  headers?: Record<string, string>
  credentials?: boolean
  allowedMethods?: string[]
  allowedHeaders?: string[]
}

export interface MockCORSResponse {
  status: number
  headers: Headers
  json: () => Promise<any>
  text: () => Promise<string>
  ok: boolean
}

/**
 * Create a mock CORS-enabled request for testing
 */
export function createCORSRequest(url: string, options: CORSTestOptions = {}): NextRequest {
  const {
    origin = 'http://localhost:3000',
    method = 'GET',
    headers = {},
    credentials = true
  } = options

  const requestHeaders = {
    'Origin': origin,
    'Access-Control-Request-Method': method,
    'Access-Control-Request-Headers': 'Content-Type, Authorization, X-CSRF-Token',
    ...headers
  }

  return new NextRequest(url, {
    method,
    headers: requestHeaders,
    credentials: credentials ? 'include' : 'omit'
  })
}

/**
 * Create a CORS preflight OPTIONS request
 */
export function createPreflightRequest(url: string, options: CORSTestOptions = {}): NextRequest {
  const {
    origin = 'http://localhost:3000',
    allowedMethods = ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders = ['Content-Type', 'Authorization', 'X-CSRF-Token']
  } = options

  return new NextRequest(url, {
    method: 'OPTIONS',
    headers: {
      'Origin': origin,
      'Access-Control-Request-Method': allowedMethods.join(', '),
      'Access-Control-Request-Headers': allowedHeaders.join(', ')
    }
  })
}

/**
 * Create a mock CORS response with proper headers
 */
export function createCORSResponse(data: any = {}, options: CORSTestOptions = {}): MockCORSResponse {
  const {
    origin = '*',
    allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders = ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    credentials = true
  } = options

  const headers = new Headers({
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': allowedMethods.join(', '),
    'Access-Control-Allow-Headers': allowedHeaders.join(', '),
    'Access-Control-Allow-Credentials': credentials.toString(),
    'Content-Type': 'application/json'
  })

  return {
    status: 200,
    headers,
    json: async () => data,
    text: async () => JSON.stringify(data),
    ok: true
  }
}

/**
 * Validate CORS headers in a response
 */
export function validateCORSHeaders(response: any, expectedOptions: CORSTestOptions = {}): boolean {
  const {
    origin = '*',
    allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders = ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    credentials = true
  } = expectedOptions

  const headers = response.headers

  // Check required CORS headers
  const allowOrigin = headers.get('Access-Control-Allow-Origin')
  const allowMethods = headers.get('Access-Control-Allow-Methods')
  const allowHeadersHeader = headers.get('Access-Control-Allow-Headers')
  const allowCredentials = headers.get('Access-Control-Allow-Credentials')

  if (!allowOrigin) return false
  if (origin !== '*' && allowOrigin !== origin) return false
  
  if (allowMethods) {
    const responseMethods = allowMethods.split(',').map(m => m.trim())
    const hasAllMethods = allowedMethods.every(method => 
      responseMethods.some(rm => rm.toUpperCase() === method.toUpperCase())
    )
    if (!hasAllMethods) return false
  }

  if (allowHeadersHeader) {
    const responseHeaders = allowHeadersHeader.split(',').map(h => h.trim().toLowerCase())
    const hasAllHeaders = allowedHeaders.every(header => 
      responseHeaders.includes(header.toLowerCase())
    )
    if (!hasAllHeaders) return false
  }

  if (credentials && allowCredentials !== 'true') return false

  return true
}

/**
 * Mock fetch with CORS support for testing
 */
export function mockFetchWithCORS(mockResponses: Record<string, any> = {}) {
  return jest.fn((input: string | Request, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input.url
    const method = init.method || 'GET'
    
    // Handle preflight requests
    if (method === 'OPTIONS') {
      return Promise.resolve(createCORSResponse({}, {
        allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
      }))
    }

    // Return mock response if available
    const mockKey = `${method}:${url}`
    const mockData = mockResponses[mockKey] || mockResponses[url] || {}
    
    return Promise.resolve(createCORSResponse(mockData))
  })
}

/**
 * Test helper to verify CORS preflight behavior
 */
export async function testCORSPreflight(
  handler: (request: NextRequest) => Promise<Response>,
  url: string,
  options: CORSTestOptions = {}
): Promise<{ success: boolean; response?: any; error?: string }> {
  try {
    const preflightRequest = createPreflightRequest(url, options)
    const response = await handler(preflightRequest)
    
    if (response.status !== 200 && response.status !== 204) {
      return { success: false, error: `Preflight failed with status ${response.status}` }
    }

    const isValidCORS = validateCORSHeaders(response, options)
    if (!isValidCORS) {
      return { success: false, error: 'Invalid CORS headers in preflight response' }
    }

    return { success: true, response }
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : 'Unknown error' }
  }
}

/**
 * Test helper to verify actual CORS request behavior
 */
export async function testCORSRequest(
  handler: (request: NextRequest) => Promise<Response>,
  url: string,
  options: CORSTestOptions = {}
): Promise<{ success: boolean; response?: any; error?: string }> {
  try {
    const corsRequest = createCORSRequest(url, options)
    const response = await handler(corsRequest)
    
    const isValidCORS = validateCORSHeaders(response, options)
    if (!isValidCORS) {
      return { success: false, error: 'Invalid CORS headers in response' }
    }

    return { success: true, response }
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : 'Unknown error' }
  }
}

/**
 * Comprehensive CORS test suite helper
 */
export async function runCORSTestSuite(
  handler: (request: NextRequest) => Promise<Response>,
  url: string,
  options: CORSTestOptions = {}
): Promise<{
  preflight: { success: boolean; error?: string }
  request: { success: boolean; error?: string }
  overall: boolean
}> {
  const preflightResult = await testCORSPreflight(handler, url, options)
  const requestResult = await testCORSRequest(url, options)
  
  return {
    preflight: preflightResult,
    request: requestResult,
    overall: preflightResult.success && requestResult.success
  }
}

/**
 * Create test environment with CORS mocks
 */
export function setupCORSTestEnvironment() {
  const originalFetch = global.fetch
  const originalXMLHttpRequest = global.XMLHttpRequest
  
  // Set up CORS-enabled mocks
  global.fetch = mockFetchWithCORS()
  
  return {
    cleanup: () => {
      global.fetch = originalFetch
      global.XMLHttpRequest = originalXMLHttpRequest
    }
  }
}
