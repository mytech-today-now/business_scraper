/**
 * Static Resource Handler
 * Enhanced error handling for static resources including favicon, images, and assets
 * Prevents 500 errors and provides graceful fallbacks
 */

import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'

/**
 * Static resource types and their configurations
 */
interface StaticResourceConfig {
  contentType: string
  maxAge: number
  fallbackPath?: string
  generateFallback?: () => Buffer
}

const STATIC_RESOURCE_CONFIGS: Record<string, StaticResourceConfig> = {
  '.ico': {
    contentType: 'image/x-icon',
    maxAge: 86400, // 24 hours
    fallbackPath: '/favicon.png',
  },
  '.png': {
    contentType: 'image/png',
    maxAge: 86400,
    generateFallback: generateTransparentPng,
  },
  '.jpg': {
    contentType: 'image/jpeg',
    maxAge: 86400,
    generateFallback: generateTransparentPng,
  },
  '.jpeg': {
    contentType: 'image/jpeg',
    maxAge: 86400,
    generateFallback: generateTransparentPng,
  },
  '.gif': {
    contentType: 'image/gif',
    maxAge: 86400,
    generateFallback: generateTransparentPng,
  },
  '.svg': {
    contentType: 'image/svg+xml',
    maxAge: 86400,
    generateFallback: generateMinimalSvg,
  },
  '.css': {
    contentType: 'text/css',
    maxAge: 3600, // 1 hour
    generateFallback: () => Buffer.from('/* Fallback CSS */'),
  },
  '.js': {
    contentType: 'application/javascript',
    maxAge: 3600,
    generateFallback: () => Buffer.from('// Fallback JS'),
  },
}

/**
 * Handle static resource requests with comprehensive error handling
 */
export async function handleStaticResource(
  request: NextRequest,
  pathname: string
): Promise<NextResponse | null> {
  try {
    // Check if this is a static resource request
    const extension = getFileExtension(pathname)
    const config = STATIC_RESOURCE_CONFIGS[extension]
    
    if (!config) {
      return null // Not a static resource we handle
    }
    
    // Special handling for favicon requests
    if (pathname === '/favicon.ico') {
      return handleFaviconRequest(request)
    }
    
    // For other static resources, let Next.js handle them normally
    // This function primarily provides fallback handling
    return null
  } catch (error) {
    logger.error('StaticResourceHandler', 'Error handling static resource', {
      pathname,
      error: error instanceof Error ? error.message : 'Unknown error',
    })
    
    return null
  }
}

/**
 * Handle favicon requests specifically
 */
async function handleFaviconRequest(request: NextRequest): Promise<NextResponse> {
  try {
    // Redirect to our favicon API endpoint for proper handling
    const faviconApiUrl = new URL('/api/favicon', request.url)
    
    return NextResponse.redirect(faviconApiUrl, {
      status: 302, // Temporary redirect
      headers: {
        'Cache-Control': 'public, max-age=3600',
        'X-Favicon-Redirect': 'api-endpoint',
      },
    })
  } catch (error) {
    logger.error('StaticResourceHandler', 'Error redirecting favicon request', {
      error: error instanceof Error ? error.message : 'Unknown error',
    })
    
    // Return a 204 No Content as final fallback
    return new NextResponse(null, {
      status: 204,
      headers: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Favicon-Error': 'redirect-failed',
      },
    })
  }
}

/**
 * Generate error response for static resources
 */
export function generateStaticResourceError(
  pathname: string,
  error: Error
): NextResponse {
  const extension = getFileExtension(pathname)
  const config = STATIC_RESOURCE_CONFIGS[extension]
  
  if (!config) {
    return new NextResponse('Not Found', { status: 404 })
  }
  
  try {
    // Try to generate a fallback resource
    if (config.generateFallback) {
      const fallbackContent = config.generateFallback()
      
      return new NextResponse(fallbackContent, {
        status: 200,
        headers: {
          'Content-Type': config.contentType,
          'Cache-Control': `public, max-age=${Math.min(config.maxAge, 3600)}`, // Shorter cache for fallbacks
          'X-Resource-Status': 'generated-fallback',
          'X-Original-Error': error.message,
        },
      })
    }
    
    // For resources without fallback generators, return 404
    return new NextResponse('Resource Not Found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'X-Resource-Status': 'not-found',
      },
    })
  } catch (fallbackError) {
    logger.error('StaticResourceHandler', 'Error generating fallback resource', {
      pathname,
      originalError: error.message,
      fallbackError: fallbackError instanceof Error ? fallbackError.message : 'Unknown error',
    })
    
    return new NextResponse('Internal Server Error', {
      status: 500,
      headers: {
        'Content-Type': 'text/plain',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      },
    })
  }
}

/**
 * Get file extension from pathname
 */
function getFileExtension(pathname: string): string {
  const lastDot = pathname.lastIndexOf('.')
  return lastDot === -1 ? '' : pathname.substring(lastDot).toLowerCase()
}

/**
 * Generate a 1x1 transparent PNG
 */
function generateTransparentPng(): Buffer {
  // Base64 encoded 1x1 transparent PNG
  const base64Png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChAI9jU77zgAAAABJRU5ErkJggg=='
  return Buffer.from(base64Png, 'base64')
}

/**
 * Generate a minimal SVG
 */
function generateMinimalSvg(): Buffer {
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1" fill="transparent"/></svg>'
  return Buffer.from(svg, 'utf8')
}

/**
 * Check if a request is for a static resource
 */
export function isStaticResourceRequest(pathname: string): boolean {
  const extension = getFileExtension(pathname)
  return extension in STATIC_RESOURCE_CONFIGS
}

/**
 * Get cache headers for static resources
 */
export function getStaticResourceHeaders(pathname: string): Record<string, string> {
  const extension = getFileExtension(pathname)
  const config = STATIC_RESOURCE_CONFIGS[extension]
  
  if (!config) {
    return {}
  }
  
  return {
    'Content-Type': config.contentType,
    'Cache-Control': `public, max-age=${config.maxAge}, immutable`,
    'X-Resource-Type': 'static',
  }
}

/**
 * Validate static resource request
 */
export function validateStaticResourceRequest(request: NextRequest): {
  isValid: boolean
  error?: string
} {
  try {
    const pathname = request.nextUrl.pathname
    
    // Check for path traversal attempts
    if (pathname.includes('..') || pathname.includes('//')) {
      return {
        isValid: false,
        error: 'Invalid path: path traversal detected',
      }
    }
    
    // Check for suspicious patterns
    if (pathname.includes('\0') || pathname.includes('%00')) {
      return {
        isValid: false,
        error: 'Invalid path: null bytes detected',
      }
    }
    
    return { isValid: true }
  } catch (error) {
    return {
      isValid: false,
      error: error instanceof Error ? error.message : 'Unknown validation error',
    }
  }
}
