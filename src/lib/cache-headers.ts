'use strict'

import { NextRequest, NextResponse } from 'next/server'
import { logger } from '@/utils/logger'

/**
 * Cache control configuration for different resource types
 */
interface CacheConfig {
  maxAge: number
  staleWhileRevalidate?: number
  mustRevalidate?: boolean
  noCache?: boolean
  noStore?: boolean
  public?: boolean
  private?: boolean
  immutable?: boolean
}

/**
 * Default cache configurations for different resource types
 */
const CACHE_CONFIGS: Record<string, CacheConfig> = {
  // Static assets (images, fonts, etc.)
  static: {
    maxAge: 31536000, // 1 year
    public: true,
    immutable: true,
  },

  // JavaScript and CSS files
  assets: {
    maxAge: 86400, // 1 day
    staleWhileRevalidate: 3600, // 1 hour
    public: true,
  },

  // API responses with business data
  businessData: {
    maxAge: 300, // 5 minutes
    staleWhileRevalidate: 60, // 1 minute
    public: false,
    private: true,
  },

  // Search results
  searchResults: {
    maxAge: 600, // 10 minutes
    staleWhileRevalidate: 120, // 2 minutes
    public: false,
    private: true,
  },

  // Industry data (rarely changes)
  industryData: {
    maxAge: 3600, // 1 hour
    staleWhileRevalidate: 600, // 10 minutes
    public: true,
  },

  // Configuration data
  configData: {
    maxAge: 1800, // 30 minutes
    staleWhileRevalidate: 300, // 5 minutes
    public: false,
    private: true,
  },

  // No cache for sensitive operations
  noCache: {
    maxAge: 0,
    noCache: true,
    noStore: true,
    mustRevalidate: true,
    private: true,
  },
}

/**
 * Build cache control header string from configuration
 */
function buildCacheControlHeader(config: CacheConfig): string {
  const directives: string[] = []

  if (config.noCache) {
    directives.push('no-cache')
  }

  if (config.noStore) {
    directives.push('no-store')
  }

  if (config.mustRevalidate) {
    directives.push('must-revalidate')
  }

  if (config.public) {
    directives.push('public')
  }

  if (config.private) {
    directives.push('private')
  }

  if (config.maxAge !== undefined) {
    directives.push(`max-age=${config.maxAge}`)
  }

  if (config.staleWhileRevalidate !== undefined) {
    directives.push(`stale-while-revalidate=${config.staleWhileRevalidate}`)
  }

  if (config.immutable) {
    directives.push('immutable')
  }

  return directives.join(', ')
}

/**
 * Determine cache type based on request path and content type
 */
function determineCacheType(request: NextRequest): string {
  const pathname = request.nextUrl.pathname
  const url = request.url

  // Static assets
  if (pathname.match(/\.(jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot)$/i)) {
    return 'static'
  }

  // JavaScript and CSS
  if (pathname.match(/\.(js|css)$/i)) {
    return 'assets'
  }

  // API endpoints
  if (pathname.startsWith('/api/')) {
    if (pathname.includes('/search')) {
      return 'searchResults'
    }
    if (pathname.includes('/business') || pathname.includes('/scrape')) {
      return 'businessData'
    }
    if (pathname.includes('/industry')) {
      return 'industryData'
    }
    if (pathname.includes('/config')) {
      return 'configData'
    }
    if (pathname.includes('/auth') || pathname.includes('/session')) {
      return 'noCache'
    }
    // Default for other API endpoints
    return 'businessData'
  }

  // Default for pages
  return 'configData'
}

/**
 * Add cache headers to response
 */
export function addCacheHeaders(response: NextResponse, cacheType: string): NextResponse {
  const config = CACHE_CONFIGS[cacheType] || CACHE_CONFIGS.configData
  const cacheControl = buildCacheControlHeader(config)

  response.headers.set('Cache-Control', cacheControl)

  // Add additional headers for better caching
  if (config.public) {
    response.headers.set('Vary', 'Accept-Encoding')
  }

  // Add ETag for better cache validation
  const etag = generateETag(response)
  if (etag) {
    response.headers.set('ETag', etag)
  }

  // Add Last-Modified header
  response.headers.set('Last-Modified', new Date().toUTCString())

  logger.debug('Cache', `Added cache headers: ${cacheControl} for type: ${cacheType}`)

  return response
}

/**
 * Middleware to automatically add cache headers
 */
export function withCacheHeaders(handler: (request: NextRequest) => Promise<NextResponse>) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const response = await handler(request)
    const cacheType = determineCacheType(request)

    return addCacheHeaders(response, cacheType)
  }
}

/**
 * Generate ETag for response
 */
function generateETag(response: NextResponse): string | null {
  try {
    // Simple ETag generation based on content
    const content = response.body?.toString() || ''
    if (content.length === 0) {
      return null
    }

    // Create a simple hash of the content
    let hash = 0
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i)
      hash = (hash << 5) - hash + char
      hash = hash & hash // Convert to 32-bit integer
    }

    return `"${Math.abs(hash).toString(16)}"`
  } catch (error) {
    logger.warn('Cache', 'Failed to generate ETag', error)
    return null
  }
}

/**
 * Check if request has valid cache headers
 */
export function hasValidCache(request: NextRequest, etag?: string): boolean {
  const ifNoneMatch = request.headers.get('if-none-match')
  const ifModifiedSince = request.headers.get('if-modified-since')

  // Check ETag
  if (etag && ifNoneMatch) {
    return ifNoneMatch === etag
  }

  // Check Last-Modified (simple check - in production you'd want more sophisticated logic)
  if (ifModifiedSince) {
    const modifiedSince = new Date(ifModifiedSince)
    const now = new Date()
    const oneHour = 60 * 60 * 1000

    return now.getTime() - modifiedSince.getTime() < oneHour
  }

  return false
}

/**
 * Create a cached response with 304 Not Modified
 */
export function createNotModifiedResponse(): NextResponse {
  return new NextResponse(null, {
    status: 304,
    headers: {
      'Cache-Control': 'public, max-age=300',
      'Last-Modified': new Date().toUTCString(),
    },
  })
}

/**
 * Cache configuration utilities
 */
export const CacheUtils = {
  /**
   * Get cache configuration for a specific type
   */
  getConfig(type: string): CacheConfig {
    return CACHE_CONFIGS[type] || CACHE_CONFIGS.configData
  },

  /**
   * Set custom cache configuration
   */
  setConfig(type: string, config: CacheConfig): void {
    CACHE_CONFIGS[type] = config
  },

  /**
   * Get all available cache types
   */
  getAvailableTypes(): string[] {
    return Object.keys(CACHE_CONFIGS)
  },

  /**
   * Build cache control header for custom configuration
   */
  buildHeader(config: CacheConfig): string {
    return buildCacheControlHeader(config)
  },
}

export { CACHE_CONFIGS, type CacheConfig }
