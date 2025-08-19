/**
 * Console Filtering Utilities
 * Provides utilities for filtering browser console noise during web scraping
 */

import { Page } from 'puppeteer'
import { logger } from '@/utils/logger'

export interface ConsoleFilterOptions {
  filterLevel: 'strict' | 'moderate' | 'minimal'
  logCriticalErrors: boolean
  logPageErrors: boolean
  customFilters?: string[]
}

/**
 * Common console message patterns that should be filtered out
 */
export const COMMON_CONSOLE_FILTERS = {
  // Browser policy and feature warnings
  PERMISSIONS_POLICY: [
    'Permissions-Policy header: Unrecognized feature',
    'interest-cohort',
    'browsing-topics'
  ],
  
  // Resource loading errors
  RESOURCE_ERRORS: [
    'Failed to load resource',
    'net::ERR_FAILED',
    'net::ERR_ABORTED',
    'net::ERR_BLOCKED_BY_CLIENT',
    '404',
    '403',
    'favicon',
    '.ico',
    'mapkit',
    'apple-mapkit'
  ],
  
  // Preload warnings
  PRELOAD_WARNINGS: [
    'was preloaded using link preload but not used',
    'preload',
    'link preload'
  ],
  
  // DuckDuckGo specific
  DUCKDUCKGO_SPECIFIC: [
    'useTranslation: DISMISS is not available',
    'expanded-maps-vertical',
    'duckassist-ia',
    'wpm.'
  ],
  
  // General web app noise
  WEB_APP_NOISE: [
    'Non-passive event listener',
    'Violation',
    'deprecated',
    'DevTools'
  ]
}

/**
 * Apply console filtering to a Puppeteer page
 */
export async function applyConsoleFiltering(
  page: Page, 
  options: ConsoleFilterOptions = {
    filterLevel: 'moderate',
    logCriticalErrors: true,
    logPageErrors: true
  }
): Promise<void> {
  const { filterLevel, logCriticalErrors, logPageErrors, customFilters = [] } = options

  // Build filter patterns based on level
  const filterPatterns = buildFilterPatterns(filterLevel, customFilters)

  // Set up console message filtering
  page.on('console', (msg) => {
    const text = msg.text()
    const type = msg.type()
    
    // Check if message should be filtered
    const shouldFilter = filterPatterns.some(pattern => 
      text.toLowerCase().includes(pattern.toLowerCase())
    )

    // Log critical errors if not filtered and logging is enabled
    if (type === 'error' && !shouldFilter && logCriticalErrors) {
      logger.warn('ConsoleFilter', `Browser console error: ${text}`)
    } else if (type === 'warn' && !shouldFilter && filterLevel === 'minimal') {
      logger.debug('ConsoleFilter', `Browser console warning: ${text}`)
    }
  })

  // Set up page error filtering
  if (logPageErrors) {
    page.on('pageerror', (error) => {
      const message = error.message
      
      // Check if page error should be filtered
      const shouldFilter = filterPatterns.some(pattern => 
        message.toLowerCase().includes(pattern.toLowerCase())
      )

      if (!shouldFilter) {
        logger.warn('ConsoleFilter', `Page error: ${message}`)
      }
    })
  }

  // Handle request failures that might cause console noise
  page.on('requestfailed', (request) => {
    const url = request.url()
    const failure = request.failure()
    
    // Only log significant request failures
    if (failure && !isFilteredResource(url)) {
      logger.debug('ConsoleFilter', `Request failed: ${url} - ${failure.errorText}`)
    }
  })
}

/**
 * Build filter patterns based on filter level
 */
function buildFilterPatterns(filterLevel: string, customFilters: string[]): string[] {
  const patterns: string[] = [...customFilters]

  switch (filterLevel) {
    case 'strict':
      // Filter almost everything except critical errors
      patterns.push(
        ...COMMON_CONSOLE_FILTERS.PERMISSIONS_POLICY,
        ...COMMON_CONSOLE_FILTERS.RESOURCE_ERRORS,
        ...COMMON_CONSOLE_FILTERS.PRELOAD_WARNINGS,
        ...COMMON_CONSOLE_FILTERS.DUCKDUCKGO_SPECIFIC,
        ...COMMON_CONSOLE_FILTERS.WEB_APP_NOISE
      )
      break
      
    case 'moderate':
      // Filter common noise but allow some warnings
      patterns.push(
        ...COMMON_CONSOLE_FILTERS.PERMISSIONS_POLICY,
        ...COMMON_CONSOLE_FILTERS.RESOURCE_ERRORS,
        ...COMMON_CONSOLE_FILTERS.PRELOAD_WARNINGS,
        ...COMMON_CONSOLE_FILTERS.DUCKDUCKGO_SPECIFIC
      )
      break
      
    case 'minimal':
      // Only filter the most obvious noise
      patterns.push(
        ...COMMON_CONSOLE_FILTERS.PERMISSIONS_POLICY,
        ...COMMON_CONSOLE_FILTERS.PRELOAD_WARNINGS
      )
      break
  }

  return patterns
}

/**
 * Check if a resource URL should be filtered from logging
 */
function isFilteredResource(url: string): boolean {
  const filteredPatterns = [
    'favicon',
    '.ico',
    'mapkit',
    'analytics',
    'tracking',
    'ads',
    'doubleclick'
  ]

  return filteredPatterns.some(pattern => url.includes(pattern))
}

/**
 * Enhanced resource blocking patterns for common scraping scenarios
 */
export const RESOURCE_BLOCKING_PATTERNS = {
  // Resources that commonly cause console errors
  CONSOLE_ERROR_SOURCES: [
    'mapkit',
    'favicon',
    '.ico',
    'apple-mapkit',
    'preload',
    'expanded-maps-vertical',
    'duckassist-ia'
  ],
  
  // Performance optimization blocks
  PERFORMANCE_BLOCKS: [
    'image',
    'stylesheet', 
    'font',
    'media'
  ],
  
  // Privacy and tracking blocks
  TRACKING_BLOCKS: [
    'google-analytics',
    'googletagmanager',
    'facebook.com',
    'doubleclick',
    'adsystem',
    'analytics',
    'tracking'
  ]
}

/**
 * Apply enhanced resource blocking to reduce console errors
 */
export async function applyResourceBlocking(
  page: Page,
  blockLevel: 'strict' | 'moderate' | 'minimal' = 'moderate'
): Promise<void> {
  await page.setRequestInterception(true)
  
  page.on('request', (request) => {
    const resourceType = request.resourceType()
    const url = request.url()
    
    let shouldBlock = false
    
    // Apply blocking based on level
    switch (blockLevel) {
      case 'strict':
        shouldBlock = 
          RESOURCE_BLOCKING_PATTERNS.PERFORMANCE_BLOCKS.includes(resourceType) ||
          RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES.some(pattern => url.includes(pattern)) ||
          RESOURCE_BLOCKING_PATTERNS.TRACKING_BLOCKS.some(pattern => url.includes(pattern))
        break
        
      case 'moderate':
        shouldBlock = 
          RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES.some(pattern => url.includes(pattern)) ||
          RESOURCE_BLOCKING_PATTERNS.TRACKING_BLOCKS.some(pattern => url.includes(pattern))
        break
        
      case 'minimal':
        shouldBlock = 
          RESOURCE_BLOCKING_PATTERNS.CONSOLE_ERROR_SOURCES.some(pattern => url.includes(pattern))
        break
    }
    
    if (shouldBlock) {
      request.abort()
    } else {
      // Add small random delay to appear more human-like
      const delay = Math.random() * 100 + 50
      setTimeout(() => {
        request.continue()
      }, delay)
    }
  })
}

/**
 * Comprehensive setup for clean scraping with minimal console noise
 */
export async function setupCleanScraping(
  page: Page,
  options: {
    consoleFilter?: ConsoleFilterOptions
    resourceBlocking?: 'strict' | 'moderate' | 'minimal'
  } = {}
): Promise<void> {
  const {
    consoleFilter = {
      filterLevel: 'moderate',
      logCriticalErrors: true,
      logPageErrors: true
    },
    resourceBlocking = 'moderate'
  } = options

  // Apply console filtering
  await applyConsoleFiltering(page, consoleFilter)
  
  // Apply resource blocking
  await applyResourceBlocking(page, resourceBlocking)
  
  logger.debug('ConsoleFilter', 'Clean scraping setup completed', {
    consoleFilterLevel: consoleFilter.filterLevel,
    resourceBlockingLevel: resourceBlocking
  })
}
