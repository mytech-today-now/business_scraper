/**
 * Unified Crypto Utility - Cross-Environment Compatibility
 * Business Scraper Application - Edge Runtime, Node.js, Browser, and Test Support
 */

import { logger } from '@/utils/logger'

/**
 * Check if we're in a Node.js environment (Edge Runtime compatible)
 */
function isNodeEnvironment(): boolean {
  try {
    return typeof process !== 'undefined' &&
           typeof process.versions !== 'undefined' &&
           typeof process.versions.node !== 'undefined'
  } catch {
    return false
  }
}

/**
 * Check if we're in a test environment (Edge Runtime compatible)
 */
function isTestEnvironment(): boolean {
  try {
    return (typeof process !== 'undefined' &&
            (process.env?.NODE_ENV === 'test' ||
             typeof process.env?.JEST_WORKER_ID !== 'undefined'))
  } catch {
    return false
  }
}

/**
 * Check if Web Crypto API is available
 */
function isWebCryptoAvailable(): boolean {
  return typeof globalThis !== 'undefined' && 
         typeof globalThis.crypto !== 'undefined' && 
         typeof globalThis.crypto.getRandomValues === 'function'
}

/**
 * Check if crypto.randomUUID is available
 */
function isRandomUUIDAvailable(): boolean {
  return typeof globalThis !== 'undefined' && 
         typeof globalThis.crypto !== 'undefined' && 
         typeof globalThis.crypto.randomUUID === 'function'
}

/**
 * Polyfill for crypto.randomUUID using crypto.getRandomValues
 */
function polyfillRandomUUID(): string {
  if (isWebCryptoAvailable()) {
    // Use Web Crypto API to generate UUID v4
    const array = new Uint8Array(16)
    globalThis.crypto.getRandomValues(array)
    
    // Set version (4) and variant bits according to RFC 4122
    array[6] = (array[6] & 0x0f) | 0x40 // Version 4
    array[8] = (array[8] & 0x3f) | 0x80 // Variant 10
    
    // Convert to UUID string format
    const hex = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`
  }
  
  // Fallback for environments without Web Crypto API
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

/**
 * Generate a cryptographically secure random UUID
 * Works across Node.js, Edge Runtime, Browser, and Test environments
 */
export function randomUUID(): string {
  try {
    // Use native crypto.randomUUID if available
    if (isRandomUUIDAvailable()) {
      return globalThis.crypto.randomUUID()
    }
    
    // Use Node.js crypto module in Node.js environment
    if (isNodeEnvironment() && !isTestEnvironment()) {
      try {
        const crypto = require('crypto')
        if (crypto.randomUUID) {
          return crypto.randomUUID()
        }
      } catch (error) {
        logger.warn('crypto', 'Node.js crypto module not available, using polyfill', { error })
      }
    }
    
    // Use polyfill for other environments
    return polyfillRandomUUID()
  } catch (error) {
    logger.error('crypto', 'Failed to generate UUID, using fallback', { error })
    // Ultimate fallback - less secure but functional
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
  }
}

/**
 * Generate cryptographically secure random bytes
 */
export function getRandomValues(array: Uint8Array): Uint8Array {
  try {
    if (isWebCryptoAvailable()) {
      return globalThis.crypto.getRandomValues(array)
    }
    
    // Node.js fallback
    if (isNodeEnvironment() && !isTestEnvironment()) {
      try {
        const crypto = require('crypto')
        const bytes = crypto.randomBytes(array.length)
        array.set(bytes)
        return array
      } catch (error) {
        logger.warn('crypto', 'Node.js crypto module not available for random bytes', { error })
      }
    }
    
    // Fallback using Math.random (less secure)
    for (let i = 0; i < array.length; i++) {
      array[i] = Math.floor(Math.random() * 256)
    }
    return array
  } catch (error) {
    logger.error('crypto', 'Failed to generate random bytes', { error })
    // Fill with zeros as ultimate fallback
    array.fill(0)
    return array
  }
}

/**
 * Generate a secure nonce for CSP headers
 */
export function generateSecureNonce(): string {
  try {
    const array = new Uint8Array(16)
    getRandomValues(array)
    return btoa(String.fromCharCode(...array))
  } catch (error) {
    logger.error('crypto', 'Failed to generate secure nonce', { error })
    // Fallback nonce
    return btoa(`fallback-${Date.now()}-${Math.random()}`)
  }
}

/**
 * Generate a secure token for authentication/session purposes
 */
export function generateSecureToken(length: number = 32): string {
  try {
    const array = new Uint8Array(length)
    getRandomValues(array)
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
  } catch (error) {
    logger.error('crypto', 'Failed to generate secure token', { error })
    // Fallback token
    return Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join('')
  }
}

/**
 * Initialize crypto polyfills for test environments
 */
export function initializeCryptoPolyfills(): void {
  if (isTestEnvironment()) {
    // Set up crypto polyfills for Jest
    if (typeof globalThis.crypto === 'undefined') {
      Object.defineProperty(globalThis, 'crypto', {
        value: {
          randomUUID: () => 'test-uuid-' + Math.random().toString(36).substr(2, 9),
          getRandomValues: (arr: Uint8Array) => {
            for (let i = 0; i < arr.length; i++) {
              arr[i] = Math.floor(Math.random() * 256)
            }
            return arr
          },
          subtle: {} // Mock subtle crypto for tests
        },
        writable: true,
        configurable: true
      })
    }
    
    logger.info('crypto', 'Crypto polyfills initialized for test environment')
  }
}

/**
 * Crypto utility object with all methods
 */
export const crypto = {
  randomUUID,
  getRandomValues,
  generateSecureNonce,
  generateSecureToken,
  initializeCryptoPolyfills,
  isWebCryptoAvailable,
  isRandomUUIDAvailable,
  isNodeEnvironment,
  isTestEnvironment
}

export default crypto
