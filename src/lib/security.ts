/**
 * Security configuration and utilities for the business scraper application
 * Implements authentication, authorization, input validation, and security headers
 */

import crypto from 'crypto'
import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import { getCSPHeader } from './cspConfig'
import { getSecurityConfig } from './config'

// Security configuration
export interface SecurityConfig {
  // Authentication
  enableAuth: boolean
  sessionTimeout: number
  maxLoginAttempts: number
  lockoutDuration: number

  // Rate limiting
  rateLimitWindow: number
  rateLimitMax: number
  scrapingRateLimit: number

  // CSRF protection
  csrfTokenLength: number
  csrfTokenExpiry: number

  // Encryption
  encryptionAlgorithm: string
  keyDerivationIterations: number

  // Security headers
  enableSecurityHeaders: boolean
  contentSecurityPolicy: string
}

// Get security configuration from centralized config
function getSecurityConfiguration(): SecurityConfig {
  try {
    const config = getSecurityConfig()

    return {
      enableAuth: config.enableAuth,
      sessionTimeout: config.sessionTimeout,
      maxLoginAttempts: config.maxLoginAttempts,
      lockoutDuration: config.lockoutDuration,
      rateLimitWindow: config.rateLimitWindow,
      rateLimitMax: config.rateLimitMax,
      scrapingRateLimit: config.scrapingRateLimit,

      csrfTokenLength: 32,
      csrfTokenExpiry: 3600000, // 1 hour

      encryptionAlgorithm: 'aes-256-gcm',
      keyDerivationIterations: 100000,

      enableSecurityHeaders: true,
      contentSecurityPolicy: process.env.NODE_ENV === 'development'
        ? "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-eval' 'unsafe-inline' https://js.stripe.com; style-src 'self' 'unsafe-inline';"
        : getCSPHeader(), // Use centralized CSP configuration for production
    }
  } catch (error) {
    // Fallback to environment variables if config system not available
    return {
      enableAuth: process.env.ENABLE_AUTH === 'true',
      sessionTimeout: parseInt(process.env.SESSION_TIMEOUT || '3600000'),
      maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
      lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900000'),
      rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '60000'),
      rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100'),
      scrapingRateLimit: parseInt(process.env.SCRAPING_RATE_LIMIT || '10'),

      csrfTokenLength: 32,
      csrfTokenExpiry: 3600000,
      encryptionAlgorithm: 'aes-256-gcm',
      keyDerivationIterations: 100000,
      enableSecurityHeaders: true,
      contentSecurityPolicy: getCSPHeader(), // Use centralized CSP configuration
    }
  }
}

// Default security configuration
export const defaultSecurityConfig: SecurityConfig = getSecurityConfiguration()

// Session management
export interface Session {
  id: string
  createdAt: Date
  lastAccessed: Date
  isValid: boolean
  csrfToken: string
}

// In-memory session store (for single-user application)
const sessions = new Map<string, Session>()
const loginAttempts = new Map<string, { count: number; lastAttempt: Date }>()

// Rate limiting store
const rateLimitStore = new Map<string, { count: number; resetTime: number }>()

/**
 * Generate a secure random token
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('hex')
}

/**
 * Generate a secure random salt for password hashing
 */
export function generateSalt(length: number = 16): string {
  return crypto.randomBytes(length).toString('hex')
}

/**
 * Generate a unique ID
 */
export function generateId(length: number = 16): string {
  return crypto.randomBytes(length).toString('hex')
}

/**
 * Hash a password using PBKDF2
 */
export function hashPassword(password: string, salt?: string): { hash: string; salt: string } {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex')
  const hash = crypto
    .pbkdf2Sync(password, actualSalt, defaultSecurityConfig.keyDerivationIterations, 64, 'sha512')
    .toString('hex')
  return { hash, salt: actualSalt }
}

/**
 * Verify a password against a hash
 */
export function verifyPassword(password: string, hash: string, salt: string): boolean {
  const { hash: computedHash } = hashPassword(password, salt)
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(computedHash, 'hex'))
}

/**
 * Encrypt sensitive data
 */
export function encryptData(
  data: string,
  key: string
): { encrypted: string; iv: string; tag: string } {
  const iv = crypto.randomBytes(16)
  const keyHash = crypto.createHash('sha256').update(key).digest()
  const cipher = crypto.createCipheriv('aes-256-cbc', keyHash, iv)

  let encrypted = cipher.update(data, 'utf8', 'hex')
  encrypted += cipher.final('hex')

  return {
    encrypted,
    iv: iv.toString('hex'),
    tag: '', // Not used with CBC mode
  }
}

/**
 * Decrypt sensitive data
 */
export function decryptData(encryptedData: string, key: string, iv: string): string {
  const keyHash = crypto.createHash('sha256').update(key).digest()
  const decipher = crypto.createDecipheriv('aes-256-cbc', keyHash, Buffer.from(iv, 'hex'))

  let decrypted = decipher.update(encryptedData, 'hex', 'utf8')
  decrypted += decipher.final('utf8')

  return decrypted
}

/**
 * Create a new session
 */
export function createSession(): Session {
  const sessionId = generateSecureToken()
  const session: Session = {
    id: sessionId,
    createdAt: new Date(),
    lastAccessed: new Date(),
    isValid: true,
    csrfToken: generateSecureToken(defaultSecurityConfig.csrfTokenLength),
  }

  sessions.set(sessionId, session)
  logger.info('Security', `Created new session: ${sessionId}`)

  return session
}

/**
 * Get session by ID
 */
export function getSession(sessionId: string): Session | null {
  const session = sessions.get(sessionId)

  if (!session) {
    return null
  }

  // Check if session is expired
  const now = new Date()
  const sessionAge = now.getTime() - session.lastAccessed.getTime()

  if (sessionAge > defaultSecurityConfig.sessionTimeout) {
    sessions.delete(sessionId)
    logger.info('Security', `Session expired: ${sessionId}`)
    return null
  }

  // Update last accessed time
  session.lastAccessed = now
  sessions.set(sessionId, session)

  return session
}

/**
 * Invalidate a session
 */
export function invalidateSession(sessionId: string): void {
  sessions.delete(sessionId)
  logger.info('Security', `Session invalidated: ${sessionId}`)
}

/**
 * Clean up expired sessions
 */
export function cleanupExpiredSessions(): void {
  const now = new Date()
  let cleanedCount = 0

  // Convert entries to array to avoid iterator issues
  const sessionEntries = Array.from(sessions.entries())
  for (const [sessionId, session] of sessionEntries) {
    const sessionAge = now.getTime() - session.lastAccessed.getTime()
    if (sessionAge > defaultSecurityConfig.sessionTimeout) {
      sessions.delete(sessionId)
      cleanedCount++
    }
  }

  if (cleanedCount > 0) {
    logger.info('Security', `Cleaned up ${cleanedCount} expired sessions`)
  }
}

/**
 * Check rate limit for an IP address
 */
export function checkRateLimit(
  ip: string,
  limit: number = defaultSecurityConfig.rateLimitMax
): boolean {
  const now = Date.now()

  const record = rateLimitStore.get(ip)

  if (!record || record.resetTime <= now) {
    // Reset or create new record
    rateLimitStore.set(ip, { count: 1, resetTime: now + defaultSecurityConfig.rateLimitWindow })
    return true
  }

  if (record.count >= limit) {
    logger.warn('Security', `Rate limit exceeded for IP: ${ip}`)
    return false
  }

  record.count++
  rateLimitStore.set(ip, record)
  return true
}

/**
 * Track login attempts
 */
export function trackLoginAttempt(ip: string, success: boolean): boolean {
  const now = new Date()
  const record = loginAttempts.get(ip)

  if (success) {
    // Clear failed attempts on successful login
    loginAttempts.delete(ip)
    return true
  }

  if (!record) {
    loginAttempts.set(ip, { count: 1, lastAttempt: now })
    return true
  }

  // Check if lockout period has expired
  const timeSinceLastAttempt = now.getTime() - record.lastAttempt.getTime()
  if (timeSinceLastAttempt > defaultSecurityConfig.lockoutDuration) {
    // Reset attempts after lockout period
    loginAttempts.set(ip, { count: 1, lastAttempt: now })
    return true
  }

  record.count++
  record.lastAttempt = now
  loginAttempts.set(ip, record)

  if (record.count > defaultSecurityConfig.maxLoginAttempts) {
    logger.warn('Security', `Account locked due to too many failed attempts from IP: ${ip}`)
    return false
  }

  return true
}

/**
 * Check if IP is locked out
 */
export function isLockedOut(ip: string): boolean {
  const record = loginAttempts.get(ip)

  if (!record || record.count <= defaultSecurityConfig.maxLoginAttempts) {
    return false
  }

  const now = new Date()
  const timeSinceLastAttempt = now.getTime() - record.lastAttempt.getTime()

  if (timeSinceLastAttempt > defaultSecurityConfig.lockoutDuration) {
    // Lockout period expired
    loginAttempts.delete(ip)
    return false
  }

  return true
}

/**
 * Validate CSRF token
 */
export function validateCSRFToken(sessionId: string, token: string): boolean {
  const session = getSession(sessionId)

  if (!session || !session.isValid) {
    return false
  }

  return crypto.timingSafeEqual(Buffer.from(session.csrfToken, 'hex'), Buffer.from(token, 'hex'))
}

/**
 * Get client IP address from request
 */
export function getClientIP(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for')
  const realIP = request.headers.get('x-real-ip')

  if (forwarded) {
    const firstIP = forwarded.split(',')[0]
    return firstIP ? firstIP.trim() : 'unknown'
  }

  if (realIP) {
    return realIP
  }

  return request.ip || 'unknown'
}

/**
 * Sanitize input to prevent XSS
 */
export function sanitizeInput(input: string): string {
  return input
    .trim()
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/javascript:/gi, '') // Remove javascript: URLs
    .replace(/on\w+\s*=/gi, '') // Remove event handlers
    .replace(/[<>'"&]/g, char => {
      // Escape dangerous characters
      const escapeMap: { [key: string]: string } = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;',
      }
      return escapeMap[char] || char
    })
}

/**
 * Validate input against common injection patterns
 */
export function validateInput(input: string): { isValid: boolean; errors: string[] } {
  const errors: string[] = []

  // Check for SQL injection patterns
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)/i,
    /(--|\/\*|\*\/)/,
    /(\b(OR|AND)\b.*=.*)/i,
  ]

  for (const pattern of sqlPatterns) {
    if (pattern.test(input)) {
      errors.push('Input contains potentially dangerous SQL patterns')
      break
    }
  }

  // Check for XSS patterns
  const xssPatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
  ]

  for (const pattern of xssPatterns) {
    if (pattern.test(input)) {
      errors.push('Input contains potentially dangerous XSS patterns')
      break
    }
  }

  // Check for path traversal
  if (/\.\.\/|\.\.\\/.test(input)) {
    errors.push('Input contains path traversal patterns')
  }

  return {
    isValid: errors.length === 0,
    errors,
  }
}

// Cleanup interval for expired sessions (run every 5 minutes)
if (typeof window === 'undefined') {
  setInterval(cleanupExpiredSessions, 5 * 60 * 1000)
}
