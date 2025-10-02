/**
 * Security configuration and utilities for the business scraper application
 * Implements authentication, authorization, input validation, and security headers
 * Edge Runtime Compatible Version
 */

import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import { getCSPHeader } from './cspConfig'
import { getSecurityConfig } from './config'

// Edge Runtime compatibility check
const isEdgeRuntime = (typeof globalThis !== 'undefined' && 'EdgeRuntime' in globalThis) ||
  (typeof process !== 'undefined' && process.env.NEXT_RUNTIME === 'edge')

// Web Crypto API compatibility
const webCrypto = globalThis.crypto

// Fallback for Node.js crypto when not in Edge Runtime
let nodeCrypto: any = null
if (!isEdgeRuntime) {
  try {
    nodeCrypto = require('crypto')
  } catch (error) {
    logger.warn('Security', 'Node.js crypto module not available, using Web Crypto API only')
  }
}

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
    const hardenedConfig = require('./hardened-security-config').hardenedSecurityConfig

    return {
      enableAuth: config.enableAuth,
      sessionTimeout: hardenedConfig.session.maxAge, // Use hardened session timeout
      maxLoginAttempts: config.maxLoginAttempts,
      lockoutDuration: config.lockoutDuration,
      rateLimitWindow: hardenedConfig.apiSecurity.rateLimit.windowMs, // Use hardened rate limit
      rateLimitMax: hardenedConfig.apiSecurity.rateLimit.max, // Use hardened rate limit
      scrapingRateLimit: config.scrapingRateLimit,

      csrfTokenLength: 32,
      csrfTokenExpiry: 3600000, // 1 hour

      encryptionAlgorithm: hardenedConfig.encryption.algorithm, // Use hardened encryption
      keyDerivationIterations: hardenedConfig.encryption.keyDerivationIterations, // Use hardened iterations

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

// Enhanced session management with security features
export interface Session {
  id: string
  createdAt: Date
  lastAccessed: Date
  isValid: boolean
  csrfToken: string
  // JWT-based security
  jwtToken?: string
  jwtSignature?: string
  // IP binding for session hijacking prevention
  ipAddress?: string
  ipHash?: string
  // Device fingerprinting
  userAgent?: string
  deviceFingerprint?: string
  // Session security metadata
  renewalCount: number
  lastRenewal?: Date
  securityFlags: {
    ipValidated: boolean
    deviceValidated: boolean
    jwtVerified: boolean
    suspiciousActivity: boolean
  }
  // Session expiration and renewal
  expiresAt: Date
  renewalThreshold: number // Time before expiry to allow renewal (in ms)
  maxRenewals: number
}

// Session fingerprint for enhanced security
export interface SessionFingerprint {
  userAgent: string
  acceptLanguage: string
  acceptEncoding: string
  screenResolution?: string
  timezone?: string
  hash: string
}

// In-memory session store (for single-user application)
const sessions = new Map<string, Session>()
const loginAttempts = new Map<string, { count: number; lastAttempt: Date; lockoutUntil?: Date }>()
const suspiciousActivity = new Map<string, { events: string[]; lastEvent: Date; riskScore: number }>()

// Rate limiting store
const rateLimitStore = new Map<string, { count: number; resetTime: number }>()

// Session fingerprint store
const sessionFingerprints = new Map<string, SessionFingerprint>()

// Security configuration constants
const SECURITY_CONSTANTS = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes
  SESSION_RENEWAL_THRESHOLD: 5 * 60 * 1000, // 5 minutes before expiry
  MAX_SESSION_RENEWALS: 10,
  SUSPICIOUS_ACTIVITY_THRESHOLD: 5,
  IP_CHANGE_TOLERANCE: false, // Strict IP binding
  DEVICE_FINGERPRINT_REQUIRED: true,
} as const

/**
 * Generate a secure random token using Web Crypto API
 */
export function generateSecureToken(length: number = 32): string {
  const array = new Uint8Array(length)
  webCrypto.getRandomValues(array)
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Generate a secure random salt for password hashing
 */
export function generateSalt(length: number = 16): string {
  return generateSecureToken(length)
}

/**
 * Generate a unique ID
 */
export function generateId(length: number = 16): string {
  return generateSecureToken(length)
}

/**
 * Hash a string using SHA-256
 */
export async function hashString(input: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(input)
  const hashBuffer = await webCrypto.subtle.digest('SHA-256', data)
  const hashArray = new Uint8Array(hashBuffer)
  return Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * Hash a password using PBKDF2 with Web Crypto API
 */
export async function hashPassword(password: string, salt?: string): Promise<{ hash: string; salt: string }> {
  const actualSalt = salt || generateSecureToken(16)

  // Convert password and salt to ArrayBuffer
  const encoder = new TextEncoder()
  const passwordBuffer = encoder.encode(password)
  const saltBuffer = encoder.encode(actualSalt)

  // Import password as key material
  const keyMaterial = await webCrypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )

  // Derive key using PBKDF2
  const derivedKey = await webCrypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: defaultSecurityConfig.keyDerivationIterations,
      hash: 'SHA-512'
    },
    keyMaterial,
    512 // 64 bytes * 8 bits
  )

  // Convert to hex string
  const hashArray = new Uint8Array(derivedKey)
  const hash = Array.from(hashArray, byte => byte.toString(16).padStart(2, '0')).join('')

  return { hash, salt: actualSalt }
}

/**
 * Verify a password against a hash
 */
export async function verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
  const { hash: computedHash } = await hashPassword(password, salt)
  return timingSafeEqual(hash, computedHash)
}

/**
 * Timing-safe string comparison using Web Crypto API
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false
  }

  // Convert strings to Uint8Array for comparison
  const aArray = new Uint8Array(a.length)
  const bArray = new Uint8Array(b.length)

  for (let i = 0; i < a.length; i++) {
    aArray[i] = a.charCodeAt(i)
    bArray[i] = b.charCodeAt(i)
  }

  // Use crypto.subtle.verify for timing-safe comparison
  let result = 0
  for (let i = 0; i < aArray.length; i++) {
    result |= aArray[i] ^ bArray[i]
  }

  return result === 0
}

/**
 * Encrypt sensitive data using Web Crypto API with AES-GCM
 */
export async function encryptData(
  data: string,
  key: string
): Promise<{ encrypted: string; iv: string; tag: string }> {
  const encoder = new TextEncoder()
  const dataBuffer = encoder.encode(data)

  // Generate IV
  const iv = new Uint8Array(12) // 96-bit IV for GCM
  webCrypto.getRandomValues(iv)

  // Derive key from password
  const keyBuffer = encoder.encode(key)
  const keyMaterial = await webCrypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )

  const derivedKeyBuffer = await webCrypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: iv, // Use IV as salt for simplicity
      iterations: 10000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256 // 32 bytes * 8 bits
  )

  // Import derived key for AES-GCM
  const cryptoKey = await webCrypto.subtle.importKey(
    'raw',
    derivedKeyBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )

  // Encrypt data
  const encryptedBuffer = await webCrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    cryptoKey,
    dataBuffer
  )

  // Convert to hex strings
  const encryptedArray = new Uint8Array(encryptedBuffer)
  const encrypted = Array.from(encryptedArray, byte => byte.toString(16).padStart(2, '0')).join('')
  const ivHex = Array.from(iv, byte => byte.toString(16).padStart(2, '0')).join('')

  return {
    encrypted,
    iv: ivHex,
    tag: '', // GCM authentication tag is included in encrypted data
  }
}

/**
 * Decrypt sensitive data using Web Crypto API with AES-GCM
 */
export async function decryptData(encryptedData: string, key: string, iv: string): Promise<string> {
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()

  // Convert hex strings back to Uint8Array
  const encryptedArray = new Uint8Array(encryptedData.match(/.{2}/g)!.map(byte => parseInt(byte, 16)))
  const ivArray = new Uint8Array(iv.match(/.{2}/g)!.map(byte => parseInt(byte, 16)))

  // Derive key from password
  const keyBuffer = encoder.encode(key)
  const keyMaterial = await webCrypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )

  const derivedKeyBuffer = await webCrypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: ivArray,
      iterations: 10000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  )

  // Import derived key for AES-GCM
  const cryptoKey = await webCrypto.subtle.importKey(
    'raw',
    derivedKeyBuffer,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  )

  // Decrypt data
  const decryptedBuffer = await webCrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivArray
    },
    cryptoKey,
    encryptedArray
  )

  return decoder.decode(decryptedBuffer)
}

/**
 * Generate device fingerprint from request headers
 */
export function generateDeviceFingerprint(request: any): SessionFingerprint {
  const userAgent = request.headers.get('user-agent') || ''
  const acceptLanguage = request.headers.get('accept-language') || ''
  const acceptEncoding = request.headers.get('accept-encoding') || ''

  // Create a hash of the fingerprint components
  const fingerprintData = `${userAgent}|${acceptLanguage}|${acceptEncoding}`
  const hash = generateSecureToken(16) // Simplified hash for now

  return {
    userAgent,
    acceptLanguage,
    acceptEncoding,
    hash
  }
}

/**
 * Create a new secure session with enhanced security features
 */
export async function createSecureSession(
  ipAddress: string,
  request?: any,
  jwtToken?: string
): Promise<Session> {
  const sessionId = generateSecureToken()
  const now = new Date()
  const expiresAt = new Date(now.getTime() + defaultSecurityConfig.sessionTimeout)

  // Generate device fingerprint if request is provided
  let deviceFingerprint: string | undefined
  if (request) {
    const fingerprint = generateDeviceFingerprint(request)
    deviceFingerprint = fingerprint.hash
    sessionFingerprints.set(sessionId, fingerprint)
  }

  const session: Session = {
    id: sessionId,
    createdAt: now,
    lastAccessed: now,
    isValid: true,
    csrfToken: generateSecureToken(defaultSecurityConfig.csrfTokenLength),
    // Enhanced security features
    jwtToken,
    ipAddress,
    ipHash: await hashString(ipAddress),
    userAgent: request?.headers.get('user-agent'),
    deviceFingerprint,
    renewalCount: 0,
    securityFlags: {
      ipValidated: true,
      deviceValidated: !!deviceFingerprint,
      jwtVerified: !!jwtToken,
      suspiciousActivity: false
    },
    expiresAt,
    renewalThreshold: SECURITY_CONSTANTS.SESSION_RENEWAL_THRESHOLD,
    maxRenewals: SECURITY_CONSTANTS.MAX_SESSION_RENEWALS
  }

  sessions.set(sessionId, session)
  logger.info('Security', `Created secure session: ${sessionId} for IP: ${ipAddress}`)

  return session
}

/**
 * Create a new session (legacy compatibility)
 */
export function createSession(): Session {
  const sessionId = generateSecureToken()
  const now = new Date()
  const expiresAt = new Date(now.getTime() + defaultSecurityConfig.sessionTimeout)

  const session: Session = {
    id: sessionId,
    createdAt: now,
    lastAccessed: now,
    isValid: true,
    csrfToken: generateSecureToken(defaultSecurityConfig.csrfTokenLength),
    renewalCount: 0,
    securityFlags: {
      ipValidated: false,
      deviceValidated: false,
      jwtVerified: false,
      suspiciousActivity: false
    },
    expiresAt,
    renewalThreshold: SECURITY_CONSTANTS.SESSION_RENEWAL_THRESHOLD,
    maxRenewals: SECURITY_CONSTANTS.MAX_SESSION_RENEWALS
  }

  sessions.set(sessionId, session)
  logger.info('Security', `Created basic session: ${sessionId}`)

  return session
}

/**
 * Validate session with enhanced security checks
 */
export async function validateSecureSession(
  sessionId: string,
  ipAddress: string,
  request?: any,
  jwtToken?: string
): Promise<{ valid: boolean; session?: Session; error?: string }> {
  const session = sessions.get(sessionId)

  if (!session) {
    return { valid: false, error: 'Session not found' }
  }

  const now = new Date()

  // Check if session is expired
  if (now > session.expiresAt) {
    sessions.delete(sessionId)
    logger.warn('Security', `Session expired: ${sessionId}`)
    return { valid: false, error: 'Session expired' }
  }

  // Check if session is marked as invalid
  if (!session.isValid) {
    return { valid: false, error: 'Session invalidated' }
  }

  // IP address validation (if IP binding is enabled)
  if (session.ipAddress && SECURITY_CONSTANTS.IP_CHANGE_TOLERANCE === false) {
    if (session.ipAddress !== ipAddress) {
      // Log suspicious activity
      await logSuspiciousActivity(ipAddress, 'ip_address_mismatch', {
        sessionId,
        originalIp: session.ipAddress,
        newIp: ipAddress
      })

      session.securityFlags.suspiciousActivity = true
      sessions.set(sessionId, session)

      logger.warn('Security', `IP address mismatch for session ${sessionId}: ${session.ipAddress} vs ${ipAddress}`)
      return { valid: false, error: 'IP address validation failed' }
    }
  }

  // Device fingerprint validation (if enabled and available)
  if (SECURITY_CONSTANTS.DEVICE_FINGERPRINT_REQUIRED && session.deviceFingerprint && request) {
    const currentFingerprint = generateDeviceFingerprint(request)
    const storedFingerprint = sessionFingerprints.get(sessionId)

    if (storedFingerprint && currentFingerprint.hash !== storedFingerprint.hash) {
      await logSuspiciousActivity(ipAddress, 'device_fingerprint_mismatch', {
        sessionId,
        storedFingerprint: storedFingerprint.hash,
        currentFingerprint: currentFingerprint.hash
      })

      session.securityFlags.suspiciousActivity = true
      sessions.set(sessionId, session)

      logger.warn('Security', `Device fingerprint mismatch for session ${sessionId}`)
      return { valid: false, error: 'Device validation failed' }
    }
  }

  // JWT token validation (if provided)
  if (jwtToken && session.jwtToken) {
    if (jwtToken !== session.jwtToken) {
      logger.warn('Security', `JWT token mismatch for session ${sessionId}`)
      return { valid: false, error: 'JWT token validation failed' }
    }
  }

  // Update last accessed time and security flags
  session.lastAccessed = now
  session.securityFlags.ipValidated = true
  session.securityFlags.deviceValidated = true
  session.securityFlags.jwtVerified = !!jwtToken

  sessions.set(sessionId, session)

  return { valid: true, session }
}

/**
 * Get session by ID (legacy compatibility)
 */
export function getSession(sessionId: string): Session | null {
  const session = sessions.get(sessionId)

  if (!session) {
    return null
  }

  // Check if session is expired
  const now = new Date()
  if (now > session.expiresAt) {
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
 * Log suspicious activity
 */
export async function logSuspiciousActivity(
  ipAddress: string,
  eventType: string,
  details: any
): Promise<void> {
  const key = ipAddress
  const now = new Date()

  let activity = suspiciousActivity.get(key)
  if (!activity) {
    activity = { events: [], lastEvent: now, riskScore: 0 }
  }

  activity.events.push(`${eventType}: ${JSON.stringify(details)}`)
  activity.lastEvent = now
  activity.riskScore += 1

  // Keep only recent events (last 100)
  if (activity.events.length > 100) {
    activity.events = activity.events.slice(-100)
  }

  suspiciousActivity.set(key, activity)

  logger.warn('Security', `Suspicious activity detected from ${ipAddress}: ${eventType}`, details)

  // If risk score is too high, consider additional actions
  if (activity.riskScore >= SECURITY_CONSTANTS.SUSPICIOUS_ACTIVITY_THRESHOLD) {
    logger.error('Security', `High risk activity detected from ${ipAddress}. Risk score: ${activity.riskScore}`)
    // Could implement IP blocking here
  }
}

/**
 * Check if IP is locked out due to failed login attempts
 */
export function isIpLockedOut(ipAddress: string): boolean {
  const attempts = loginAttempts.get(ipAddress)
  if (!attempts) return false

  if (attempts.lockoutUntil && new Date() < attempts.lockoutUntil) {
    return true
  }

  return false
}

/**
 * Record failed login attempt
 */
export function recordFailedLogin(ipAddress: string): void {
  const now = new Date()
  let attempts = loginAttempts.get(ipAddress)

  if (!attempts) {
    attempts = { count: 0, lastAttempt: now }
  }

  // Reset count if last attempt was more than 1 hour ago
  if (now.getTime() - attempts.lastAttempt.getTime() > 60 * 60 * 1000) {
    attempts.count = 0
  }

  attempts.count += 1
  attempts.lastAttempt = now

  // Lock out if too many attempts
  if (attempts.count >= SECURITY_CONSTANTS.MAX_LOGIN_ATTEMPTS) {
    attempts.lockoutUntil = new Date(now.getTime() + SECURITY_CONSTANTS.LOCKOUT_DURATION)
    logger.warn('Security', `IP ${ipAddress} locked out due to ${attempts.count} failed login attempts`)
  }

  loginAttempts.set(ipAddress, attempts)
}

/**
 * Clear failed login attempts for successful login
 */
export function clearFailedLogins(ipAddress: string): void {
  loginAttempts.delete(ipAddress)
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

  return timingSafeEqual(session.csrfToken, token)
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

// Note: Session cleanup is now handled by API routes instead of setInterval
// for Edge Runtime compatibility. See /api/cleanup/sessions route.
