/**
 * Authentication Rate Limiter
 * Implements rate limiting and account lockout for authentication attempts
 */

import { NextRequest } from 'next/server'
import { getClientIP } from './security'
import { logger } from '@/utils/logger'

export interface RateLimitConfig {
  windowMs: number // Time window in milliseconds
  maxAttempts: number // Maximum attempts per window
  lockoutDuration: number // Lockout duration in milliseconds
  progressiveLockout: boolean // Enable progressive lockout
  blockSuspiciousIPs: boolean // Block IPs with suspicious patterns
}

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetTime: number
  lockoutUntil?: number
  reason?: string
}

export interface LoginAttempt {
  ip: string
  timestamp: number
  success: boolean
  userAgent?: string
  endpoint?: string
  sessionId?: string
}

export interface IPLockout {
  ip: string
  lockedAt: number
  lockoutUntil: number
  attemptCount: number
  reason: string
  progressiveLevel: number
}

// Rate limiting configurations for different endpoints
const RATE_LIMIT_CONFIGS: Record<string, RateLimitConfig> = {
  login: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
    progressiveLockout: true,
    blockSuspiciousIPs: true
  },
  session_validation: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    maxAttempts: 50,
    lockoutDuration: 5 * 60 * 1000, // 5 minutes
    progressiveLockout: false,
    blockSuspiciousIPs: true
  },
  password_reset: {
    windowMs: 60 * 60 * 1000, // 1 hour
    maxAttempts: 3,
    lockoutDuration: 60 * 60 * 1000, // 1 hour
    progressiveLockout: true,
    blockSuspiciousIPs: true
  }
}

export class AuthRateLimiter {
  private static instance: AuthRateLimiter
  private attempts = new Map<string, LoginAttempt[]>()
  private lockouts = new Map<string, IPLockout>()
  private suspiciousIPs = new Set<string>()

  static getInstance(): AuthRateLimiter {
    if (!AuthRateLimiter.instance) {
      AuthRateLimiter.instance = new AuthRateLimiter()
    }
    return AuthRateLimiter.instance
  }

  /**
   * Check if request is rate limited
   */
  checkRateLimit(request: NextRequest, endpoint: string = 'login'): RateLimitResult {
    const ip = getClientIP(request)
    const config = RATE_LIMIT_CONFIGS[endpoint] || RATE_LIMIT_CONFIGS.login
    const now = Date.now()
    const key = `${ip}:${endpoint}`

    // Check if IP is currently locked out
    const lockout = this.lockouts.get(ip)
    if (lockout && now < lockout.lockoutUntil) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: lockout.lockoutUntil,
        lockoutUntil: lockout.lockoutUntil,
        reason: `IP locked out: ${lockout.reason}`
      }
    }

    // Clean up expired lockouts
    if (lockout && now >= lockout.lockoutUntil) {
      this.lockouts.delete(ip)
    }

    // Check if IP is marked as suspicious
    if (config.blockSuspiciousIPs && this.suspiciousIPs.has(ip)) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: now + config.lockoutDuration,
        reason: 'IP marked as suspicious'
      }
    }

    // Get recent attempts for this IP and endpoint
    const attempts = this.attempts.get(key) || []
    const windowStart = now - config.windowMs

    // Filter attempts within the current window
    const recentAttempts = attempts.filter(attempt => attempt.timestamp > windowStart)
    
    // Update the attempts array
    this.attempts.set(key, recentAttempts)

    // Count failed attempts
    const failedAttempts = recentAttempts.filter(attempt => !attempt.success)

    if (failedAttempts.length >= config.maxAttempts) {
      // Create lockout
      this.createLockout(ip, endpoint, failedAttempts.length, config)
      
      return {
        allowed: false,
        remaining: 0,
        resetTime: now + config.lockoutDuration,
        lockoutUntil: now + config.lockoutDuration,
        reason: 'Rate limit exceeded'
      }
    }

    return {
      allowed: true,
      remaining: config.maxAttempts - failedAttempts.length,
      resetTime: windowStart + config.windowMs
    }
  }

  /**
   * Record authentication attempt
   */
  recordAttempt(
    request: NextRequest,
    endpoint: string,
    success: boolean,
    sessionId?: string
  ): void {
    const ip = getClientIP(request)
    const key = `${ip}:${endpoint}`
    const now = Date.now()

    const attempt: LoginAttempt = {
      ip,
      timestamp: now,
      success,
      userAgent: request.headers.get('user-agent') || undefined,
      endpoint,
      sessionId
    }

    const attempts = this.attempts.get(key) || []
    attempts.push(attempt)

    // Keep only recent attempts (last 24 hours)
    const dayAgo = now - 24 * 60 * 60 * 1000
    const recentAttempts = attempts.filter(a => a.timestamp > dayAgo)
    this.attempts.set(key, recentAttempts)

    // Analyze patterns for suspicious activity
    if (!success) {
      this.analyzeSuspiciousActivity(ip, recentAttempts)
    }

    logger.info('AuthRateLimiter', `Recorded ${success ? 'successful' : 'failed'} ${endpoint} attempt from ${ip}`)
  }

  /**
   * Create IP lockout with progressive penalties
   */
  private createLockout(
    ip: string,
    endpoint: string,
    attemptCount: number,
    config: RateLimitConfig
  ): void {
    const now = Date.now()
    const existingLockout = this.lockouts.get(ip)
    
    let progressiveLevel = 1
    let lockoutDuration = config.lockoutDuration

    if (config.progressiveLockout && existingLockout) {
      // Progressive lockout - increase duration for repeat offenders
      progressiveLevel = existingLockout.progressiveLevel + 1
      lockoutDuration = config.lockoutDuration * Math.pow(2, progressiveLevel - 1)
      
      // Cap at 24 hours
      lockoutDuration = Math.min(lockoutDuration, 24 * 60 * 60 * 1000)
    }

    const lockout: IPLockout = {
      ip,
      lockedAt: now,
      lockoutUntil: now + lockoutDuration,
      attemptCount,
      reason: `Too many failed ${endpoint} attempts`,
      progressiveLevel
    }

    this.lockouts.set(ip, lockout)

    logger.warn('AuthRateLimiter', 
      `IP ${ip} locked out for ${lockoutDuration / 1000}s (level ${progressiveLevel}) due to ${attemptCount} failed ${endpoint} attempts`
    )
  }

  /**
   * Analyze patterns for suspicious activity
   */
  private analyzeSuspiciousActivity(ip: string, attempts: LoginAttempt[]): void {
    const now = Date.now()
    const lastHour = now - 60 * 60 * 1000
    const recentAttempts = attempts.filter(a => a.timestamp > lastHour)
    
    // Check for suspicious patterns
    const failedAttempts = recentAttempts.filter(a => !a.success)
    const uniqueUserAgents = new Set(recentAttempts.map(a => a.userAgent)).size
    const attemptFrequency = recentAttempts.length / (60 * 60) // attempts per second

    let suspiciousScore = 0

    // High frequency of attempts
    if (attemptFrequency > 0.1) { // More than 1 attempt per 10 seconds
      suspiciousScore += 2
    }

    // High failure rate
    if (failedAttempts.length > 10) {
      suspiciousScore += 3
    }

    // Multiple user agents (possible bot)
    if (uniqueUserAgents > 3) {
      suspiciousScore += 2
    }

    // Rapid-fire attempts (less than 1 second apart)
    const rapidAttempts = recentAttempts.filter((attempt, index) => {
      if (index === 0) return false
      return attempt.timestamp - recentAttempts[index - 1].timestamp < 1000
    })
    
    if (rapidAttempts.length > 3) {
      suspiciousScore += 3
    }

    // Mark as suspicious if score is high
    if (suspiciousScore >= 5) {
      this.suspiciousIPs.add(ip)
      logger.error('AuthRateLimiter', 
        `IP ${ip} marked as suspicious (score: ${suspiciousScore}). Recent attempts: ${recentAttempts.length}, Failed: ${failedAttempts.length}`
      )
    }
  }

  /**
   * Clear failed attempts for successful authentication
   */
  clearFailedAttempts(ip: string, endpoint: string = 'login'): void {
    const key = `${ip}:${endpoint}`
    const attempts = this.attempts.get(key) || []
    
    // Keep only successful attempts
    const successfulAttempts = attempts.filter(attempt => attempt.success)
    this.attempts.set(key, successfulAttempts)
    
    // Remove from suspicious IPs if present
    this.suspiciousIPs.delete(ip)
    
    logger.info('AuthRateLimiter', `Cleared failed attempts for ${ip}:${endpoint}`)
  }

  /**
   * Manually unlock IP address
   */
  unlockIP(ip: string, reason: string = 'manual unlock'): boolean {
    const lockout = this.lockouts.get(ip)
    if (lockout) {
      this.lockouts.delete(ip)
      this.suspiciousIPs.delete(ip)
      logger.info('AuthRateLimiter', `Manually unlocked IP ${ip}: ${reason}`)
      return true
    }
    return false
  }

  /**
   * Get lockout status for IP
   */
  getLockoutStatus(ip: string): IPLockout | null {
    const lockout = this.lockouts.get(ip)
    if (lockout && Date.now() < lockout.lockoutUntil) {
      return lockout
    }
    return null
  }

  /**
   * Get recent attempts for IP
   */
  getRecentAttempts(ip: string, endpoint?: string): LoginAttempt[] {
    if (endpoint) {
      const key = `${ip}:${endpoint}`
      return this.attempts.get(key) || []
    }
    
    // Get all attempts for IP across all endpoints
    const allAttempts: LoginAttempt[] = []
    for (const [key, attempts] of this.attempts.entries()) {
      if (key.startsWith(`${ip}:`)) {
        allAttempts.push(...attempts)
      }
    }
    
    return allAttempts.sort((a, b) => b.timestamp - a.timestamp)
  }

  /**
   * Clean up old data
   */
  cleanup(): void {
    const now = Date.now()
    const dayAgo = now - 24 * 60 * 60 * 1000

    // Clean up old attempts
    for (const [key, attempts] of this.attempts.entries()) {
      const recentAttempts = attempts.filter(a => a.timestamp > dayAgo)
      if (recentAttempts.length === 0) {
        this.attempts.delete(key)
      } else {
        this.attempts.set(key, recentAttempts)
      }
    }

    // Clean up expired lockouts
    for (const [ip, lockout] of this.lockouts.entries()) {
      if (now >= lockout.lockoutUntil) {
        this.lockouts.delete(ip)
      }
    }

    logger.info('AuthRateLimiter', 'Completed cleanup of old rate limiting data')
  }
}

// Export singleton instance
export const authRateLimiter = AuthRateLimiter.getInstance()

// Schedule periodic cleanup
if (typeof setInterval !== 'undefined') {
  setInterval(() => {
    authRateLimiter.cleanup()
  }, 60 * 60 * 1000) // Clean up every hour
}
