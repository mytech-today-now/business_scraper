/**
 * Enhanced Password Security Implementation
 * Implements comprehensive password security with strength validation, secure hashing, and password history tracking
 */

import bcrypt from 'bcryptjs'
import zxcvbn from 'zxcvbn'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

export interface PasswordSecurityConfig {
  minLength: number
  requireUppercase: boolean
  requireLowercase: boolean
  requireNumbers: boolean
  requireSpecialChars: boolean
  maxAge: number // in milliseconds
  preventReuse: number // number of previous passwords to check
  minStrengthScore: number // zxcvbn score (0-4)
  saltRounds: number // bcrypt salt rounds
}

export interface PasswordValidationResult {
  isValid: boolean
  score: number
  feedback: string[]
  errors: string[]
  warning?: string
}

export interface PasswordHashResult {
  hash: string
  salt: string
  algorithm: string
  iterations: number
  createdAt: Date
}

export interface PasswordHistoryEntry {
  hash: string
  salt: string
  algorithm: string
  createdAt: Date
  expiresAt: Date
}

// Enhanced password security configuration
export const passwordSecurityConfig: PasswordSecurityConfig = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  maxAge: 90 * 24 * 60 * 60 * 1000, // 90 days
  preventReuse: 12, // Last 12 passwords
  minStrengthScore: 3, // Strong password required
  saltRounds: 14, // High cost factor for bcrypt
}

// In-memory password history store (in production, this should be in database)
const passwordHistory = new Map<string, PasswordHistoryEntry[]>()

export class PasswordSecurityService {
  private static instance: PasswordSecurityService

  static getInstance(): PasswordSecurityService {
    if (!PasswordSecurityService.instance) {
      PasswordSecurityService.instance = new PasswordSecurityService()
    }
    return PasswordSecurityService.instance
  }

  /**
   * Validate password strength and complexity
   */
  validatePasswordStrength(password: string, userInputs: string[] = []): PasswordValidationResult {
    const errors: string[] = []
    const feedback: string[] = []

    // Basic length check
    if (password.length < passwordSecurityConfig.minLength) {
      errors.push(`Password must be at least ${passwordSecurityConfig.minLength} characters long`)
    }

    // Character requirements
    if (passwordSecurityConfig.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter')
    }

    if (passwordSecurityConfig.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter')
    }

    if (passwordSecurityConfig.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number')
    }

    if (passwordSecurityConfig.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character')
    }

    // Use zxcvbn for advanced strength analysis
    const strengthAnalysis = zxcvbn(password, userInputs)

    // Check minimum strength score
    if (strengthAnalysis.score < passwordSecurityConfig.minStrengthScore) {
      errors.push(`Password is too weak. Current strength: ${strengthAnalysis.score}/4, required: ${passwordSecurityConfig.minStrengthScore}/4`)
    }

    // Add zxcvbn feedback
    if (strengthAnalysis.feedback.warning) {
      feedback.push(strengthAnalysis.feedback.warning)
    }
    feedback.push(...strengthAnalysis.feedback.suggestions)

    return {
      isValid: errors.length === 0,
      score: strengthAnalysis.score,
      feedback,
      errors,
      warning: strengthAnalysis.feedback.warning
    }
  }

  /**
   * Hash password using bcrypt with high cost factor
   */
  async hashPassword(password: string): Promise<PasswordHashResult> {
    try {
      // Validate password strength first
      const validation = this.validatePasswordStrength(password)
      if (!validation.isValid) {
        throw new Error(`Password validation failed: ${validation.errors.join(', ')}`)
      }

      // Generate salt and hash
      const salt = await bcrypt.genSalt(passwordSecurityConfig.saltRounds)
      const hash = await bcrypt.hash(password, salt)

      const result: PasswordHashResult = {
        hash,
        salt,
        algorithm: 'bcrypt',
        iterations: passwordSecurityConfig.saltRounds,
        createdAt: new Date()
      }

      logger.info('PasswordSecurity', 'Password hashed successfully with enhanced security')
      
      return result
    } catch (error) {
      logger.error('PasswordSecurity', 'Failed to hash password', error)
      throw new Error('Password hashing failed')
    }
  }

  /**
   * Verify password against hash
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      const isValid = await bcrypt.compare(password, hash)
      
      // Log verification attempt
      await auditService.logSecurityEvent('password_verification', {
        success: isValid,
        timestamp: new Date()
      })

      return isValid
    } catch (error) {
      logger.error('PasswordSecurity', 'Password verification failed', error)
      await auditService.logSecurityEvent('password_verification_error', {
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date()
      })
      return false
    }
  }

  /**
   * Check if password has been used recently (password history)
   */
  async checkPasswordHistory(userId: string, newPassword: string): Promise<boolean> {
    const userHistory = passwordHistory.get(userId) || []
    
    // Clean up expired entries
    const now = new Date()
    const validHistory = userHistory.filter(entry => entry.expiresAt > now)
    passwordHistory.set(userId, validHistory)

    // Check against recent passwords
    for (const entry of validHistory) {
      const isReused = await bcrypt.compare(newPassword, entry.hash)
      if (isReused) {
        logger.warn('PasswordSecurity', `Password reuse detected for user ${userId}`)
        await auditService.logSecurityEvent('password_reuse_attempt', {
          userId,
          timestamp: new Date()
        })
        return true
      }
    }

    return false
  }

  /**
   * Add password to history
   */
  async addToPasswordHistory(userId: string, passwordHash: PasswordHashResult): Promise<void> {
    const userHistory = passwordHistory.get(userId) || []
    
    const historyEntry: PasswordHistoryEntry = {
      hash: passwordHash.hash,
      salt: passwordHash.salt,
      algorithm: passwordHash.algorithm,
      createdAt: passwordHash.createdAt,
      expiresAt: new Date(Date.now() + passwordSecurityConfig.maxAge)
    }

    userHistory.push(historyEntry)

    // Keep only the last N passwords
    if (userHistory.length > passwordSecurityConfig.preventReuse) {
      userHistory.splice(0, userHistory.length - passwordSecurityConfig.preventReuse)
    }

    passwordHistory.set(userId, userHistory)
    
    logger.info('PasswordSecurity', `Added password to history for user ${userId}`)
  }

  /**
   * Check if password needs to be changed (age-based)
   */
  isPasswordExpired(passwordCreatedAt: Date): boolean {
    const now = new Date()
    const ageMs = now.getTime() - passwordCreatedAt.getTime()
    return ageMs > passwordSecurityConfig.maxAge
  }

  /**
   * Generate secure password suggestion
   */
  generateSecurePassword(length: number = 16): string {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    const lowercase = 'abcdefghijklmnopqrstuvwxyz'
    const numbers = '0123456789'
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    const allChars = uppercase + lowercase + numbers + special
    let password = ''

    // Ensure at least one character from each required set
    password += uppercase[Math.floor(Math.random() * uppercase.length)]
    password += lowercase[Math.floor(Math.random() * lowercase.length)]
    password += numbers[Math.floor(Math.random() * numbers.length)]
    password += special[Math.floor(Math.random() * special.length)]

    // Fill the rest randomly
    for (let i = 4; i < length; i++) {
      password += allChars[Math.floor(Math.random() * allChars.length)]
    }

    // Shuffle the password
    return password.split('').sort(() => Math.random() - 0.5).join('')
  }

  /**
   * Get password security metrics
   */
  getPasswordSecurityMetrics(userId: string): {
    historyCount: number
    oldestPasswordAge: number | null
    newestPasswordAge: number | null
  } {
    const userHistory = passwordHistory.get(userId) || []
    const now = new Date()

    if (userHistory.length === 0) {
      return {
        historyCount: 0,
        oldestPasswordAge: null,
        newestPasswordAge: null
      }
    }

    const ages = userHistory.map(entry => now.getTime() - entry.createdAt.getTime())
    
    return {
      historyCount: userHistory.length,
      oldestPasswordAge: Math.max(...ages),
      newestPasswordAge: Math.min(...ages)
    }
  }
}

// Export singleton instance
export const passwordSecurity = PasswordSecurityService.getInstance()
