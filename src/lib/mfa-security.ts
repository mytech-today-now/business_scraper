/**
 * Multi-Factor Authentication (MFA) Security Implementation
 * Enhanced MFA implementation with TOTP, backup codes, and security hardening
 */

import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import crypto from 'crypto'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

export interface MFAConfig {
  issuer: string
  window: number // Time step tolerance
  step: number // Time step in seconds
  secretLength: number
  backupCodeCount: number
  backupCodeLength: number
  maxFailedAttempts: number
  lockoutDuration: number // in milliseconds
}

export interface MFASecret {
  secret: string
  qrCodeUrl: string
  qrCodeDataUrl: string
  backupCodes: string[]
  createdAt: Date
}

export interface MFAVerificationResult {
  success: boolean
  usedBackupCode?: boolean
  remainingBackupCodes?: number
  error?: string
  lockoutUntil?: Date
}

export interface MFAStatus {
  enabled: boolean
  verified: boolean
  secretConfigured: boolean
  backupCodesRemaining: number
  lastUsed?: Date
  failedAttempts: number
  lockedUntil?: Date
}

// MFA configuration
export const mfaConfig: MFAConfig = {
  issuer: 'Business Scraper App',
  window: 1, // Allow 1 time step tolerance (30 seconds before/after)
  step: 30, // 30 second time step
  secretLength: 32, // 32 byte secret
  backupCodeCount: 10, // 10 backup codes
  backupCodeLength: 8, // 8 character backup codes
  maxFailedAttempts: 5, // Max failed attempts before lockout
  lockoutDuration: 15 * 60 * 1000, // 15 minutes lockout
}

// In-memory MFA data store (in production, this should be in database)
const mfaSecrets = new Map<string, { secret: string; verified: boolean; createdAt: Date }>()
const backupCodes = new Map<string, Set<string>>()
const mfaAttempts = new Map<string, { count: number; lastAttempt: Date; lockoutUntil?: Date }>()

export class MFASecurityService {
  private static instance: MFASecurityService

  static getInstance(): MFASecurityService {
    if (!MFASecurityService.instance) {
      MFASecurityService.instance = new MFASecurityService()
    }
    return MFASecurityService.instance
  }

  /**
   * Generate MFA secret and QR code for user
   */
  async generateMFASecret(userId: string, userEmail: string): Promise<MFASecret> {
    try {
      // Generate secret
      const secret = speakeasy.generateSecret({
        name: `${mfaConfig.issuer} (${userEmail})`,
        issuer: mfaConfig.issuer,
        length: mfaConfig.secretLength
      })

      if (!secret.base32) {
        throw new Error('Failed to generate MFA secret')
      }

      // Generate QR code data URL
      const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url!)

      // Generate backup codes
      const backupCodesList = this.generateBackupCodes()

      // Store secret (not verified yet)
      mfaSecrets.set(userId, {
        secret: secret.base32,
        verified: false,
        createdAt: new Date()
      })

      // Store backup codes
      backupCodes.set(userId, new Set(backupCodesList))

      // Log MFA setup initiation
      await auditService.logSecurityEvent('mfa_setup_initiated', {
        userId,
        timestamp: new Date()
      })

      logger.info('MFASecurity', `Generated MFA secret for user ${userId}`)

      return {
        secret: secret.base32,
        qrCodeUrl: secret.otpauth_url!,
        qrCodeDataUrl,
        backupCodes: backupCodesList,
        createdAt: new Date()
      }
    } catch (error) {
      logger.error('MFASecurity', 'Failed to generate MFA secret', error)
      throw new Error('MFA secret generation failed')
    }
  }

  /**
   * Verify TOTP token and complete MFA setup
   */
  async verifyMFASetup(userId: string, token: string): Promise<boolean> {
    try {
      const userMFA = mfaSecrets.get(userId)
      if (!userMFA) {
        throw new Error('No MFA secret found for user')
      }

      const isValid = speakeasy.totp.verify({
        secret: userMFA.secret,
        encoding: 'base32',
        token,
        window: mfaConfig.window,
        step: mfaConfig.step
      })

      if (isValid) {
        // Mark as verified
        userMFA.verified = true
        mfaSecrets.set(userId, userMFA)

        // Log successful MFA setup
        await auditService.logSecurityEvent('mfa_setup_completed', {
          userId,
          timestamp: new Date()
        })

        logger.info('MFASecurity', `MFA setup completed for user ${userId}`)
        return true
      } else {
        // Log failed setup attempt
        await auditService.logSecurityEvent('mfa_setup_failed', {
          userId,
          reason: 'invalid_token',
          timestamp: new Date()
        })

        logger.warn('MFASecurity', `MFA setup failed for user ${userId} - invalid token`)
        return false
      }
    } catch (error) {
      logger.error('MFASecurity', 'MFA setup verification failed', error)
      await auditService.logSecurityEvent('mfa_setup_error', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date()
      })
      return false
    }
  }

  /**
   * Verify MFA token during authentication
   */
  async verifyMFAToken(userId: string, token: string): Promise<MFAVerificationResult> {
    try {
      // Check if user is locked out
      const attempts = mfaAttempts.get(userId)
      if (attempts?.lockoutUntil && new Date() < attempts.lockoutUntil) {
        return {
          success: false,
          error: 'Account temporarily locked due to too many failed MFA attempts',
          lockoutUntil: attempts.lockoutUntil
        }
      }

      const userMFA = mfaSecrets.get(userId)
      if (!userMFA || !userMFA.verified) {
        return {
          success: false,
          error: 'MFA not configured for user'
        }
      }

      // Try TOTP verification first
      const isTOTPValid = speakeasy.totp.verify({
        secret: userMFA.secret,
        encoding: 'base32',
        token,
        window: mfaConfig.window,
        step: mfaConfig.step
      })

      if (isTOTPValid) {
        // Clear failed attempts
        mfaAttempts.delete(userId)

        await auditService.logSecurityEvent('mfa_verification_success', {
          userId,
          method: 'totp',
          timestamp: new Date()
        })

        return { success: true }
      }

      // Try backup code verification
      const userBackupCodes = backupCodes.get(userId)
      if (userBackupCodes && userBackupCodes.has(token.toUpperCase())) {
        // Remove used backup code
        userBackupCodes.delete(token.toUpperCase())
        backupCodes.set(userId, userBackupCodes)

        // Clear failed attempts
        mfaAttempts.delete(userId)

        await auditService.logSecurityEvent('mfa_verification_success', {
          userId,
          method: 'backup_code',
          remainingCodes: userBackupCodes.size,
          timestamp: new Date()
        })

        return {
          success: true,
          usedBackupCode: true,
          remainingBackupCodes: userBackupCodes.size
        }
      }

      // Failed verification - track attempts
      this.recordFailedMFAAttempt(userId)

      await auditService.logSecurityEvent('mfa_verification_failed', {
        userId,
        timestamp: new Date()
      })

      return {
        success: false,
        error: 'Invalid MFA token'
      }
    } catch (error) {
      logger.error('MFASecurity', 'MFA verification failed', error)
      return {
        success: false,
        error: 'MFA verification error'
      }
    }
  }

  /**
   * Generate new backup codes
   */
  generateBackupCodes(): string[] {
    const codes: string[] = []
    for (let i = 0; i < mfaConfig.backupCodeCount; i++) {
      codes.push(crypto.randomBytes(mfaConfig.backupCodeLength / 2).toString('hex').toUpperCase())
    }
    return codes
  }

  /**
   * Regenerate backup codes for user
   */
  async regenerateBackupCodes(userId: string): Promise<string[]> {
    const userMFA = mfaSecrets.get(userId)
    if (!userMFA || !userMFA.verified) {
      throw new Error('MFA not configured for user')
    }

    const newCodes = this.generateBackupCodes()
    backupCodes.set(userId, new Set(newCodes))

    await auditService.logSecurityEvent('mfa_backup_codes_regenerated', {
      userId,
      timestamp: new Date()
    })

    logger.info('MFASecurity', `Regenerated backup codes for user ${userId}`)
    return newCodes
  }

  /**
   * Disable MFA for user
   */
  async disableMFA(userId: string): Promise<void> {
    mfaSecrets.delete(userId)
    backupCodes.delete(userId)
    mfaAttempts.delete(userId)

    await auditService.logSecurityEvent('mfa_disabled', {
      userId,
      timestamp: new Date()
    })

    logger.info('MFASecurity', `MFA disabled for user ${userId}`)
  }

  /**
   * Get MFA status for user
   */
  getMFAStatus(userId: string): MFAStatus {
    const userMFA = mfaSecrets.get(userId)
    const userBackupCodes = backupCodes.get(userId)
    const attempts = mfaAttempts.get(userId)

    return {
      enabled: !!userMFA,
      verified: userMFA?.verified || false,
      secretConfigured: !!userMFA?.secret,
      backupCodesRemaining: userBackupCodes?.size || 0,
      failedAttempts: attempts?.count || 0,
      lockedUntil: attempts?.lockoutUntil
    }
  }

  /**
   * Record failed MFA attempt
   */
  private recordFailedMFAAttempt(userId: string): void {
    const now = new Date()
    const attempts = mfaAttempts.get(userId) || { count: 0, lastAttempt: now }

    attempts.count++
    attempts.lastAttempt = now

    if (attempts.count >= mfaConfig.maxFailedAttempts) {
      attempts.lockoutUntil = new Date(now.getTime() + mfaConfig.lockoutDuration)
      logger.warn('MFASecurity', `User ${userId} locked out due to ${attempts.count} failed MFA attempts`)
    }

    mfaAttempts.set(userId, attempts)
  }

  /**
   * Check if MFA is required for user
   */
  isMFARequired(userId: string): boolean {
    const userMFA = mfaSecrets.get(userId)
    return userMFA?.verified || false
  }
}

// Export singleton instance
export const mfaSecurity = MFASecurityService.getInstance()
