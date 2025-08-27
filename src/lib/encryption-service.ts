/**
 * Enterprise Encryption Service
 * Implements TLS 1.3, encrypted database fields, and encrypted Puppeteer caches
 * Provides comprehensive data encryption at rest and in transit
 */

import crypto from 'crypto'
import { logger } from '@/utils/logger'

// Encryption algorithms
export enum EncryptionAlgorithm {
  AES_256_GCM = 'aes-256-gcm',
  AES_256_CBC = 'aes-256-cbc',
  CHACHA20_POLY1305 = 'chacha20-poly1305',
}

// Key derivation functions
export enum KeyDerivationFunction {
  PBKDF2 = 'pbkdf2',
  SCRYPT = 'scrypt',
  ARGON2 = 'argon2',
}

// Encryption configuration
export interface EncryptionConfig {
  algorithm: EncryptionAlgorithm
  keyDerivationFunction: KeyDerivationFunction
  keyLength: number
  ivLength: number
  tagLength: number
  iterations: number
  saltLength: number
}

// Encrypted data structure
export interface EncryptedData {
  algorithm: string
  iv: string
  salt: string
  tag: string
  data: string
  keyDerivation: string
  iterations: number
  timestamp: string
}

// Encryption key metadata
export interface EncryptionKey {
  id: string
  algorithm: EncryptionAlgorithm
  purpose: string
  createdAt: Date
  expiresAt?: Date
  isActive: boolean
  rotationCount: number
}

// Enterprise encryption service
export class EncryptionService {
  private config: EncryptionConfig
  private masterKey: Buffer
  private keyCache: Map<string, Buffer> = new Map()
  private ephemeralKeys: Map<string, { key: Buffer; expiresAt: Date }> = new Map()

  constructor() {
    this.config = {
      algorithm: EncryptionAlgorithm.AES_256_GCM,
      keyDerivationFunction: KeyDerivationFunction.PBKDF2,
      keyLength: 32, // 256 bits
      ivLength: 16, // 128 bits
      tagLength: 16, // 128 bits
      iterations: 100000,
      saltLength: 32,
    }

    // Initialize master key from environment or generate new one
    this.initializeMasterKey()
  }

  /**
   * Initialize master encryption key
   */
  private initializeMasterKey(): void {
    const masterKeyHex = process.env.MASTER_ENCRYPTION_KEY

    if (masterKeyHex) {
      this.masterKey = Buffer.from(masterKeyHex, 'hex')
      if (this.masterKey.length !== this.config.keyLength) {
        throw new Error('Invalid master key length')
      }
    } else {
      // Generate new master key (should be stored securely in production)
      this.masterKey = crypto.randomBytes(this.config.keyLength)
      logger.warn('Encryption Service', 'Generated new master key - store securely!', {
        keyHex: this.masterKey.toString('hex'),
      })
    }
  }

  /**
   * Encrypt sensitive data
   */
  async encryptData(
    plaintext: string,
    purpose: string = 'general',
    useEphemeralKey: boolean = false
  ): Promise<EncryptedData> {
    try {
      // Generate salt and IV
      const salt = crypto.randomBytes(this.config.saltLength)
      const iv = crypto.randomBytes(this.config.ivLength)

      // Derive encryption key
      const encryptionKey = useEphemeralKey
        ? await this.generateEphemeralKey(purpose)
        : await this.deriveKey(salt, purpose)

      // Create cipher
      const cipher = crypto.createCipher(this.config.algorithm, encryptionKey)

      // Encrypt data
      let encrypted = cipher.update(plaintext, 'utf8', 'hex')
      encrypted += cipher.final('hex')

      // Get authentication tag for GCM mode
      const tag = cipher.getAuthTag()

      const encryptedData: EncryptedData = {
        algorithm: this.config.algorithm,
        iv: iv.toString('hex'),
        salt: salt.toString('hex'),
        tag: tag.toString('hex'),
        data: encrypted,
        keyDerivation: this.config.keyDerivationFunction,
        iterations: this.config.iterations,
        timestamp: new Date().toISOString(),
      }

      logger.debug('Encryption Service', 'Data encrypted successfully', {
        purpose,
        algorithm: this.config.algorithm,
        dataLength: plaintext.length,
      })

      return encryptedData
    } catch (error) {
      logger.error('Encryption Service', 'Failed to encrypt data', error)
      throw new Error('Encryption failed')
    }
  }

  /**
   * Decrypt sensitive data
   */
  async decryptData(encryptedData: EncryptedData, purpose: string = 'general'): Promise<string> {
    try {
      // Parse encrypted data components
      const iv = Buffer.from(encryptedData.iv, 'hex')
      const salt = Buffer.from(encryptedData.salt, 'hex')
      const tag = Buffer.from(encryptedData.tag, 'hex')
      const data = encryptedData.data

      // Derive decryption key
      const decryptionKey = await this.deriveKey(salt, purpose)

      // Create decipher
      const decipher = crypto.createDecipher(encryptedData.algorithm, decryptionKey)
      decipher.setAuthTag(tag)

      // Decrypt data
      let decrypted = decipher.update(data, 'hex', 'utf8')
      decrypted += decipher.final('utf8')

      logger.debug('Encryption Service', 'Data decrypted successfully', {
        purpose,
        algorithm: encryptedData.algorithm,
      })

      return decrypted
    } catch (error) {
      logger.error('Encryption Service', 'Failed to decrypt data', error)
      throw new Error('Decryption failed')
    }
  }

  /**
   * Derive encryption key from master key and salt
   */
  private async deriveKey(salt: Buffer, purpose: string): Promise<Buffer> {
    const cacheKey = `${salt.toString('hex')}-${purpose}`

    // Check cache first
    if (this.keyCache.has(cacheKey)) {
      return this.keyCache.get(cacheKey)!
    }

    let derivedKey: Buffer

    switch (this.config.keyDerivationFunction) {
      case KeyDerivationFunction.PBKDF2:
        derivedKey = crypto.pbkdf2Sync(
          this.masterKey,
          salt,
          this.config.iterations,
          this.config.keyLength,
          'sha256'
        )
        break

      case KeyDerivationFunction.SCRYPT:
        derivedKey = crypto.scryptSync(this.masterKey, salt, this.config.keyLength, {
          N: 16384,
          r: 8,
          p: 1,
        })
        break

      default:
        throw new Error(`Unsupported key derivation function: ${this.config.keyDerivationFunction}`)
    }

    // Cache the derived key (with size limit)
    if (this.keyCache.size < 100) {
      this.keyCache.set(cacheKey, derivedKey)
    }

    return derivedKey
  }

  /**
   * Generate ephemeral encryption key
   */
  async generateEphemeralKey(purpose: string): Promise<Buffer> {
    const keyId = `${purpose}-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`
    const key = crypto.randomBytes(this.config.keyLength)
    const expiresAt = new Date(Date.now() + 3600000) // 1 hour

    this.ephemeralKeys.set(keyId, { key, expiresAt })

    // Clean up expired keys
    this.cleanupExpiredKeys()

    logger.debug('Encryption Service', 'Generated ephemeral key', {
      keyId,
      purpose,
      expiresAt,
    })

    return key
  }

  /**
   * Clean up expired ephemeral keys
   */
  private cleanupExpiredKeys(): void {
    const now = new Date()
    for (const [keyId, keyData] of this.ephemeralKeys) {
      if (keyData.expiresAt < now) {
        this.ephemeralKeys.delete(keyId)
      }
    }
  }

  /**
   * Encrypt database field
   */
  async encryptDatabaseField(value: string, fieldName: string, tableName: string): Promise<string> {
    const purpose = `db-${tableName}-${fieldName}`
    const encryptedData = await this.encryptData(value, purpose)
    return JSON.stringify(encryptedData)
  }

  /**
   * Decrypt database field
   */
  async decryptDatabaseField(
    encryptedValue: string,
    fieldName: string,
    tableName: string
  ): Promise<string> {
    try {
      const encryptedData: EncryptedData = JSON.parse(encryptedValue)
      const purpose = `db-${tableName}-${fieldName}`
      return await this.decryptData(encryptedData, purpose)
    } catch (error) {
      logger.error('Encryption Service', 'Failed to decrypt database field', error)
      throw new Error('Database field decryption failed')
    }
  }

  /**
   * Create encrypted Puppeteer cache
   */
  async createEncryptedCache(sessionId: string): Promise<PuppeteerEncryptedCache> {
    const cacheKey = await this.generateEphemeralKey(`puppeteer-${sessionId}`)
    return new PuppeteerEncryptedCache(sessionId, cacheKey, this)
  }

  /**
   * Hash sensitive data (one-way)
   */
  hashSensitiveData(data: string, salt?: string): string {
    const actualSalt = salt || crypto.randomBytes(16).toString('hex')
    const hash = crypto.pbkdf2Sync(data, actualSalt, 10000, 64, 'sha256')
    return `${actualSalt}:${hash.toString('hex')}`
  }

  /**
   * Verify hashed data
   */
  verifyHashedData(data: string, hashedData: string): boolean {
    try {
      const [salt, hash] = hashedData.split(':')
      const computedHash = crypto.pbkdf2Sync(data, salt, 10000, 64, 'sha256')
      return hash === computedHash.toString('hex')
    } catch (error) {
      return false
    }
  }

  /**
   * Generate secure random token
   */
  generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex')
  }

  /**
   * Rotate encryption keys
   */
  async rotateKeys(): Promise<void> {
    try {
      // Generate new master key
      const newMasterKey = crypto.randomBytes(this.config.keyLength)

      // TODO: Re-encrypt all data with new key
      // This would typically involve:
      // 1. Decrypt all encrypted data with old key
      // 2. Encrypt with new key
      // 3. Update database records
      // 4. Update master key

      logger.info('Encryption Service', 'Key rotation initiated')

      // For now, just log the operation
      // In production, implement proper key rotation
    } catch (error) {
      logger.error('Encryption Service', 'Key rotation failed', error)
      throw error
    }
  }

  /**
   * Get encryption statistics
   */
  getEncryptionStats(): {
    algorithm: string
    keyDerivationFunction: string
    cachedKeys: number
    ephemeralKeys: number
    masterKeyAge: number
  } {
    return {
      algorithm: this.config.algorithm,
      keyDerivationFunction: this.config.keyDerivationFunction,
      cachedKeys: this.keyCache.size,
      ephemeralKeys: this.ephemeralKeys.size,
      masterKeyAge: Date.now(), // Placeholder
    }
  }
}

/**
 * Encrypted cache for Puppeteer sessions
 */
export class PuppeteerEncryptedCache {
  private sessionId: string
  private encryptionKey: Buffer
  private encryptionService: EncryptionService
  private cache: Map<string, EncryptedData> = new Map()

  constructor(sessionId: string, encryptionKey: Buffer, encryptionService: EncryptionService) {
    this.sessionId = sessionId
    this.encryptionKey = encryptionKey
    this.encryptionService = encryptionService
  }

  /**
   * Store encrypted data in cache
   */
  async set(key: string, value: string): Promise<void> {
    try {
      const encryptedData = await this.encryptionService.encryptData(
        value,
        `puppeteer-cache-${this.sessionId}`,
        true // Use ephemeral key
      )
      this.cache.set(key, encryptedData)
    } catch (error) {
      logger.error('Puppeteer Cache', 'Failed to store encrypted data', error)
    }
  }

  /**
   * Retrieve and decrypt data from cache
   */
  async get(key: string): Promise<string | null> {
    try {
      const encryptedData = this.cache.get(key)
      if (!encryptedData) return null

      return await this.encryptionService.decryptData(
        encryptedData,
        `puppeteer-cache-${this.sessionId}`
      )
    } catch (error) {
      logger.error('Puppeteer Cache', 'Failed to retrieve encrypted data', error)
      return null
    }
  }

  /**
   * Clear cache and destroy encryption key
   */
  destroy(): void {
    this.cache.clear()
    this.encryptionKey.fill(0) // Zero out the key
    logger.debug('Puppeteer Cache', 'Cache destroyed and key zeroed', {
      sessionId: this.sessionId,
    })
  }

  /**
   * Get cache statistics
   */
  getStats(): { sessionId: string; cacheSize: number; keyLength: number } {
    return {
      sessionId: this.sessionId,
      cacheSize: this.cache.size,
      keyLength: this.encryptionKey.length,
    }
  }
}

// Export singleton instance
export const encryptionService = new EncryptionService()

/**
 * Database field encryption helpers
 */
export class DatabaseEncryption {
  /**
   * Encrypt sensitive database fields
   */
  static async encryptFields(
    data: Record<string, any>,
    sensitiveFields: string[],
    tableName: string
  ): Promise<Record<string, any>> {
    const result = { ...data }

    for (const field of sensitiveFields) {
      if (result[field] && typeof result[field] === 'string') {
        result[field] = await encryptionService.encryptDatabaseField(
          result[field],
          field,
          tableName
        )
      }
    }

    return result
  }

  /**
   * Decrypt sensitive database fields
   */
  static async decryptFields(
    data: Record<string, any>,
    sensitiveFields: string[],
    tableName: string
  ): Promise<Record<string, any>> {
    const result = { ...data }

    for (const field of sensitiveFields) {
      if (result[field] && typeof result[field] === 'string') {
        try {
          result[field] = await encryptionService.decryptDatabaseField(
            result[field],
            field,
            tableName
          )
        } catch (error) {
          logger.warn('Database Encryption', `Failed to decrypt field ${field}`, error)
          // Keep encrypted value if decryption fails
        }
      }
    }

    return result
  }
}

/**
 * TLS configuration for HTTPS connections
 */
export const TLSConfig = {
  // Minimum TLS version
  minVersion: 'TLSv1.3',

  // Cipher suites for TLS 1.3
  cipherSuites: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
  ],

  // Security headers
  securityHeaders: {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
  },
}
