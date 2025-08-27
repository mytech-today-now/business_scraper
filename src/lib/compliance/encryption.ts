/**
 * Enterprise Encryption Service
 * Provides end-to-end encryption for sensitive data in compliance with SOC 2, GDPR, and CCPA
 */

import crypto from 'crypto'
import { logger } from '@/utils/logger'

// Encryption configuration
const ENCRYPTION_ALGORITHM = 'aes-256-gcm'
const KEY_LENGTH = 32 // 256 bits
const IV_LENGTH = 16 // 128 bits
const TAG_LENGTH = 16 // 128 bits
const SALT_LENGTH = 32 // 256 bits

// Key derivation configuration
const PBKDF2_ITERATIONS = 100000
const SCRYPT_OPTIONS = {
  N: 16384, // CPU/memory cost parameter
  r: 8, // Block size parameter
  p: 1, // Parallelization parameter
  maxmem: 32 * 1024 * 1024, // 32MB max memory
}

/**
 * Encrypted data structure
 */
export interface EncryptedData {
  data: string // Base64 encoded encrypted data
  iv: string // Base64 encoded initialization vector
  tag: string // Base64 encoded authentication tag
  salt?: string // Base64 encoded salt (for password-derived keys)
  algorithm: string
  keyDerivation?: 'pbkdf2' | 'scrypt'
}

/**
 * Encryption service class
 */
export class EncryptionService {
  private masterKey: Buffer | null = null

  constructor() {
    this.initializeMasterKey()
  }

  /**
   * Initialize master encryption key from environment
   */
  private initializeMasterKey(): void {
    const masterKeyHex = process.env.ENCRYPTION_MASTER_KEY

    if (!masterKeyHex) {
      logger.error('Encryption', 'ENCRYPTION_MASTER_KEY environment variable not set')
      throw new Error('Master encryption key not configured')
    }

    try {
      this.masterKey = Buffer.from(masterKeyHex, 'hex')

      if (this.masterKey.length !== KEY_LENGTH) {
        throw new Error(
          `Invalid master key length: expected ${KEY_LENGTH} bytes, got ${this.masterKey.length}`
        )
      }

      logger.info('Encryption', 'Master encryption key initialized successfully')
    } catch (error) {
      logger.error('Encryption', 'Failed to initialize master key', error)
      throw new Error('Invalid master encryption key format')
    }
  }

  /**
   * Generate a random encryption key
   */
  public generateKey(): Buffer {
    return crypto.randomBytes(KEY_LENGTH)
  }

  /**
   * Derive key from password using PBKDF2
   */
  public deriveKeyPBKDF2(password: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
    const actualSalt = salt || crypto.randomBytes(SALT_LENGTH)
    const key = crypto.pbkdf2Sync(password, actualSalt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256')

    return { key, salt: actualSalt }
  }

  /**
   * Derive key from password using scrypt
   */
  public deriveKeyScrypt(password: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
    const actualSalt = salt || crypto.randomBytes(SALT_LENGTH)
    const key = crypto.scryptSync(password, actualSalt, KEY_LENGTH, SCRYPT_OPTIONS)

    return { key, salt: actualSalt }
  }

  /**
   * Encrypt data with master key
   */
  public encrypt(data: string | Buffer): EncryptedData {
    if (!this.masterKey) {
      throw new Error('Encryption service not initialized')
    }

    try {
      const iv = crypto.randomBytes(IV_LENGTH)
      const cipher = crypto.createCipher(ENCRYPTION_ALGORITHM, this.masterKey)

      const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data

      let encrypted = cipher.update(dataBuffer)
      encrypted = Buffer.concat([encrypted, cipher.final()])

      const tag = cipher.getAuthTag()

      return {
        data: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        algorithm: ENCRYPTION_ALGORITHM,
      }
    } catch (error) {
      logger.error('Encryption', 'Failed to encrypt data', error)
      throw new Error('Encryption failed')
    }
  }

  /**
   * Decrypt data with master key
   */
  public decrypt(encryptedData: EncryptedData): Buffer {
    if (!this.masterKey) {
      throw new Error('Encryption service not initialized')
    }

    try {
      const iv = Buffer.from(encryptedData.iv, 'base64')
      const tag = Buffer.from(encryptedData.tag, 'base64')
      const data = Buffer.from(encryptedData.data, 'base64')

      const decipher = crypto.createDecipher(encryptedData.algorithm, this.masterKey)
      decipher.setAuthTag(tag)

      let decrypted = decipher.update(data)
      decrypted = Buffer.concat([decrypted, decipher.final()])

      return decrypted
    } catch (error) {
      logger.error('Encryption', 'Failed to decrypt data', error)
      throw new Error('Decryption failed')
    }
  }

  /**
   * Encrypt data with password-derived key
   */
  public encryptWithPassword(
    data: string | Buffer,
    password: string,
    useScrypt = false
  ): EncryptedData {
    try {
      const keyDerivation = useScrypt ? 'scrypt' : 'pbkdf2'
      const { key, salt } = useScrypt
        ? this.deriveKeyScrypt(password)
        : this.deriveKeyPBKDF2(password)

      const iv = crypto.randomBytes(IV_LENGTH)
      const cipher = crypto.createCipher(ENCRYPTION_ALGORITHM, key)

      const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data

      let encrypted = cipher.update(dataBuffer)
      encrypted = Buffer.concat([encrypted, cipher.final()])

      const tag = cipher.getAuthTag()

      return {
        data: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        salt: salt.toString('base64'),
        algorithm: ENCRYPTION_ALGORITHM,
        keyDerivation,
      }
    } catch (error) {
      logger.error('Encryption', 'Failed to encrypt data with password', error)
      throw new Error('Password encryption failed')
    }
  }

  /**
   * Decrypt data with password-derived key
   */
  public decryptWithPassword(encryptedData: EncryptedData, password: string): Buffer {
    if (!encryptedData.salt || !encryptedData.keyDerivation) {
      throw new Error('Invalid encrypted data: missing salt or key derivation method')
    }

    try {
      const salt = Buffer.from(encryptedData.salt, 'base64')
      const { key } =
        encryptedData.keyDerivation === 'scrypt'
          ? this.deriveKeyScrypt(password, salt)
          : this.deriveKeyPBKDF2(password, salt)

      const iv = Buffer.from(encryptedData.iv, 'base64')
      const tag = Buffer.from(encryptedData.tag, 'base64')
      const data = Buffer.from(encryptedData.data, 'base64')

      const decipher = crypto.createDecipher(encryptedData.algorithm, key)
      decipher.setAuthTag(tag)

      let decrypted = decipher.update(data)
      decrypted = Buffer.concat([decrypted, decipher.final()])

      return decrypted
    } catch (error) {
      logger.error('Encryption', 'Failed to decrypt data with password', error)
      throw new Error('Password decryption failed')
    }
  }

  /**
   * Generate secure hash of data
   */
  public hash(data: string | Buffer, algorithm = 'sha256'): string {
    const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data
    return crypto.createHash(algorithm).update(dataBuffer).digest('hex')
  }

  /**
   * Generate HMAC of data
   */
  public hmac(data: string | Buffer, key: string | Buffer, algorithm = 'sha256'): string {
    const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data
    const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'utf8') : key
    return crypto.createHmac(algorithm, keyBuffer).update(dataBuffer).digest('hex')
  }

  /**
   * Securely compare two strings (constant time)
   */
  public secureCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false
    }

    const bufferA = Buffer.from(a, 'utf8')
    const bufferB = Buffer.from(b, 'utf8')

    return crypto.timingSafeEqual(bufferA, bufferB)
  }

  /**
   * Generate cryptographically secure random string
   */
  public generateSecureToken(length = 32): string {
    return crypto.randomBytes(length).toString('hex')
  }
}

// Global encryption service instance (lazy initialization)
let _encryptionService: EncryptionService | null = null

export const encryptionService = {
  get instance(): EncryptionService {
    if (!_encryptionService) {
      _encryptionService = new EncryptionService()
    }
    return _encryptionService
  },

  // Delegate all methods to the instance
  generateKey: () => encryptionService.instance.generateKey(),
  deriveKeyPBKDF2: (password: string, salt?: Buffer) =>
    encryptionService.instance.deriveKeyPBKDF2(password, salt),
  deriveKeyScrypt: (password: string, salt?: Buffer) =>
    encryptionService.instance.deriveKeyScrypt(password, salt),
  encrypt: (data: string | Buffer) => encryptionService.instance.encrypt(data),
  decrypt: (encryptedData: EncryptedData) => encryptionService.instance.decrypt(encryptedData),
  encryptWithPassword: (data: string | Buffer, password: string, useScrypt = false) =>
    encryptionService.instance.encryptWithPassword(data, password, useScrypt),
  decryptWithPassword: (encryptedData: EncryptedData, password: string) =>
    encryptionService.instance.decryptWithPassword(encryptedData, password),
  hash: (data: string | Buffer, algorithm = 'sha256') =>
    encryptionService.instance.hash(data, algorithm),
  hmac: (data: string | Buffer, key: string | Buffer, algorithm = 'sha256') =>
    encryptionService.instance.hmac(data, key, algorithm),
  secureCompare: (a: string, b: string) => encryptionService.instance.secureCompare(a, b),
  generateSecureToken: (length = 32) => encryptionService.instance.generateSecureToken(length),
}

/**
 * Utility functions for common encryption tasks
 */
export const EncryptionUtils = {
  /**
   * Encrypt sensitive field for database storage
   */
  encryptField: (value: string): EncryptedData => {
    return encryptionService.encrypt(value)
  },

  /**
   * Decrypt sensitive field from database
   */
  decryptField: (encryptedData: EncryptedData): string => {
    return encryptionService.decrypt(encryptedData).toString('utf8')
  },

  /**
   * Hash password for storage
   */
  hashPassword: (password: string): string => {
    const salt = crypto.randomBytes(16).toString('hex')
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
    return `${salt}:${hash}`
  },

  /**
   * Verify password against hash
   */
  verifyPassword: (password: string, storedHash: string): boolean => {
    const [salt, hash] = storedHash.split(':')
    const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex')
    return encryptionService.secureCompare(hash, verifyHash)
  },
}
