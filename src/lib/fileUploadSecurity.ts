/**
 * File Upload Security Utility
 * Comprehensive security scanning and validation for uploaded files
 */

import { logger } from '@/utils/logger'
import { validationService, FileValidationOptions } from '@/utils/validation'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'

export interface FileSecurityScanResult {
  isSecure: boolean
  threats: string[]
  warnings: string[]
  quarantined: boolean
  scanDuration: number
  fileHash: string
}

export interface FileUploadSecurityOptions extends FileValidationOptions {
  enableQuarantine?: boolean
  quarantineDirectory?: string
  enableHashChecking?: boolean
  knownMalwareHashes?: string[]
  enableContentAnalysis?: boolean
  maxScanTime?: number
}

/**
 * File Upload Security Service
 */
export class FileUploadSecurityService {
  private quarantineDir: string
  private knownMalwareHashes: Set<string>

  constructor() {
    // Validate and sanitize quarantine directory path
    const baseQuarantineDir = process.env.QUARANTINE_DIR || './quarantine'
    this.quarantineDir = path.resolve(baseQuarantineDir)

    // Security check: ensure quarantine directory is within allowed paths
    const allowedBasePaths = [
      path.resolve('./quarantine'),
      path.resolve('./temp'),
      path.resolve(process.cwd(), 'quarantine'),
    ]

    const isAllowedPath = allowedBasePaths.some(basePath => this.quarantineDir.startsWith(basePath))

    if (!isAllowedPath) {
      throw new Error('Quarantine directory path not allowed')
    }

    this.knownMalwareHashes = new Set()
    this.initializeQuarantineDirectory()
  }

  /**
   * Comprehensive security scan of uploaded file
   * @param file - File object or file buffer
   * @param options - Security scanning options
   * @returns Promise resolving to security scan result
   */
  async scanFile(
    file: File | Buffer,
    filename: string,
    options: FileUploadSecurityOptions = {}
  ): Promise<FileSecurityScanResult> {
    const startTime = Date.now()
    const result: FileSecurityScanResult = {
      isSecure: true,
      threats: [],
      warnings: [],
      quarantined: false,
      scanDuration: 0,
      fileHash: '',
    }

    try {
      // Generate file hash
      const buffer = file instanceof File ? await this.fileToBuffer(file) : file
      result.fileHash = this.generateFileHash(buffer)

      // Check against known malware hashes
      if (options.enableHashChecking && this.knownMalwareHashes.has(result.fileHash)) {
        result.isSecure = false
        result.threats.push('File matches known malware signature')

        if (options.enableQuarantine) {
          await this.quarantineFile(buffer, filename, 'Known malware hash')
          result.quarantined = true
        }

        result.scanDuration = Date.now() - startTime
        return result
      }

      // Basic file validation
      const fileInfo = {
        name: filename,
        size: buffer.length,
        type: this.detectMimeType(buffer, filename),
      }

      const validationResult = validationService.validateFileUpload(fileInfo, options)
      if (!validationResult.isValid) {
        result.isSecure = false
        result.threats.push(...validationResult.errors)
      }
      result.warnings.push(...validationResult.warnings)

      // Content-based security analysis
      if (options.enableContentAnalysis) {
        const contentAnalysis = await this.analyzeFileContent(buffer, filename)
        result.threats.push(...contentAnalysis.threats)
        result.warnings.push(...contentAnalysis.warnings)

        if (contentAnalysis.threats.length > 0) {
          result.isSecure = false
        }
      }

      // Quarantine if threats detected
      if (!result.isSecure && options.enableQuarantine) {
        await this.quarantineFile(buffer, filename, result.threats.join(', '))
        result.quarantined = true
      }
    } catch (error) {
      logger.error('FileUploadSecurity', 'File scan failed', error)
      result.isSecure = false
      result.threats.push('File scan failed - potential security risk')
    }

    result.scanDuration = Date.now() - startTime
    return result
  }

  /**
   * Analyze file content for security threats
   * @param buffer - File buffer
   * @param filename - Original filename
   * @returns Analysis result
   */
  private async analyzeFileContent(
    buffer: Buffer,
    _filename: string
  ): Promise<{ threats: string[]; warnings: string[] }> {
    const threats: string[] = []
    const warnings: string[] = []

    try {
      const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1024 * 1024)) // First 1MB

      // Check for embedded executables
      const executableSignatures = [
        Buffer.from([0x4d, 0x5a]), // PE executable
        Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF executable
        Buffer.from([0xca, 0xfe, 0xba, 0xbe]), // Java class file
        Buffer.from([0xfe, 0xed, 0xfa, 0xce]), // Mach-O executable
      ]

      for (const signature of executableSignatures) {
        if (buffer.indexOf(signature) !== -1) {
          threats.push('File contains embedded executable code')
          break
        }
      }

      // Check for script injection patterns
      const scriptPatterns = [
        /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /on\w+\s*=/gi,
        /eval\s*\(/gi,
        /document\.write/gi,
        /window\.location/gi,
      ]

      for (const pattern of scriptPatterns) {
        if (pattern.test(content)) {
          threats.push('File contains potentially malicious script content')
          break
        }
      }

      // Check for suspicious command patterns
      const commandPatterns = [
        /cmd\.exe/gi,
        /powershell/gi,
        /bash/gi,
        /sh\s/gi,
        /system\(/gi,
        /exec\(/gi,
        /shell_exec/gi,
        /passthru/gi,
      ]

      for (const pattern of commandPatterns) {
        if (pattern.test(content)) {
          warnings.push('File contains command execution patterns')
          break
        }
      }

      // Check for data exfiltration patterns
      const exfiltrationPatterns = [
        /curl\s+.*http/gi,
        /wget\s+.*http/gi,
        /fetch\s*\(/gi,
        /XMLHttpRequest/gi,
        /sendBeacon/gi,
      ]

      for (const pattern of exfiltrationPatterns) {
        if (pattern.test(content)) {
          warnings.push('File contains network communication patterns')
          break
        }
      }

      // Check for obfuscation
      const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/g
      const base64Matches = content.match(base64Pattern)
      if (base64Matches && base64Matches.length > 5) {
        warnings.push('File contains multiple base64 encoded strings')
      }

      // Check for excessive entropy (possible encryption/obfuscation)
      const entropy = this.calculateEntropy(content)
      if (entropy > 7.5) {
        warnings.push('File has high entropy - possible obfuscation or encryption')
      }
    } catch (error) {
      warnings.push('Could not analyze file content')
    }

    return { threats, warnings }
  }

  /**
   * Calculate Shannon entropy of content
   * @param content - Content to analyze
   * @returns Entropy value
   */
  private calculateEntropy(content: string): number {
    const frequencies: Record<string, number> = {}

    for (const char of content) {
      frequencies[char] = (frequencies[char] || 0) + 1
    }

    let entropy = 0
    const length = content.length

    for (const freq of Object.values(frequencies)) {
      const probability = freq / length
      entropy -= probability * Math.log2(probability)
    }

    return entropy
  }

  /**
   * Generate SHA-256 hash of file
   * @param buffer - File buffer
   * @returns File hash
   */
  private generateFileHash(buffer: Buffer): string {
    return crypto.createHash('sha256').update(buffer).digest('hex')
  }

  /**
   * Detect MIME type from file content
   * @param buffer - File buffer
   * @param filename - Original filename
   * @returns Detected MIME type
   */
  private detectMimeType(buffer: Buffer, filename: string): string {
    // Check magic numbers
    const magicNumbers: Record<string, string> = {
      ffd8ff: 'image/jpeg',
      '89504e47': 'image/png',
      '474946383761': 'image/gif',
      '474946383961': 'image/gif',
      '255044462d': 'application/pdf',
      '504b0304': 'application/zip',
      '504b0506': 'application/zip',
      d0cf11e0: 'application/msword',
    }

    const hex = buffer.toString('hex', 0, 8).toLowerCase()

    for (const [signature, mimeType] of Object.entries(magicNumbers)) {
      if (hex.startsWith(signature)) {
        return mimeType
      }
    }

    // Fallback to extension-based detection
    const ext = path.extname(filename).toLowerCase()
    const extensionMap: Record<string, string> = {
      '.txt': 'text/plain',
      '.json': 'application/json',
      '.csv': 'text/csv',
      '.xml': 'application/xml',
    }

    return extensionMap[ext] || 'application/octet-stream'
  }

  /**
   * Convert File object to Buffer
   * @param file - File object
   * @returns Promise resolving to Buffer
   */
  private async fileToBuffer(file: File): Promise<Buffer> {
    const arrayBuffer = await file.arrayBuffer()
    return Buffer.from(arrayBuffer)
  }

  /**
   * Quarantine suspicious file
   * @param buffer - File buffer
   * @param filename - Original filename
   * @param reason - Quarantine reason
   */
  private async quarantineFile(buffer: Buffer, filename: string, reason: string): Promise<void> {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
      const quarantineFilename = `${timestamp}_${filename}`
      const quarantinePath = path.resolve(path.join(this.quarantineDir, quarantineFilename))

      // Security check: ensure quarantine path is within quarantine directory
      if (!quarantinePath.startsWith(this.quarantineDir)) {
        throw new Error('Quarantine path outside quarantine directory not allowed')
      }

      // eslint-disable-next-line security/detect-non-literal-fs-filename
      await fs.promises.writeFile(quarantinePath, buffer)

      // Create metadata file
      const metadata = {
        originalFilename: filename,
        quarantineReason: reason,
        timestamp: new Date().toISOString(),
        fileSize: buffer.length,
        fileHash: this.generateFileHash(buffer),
      }

      const metaPath = path.resolve(quarantinePath + '.meta')

      // Security check: ensure meta path is within quarantine directory
      if (!metaPath.startsWith(this.quarantineDir)) {
        throw new Error('Meta path outside quarantine directory not allowed')
      }

      // eslint-disable-next-line security/detect-non-literal-fs-filename
      await fs.promises.writeFile(metaPath, JSON.stringify(metadata, null, 2))

      logger.warn('FileUploadSecurity', `File quarantined: ${filename}`, { reason, quarantinePath })
    } catch (error) {
      logger.error('FileUploadSecurity', 'Failed to quarantine file', error)
    }
  }

  /**
   * Initialize quarantine directory
   */
  private initializeQuarantineDirectory(): void {
    try {
      // Use the already validated quarantine directory path
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      if (!fs.existsSync(this.quarantineDir)) {
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        fs.mkdirSync(this.quarantineDir, { recursive: true })
      }
    } catch (error) {
      logger.error('FileUploadSecurity', 'Failed to initialize quarantine directory', error)
    }
  }

  /**
   * Add known malware hash
   * @param hash - SHA-256 hash of known malware
   */
  addMalwareHash(hash: string): void {
    this.knownMalwareHashes.add(hash.toLowerCase())
  }

  /**
   * Load malware hashes from file
   * @param filePath - Path to file containing malware hashes
   */
  async loadMalwareHashes(filePath: string): Promise<void> {
    try {
      // Validate and sanitize file path
      const resolvedPath = path.resolve(filePath)

      // Security check: ensure file path is within allowed directories
      const allowedBasePaths = [
        path.resolve('./config'),
        path.resolve('./data'),
        path.resolve(process.cwd(), 'config'),
        path.resolve(process.cwd(), 'data'),
      ]

      const isAllowedPath = allowedBasePaths.some(basePath => resolvedPath.startsWith(basePath))

      if (!isAllowedPath) {
        throw new Error('Malware hash file path not allowed')
      }

      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const content = await fs.promises.readFile(resolvedPath, 'utf8')
      const hashes = content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line)

      for (const hash of hashes) {
        this.addMalwareHash(hash)
      }

      logger.info('FileUploadSecurity', `Loaded ${hashes.length} malware hashes`)
    } catch (error) {
      logger.error('FileUploadSecurity', 'Failed to load malware hashes', error)
    }
  }
}

// Export singleton instance
export const fileUploadSecurityService = new FileUploadSecurityService()
