/**
 * File Upload Security Middleware
 * Provides comprehensive security controls for file upload endpoints
 */

import { NextRequest, NextResponse } from 'next/server'
import { fileUploadSecurityService, FileUploadSecurityOptions } from '@/lib/fileUploadSecurity'
import { getClientIP } from '@/lib/security'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { logger } from '@/utils/logger'

export interface FileUploadMiddlewareOptions extends FileUploadSecurityOptions {
  requireAuth?: boolean
  maxFiles?: number
  rateLimit?: boolean
  rateLimitKey?: string
  allowedOrigins?: string[]
  logUploads?: boolean
}

export interface ProcessedFile {
  originalName: string
  buffer: Buffer
  size: number
  mimeType: string
  isSecure: boolean
  securityScanResult: any
}

/**
 * File upload security middleware
 */
export function withFileUploadSecurity(
  handler: (request: NextRequest, files: ProcessedFile[]) => Promise<NextResponse>,
  options: FileUploadMiddlewareOptions = {}
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const {
      requireAuth: _requireAuth = true, // TODO: Implement authentication check
      maxFiles = 10,
      rateLimit = true,
      rateLimitKey = 'upload',
      allowedOrigins = [],
      logUploads = true,
      maxSize = 10 * 1024 * 1024, // 10MB default
      enableQuarantine = true,
      enableContentAnalysis = true,
      enableHashChecking = true,
    } = options

    const ip = getClientIP(request)
    const method = request.method
    const pathname = request.nextUrl.pathname

    try {
      // Log upload attempt
      if (logUploads) {
        logger.info('FileUploadMiddleware', `Upload attempt from IP: ${ip}`, {
          method,
          pathname,
          userAgent: request.headers.get('user-agent'),
        })
      }

      // Check HTTP method
      if (method !== 'POST') {
        return NextResponse.json({ error: 'Method not allowed' }, { status: 405 })
      }

      // Rate limiting
      if (rateLimit) {
        const rateLimitResult = await advancedRateLimitService.checkRateLimit(
          ip,
          rateLimitKey,
          { windowMs: 60000, maxRequests: 10 } // 10 uploads per minute
        )

        if (!rateLimitResult.allowed) {
          logger.warn('FileUploadMiddleware', `Rate limit exceeded for IP: ${ip}`)
          return NextResponse.json(
            {
              error: 'Rate limit exceeded',
              retryAfter: rateLimitResult.retryAfter,
            },
            { status: 429 }
          )
        }
      }

      // Origin validation
      if (allowedOrigins.length > 0) {
        const origin = request.headers.get('origin')
        if (!origin || !allowedOrigins.includes(origin)) {
          logger.warn('FileUploadMiddleware', `Invalid origin: ${origin}`)
          return NextResponse.json({ error: 'Origin not allowed' }, { status: 403 })
        }
      }

      // Parse multipart form data
      const formData = await request.formData()
      const files: ProcessedFile[] = []

      // Process each file
      let fileCount = 0
      for (const [_key, value] of formData.entries()) {
        if (value instanceof File) {
          fileCount++

          // Check file count limit
          if (fileCount > maxFiles) {
            return NextResponse.json(
              { error: `Maximum ${maxFiles} files allowed` },
              { status: 400 }
            )
          }

          // Basic file validation
          if (value.size === 0) {
            return NextResponse.json({ error: `File '${value.name}' is empty` }, { status: 400 })
          }

          if (value.size > maxSize) {
            return NextResponse.json(
              {
                error: `File '${value.name}' exceeds size limit (${Math.round(maxSize / 1024 / 1024)}MB)`,
              },
              { status: 400 }
            )
          }

          // Convert file to buffer
          const buffer = Buffer.from(await value.arrayBuffer())

          // Security scan
          const scanResult = await fileUploadSecurityService.scanFile(buffer, value.name, {
            maxSize,
            enableQuarantine,
            enableContentAnalysis,
            enableHashChecking,
            ...options,
          })

          // Check security scan results
          if (!scanResult.isSecure) {
            logger.warn('FileUploadMiddleware', `Malicious file detected: ${value.name}`, {
              threats: scanResult.threats,
              fileHash: scanResult.fileHash,
              quarantined: scanResult.quarantined,
            })

            return NextResponse.json(
              {
                error: `File '${value.name}' failed security scan`,
                threats: scanResult.threats,
                quarantined: scanResult.quarantined,
              },
              { status: 400 }
            )
          }

          // Log security warnings
          if (scanResult.warnings.length > 0) {
            logger.warn('FileUploadMiddleware', `File security warnings: ${value.name}`, {
              warnings: scanResult.warnings,
            })
          }

          // Add processed file
          files.push({
            originalName: value.name,
            buffer,
            size: value.size,
            mimeType: value.type,
            isSecure: scanResult.isSecure,
            securityScanResult: scanResult,
          })

          // Log successful file processing
          if (logUploads) {
            logger.info('FileUploadMiddleware', `File processed successfully: ${value.name}`, {
              size: value.size,
              mimeType: value.type,
              scanDuration: scanResult.scanDuration,
              warnings: scanResult.warnings.length,
            })
          }
        }
      }

      // Check if any files were uploaded
      if (files.length === 0) {
        return NextResponse.json({ error: 'No files uploaded' }, { status: 400 })
      }

      // Call the actual handler with processed files
      return await handler(request, files)
    } catch (error) {
      logger.error('FileUploadMiddleware', 'File upload processing failed', error)

      return NextResponse.json({ error: 'File upload processing failed' }, { status: 500 })
    }
  }
}

/**
 * Simple file upload validation (for client-side use)
 */
export function validateFileUpload(
  file: File,
  options: {
    maxSize?: number
    allowedTypes?: string[]
    allowedExtensions?: string[]
  } = {}
): { isValid: boolean; errors: string[] } {
  const {
    maxSize = 10 * 1024 * 1024, // 10MB
    allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf'],
    allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.txt', '.pdf'],
  } = options

  const errors: string[] = []

  // Basic validations
  if (!file) {
    errors.push('No file selected')
    return { isValid: false, errors }
  }

  if (file.size === 0) {
    errors.push('File is empty')
  }

  if (file.size > maxSize) {
    errors.push(`File size exceeds limit (${Math.round(maxSize / 1024 / 1024)}MB)`)
  }

  // Type validation
  if (!allowedTypes.includes(file.type)) {
    errors.push(`File type '${file.type}' is not allowed`)
  }

  // Extension validation
  const extension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
  if (!allowedExtensions.includes(extension)) {
    errors.push(`File extension '${extension}' is not allowed`)
  }

  // Filename validation
  if (file.name.length > 255) {
    errors.push('Filename is too long')
  }

  if (file.name.includes('\0')) {
    errors.push('Filename contains invalid characters')
  }

  // Path traversal check
  if (/\.\.[\/\\]/.test(file.name)) {
    errors.push('Filename contains path traversal sequences')
  }

  // Executable check
  const executableExtensions = [
    '.exe',
    '.bat',
    '.cmd',
    '.com',
    '.scr',
    '.pif',
    '.vbs',
    '.js',
    '.jar',
  ]
  if (executableExtensions.some(ext => file.name.toLowerCase().endsWith(ext))) {
    errors.push('Executable files are not allowed')
  }

  return {
    isValid: errors.length === 0,
    errors,
  }
}

/**
 * Generate secure filename
 */
export function generateSecureFilename(
  originalName: string,
  preserveExtension: boolean = true
): string {
  // Remove path components
  const basename = originalName.replace(/^.*[\\\/]/, '')

  // Extract extension if preserving
  const extension = preserveExtension ? basename.substring(basename.lastIndexOf('.')) : ''
  const nameWithoutExt = preserveExtension
    ? basename.substring(0, basename.lastIndexOf('.'))
    : basename

  // Sanitize filename
  const sanitized = nameWithoutExt
    .replace(/[^a-zA-Z0-9._-]/g, '_') // Replace invalid chars with underscore
    .replace(/_{2,}/g, '_') // Replace multiple underscores with single
    .replace(/^_+|_+$/g, '') // Remove leading/trailing underscores
    .substring(0, 100) // Limit length

  // Add timestamp to ensure uniqueness
  const timestamp = Date.now()

  return `${sanitized}_${timestamp}${extension}`
}

/**
 * File upload configuration for different contexts
 */
export const fileUploadConfigs = {
  // Configuration backup files
  backup: {
    maxSize: 1024 * 1024, // 1MB
    allowedTypes: ['text/plain', 'application/json'],
    allowedExtensions: ['.txt', '.json'],
    maxFiles: 1,
    enableContentAnalysis: true,
  },

  // Industry data import
  dataImport: {
    maxSize: 5 * 1024 * 1024, // 5MB
    allowedTypes: ['application/json', 'text/csv', 'application/vnd.ms-excel'],
    allowedExtensions: ['.json', '.csv', '.xlsx'],
    maxFiles: 5,
    enableContentAnalysis: true,
  },

  // General document upload
  documents: {
    maxSize: 10 * 1024 * 1024, // 10MB
    allowedTypes: ['application/pdf', 'text/plain', 'image/jpeg', 'image/png'],
    allowedExtensions: ['.pdf', '.txt', '.jpg', '.jpeg', '.png'],
    maxFiles: 10,
    enableContentAnalysis: true,
  },

  // Image upload only
  images: {
    maxSize: 5 * 1024 * 1024, // 5MB
    allowedTypes: ['image/jpeg', 'image/png', 'image/gif'],
    allowedExtensions: ['.jpg', '.jpeg', '.png', '.gif'],
    maxFiles: 20,
    enableContentAnalysis: false,
  },
}
