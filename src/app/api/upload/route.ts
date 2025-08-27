/**
 * Secure File Upload API Endpoint
 * Handles file uploads with comprehensive security measures
 */

import { NextRequest, NextResponse } from 'next/server'
import {
  withFileUploadSecurity,
  fileUploadConfigs,
  generateSecureFilename,
  ProcessedFile,
} from '@/lib/fileUploadMiddleware'
import { withApiSecurity } from '@/lib/api-security'
import { withValidation } from '@/lib/validation-middleware'
import { getClientIP } from '@/lib/security'
import { logger } from '@/utils/logger'
import fs from 'fs'
import path from 'path'

/**
 * Interface for upload result
 */
interface UploadResult {
  originalName: string
  size: number
  mimeType: string
  isSecure: boolean
  processed: boolean | unknown
  securityScan?: {
    scanDuration: number
    fileHash: string
    threats: string[]
    warnings: string[]
    quarantined: boolean
  }
  savedAs?: string
  savedPath?: string
  saveError?: string
}

/**
 * POST /api/upload - Secure file upload endpoint
 */
const uploadHandler = withApiSecurity(
  withFileUploadSecurity(
    async (request: NextRequest, files: ProcessedFile[]) => {
      const ip = getClientIP(request)
      const url = new URL(request.url)
      const uploadType = url.searchParams.get('type') || 'documents'
      const saveFiles = url.searchParams.get('save') === 'true'

      logger.info('UploadAPI', `Processing ${files.length} files from IP: ${ip}`, {
        uploadType,
        saveFiles,
        filenames: files.map(f => f.originalName),
      })

      try {
        const results = []
        // Validate and sanitize upload directory path
        const baseUploadDir = process.env.UPLOAD_DIR || './uploads'
        const uploadDir = path.resolve(baseUploadDir)

        // Security check: ensure upload directory is within allowed paths
        const allowedBasePaths = [
          path.resolve('./uploads'),
          path.resolve('./temp'),
          path.resolve(process.cwd(), 'uploads'),
        ]

        const isAllowedPath = allowedBasePaths.some(basePath => uploadDir.startsWith(basePath))

        if (!isAllowedPath) {
          throw new Error('Upload directory path not allowed')
        }

        // Ensure upload directory exists - using validated path
        // eslint-disable-next-line security/detect-non-literal-fs-filename
        if (saveFiles && !fs.existsSync(uploadDir)) {
          // eslint-disable-next-line security/detect-non-literal-fs-filename
          fs.mkdirSync(uploadDir, { recursive: true })
        }

        for (const file of files) {
          const result: UploadResult = {
            originalName: file.originalName,
            size: file.size,
            mimeType: file.mimeType,
            isSecure: file.isSecure,
            processed: true,
          }

          // Add security scan details
          if (file.securityScanResult) {
            result.securityScan = {
              scanDuration: file.securityScanResult.scanDuration,
              fileHash: file.securityScanResult.fileHash,
              threats: file.securityScanResult.threats,
              warnings: file.securityScanResult.warnings,
              quarantined: file.securityScanResult.quarantined,
            }
          }

          // Save file if requested
          if (saveFiles) {
            const secureFilename = generateSecureFilename(file.originalName)
            const filePath = path.resolve(path.join(uploadDir, secureFilename))

            // Security check: ensure file path is within upload directory
            if (!filePath.startsWith(uploadDir)) {
              throw new Error('File path outside upload directory not allowed')
            }

            try {
              // eslint-disable-next-line security/detect-non-literal-fs-filename
              await fs.promises.writeFile(filePath, file.buffer)
              result.savedAs = secureFilename
              result.savedPath = filePath

              logger.info('UploadAPI', `File saved: ${file.originalName} -> ${secureFilename}`)
            } catch (saveError) {
              logger.error('UploadAPI', `Failed to save file: ${file.originalName}`, saveError)
              result.saveError = 'Failed to save file'
            }
          }

          // Process file based on type
          switch (uploadType) {
            case 'backup':
              result.processed = await processBackupFile(file)
              break
            case 'dataImport':
              result.processed = await processDataImportFile(file)
              break
            case 'images':
              result.processed = await processImageFile(file)
              break
            default:
              result.processed = await processDocumentFile(file)
          }

          results.push(result)
        }

        return NextResponse.json({
          success: true,
          uploadType,
          filesProcessed: files.length,
          results,
          timestamp: new Date().toISOString(),
        })
      } catch (error) {
        logger.error('UploadAPI', 'File processing failed', error)

        return NextResponse.json(
          {
            error: 'File processing failed',
            details: error instanceof Error ? error.message : 'Unknown error',
          },
          { status: 500 }
        )
      }
    },
    {
      // Dynamic configuration based on upload type
      ...getUploadConfig(
        new URL('http://localhost' + (process.env.NODE_ENV === 'test' ? '/api/upload' : ''))
      ),
    }
  ),
  {
    requireAuth: true,
    requireCSRF: true,
    rateLimit: 'upload',
    validateInput: false, // File validation handled by upload middleware
    logRequests: true,
  }
)

/**
 * Get upload configuration based on type parameter
 */
function getUploadConfig(url: URL) {
  const uploadType = url.searchParams.get('type') || 'documents'

  const configs: Record<string, any> = {
    backup: {
      ...fileUploadConfigs.backup,
      enableQuarantine: true,
      enableContentAnalysis: true,
      enableHashChecking: true,
    },
    dataImport: {
      ...fileUploadConfigs.dataImport,
      enableQuarantine: true,
      enableContentAnalysis: true,
      enableHashChecking: false,
    },
    images: {
      ...fileUploadConfigs.images,
      enableQuarantine: false,
      enableContentAnalysis: false,
      enableHashChecking: false,
    },
    documents: {
      ...fileUploadConfigs.documents,
      enableQuarantine: true,
      enableContentAnalysis: true,
      enableHashChecking: true,
    },
  }

  return Object.prototype.hasOwnProperty.call(configs, uploadType)
    ? configs[uploadType as keyof typeof configs]
    : configs.documents
}

/**
 * Process backup file
 */
async function processBackupFile(file: ProcessedFile): Promise<boolean> {
  try {
    const content = file.buffer.toString('utf8')

    // Validate JSON structure for backup files
    if (file.originalName.endsWith('.json')) {
      JSON.parse(content)
    }

    // Additional backup-specific validation
    if (content.includes('apiKey') || content.includes('password')) {
      logger.warn('UploadAPI', `Backup file contains sensitive data: ${file.originalName}`)
    }

    return true
  } catch (error) {
    logger.error('UploadAPI', `Backup file processing failed: ${file.originalName}`, error)
    return false
  }
}

/**
 * Process data import file
 */
async function processDataImportFile(file: ProcessedFile): Promise<boolean> {
  try {
    const content = file.buffer.toString('utf8')

    // Validate data structure
    if (file.originalName.endsWith('.json')) {
      const data = JSON.parse(content)

      // Basic structure validation for industry data
      if (Array.isArray(data)) {
        for (const item of data.slice(0, 10)) {
          // Check first 10 items
          if (typeof item !== 'object' || !item.name) {
            throw new Error('Invalid data structure')
          }
        }
      }
    } else if (file.originalName.endsWith('.csv')) {
      // Basic CSV validation
      const lines = content.split('\n')
      if (lines.length < 2) {
        throw new Error('CSV file must have header and data rows')
      }
    }

    return true
  } catch (error) {
    logger.error('UploadAPI', `Data import file processing failed: ${file.originalName}`, error)
    return false
  }
}

/**
 * Process image file
 */
async function processImageFile(file: ProcessedFile): Promise<boolean> {
  try {
    // Basic image validation (magic number already checked in security scan)
    const validImageTypes = ['image/jpeg', 'image/png', 'image/gif']

    if (!validImageTypes.includes(file.mimeType)) {
      throw new Error('Invalid image type')
    }

    // Check for reasonable image size
    if (file.size < 100) {
      // Less than 100 bytes is suspicious
      throw new Error('Image file too small')
    }

    return true
  } catch (error) {
    logger.error('UploadAPI', `Image file processing failed: ${file.originalName}`, error)
    return false
  }
}

/**
 * Process document file
 */
async function processDocumentFile(file: ProcessedFile): Promise<boolean> {
  try {
    // Basic document validation
    const validDocTypes = ['application/pdf', 'text/plain']

    if (validDocTypes.includes(file.mimeType)) {
      // Additional PDF validation could be added here
      return true
    }

    // For text files, check encoding
    if (file.mimeType === 'text/plain') {
      const content = file.buffer.toString('utf8')

      // Check for binary content in text files
      if (content.includes('\0')) {
        throw new Error('Text file contains binary data')
      }
    }

    return true
  } catch (error) {
    logger.error('UploadAPI', `Document file processing failed: ${file.originalName}`, error)
    return false
  }
}

export const POST = uploadHandler

/**
 * GET /api/upload - Get upload configuration and status
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const url = new URL(request.url)
    const type = url.searchParams.get('type') || 'documents'

    const config = getUploadConfig(url)

    return NextResponse.json({
      success: true,
      uploadType: type,
      configuration: {
        maxSize: config.maxSize,
        maxFiles: config.maxFiles,
        allowedTypes: config.allowedTypes,
        allowedExtensions: config.allowedExtensions,
        securityFeatures: {
          enableQuarantine: config.enableQuarantine,
          enableContentAnalysis: config.enableContentAnalysis,
          enableHashChecking: config.enableHashChecking,
        },
      },
      limits: {
        maxSizeFormatted: `${Math.round(config.maxSize / 1024 / 1024)}MB`,
        maxFiles: config.maxFiles,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('UploadAPI', 'Failed to get upload configuration', error)

    return NextResponse.json({ error: 'Failed to get upload configuration' }, { status: 500 })
  }
}
