/**
 * File Upload Security Tests
 * Comprehensive tests for file upload validation and security scanning
 */

import { FileUploadSecurityService } from '@/lib/fileUploadSecurity'
import { validateFileUpload, generateSecureFilename } from '@/lib/fileUploadMiddleware'
import { validationService } from '@/utils/validation'
import { jest } from '@jest/globals'
import {
  createMockFileSystem,
  createMockEnvironment,
  createMockFile
} from './utils/mockHelpers'
import {
  testPaths,
  testFileContents,
  encodedSecurityPatterns,
  decodeSecurityPattern
} from './fixtures/testData'
import { setupTest, cleanupTest, securityTestHelpers } from './setup/testSetup'

// Mock file system operations
const mockFs = createMockFileSystem()
const mockEnv = createMockEnvironment()

jest.mock('fs', () => mockFs)
jest.mock('crypto', () => ({
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(() => 'test-hash-12345')
  }))
}))

describe('File Upload Security', () => {
  let securityService: FileUploadSecurityService

  beforeEach(() => {
    setupTest()
    securityService = new FileUploadSecurityService()
    mockFs.reset()
    mockEnv.restore()
  })

  afterEach(() => {
    cleanupTest()
    // Validate no real file operations occurred
    securityTestHelpers.validateNoRealFileOperations()
    securityTestHelpers.validateEnvironmentIntegrity()
  })

  describe('File Validation', () => {
    test('should validate file size limits', () => {
      const largeFile = new File(['x'.repeat(11 * 1024 * 1024)], 'large.txt', { type: 'text/plain' })
      const result = validateFileUpload(largeFile, { maxSize: 10 * 1024 * 1024 })

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('File size exceeds limit (10MB)')
    })

    test('should validate file types', () => {
      const executableFile = new File(['content'], 'malware.exe', { type: 'application/octet-stream' })
      const result = validateFileUpload(executableFile)

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Executable files are not allowed')
    })

    test('should validate file extensions', () => {
      const scriptFile = createMockFile('content', 'script.js', 'application/javascript')
      const result = validateFileUpload(scriptFile)

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Executable files are not allowed')
    })

    test('should detect path traversal attempts', () => {
      const pathTraversalName = decodeSecurityPattern(encodedSecurityPatterns.pathTraversalPattern)
      const maliciousFile = createMockFile('content', pathTraversalName, 'text/plain')
      const result = validateFileUpload(maliciousFile)

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Filename contains path traversal sequences')
    })

    test('should detect null bytes in filename', () => {
      const maliciousFile = new File(['content'], 'file.txt\0.exe', { type: 'text/plain' })
      const result = validateFileUpload(maliciousFile)

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Filename contains invalid characters')
    })

    test('should validate empty files', () => {
      const emptyFile = new File([], 'empty.txt', { type: 'text/plain' })
      const result = validateFileUpload(emptyFile)

      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('File is empty')
    })

    test('should accept valid files', () => {
      const validFile = new File(['Hello, World!'], 'document.txt', { type: 'text/plain' })
      const result = validateFileUpload(validFile)

      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })
  })

  describe('Magic Number Validation', () => {
    test('should validate JPEG magic numbers', async () => {
      // JPEG magic number: FF D8 FF
      const jpegBuffer = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46])
      const result = await securityService.scanFile(jpegBuffer, 'image.jpg', {
        enableContentAnalysis: false,
        validateMagicNumbers: true
      })

      expect(result.isSecure).toBe(true)
    })

    test('should detect mismatched file types', async () => {
      // PNG magic number in a .jpg file
      const pngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
      const result = await securityService.scanFile(pngBuffer, 'fake.jpg', {
        enableContentAnalysis: false,
        validateMagicNumbers: true
      })

      expect(result.warnings).toContain("File content doesn't match expected type for .jpg")
    })

    test('should detect embedded executables', async () => {
      // PE executable magic number: MZ
      const executableBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00])
      const result = await securityService.scanFile(executableBuffer, 'document.pdf', {
        enableContentAnalysis: true,
        validateMagicNumbers: true
      })

      expect(result.isSecure).toBe(false)
      expect(result.threats).toContain('File contains embedded executable code')
    })
  })

  describe('Content Analysis', () => {
    test('should detect script injection patterns', async () => {
      const maliciousContent = decodeSecurityPattern(encodedSecurityPatterns.xssPattern)
      const buffer = Buffer.from(maliciousContent)
      const result = await securityService.scanFile(buffer, 'malicious.html', {
        enableContentAnalysis: true
      })

      expect(result.isSecure).toBe(false)
      expect(result.threats).toContain('File contains potentially malicious script content')
    })

    test('should detect command execution patterns', async () => {
      const maliciousContent = 'system("rm -rf /")'
      const buffer = Buffer.from(maliciousContent)
      const result = await securityService.scanFile(buffer, 'malicious.txt', {
        enableContentAnalysis: true
      })

      expect(result.warnings).toContain('File contains command execution patterns')
    })

    test('should detect high entropy content', async () => {
      // Generate high entropy content (random-looking)
      const highEntropyContent = 'aB3xY9mK2pQ7wE5rT8uI1oP6sD4fG0hJ'
      const buffer = Buffer.from(highEntropyContent.repeat(100))
      const result = await securityService.scanFile(buffer, 'suspicious.txt', {
        enableContentAnalysis: true
      })

      expect(result.warnings).toContain('File has high entropy - possible obfuscation or encryption')
    })

    test('should detect multiple base64 strings', async () => {
      const base64Content = 'SGVsbG8gV29ybGQ= ' + 'VGhpcyBpcyBhIHRlc3Q= '.repeat(10)
      const buffer = Buffer.from(base64Content)
      const result = await securityService.scanFile(buffer, 'encoded.txt', {
        enableContentAnalysis: true
      })

      expect(result.warnings).toContain('File contains multiple base64 encoded strings')
    })
  })

  describe('Quarantine Functionality', () => {
    test('should quarantine malicious files', async () => {
      const maliciousContent = decodeSecurityPattern(encodedSecurityPatterns.xssPattern)
      const maliciousBuffer = Buffer.from(maliciousContent)
      const result = await securityService.scanFile(maliciousBuffer, 'malicious.html', {
        enableQuarantine: true,
        enableContentAnalysis: true,
        quarantineDirectory: testPaths.quarantineDir
      })

      expect(result.quarantined).toBe(true)
      expect(result.isSecure).toBe(false)
    })

    test('should not quarantine safe files', async () => {
      const safeBuffer = Buffer.from(testFileContents.plainText)
      const result = await securityService.scanFile(safeBuffer, 'safe.txt', {
        enableQuarantine: true,
        enableContentAnalysis: true,
        quarantineDirectory: testPaths.quarantineDir
      })

      expect(result.quarantined).toBe(false)
      expect(result.isSecure).toBe(true)
    })
  })

  describe('Hash Checking', () => {
    test('should detect known malware hashes', async () => {
      const testBuffer = Buffer.from('test malware content')
      const mockHash = 'test-hash-12345' // Using mocked hash value

      securityService.addMalwareHash(mockHash)

      const result = await securityService.scanFile(testBuffer, 'malware.exe', {
        enableHashChecking: true
      })

      expect(result.isSecure).toBe(false)
      expect(result.threats).toContain('File matches known malware signature')
    })
  })

  describe('Filename Security', () => {
    test('should generate secure filenames', () => {
      const maliciousName = '../../../etc/passwd'
      const secureName = generateSecureFilename(maliciousName)

      expect(secureName).not.toContain('../')
      expect(secureName).not.toContain('/')
      expect(secureName).toMatch(/^[a-zA-Z0-9._-]+_\d+$/)
    })

    test('should preserve file extensions', () => {
      const filename = 'document.pdf'
      const secureName = generateSecureFilename(filename, true)

      expect(secureName).toEndWith('.pdf')
    })

    test('should handle long filenames', () => {
      const longName = 'a'.repeat(200) + '.txt'
      const secureName = generateSecureFilename(longName)

      expect(secureName.length).toBeLessThan(150) // Including timestamp
    })

    test('should remove invalid characters', () => {
      const invalidName = 'file<>:"|?*.txt'
      const secureName = generateSecureFilename(invalidName)

      expect(secureName).not.toMatch(/[<>:"|?*]/)
    })
  })

  describe('Performance and Limits', () => {
    test('should handle scan timeout', async () => {
      const largeBuffer = Buffer.alloc(1024 * 1024, 'a') // 1MB of 'a'
      const startTime = Date.now()

      const result = await securityService.scanFile(largeBuffer, 'large.txt', {
        enableContentAnalysis: true,
        maxScanTime: 100 // Very short timeout
      })

      const duration = Date.now() - startTime
      expect(duration).toBeLessThan(5000) // Should not take too long
      expect(result.scanDuration).toBeGreaterThan(0)
    })

    test('should limit content analysis to reasonable size', async () => {
      // Test that very large files don't cause memory issues
      const hugeBuffer = Buffer.alloc(10 * 1024 * 1024, 'x') // 10MB
      const result = await securityService.scanFile(hugeBuffer, 'huge.txt', {
        enableContentAnalysis: true
      })

      // Should complete without throwing memory errors
      expect(result).toBeDefined()
      expect(result.scanDuration).toBeGreaterThan(0)
    })
  })

  describe('Integration with Validation Service', () => {
    test('should integrate with existing validation service', () => {
      const file = {
        name: 'test.txt',
        size: 1024,
        type: 'text/plain'
      }

      const result = validationService.validateFileUpload(file, {
        maxSize: 2048,
        allowedTypes: ['text/plain'],
        allowedExtensions: ['.txt']
      })

      expect(result.isValid).toBe(true)
    })

    test('should handle malware scanning integration', async () => {
      const file = new File(['test content'], 'test.txt', { type: 'text/plain' })

      const scanResult = await validationService.scanFileForMalware(file)

      expect(scanResult).toBeDefined()
      expect(scanResult.isValid).toBe(true)
    })
  })
})