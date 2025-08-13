/**
 * File Upload API Integration Tests
 * Tests for the secure file upload endpoint
 */

import { NextRequest } from 'next/server'
import { POST, GET } from '@/app/api/upload/route'
import fs from 'fs'
import path from 'path'

// Mock dependencies
jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1'),
  getSession: jest.fn(() => ({ user: { id: 'test-user' } }))
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

describe('/api/upload', () => {
  beforeEach(() => {
    // Clean up test directories
    const testDirs = ['./test-uploads', './test-quarantine']
    testDirs.forEach(dir => {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true })
      }
    })
  })

  afterEach(() => {
    // Clean up test directories
    const testDirs = ['./test-uploads', './test-quarantine']
    testDirs.forEach(dir => {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true })
      }
    })
  })

  describe('GET /api/upload', () => {
    test('should return upload configuration', async () => {
      const request = new NextRequest('http://localhost:3000/api/upload?type=documents')
      const response = await GET(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.uploadType).toBe('documents')
      expect(data.configuration).toBeDefined()
      expect(data.configuration.maxSize).toBeDefined()
      expect(data.configuration.allowedTypes).toBeDefined()
      expect(data.configuration.allowedExtensions).toBeDefined()
    })

    test('should return different configs for different types', async () => {
      const imageRequest = new NextRequest('http://localhost:3000/api/upload?type=images')
      const imageResponse = await GET(imageRequest)
      const imageData = await imageResponse.json()

      const backupRequest = new NextRequest('http://localhost:3000/api/upload?type=backup')
      const backupResponse = await GET(backupRequest)
      const backupData = await backupResponse.json()

      expect(imageData.configuration.allowedTypes).toContain('image/jpeg')
      expect(backupData.configuration.allowedTypes).toContain('text/plain')
      expect(imageData.configuration.maxFiles).not.toBe(backupData.configuration.maxFiles)
    })
  })

  describe('POST /api/upload', () => {
    test('should reject non-POST requests', async () => {
      const request = new NextRequest('http://localhost:3000/api/upload', { method: 'GET' })
      const response = await POST(request)

      expect(response.status).toBe(405)
    })

    test('should accept valid file uploads', async () => {
      const formData = new FormData()
      const testFile = new File(['Hello, World!'], 'test.txt', { type: 'text/plain' })
      formData.append('file', testFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.filesProcessed).toBe(1)
      expect(data.results).toHaveLength(1)
      expect(data.results[0].isSecure).toBe(true)
    })

    test('should reject files exceeding size limit', async () => {
      const formData = new FormData()
      const largeContent = 'x'.repeat(11 * 1024 * 1024) // 11MB
      const largeFile = new File([largeContent], 'large.txt', { type: 'text/plain' })
      formData.append('file', largeFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('exceeds size limit')
    })

    test('should reject executable files', async () => {
      const formData = new FormData()
      const execFile = new File(['MZ'], 'malware.exe', { type: 'application/octet-stream' })
      formData.append('file', execFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('failed security scan')
    })

    test('should reject empty files', async () => {
      const formData = new FormData()
      const emptyFile = new File([], 'empty.txt', { type: 'text/plain' })
      formData.append('file', emptyFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('empty')
    })

    test('should handle multiple file uploads', async () => {
      const formData = new FormData()
      const file1 = new File(['Content 1'], 'file1.txt', { type: 'text/plain' })
      const file2 = new File(['Content 2'], 'file2.txt', { type: 'text/plain' })
      
      formData.append('file1', file1)
      formData.append('file2', file2)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.success).toBe(true)
      expect(data.filesProcessed).toBe(2)
      expect(data.results).toHaveLength(2)
    })

    test('should enforce file count limits', async () => {
      const formData = new FormData()
      
      // Add more files than allowed for backup type (limit: 1)
      for (let i = 0; i < 3; i++) {
        const file = new File([`Content ${i}`], `file${i}.txt`, { type: 'text/plain' })
        formData.append(`file${i}`, file)
      }

      const request = new NextRequest('http://localhost:3000/api/upload?type=backup', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('Maximum')
    })

    test('should save files when requested', async () => {
      const formData = new FormData()
      const testFile = new File(['Test content'], 'test.txt', { type: 'text/plain' })
      formData.append('file', testFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents&save=true', {
        method: 'POST',
        body: formData
      })

      // Set upload directory for test
      process.env.UPLOAD_DIR = './test-uploads'

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.results[0].savedAs).toBeDefined()
      expect(data.results[0].savedPath).toBeDefined()
    })

    test('should handle malicious script content', async () => {
      const formData = new FormData()
      const maliciousFile = new File(['<script>alert("XSS")</script>'], 'malicious.html', { type: 'text/html' })
      formData.append('file', maliciousFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('failed security scan')
      expect(data.threats).toBeDefined()
    })

    test('should validate JSON structure for backup files', async () => {
      const formData = new FormData()
      const validJson = new File(['{"key": "value"}'], 'backup.json', { type: 'application/json' })
      formData.append('file', validJson)

      const request = new NextRequest('http://localhost:3000/api/upload?type=backup', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.results[0].processed).toBe(true)
    })

    test('should reject invalid JSON for backup files', async () => {
      const formData = new FormData()
      const invalidJson = new File(['invalid json content'], 'backup.json', { type: 'application/json' })
      formData.append('file', invalidJson)

      const request = new NextRequest('http://localhost:3000/api/upload?type=backup', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.results[0].processed).toBe(false)
    })

    test('should validate CSV structure for data import', async () => {
      const formData = new FormData()
      const validCsv = new File(['name,category\nBusiness 1,Retail'], 'data.csv', { type: 'text/csv' })
      formData.append('file', validCsv)

      const request = new NextRequest('http://localhost:3000/api/upload?type=dataImport', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.results[0].processed).toBe(true)
    })

    test('should include security scan details in response', async () => {
      const formData = new FormData()
      const testFile = new File(['Test content'], 'test.txt', { type: 'text/plain' })
      formData.append('file', testFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.results[0].securityScan).toBeDefined()
      expect(data.results[0].securityScan.scanDuration).toBeGreaterThan(0)
      expect(data.results[0].securityScan.fileHash).toBeDefined()
      expect(data.results[0].securityScan.threats).toBeDefined()
      expect(data.results[0].securityScan.warnings).toBeDefined()
    })

    test('should handle file processing errors gracefully', async () => {
      const formData = new FormData()
      const testFile = new File(['Test content'], 'test.txt', { type: 'text/plain' })
      formData.append('file', testFile)

      // Mock a processing error
      const originalEnv = process.env.UPLOAD_DIR
      process.env.UPLOAD_DIR = '/invalid/path/that/does/not/exist'

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents&save=true', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      // Should still succeed for security scan, but fail to save
      expect(response.status).toBe(200)
      expect(data.results[0].saveError).toBeDefined()

      // Restore environment
      process.env.UPLOAD_DIR = originalEnv
    })
  })

  describe('Security Features', () => {
    test('should quarantine malicious files', async () => {
      const formData = new FormData()
      const maliciousFile = new File(['<script>alert("XSS")</script>'], 'malicious.html', { type: 'text/html' })
      formData.append('file', maliciousFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.quarantined).toBe(true)
    })

    test('should detect path traversal in filenames', async () => {
      const formData = new FormData()
      const maliciousFile = new File(['content'], '../../../etc/passwd', { type: 'text/plain' })
      formData.append('file', maliciousFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=documents', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(400)
      expect(data.error).toContain('failed security scan')
    })

    test('should handle different upload types with appropriate security', async () => {
      const formData = new FormData()
      const imageFile = new File([new Uint8Array([0xFF, 0xD8, 0xFF])], 'image.jpg', { type: 'image/jpeg' })
      formData.append('file', imageFile)

      const request = new NextRequest('http://localhost:3000/api/upload?type=images', {
        method: 'POST',
        body: formData
      })

      const response = await POST(request)
      const data = await response.json()

      expect(response.status).toBe(200)
      expect(data.uploadType).toBe('images')
      expect(data.results[0].isSecure).toBe(true)
    })
  })
})
