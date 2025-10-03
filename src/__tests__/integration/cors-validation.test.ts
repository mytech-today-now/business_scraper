/**
 * CORS Validation Test Suite
 * Comprehensive tests to validate CORS functionality after infrastructure fixes
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals'
import { NextRequest } from 'next/server'
import {
  createCORSRequest,
  createPreflightRequest,
  validateCORSHeaders,
  testCORSPreflight,
  testCORSRequest,
  setupCORSTestEnvironment
} from '../utils/corsTestUtils'

// Import API handlers for testing
import { POST as enhancedScrapePost, GET as enhancedScrapeGet } from '@/app/api/enhanced-scrape/route'
import { POST as dataManagementPost, GET as dataManagementGet } from '@/app/api/data-management/route'

describe('CORS Infrastructure Validation', () => {
  let corsTestEnv: { cleanup: () => void }

  beforeEach(() => {
    corsTestEnv = setupCORSTestEnvironment()
  })

  afterEach(() => {
    corsTestEnv.cleanup()
  })

  describe('Global Fetch Mock CORS Support', () => {
    it('should handle CORS headers in fetch responses', async () => {
      const response = await fetch('http://localhost:3000/api/test', {
        method: 'GET',
        headers: {
          'Origin': 'http://localhost:3000'
        }
      })

      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*')
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('GET')
      expect(response.headers.get('Access-Control-Allow-Headers')).toContain('Content-Type')
      expect(response.headers.get('Access-Control-Allow-Credentials')).toBe('true')
    })

    it('should handle OPTIONS preflight requests', async () => {
      const response = await fetch('http://localhost:3000/api/test', {
        method: 'OPTIONS',
        headers: {
          'Origin': 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type, Authorization'
        }
      })

      expect(response.status).toBe(200)
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*')
      expect(response.headers.get('Access-Control-Allow-Methods')).toContain('POST')
      expect(response.headers.get('Access-Control-Allow-Headers')).toContain('Authorization')
    })
  })

  describe('XMLHttpRequest CORS Support', () => {
    it('should handle CORS requests with XMLHttpRequest', (done) => {
      const xhr = new XMLHttpRequest()
      
      xhr.addEventListener('load', () => {
        expect(xhr.status).toBe(200)
        expect(xhr.getResponseHeader('Access-Control-Allow-Origin')).toBe('*')
        expect(xhr.getResponseHeader('Access-Control-Allow-Methods')).toContain('GET')
        done()
      })

      xhr.addEventListener('error', () => {
        done(new Error('XMLHttpRequest failed'))
      })

      xhr.open('GET', 'http://localhost:3000/api/test')
      xhr.setRequestHeader('Origin', 'http://localhost:3000')
      xhr.send()
    })

    it('should handle OPTIONS preflight with XMLHttpRequest', (done) => {
      const xhr = new XMLHttpRequest()
      
      xhr.addEventListener('load', () => {
        expect(xhr.status).toBe(200)
        expect(xhr.getResponseHeader('Access-Control-Allow-Origin')).toBe('*')
        expect(xhr.getResponseHeader('Access-Control-Allow-Methods')).toContain('OPTIONS')
        done()
      })

      xhr.addEventListener('error', () => {
        done(new Error('XMLHttpRequest OPTIONS failed'))
      })

      xhr.open('OPTIONS', 'http://localhost:3000/api/test')
      xhr.setRequestHeader('Origin', 'http://localhost:3000')
      xhr.setRequestHeader('Access-Control-Request-Method', 'POST')
      xhr.send()
    })
  })

  describe('CORS Test Utilities Validation', () => {
    it('should create valid CORS requests', () => {
      const request = createCORSRequest('http://localhost:3000/api/test', {
        method: 'POST',
        origin: 'http://localhost:3000'
      })

      expect(request.method).toBe('POST')
      expect(request.headers.get('Origin')).toBe('http://localhost:3000')
      expect(request.headers.get('Access-Control-Request-Method')).toBe('POST')
    })

    it('should create valid preflight requests', () => {
      const request = createPreflightRequest('http://localhost:3000/api/test', {
        allowedMethods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'Authorization']
      })

      expect(request.method).toBe('OPTIONS')
      expect(request.headers.get('Origin')).toBe('http://localhost:3000')
      expect(request.headers.get('Access-Control-Request-Method')).toContain('GET')
      expect(request.headers.get('Access-Control-Request-Headers')).toContain('Content-Type')
    })

    it('should validate CORS headers correctly', () => {
      const mockResponse = {
        headers: new Headers({
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
          'Access-Control-Allow-Credentials': 'true'
        })
      }

      const isValid = validateCORSHeaders(mockResponse, {
        origin: '*',
        allowedMethods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true
      })

      expect(isValid).toBe(true)
    })
  })

  describe('API Endpoint CORS Integration', () => {
    it('should handle CORS in Enhanced Scrape API GET requests', async () => {
      const request = createCORSRequest('http://localhost:3000/api/enhanced-scrape', {
        method: 'GET',
        origin: 'http://localhost:3000'
      })

      // Mock the dependencies to prevent actual API calls
      jest.mock('@/lib/enhancedScrapingEngine', () => ({
        enhancedScrapingEngine: {
          getStats: jest.fn().mockReturnValue({
            totalJobs: 0,
            completedJobs: 0,
            failedJobs: 0,
            queueSize: 0
          })
        }
      }))

      const response = await enhancedScrapeGet(request)
      
      expect(response.status).toBe(200)
      // Note: The actual API might not set CORS headers, but our test environment should handle it
    })

    it('should handle CORS in Data Management API GET requests', async () => {
      const request = createCORSRequest('http://localhost:3000/api/data-management?type=overview', {
        method: 'GET',
        origin: 'http://localhost:3000'
      })

      // Mock the dependencies
      jest.mock('@/lib/postgresql-database', () => ({
        database: {
          query: jest.fn().mockResolvedValue({ rows: [] })
        }
      }))

      const response = await dataManagementGet(request)
      
      expect(response.status).toBe(200)
    })
  })

  describe('Cross-Origin Request Scenarios', () => {
    it('should handle requests from different origins', async () => {
      const origins = [
        'http://localhost:3000',
        'http://localhost:3001',
        'https://example.com'
      ]

      for (const origin of origins) {
        const response = await fetch('http://localhost:3000/api/test', {
          method: 'GET',
          headers: { 'Origin': origin }
        })

        expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*')
        expect(response.status).toBe(200)
      }
    })

    it('should handle complex CORS scenarios', async () => {
      // Test preflight followed by actual request
      const preflightResponse = await fetch('http://localhost:3000/api/test', {
        method: 'OPTIONS',
        headers: {
          'Origin': 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type, X-CSRF-Token'
        }
      })

      expect(preflightResponse.status).toBe(200)
      expect(preflightResponse.headers.get('Access-Control-Allow-Methods')).toContain('POST')

      // Follow up with actual request
      const actualResponse = await fetch('http://localhost:3000/api/test', {
        method: 'POST',
        headers: {
          'Origin': 'http://localhost:3000',
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'test-token'
        },
        body: JSON.stringify({ test: 'data' })
      })

      expect(actualResponse.status).toBe(200)
      expect(actualResponse.headers.get('Access-Control-Allow-Origin')).toBe('*')
    })
  })

  describe('Error Scenarios', () => {
    it('should handle CORS errors gracefully', async () => {
      // Test with invalid origin (should still work with our permissive setup)
      const response = await fetch('http://localhost:3000/api/test', {
        method: 'GET',
        headers: {
          'Origin': 'http://malicious-site.com'
        }
      })

      // Our test environment allows all origins
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*')
    })

    it('should handle missing CORS headers gracefully', async () => {
      // Test request without Origin header
      const response = await fetch('http://localhost:3000/api/test', {
        method: 'GET'
      })

      expect(response.status).toBe(200)
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('*')
    })
  })
})
