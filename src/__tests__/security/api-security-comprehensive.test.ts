/**
 * Comprehensive API Security Tests for api-security.ts
 * Tests all security middleware functionality including authentication, authorization,
 * CSRF protection, rate limiting, input validation, and security headers
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest, NextResponse } from 'next/server'
import { 
  withApiSecurity, 
  validateParameters, 
  createSecureErrorResponse,
  SecurityOptions,
  ValidationRule
} from '@/lib/api-security'
import { getSession, getClientIP, sanitizeInput, validateInput } from '@/lib/security'
import { csrfProtectionService } from '@/lib/csrfProtection'
import { advancedRateLimitService } from '@/lib/advancedRateLimit'
import { enhancedSecurityMonitoringService } from '@/lib/enhanced-security-monitoring'
import { logger } from '@/utils/logger'

// Mock all dependencies
jest.mock('@/lib/security')
jest.mock('@/lib/csrfProtection')
jest.mock('@/lib/advancedRateLimit')
jest.mock('@/lib/enhanced-security-monitoring')
jest.mock('@/utils/logger')

interface SecurityTestResult {
  testName: string
  category: string
  passed: boolean
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  vulnerabilityType?: string
  recommendation?: string
}

class ApiSecurityTester {
  private results: SecurityTestResult[] = []

  async runSecurityTest(
    testName: string,
    category: string,
    testFunction: () => Promise<boolean>,
    severity: 'low' | 'medium' | 'high' | 'critical',
    description: string,
    vulnerabilityType?: string
  ): Promise<SecurityTestResult> {
    try {
      const passed = await testFunction()
      const result: SecurityTestResult = {
        testName,
        category,
        passed,
        severity,
        description,
        vulnerabilityType,
        recommendation: passed ? undefined : 'Review and fix the identified security issue'
      }

      this.results.push(result)

      if (!passed) {
        logger.error('API Security Test', `Security issue found: ${testName}`, result)
      }

      return result
    } catch (error) {
      const result: SecurityTestResult = {
        testName,
        category,
        passed: false,
        severity: 'critical',
        description: `Test execution failed: ${error}`,
        recommendation: 'Fix test execution error and re-run security tests'
      }

      this.results.push(result)
      return result
    }
  }

  getResults(): SecurityTestResult[] {
    return this.results
  }

  getFailedTests(): SecurityTestResult[] {
    return this.results.filter(result => !result.passed)
  }

  getCriticalIssues(): SecurityTestResult[] {
    return this.results.filter(result => !result.passed && result.severity === 'critical')
  }

  generateReport(): string {
    const total = this.results.length
    const passed = this.results.filter(r => r.passed).length
    const failed = total - passed
    const critical = this.getCriticalIssues().length

    let report = '\n=== API Security Test Report ===\n'
    report += `Total Tests: ${total}\n`
    report += `Passed: ${passed}\n`
    report += `Failed: ${failed}\n`
    report += `Critical Issues: ${critical}\n\n`

    if (failed > 0) {
      report += '=== Failed Tests by Category ===\n'
      const categories = [...new Set(this.getFailedTests().map(t => t.category))]
      
      categories.forEach(category => {
        const categoryTests = this.getFailedTests().filter(t => t.category === category)
        report += `\n${category}:\n`
        categoryTests.forEach(test => {
          report += `  ❌ ${test.testName} (${test.severity})\n`
          report += `     ${test.description}\n`
        })
      })
    }

    return report
  }
}

describe('API Security Comprehensive Tests', () => {
  let apiSecurityTester: ApiSecurityTester
  let mockGetSession: jest.MockedFunction<typeof getSession>
  let mockGetClientIP: jest.MockedFunction<typeof getClientIP>
  let mockSanitizeInput: jest.MockedFunction<typeof sanitizeInput>
  let mockValidateInput: jest.MockedFunction<typeof validateInput>
  let mockCsrfService: any
  let mockRateLimitService: any
  let mockSecurityMonitoring: any
  let mockLogger: any

  beforeEach(() => {
    jest.clearAllMocks()
    apiSecurityTester = new ApiSecurityTester()
    
    // Setup mocks
    mockGetSession = getSession as jest.MockedFunction<typeof getSession>
    mockGetClientIP = getClientIP as jest.MockedFunction<typeof getClientIP>
    mockSanitizeInput = sanitizeInput as jest.MockedFunction<typeof sanitizeInput>
    mockValidateInput = validateInput as jest.MockedFunction<typeof validateInput>
    
    mockCsrfService = csrfProtectionService as any
    mockRateLimitService = advancedRateLimitService as any
    mockSecurityMonitoring = enhancedSecurityMonitoringService as any
    mockLogger = logger as any

    // Default mock implementations
    mockGetClientIP.mockReturnValue('127.0.0.1')
    mockSanitizeInput.mockImplementation((input: string) => input)
    mockValidateInput.mockReturnValue({ isValid: true, errors: [] })
    
    mockGetSession.mockReturnValue({
      userId: 'test-user',
      isValid: true,
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000
    })
    
    mockCsrfService.validateCSRFToken = jest.fn().mockReturnValue(true)
    mockRateLimitService.checkApiRateLimit = jest.fn().mockReturnValue({ 
      allowed: true, 
      remaining: 100, 
      resetTime: Date.now() + 60000 
    })
    
    mockSecurityMonitoring.analyzeRequest = jest.fn().mockReturnValue([])
    mockSecurityMonitoring.logSecurityEvent = jest.fn()
    
    mockLogger.info = jest.fn()
    mockLogger.warn = jest.fn()
    mockLogger.error = jest.fn()
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Authentication Security Tests', () => {
    test('should enforce authentication when required', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'Authentication Enforcement',
        'Authentication',
        async () => {
          const request = new NextRequest('http://localhost:3000/api/protected', {
            method: 'GET'
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ data: 'protected' })
            },
            { requireAuth: true }
          )

          const response = await handler(request)
          
          // Should return 401 when no session provided
          return response.status === 401
        },
        'critical',
        'Tests that protected endpoints require valid authentication',
        'Authentication Bypass'
      )

      expect(result.passed).toBe(true)
    })

    test('should reject invalid sessions', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'Invalid Session Rejection',
        'Authentication',
        async () => {
          mockGetSession.mockReturnValue(null)

          const request = new NextRequest('http://localhost:3000/api/protected', {
            method: 'GET',
            headers: {
              'Cookie': 'session-id=invalid-session'
            }
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ data: 'protected' })
            },
            { requireAuth: true }
          )

          const response = await handler(request)
          
          // Should return 401 for invalid session
          return response.status === 401
        },
        'critical',
        'Tests that invalid sessions are properly rejected',
        'Session Management'
      )

      expect(result.passed).toBe(true)
    })

    test('should handle expired sessions', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'Expired Session Handling',
        'Authentication',
        async () => {
          mockGetSession.mockReturnValue({
            userId: 'test-user',
            isValid: false, // Expired session
            createdAt: Date.now() - 7200000,
            expiresAt: Date.now() - 3600000
          })

          const request = new NextRequest('http://localhost:3000/api/protected', {
            method: 'GET',
            headers: {
              'Cookie': 'session-id=expired-session'
            }
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ data: 'protected' })
            },
            { requireAuth: true }
          )

          const response = await handler(request)
          
          // Should return 401 for expired session and clear cookie
          const setCookieHeader = response.headers.get('Set-Cookie')
          return response.status === 401 && setCookieHeader?.includes('session-id=;')
        },
        'high',
        'Tests that expired sessions are properly handled and cleared',
        'Session Management'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('CSRF Protection Tests', () => {
    test('should enforce CSRF protection for state-changing requests', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'CSRF Protection Enforcement',
        'CSRF Protection',
        async () => {
          const request = new NextRequest('http://localhost:3000/api/data', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Cookie': 'session-id=valid-session'
            },
            body: JSON.stringify({ data: 'test' })
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ success: true })
            },
            { requireCSRF: true }
          )

          const response = await handler(request)
          
          // Should return 403 when CSRF token is missing
          return response.status === 403
        },
        'critical',
        'Tests that CSRF protection is enforced for state-changing requests',
        'CSRF'
      )

      expect(result.passed).toBe(true)
    })

    test('should validate CSRF tokens properly', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'CSRF Token Validation',
        'CSRF Protection',
        async () => {
          mockCsrfService.validateCSRFToken.mockReturnValue(false)

          const request = new NextRequest('http://localhost:3000/api/data', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Cookie': 'session-id=valid-session',
              'X-CSRF-Token': 'invalid-token'
            },
            body: JSON.stringify({ data: 'test' })
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ success: true })
            },
            { requireCSRF: true }
          )

          const response = await handler(request)
          
          // Should return 403 for invalid CSRF token
          return response.status === 403
        },
        'critical',
        'Tests that invalid CSRF tokens are properly rejected',
        'CSRF'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('Rate Limiting Tests', () => {
    test('should enforce rate limits properly', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'Rate Limit Enforcement',
        'Rate Limiting',
        async () => {
          mockRateLimitService.checkApiRateLimit.mockReturnValue({
            allowed: false,
            remaining: 0,
            resetTime: Date.now() + 60000,
            retryAfter: 60
          })

          const request = new NextRequest('http://localhost:3000/api/test', {
            method: 'GET'
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ data: 'test' })
            },
            { rateLimit: 'general' }
          )

          const response = await handler(request)

          // Should return 429 when rate limit exceeded
          const retryAfterHeader = response.headers.get('Retry-After')
          const rateLimitHeaders = [
            response.headers.get('X-RateLimit-Remaining'),
            response.headers.get('X-RateLimit-Reset')
          ]

          return response.status === 429 &&
                 retryAfterHeader === '60' &&
                 rateLimitHeaders.every(header => header !== null)
        },
        'medium',
        'Tests that rate limiting is properly enforced with correct headers',
        'Rate Limiting'
      )

      expect(result.passed).toBe(true)
    })

    test('should handle different rate limit types', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'Rate Limit Types',
        'Rate Limiting',
        async () => {
          const rateLimitTypes = ['general', 'scraping', 'auth', 'upload', 'export']

          for (const limitType of rateLimitTypes) {
            const request = new NextRequest('http://localhost:3000/api/test', {
              method: 'GET'
            })

            const handler = withApiSecurity(
              async (req: NextRequest) => {
                return NextResponse.json({ data: 'test' })
              },
              { rateLimit: limitType as any }
            )

            await handler(request)

            // Verify rate limit service was called with correct type
            expect(mockRateLimitService.checkApiRateLimit).toHaveBeenCalledWith(
              expect.any(Object),
              limitType
            )
          }

          return true
        },
        'medium',
        'Tests that different rate limit types are properly handled',
        'Rate Limiting'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('Input Validation Tests', () => {
    test('should validate JSON input properly', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'JSON Input Validation',
        'Input Validation',
        async () => {
          mockValidateInput.mockReturnValue({
            isValid: false,
            errors: ['Invalid input detected']
          })

          const request = new NextRequest('http://localhost:3000/api/data', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              maliciousField: '<script>alert("xss")</script>'
            })
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ success: true })
            },
            { validateInput: true }
          )

          const response = await handler(request)

          // Should return 400 for invalid input
          return response.status === 400
        },
        'high',
        'Tests that malicious JSON input is properly validated and rejected',
        'Input Validation'
      )

      expect(result.passed).toBe(true)
    })

    test('should handle malformed JSON gracefully', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'Malformed JSON Handling',
        'Input Validation',
        async () => {
          const request = new NextRequest('http://localhost:3000/api/data', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: '{"invalid": json}'
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ success: true })
            },
            { validateInput: true }
          )

          const response = await handler(request)

          // Should return 400 for malformed JSON
          return response.status === 400
        },
        'medium',
        'Tests that malformed JSON is handled gracefully',
        'Input Validation'
      )

      expect(result.passed).toBe(true)
    })

    test('should sanitize input strings', async () => {
      const result = await apiSecurityTester.runSecurityTest(
        'Input Sanitization',
        'Input Validation',
        async () => {
          const maliciousInput = '<script>alert("xss")</script>'
          const sanitizedInput = 'alert("xss")'

          mockSanitizeInput.mockReturnValue(sanitizedInput)
          mockValidateInput.mockReturnValue({ isValid: true, errors: [] })

          const request = new NextRequest('http://localhost:3000/api/data', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              userInput: maliciousInput
            })
          })

          const handler = withApiSecurity(
            async (req: NextRequest) => {
              return NextResponse.json({ success: true })
            },
            { validateInput: true }
          )

          await handler(request)

          // Should call sanitizeInput for string values
          expect(mockSanitizeInput).toHaveBeenCalledWith(maliciousInput)

          return true
        },
        'high',
        'Tests that input strings are properly sanitized',
        'Input Validation'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('Test Results Summary', () => {
    test('should generate comprehensive API security test report', async () => {
      const report = apiSecurityTester.generateReport()
      const results = apiSecurityTester.getResults()
      const failedTests = apiSecurityTester.getFailedTests()
      const criticalIssues = apiSecurityTester.getCriticalIssues()

      console.log(report)

      // Security tests should have high success rate
      const passRate = (results.length - failedTests.length) / results.length
      expect(passRate).toBeGreaterThanOrEqual(0.98)

      // No critical security issues should be found
      expect(criticalIssues.length).toBe(0)

      // Should have comprehensive test coverage
      expect(results.length).toBeGreaterThanOrEqual(10)
    })
  })
})
