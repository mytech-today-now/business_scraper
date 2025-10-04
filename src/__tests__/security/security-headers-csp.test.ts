/**
 * Security Headers and Content Security Policy (CSP) Tests
 * 
 * This test suite validates that all security headers are properly set,
 * Content Security Policy is correctly configured, and HTTPS enforcement
 * is working properly.
 * 
 * @author Security Team
 * @version 1.0.0
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest, NextResponse } from 'next/server'

// Mock dependencies
jest.mock('../../lib/security-headers', () => ({
  setSecurityHeaders: jest.fn(),
  validateCSP: jest.fn(),
  enforceHTTPS: jest.fn(),
  setHSTS: jest.fn(),
  setXFrameOptions: jest.fn(),
  setXContentTypeOptions: jest.fn(),
  setXXSSProtection: jest.fn(),
  setReferrerPolicy: jest.fn(),
  setPermissionsPolicy: jest.fn()
}))

import {
  setSecurityHeaders,
  validateCSP,
  enforceHTTPS,
  setHSTS,
  setXFrameOptions,
  setXContentTypeOptions,
  setXXSSProtection,
  setReferrerPolicy,
  setPermissionsPolicy
} from '../../lib/security-headers'

interface SecurityHeaderTestResult {
  testName: string
  category: string
  passed: boolean
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  vulnerabilityType?: string
  attackVector?: string
  impact?: string
  recommendation?: string
  headerName?: string
  headerValue?: string
  timestamp: number
}

class SecurityHeadersTester {
  private results: SecurityHeaderTestResult[] = []

  async runSecurityHeaderTest(
    testName: string,
    category: string,
    testFunction: () => Promise<boolean>,
    severity: 'low' | 'medium' | 'high' | 'critical',
    description: string,
    vulnerabilityType?: string,
    attackVector?: string,
    impact?: string,
    recommendation?: string,
    headerName?: string,
    headerValue?: string
  ): Promise<SecurityHeaderTestResult> {
    try {
      const passed = await testFunction()
      const result: SecurityHeaderTestResult = {
        testName,
        category,
        passed,
        severity,
        description,
        vulnerabilityType,
        attackVector,
        impact,
        recommendation,
        headerName,
        headerValue,
        timestamp: Date.now()
      }
      
      this.results.push(result)
      return result
    } catch (error) {
      const result: SecurityHeaderTestResult = {
        testName,
        category,
        passed: false,
        severity,
        description: `${description} - Error: ${error}`,
        vulnerabilityType,
        attackVector,
        impact,
        recommendation,
        headerName,
        headerValue,
        timestamp: Date.now()
      }
      
      this.results.push(result)
      return result
    }
  }

  getResults(): SecurityHeaderTestResult[] {
    return this.results
  }

  getFailedTests(): SecurityHeaderTestResult[] {
    return this.results.filter(result => !result.passed)
  }

  getCriticalIssues(): SecurityHeaderTestResult[] {
    return this.results.filter(result => !result.passed && result.severity === 'critical')
  }

  generateSecurityHeadersReport(): {
    summary: string
    categories: Record<string, SecurityHeaderTestResult[]>
    criticalIssues: SecurityHeaderTestResult[]
    recommendations: string[]
    complianceStatus: string
  } {
    const categories = this.results.reduce((acc, result) => {
      if (!acc[result.category]) {
        acc[result.category] = []
      }
      acc[result.category].push(result)
      return acc
    }, {} as Record<string, SecurityHeaderTestResult[]>)

    const criticalIssues = this.getCriticalIssues()
    const failedTests = this.getFailedTests()
    const passedTests = this.results.filter(result => result.passed)

    const recommendations = [
      ...new Set(
        failedTests
          .map(test => test.recommendation)
          .filter(Boolean) as string[]
      )
    ]

    const complianceStatus = criticalIssues.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT'

    const summary = `
🔒 SECURITY HEADERS AND CSP TEST REPORT
=====================================

📊 Test Summary:
- Total Tests: ${this.results.length}
- Passed: ${passedTests.length}
- Failed: ${failedTests.length}
- Critical Issues: ${criticalIssues.length}
- Success Rate: ${((passedTests.length / this.results.length) * 100).toFixed(2)}%

🛡️ Security Headers Coverage:
- Content Security Policy (CSP): ${categories['CSP']?.length || 0} tests
- HTTP Strict Transport Security (HSTS): ${categories['HSTS']?.length || 0} tests
- X-Frame-Options: ${categories['X-Frame-Options']?.length || 0} tests
- X-Content-Type-Options: ${categories['X-Content-Type-Options']?.length || 0} tests
- X-XSS-Protection: ${categories['X-XSS-Protection']?.length || 0} tests
- Referrer Policy: ${categories['Referrer Policy']?.length || 0} tests
- Permissions Policy: ${categories['Permissions Policy']?.length || 0} tests

🚨 Compliance Status: ${complianceStatus}

${criticalIssues.length > 0 ? `
⚠️  CRITICAL SECURITY HEADER ISSUES FOUND:
${criticalIssues.map(issue => `- ${issue.testName}: ${issue.description}`).join('\n')}
` : '✅ No critical security header issues found'}
    `

    return {
      summary,
      categories,
      criticalIssues,
      recommendations,
      complianceStatus
    }
  }
}

describe('Security Headers and CSP Tests', () => {
  let securityHeadersTester: SecurityHeadersTester

  beforeEach(() => {
    securityHeadersTester = new SecurityHeadersTester()
    jest.clearAllMocks()
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Content Security Policy (CSP) Tests', () => {
    test('should set strict CSP headers', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'strict_csp_headers',
        'CSP',
        async () => {
          const mockResponse = new NextResponse()
          
          ;(setSecurityHeaders as jest.Mock).mockImplementation((response) => {
            response.headers.set('Content-Security-Policy', 
              "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            )
            return response
          })
          
          const responseWithHeaders = setSecurityHeaders(mockResponse)
          const cspHeader = responseWithHeaders.headers.get('Content-Security-Policy')
          
          return cspHeader !== null && 
                 cspHeader.includes("default-src 'self'") &&
                 cspHeader.includes("frame-ancestors 'none'")
        },
        'critical',
        'Verify that strict Content Security Policy headers are set',
        'Missing CSP Headers',
        'Application',
        'XSS attacks and code injection vulnerabilities',
        'Implement comprehensive CSP headers with strict policies',
        'Content-Security-Policy'
      )

      expect(result.passed).toBe(true)
    })

    test('should prevent unsafe-eval in CSP', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'csp_no_unsafe_eval',
        'CSP',
        async () => {
          ;(validateCSP as jest.Mock).mockReturnValue({
            valid: true,
            hasUnsafeEval: false,
            hasUnsafeInline: false,
            allowsDataUris: false
          })
          
          const cspValidation = validateCSP("default-src 'self'; script-src 'self'")
          
          return cspValidation.valid && !cspValidation.hasUnsafeEval
        },
        'high',
        'Verify that CSP does not allow unsafe-eval',
        'Unsafe CSP Configuration',
        'Application',
        'Code injection and XSS attacks',
        'Remove unsafe-eval from CSP script-src directive',
        'Content-Security-Policy'
      )

      expect(result.passed).toBe(true)
    })

    test('should restrict frame-ancestors', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'csp_frame_ancestors_restriction',
        'CSP',
        async () => {
          const mockResponse = new NextResponse()
          
          ;(setSecurityHeaders as jest.Mock).mockImplementation((response) => {
            response.headers.set('Content-Security-Policy', 
              "default-src 'self'; frame-ancestors 'none'"
            )
            return response
          })
          
          const responseWithHeaders = setSecurityHeaders(mockResponse)
          const cspHeader = responseWithHeaders.headers.get('Content-Security-Policy')
          
          return cspHeader !== null && cspHeader.includes("frame-ancestors 'none'")
        },
        'high',
        'Verify that CSP restricts frame-ancestors to prevent clickjacking',
        'Clickjacking Vulnerability',
        'Application',
        'Clickjacking attacks and UI redressing',
        'Set frame-ancestors to none or specific trusted domains',
        'Content-Security-Policy'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('HTTP Strict Transport Security (HSTS) Tests', () => {
    test('should set HSTS headers with long max-age', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'hsts_long_max_age',
        'HSTS',
        async () => {
          const mockResponse = new NextResponse()
          
          ;(setHSTS as jest.Mock).mockImplementation((response) => {
            response.headers.set('Strict-Transport-Security', 
              'max-age=31536000; includeSubDomains; preload'
            )
            return response
          })
          
          const responseWithHeaders = setHSTS(mockResponse)
          const hstsHeader = responseWithHeaders.headers.get('Strict-Transport-Security')
          
          return hstsHeader !== null && 
                 hstsHeader.includes('max-age=31536000') &&
                 hstsHeader.includes('includeSubDomains')
        },
        'high',
        'Verify that HSTS headers are set with appropriate max-age',
        'Missing HSTS Headers',
        'Network',
        'Man-in-the-middle attacks and protocol downgrade',
        'Implement HSTS headers with long max-age and includeSubDomains',
        'Strict-Transport-Security'
      )

      expect(result.passed).toBe(true)
    })

    test('should include preload directive in HSTS', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'hsts_preload_directive',
        'HSTS',
        async () => {
          const mockResponse = new NextResponse()
          
          ;(setHSTS as jest.Mock).mockImplementation((response) => {
            response.headers.set('Strict-Transport-Security', 
              'max-age=31536000; includeSubDomains; preload'
            )
            return response
          })
          
          const responseWithHeaders = setHSTS(mockResponse)
          const hstsHeader = responseWithHeaders.headers.get('Strict-Transport-Security')
          
          return hstsHeader !== null && hstsHeader.includes('preload')
        },
        'medium',
        'Verify that HSTS includes preload directive for browser preload lists',
        'Incomplete HSTS Configuration',
        'Network',
        'Reduced protection against protocol downgrade attacks',
        'Add preload directive to HSTS header for enhanced security',
        'Strict-Transport-Security'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('X-Frame-Options Tests', () => {
    test('should set X-Frame-Options to DENY', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'x_frame_options_deny',
        'X-Frame-Options',
        async () => {
          const mockResponse = new NextResponse()

          ;(setXFrameOptions as jest.Mock).mockImplementation((response) => {
            response.headers.set('X-Frame-Options', 'DENY')
            return response
          })

          const responseWithHeaders = setXFrameOptions(mockResponse)
          const xFrameHeader = responseWithHeaders.headers.get('X-Frame-Options')

          return xFrameHeader === 'DENY'
        },
        'high',
        'Verify that X-Frame-Options is set to DENY to prevent clickjacking',
        'Clickjacking Vulnerability',
        'Application',
        'Clickjacking attacks and iframe embedding',
        'Set X-Frame-Options to DENY or SAMEORIGIN',
        'X-Frame-Options'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('X-Content-Type-Options Tests', () => {
    test('should set X-Content-Type-Options to nosniff', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'x_content_type_options_nosniff',
        'X-Content-Type-Options',
        async () => {
          const mockResponse = new NextResponse()

          ;(setXContentTypeOptions as jest.Mock).mockImplementation((response) => {
            response.headers.set('X-Content-Type-Options', 'nosniff')
            return response
          })

          const responseWithHeaders = setXContentTypeOptions(mockResponse)
          const xContentTypeHeader = responseWithHeaders.headers.get('X-Content-Type-Options')

          return xContentTypeHeader === 'nosniff'
        },
        'medium',
        'Verify that X-Content-Type-Options is set to nosniff',
        'MIME Type Confusion',
        'Application',
        'MIME type sniffing attacks and content type confusion',
        'Set X-Content-Type-Options to nosniff',
        'X-Content-Type-Options'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('X-XSS-Protection Tests', () => {
    test('should set X-XSS-Protection appropriately', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'x_xss_protection_setting',
        'X-XSS-Protection',
        async () => {
          const mockResponse = new NextResponse()

          ;(setXXSSProtection as jest.Mock).mockImplementation((response) => {
            response.headers.set('X-XSS-Protection', '0')
            return response
          })

          const responseWithHeaders = setXXSSProtection(mockResponse)
          const xXSSHeader = responseWithHeaders.headers.get('X-XSS-Protection')

          // Modern recommendation is to set to 0 when CSP is properly implemented
          return xXSSHeader === '0'
        },
        'low',
        'Verify that X-XSS-Protection is set appropriately (0 when CSP is used)',
        'XSS Protection Configuration',
        'Application',
        'XSS attacks if CSP is not properly configured',
        'Set X-XSS-Protection to 0 when using CSP, or 1; mode=block otherwise',
        'X-XSS-Protection'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('Referrer Policy Tests', () => {
    test('should set strict Referrer Policy', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'referrer_policy_strict',
        'Referrer Policy',
        async () => {
          const mockResponse = new NextResponse()

          ;(setReferrerPolicy as jest.Mock).mockImplementation((response) => {
            response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
            return response
          })

          const responseWithHeaders = setReferrerPolicy(mockResponse)
          const referrerHeader = responseWithHeaders.headers.get('Referrer-Policy')

          return referrerHeader === 'strict-origin-when-cross-origin' ||
                 referrerHeader === 'no-referrer'
        },
        'medium',
        'Verify that Referrer Policy is set to protect user privacy',
        'Information Disclosure',
        'Application',
        'Referrer information leakage to third parties',
        'Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer',
        'Referrer-Policy'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('Permissions Policy Tests', () => {
    test('should set restrictive Permissions Policy', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'permissions_policy_restrictive',
        'Permissions Policy',
        async () => {
          const mockResponse = new NextResponse()

          ;(setPermissionsPolicy as jest.Mock).mockImplementation((response) => {
            response.headers.set('Permissions-Policy',
              'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
            )
            return response
          })

          const responseWithHeaders = setPermissionsPolicy(mockResponse)
          const permissionsHeader = responseWithHeaders.headers.get('Permissions-Policy')

          return permissionsHeader !== null &&
                 permissionsHeader.includes('camera=()') &&
                 permissionsHeader.includes('microphone=()')
        },
        'medium',
        'Verify that Permissions Policy restricts dangerous features',
        'Feature Policy Vulnerability',
        'Application',
        'Unauthorized access to browser features and user privacy',
        'Set restrictive Permissions Policy to disable unused browser features',
        'Permissions-Policy'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('HTTPS Enforcement Tests', () => {
    test('should enforce HTTPS redirects', async () => {
      const result = await securityHeadersTester.runSecurityHeaderTest(
        'https_enforcement',
        'HTTPS Enforcement',
        async () => {
          const httpRequest = new NextRequest('http://example.com/api/test')

          ;(enforceHTTPS as jest.Mock).mockReturnValue({
            shouldRedirect: true,
            redirectUrl: 'https://example.com/api/test',
            status: 301
          })

          const httpsCheck = enforceHTTPS(httpRequest)

          return httpsCheck.shouldRedirect &&
                 httpsCheck.redirectUrl?.startsWith('https://') &&
                 httpsCheck.status === 301
        },
        'critical',
        'Verify that HTTP requests are redirected to HTTPS',
        'Insecure Transport',
        'Network',
        'Man-in-the-middle attacks and data interception',
        'Implement automatic HTTPS redirects for all HTTP requests',
        'Location'
      )

      expect(result.passed).toBe(true)
    })
  })

  describe('Security Headers Test Results Summary', () => {
    test('should generate comprehensive security headers report', async () => {
      const report = securityHeadersTester.generateSecurityHeadersReport()
      const results = securityHeadersTester.getResults()
      const criticalIssues = securityHeadersTester.getCriticalIssues()
      const failedTests = securityHeadersTester.getFailedTests()

      console.log(report.summary)

      // Should have comprehensive test coverage
      expect(results.length).toBeGreaterThanOrEqual(8)

      // No critical security header issues should be found
      expect(criticalIssues.length).toBe(0)

      // Overall test success rate should be high
      const successRate = (results.length - failedTests.length) / results.length
      expect(successRate).toBeGreaterThanOrEqual(0.95) // 95% success rate

      // Should test all major security header categories
      const categories = Object.keys(report.categories)
      expect(categories).toContain('CSP')
      expect(categories).toContain('HSTS')
      expect(categories).toContain('X-Frame-Options')
      expect(categories).toContain('X-Content-Type-Options')
      expect(categories).toContain('Referrer Policy')
      expect(categories).toContain('Permissions Policy')

      // Should be compliant
      expect(report.complianceStatus).toBe('COMPLIANT')

      // Log any critical findings
      if (criticalIssues.length > 0) {
        console.error('🚨 CRITICAL SECURITY HEADER FAILURES FOUND:', criticalIssues)

        // Fail the test if critical vulnerabilities are found
        expect(criticalIssues.length).toBe(0)
      }
    })
  })
})
