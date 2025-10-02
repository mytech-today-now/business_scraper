/**
 * Enhanced Security Hardening Tests
 * Comprehensive test suite for P0 critical security enhancements
 * 
 * Tests cover:
 * - CSP hardening
 * - Session security
 * - Input validation and sanitization
 * - Threat detection
 * - API security
 */

import { NextRequest } from 'next/server'
import { enhancedInputValidationService } from '@/lib/enhanced-input-validation'
import { enhancedSecurityMonitoringService } from '@/lib/enhanced-security-monitoring'
import { hardenedSecurityConfig } from '@/lib/hardened-security-config'
import { getCSPHeader } from '@/lib/cspConfig'

describe('Enhanced Security Hardening', () => {
  describe('Input Validation and Sanitization', () => {
    test('should detect and block SQL injection attempts', () => {
      const maliciousInputs = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "UNION SELECT * FROM users",
        "admin'--",
        "' OR 1=1 --"
      ]

      maliciousInputs.forEach(input => {
        const result = enhancedInputValidationService.sanitizeAndValidateInput(input, 'text')
        expect(result.detectedThreats).toContain('SQL_INJECTION')
        expect(result.warnings.some(w => w.includes('SQL injection'))).toBe(true)
      })
    })

    test('should detect and block XSS attempts', () => {
      const xssInputs = [
        '<script>alert("xss")</script>',
        '<img src="x" onerror="alert(1)">',
        'javascript:alert(1)',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<object data="javascript:alert(1)"></object>'
      ]

      xssInputs.forEach(input => {
        const result = enhancedInputValidationService.sanitizeAndValidateInput(input, 'html')
        expect(result.detectedThreats).toContain('XSS_ATTEMPT')
        expect(result.warnings.some(w => w.includes('XSS'))).toBe(true)
      })
    })

    test('should detect command injection attempts', () => {
      const commandInputs = [
        '; cat /etc/passwd',
        '| whoami',
        '`id`',
        '$(uname -a)',
        '&& ls -la'
      ]

      commandInputs.forEach(input => {
        const result = enhancedInputValidationService.sanitizeAndValidateInput(input, 'text')
        expect(result.detectedThreats).toContain('COMMAND_INJECTION')
        expect(result.warnings.some(w => w.includes('command injection'))).toBe(true)
      })
    })

    test('should validate email addresses correctly', () => {
      const validEmails = [
        'user@example.com',
        'test.email+tag@domain.co.uk',
        'valid.email@subdomain.example.org'
      ]

      const invalidEmails = [
        'invalid-email',
        '@domain.com',
        'user@',
        'user..double.dot@example.com'
      ]

      validEmails.forEach(email => {
        const result = enhancedInputValidationService.sanitizeAndValidateInput(email, 'email')
        expect(result.isValid).toBe(true)
        expect(result.errors).toHaveLength(0)
      })

      invalidEmails.forEach(email => {
        const result = enhancedInputValidationService.sanitizeAndValidateInput(email, 'email')
        expect(result.isValid).toBe(false)
        expect(result.errors.some(e => e.includes('email'))).toBe(true)
      })
    })

    test('should validate URLs correctly', () => {
      const validUrls = [
        'https://example.com',
        'http://subdomain.example.org/path',
        'https://example.com:8080/path?query=value'
      ]

      const invalidUrls = [
        'not-a-url',
        'ftp://example.com',
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>'
      ]

      validUrls.forEach(url => {
        const result = enhancedInputValidationService.sanitizeAndValidateInput(url, 'url')
        expect(result.isValid).toBe(true)
        expect(result.errors).toHaveLength(0)
      })

      invalidUrls.forEach(url => {
        const result = enhancedInputValidationService.sanitizeAndValidateInput(url, 'url')
        expect(result.isValid).toBe(false)
        expect(result.errors.some(e => e.includes('URL'))).toBe(true)
      })
    })

    test('should sanitize HTML content properly', () => {
      const htmlInput = '<p>Safe content</p><script>alert("xss")</script><b>Bold text</b>'
      const result = enhancedInputValidationService.sanitizeAndValidateInput(htmlInput, 'html')
      
      expect(result.isValid).toBe(true)
      expect(result.sanitizedValue).toContain('<p>Safe content</p>')
      expect(result.sanitizedValue).toContain('<b>Bold text</b>')
      expect(result.sanitizedValue).not.toContain('<script>')
      expect(result.sanitizedValue).not.toContain('alert')
    })

    test('should handle batch validation correctly', () => {
      const inputs = [
        { value: 'user@example.com', type: 'email' as const },
        { value: 'https://example.com', type: 'url' as const },
        { value: 'Safe text content', type: 'text' as const },
        { value: '<script>alert("xss")</script>', type: 'html' as const }
      ]

      const results = enhancedInputValidationService.batchValidate(inputs)
      
      expect(results).toHaveLength(4)
      expect(results[0].isValid).toBe(true) // Valid email
      expect(results[1].isValid).toBe(true) // Valid URL
      expect(results[2].isValid).toBe(true) // Safe text
      expect(results[3].detectedThreats).toContain('XSS_ATTEMPT') // XSS attempt
    })
  })

  describe('Security Monitoring and Threat Detection', () => {
    test('should detect SQL injection in request URLs', () => {
      const maliciousUrl = 'https://example.com/api/users?id=1\' OR \'1\'=\'1'
      const request = new NextRequest(maliciousUrl)
      
      const threats = enhancedSecurityMonitoringService.analyzeRequest(request)
      const sqlThreats = threats.filter(t => t.type === 'SQL_INJECTION')
      
      expect(sqlThreats.length).toBeGreaterThan(0)
      expect(sqlThreats[0].severity).toBe('high')
    })

    test('should detect XSS attempts in query parameters', () => {
      const maliciousUrl = 'https://example.com/search?q=<script>alert("xss")</script>'
      const request = new NextRequest(maliciousUrl)
      
      const threats = enhancedSecurityMonitoringService.analyzeRequest(request)
      const xssThreats = threats.filter(t => t.type === 'XSS')
      
      expect(xssThreats.length).toBeGreaterThan(0)
      expect(xssThreats[0].severity).toBe('high')
    })

    test('should detect suspicious user agents', () => {
      const suspiciousUserAgents = [
        'sqlmap/1.0',
        'Nikto/2.1.6',
        'Nessus SOAP',
        'Burp Suite'
      ]

      suspiciousUserAgents.forEach(userAgent => {
        const request = new NextRequest('https://example.com', {
          headers: { 'User-Agent': userAgent }
        })
        
        const threats = enhancedSecurityMonitoringService.analyzeRequest(request)
        const anomalies = threats.filter(t => t.type === 'ANOMALY')
        
        expect(anomalies.length).toBeGreaterThan(0)
        expect(anomalies[0].description).toContain('Suspicious user agent')
      })
    })

    test('should track security metrics correctly', () => {
      // Reset metrics for clean test
      const initialMetrics = enhancedSecurityMonitoringService.getSecurityMetrics()
      
      // Simulate some requests with threats
      const maliciousRequest = new NextRequest('https://example.com?id=1\' OR \'1\'=\'1')
      enhancedSecurityMonitoringService.analyzeRequest(maliciousRequest)
      
      const updatedMetrics = enhancedSecurityMonitoringService.getSecurityMetrics()
      
      expect(updatedMetrics.totalRequests).toBeGreaterThan(initialMetrics.totalRequests)
      expect(updatedMetrics.threatsDetected).toBeGreaterThan(initialMetrics.threatsDetected)
    })
  })

  describe('Hardened Security Configuration', () => {
    test('should have secure production CSP configuration', () => {
      const cspHeader = getCSPHeader()
      
      expect(cspHeader).toContain("object-src 'none'")
      expect(cspHeader).toContain("frame-ancestors 'none'")
      expect(cspHeader).toContain("base-uri 'self'")
      expect(cspHeader).toContain("form-action 'self'")
      
      // Should not contain unsafe directives in production
      if (process.env.NODE_ENV === 'production') {
        expect(cspHeader).not.toContain("'unsafe-eval'")
      }
    })

    test('should have secure session configuration', () => {
      const sessionConfig = hardenedSecurityConfig.session
      
      expect(sessionConfig.httpOnly).toBe(true)
      expect(sessionConfig.sameSite).toBe('strict')
      expect(sessionConfig.maxAge).toBeLessThanOrEqual(30 * 60 * 1000) // Max 30 minutes
      
      if (process.env.NODE_ENV === 'production') {
        expect(sessionConfig.secure).toBe(true)
      }
    })

    test('should have strong encryption settings', () => {
      const encryptionConfig = hardenedSecurityConfig.encryption
      
      expect(encryptionConfig.algorithm).toBe('aes-256-gcm')
      expect(encryptionConfig.masterKeyLength).toBeGreaterThanOrEqual(64)
      expect(encryptionConfig.keyDerivationIterations).toBeGreaterThanOrEqual(100000)
      expect(encryptionConfig.saltLength).toBeGreaterThanOrEqual(32)
    })

    test('should have comprehensive API security settings', () => {
      const apiSecurityConfig = hardenedSecurityConfig.apiSecurity
      
      expect(apiSecurityConfig.rateLimit.windowMs).toBe(15 * 60 * 1000) // 15 minutes
      expect(apiSecurityConfig.rateLimit.max).toBe(100)
      expect(apiSecurityConfig.helmet.frameguard.action).toBe('deny')
      expect(apiSecurityConfig.helmet.hsts.maxAge).toBe(31536000) // 1 year
      expect(apiSecurityConfig.helmet.hsts.includeSubDomains).toBe(true)
      expect(apiSecurityConfig.helmet.hsts.preload).toBe(true)
    })

    test('should enable compliance features', () => {
      const complianceConfig = hardenedSecurityConfig.compliance
      
      expect(complianceConfig.soc2TypeII).toBe(true)
      expect(complianceConfig.gdprCompliance).toBe(true)
      expect(complianceConfig.pciDssLevel1).toBe(true)
      expect(complianceConfig.owaspTop10Protection).toBe(true)
    })
  })

  describe('Performance and Security Balance', () => {
    test('should complete input validation within acceptable time limits', () => {
      const largeInput = 'a'.repeat(10000) // 10KB input
      const startTime = Date.now()
      
      const result = enhancedInputValidationService.sanitizeAndValidateInput(largeInput, 'text')
      
      const endTime = Date.now()
      const processingTime = endTime - startTime
      
      expect(processingTime).toBeLessThan(100) // Should complete within 100ms
      expect(result.isValid).toBe(true)
    })

    test('should handle concurrent validation requests efficiently', async () => {
      const inputs = Array(100).fill(0).map((_, i) => ({
        value: `test-input-${i}@example.com`,
        type: 'email' as const
      }))

      const startTime = Date.now()
      
      const results = enhancedInputValidationService.batchValidate(inputs)
      
      const endTime = Date.now()
      const processingTime = endTime - startTime
      
      expect(processingTime).toBeLessThan(500) // Should complete within 500ms
      expect(results).toHaveLength(100)
      expect(results.every(r => r.isValid)).toBe(true)
    })
  })
})
