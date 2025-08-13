/**
 * Content Security Policy (CSP) Tests
 * Business Scraper Application - Security Testing
 */

import { 
  getCSPConfig, 
  buildCSPHeader, 
  generateCSPNonce, 
  validateCSPConfig,
  logCSPViolation,
  CSPViolationReport
} from '@/lib/cspConfig'
import { 
  isCSPSafe, 
  sanitizeForCSP, 
  getClientCSPNonce,
  CSPReporter
} from '@/lib/cspUtils'

describe('CSP Configuration', () => {
  describe('getCSPConfig', () => {
    it('should return development config for development environment', () => {
      const config = getCSPConfig('development')
      
      expect(config.defaultSrc).toContain("'self'")
      expect(config.scriptSrc).toContain("'unsafe-eval'")
      expect(config.connectSrc).toContain('ws://localhost:*')
      expect(config.upgradeInsecureRequests).toBe(false)
    })
    
    it('should return production config for production environment', () => {
      const config = getCSPConfig('production')
      
      expect(config.defaultSrc).toContain("'self'")
      expect(config.upgradeInsecureRequests).toBe(true)
      expect(config.blockAllMixedContent).toBe(true)
      expect(config.connectSrc).not.toContain('ws://localhost:*')
    })
    
    it('should return test config for test environment', () => {
      const config = getCSPConfig('test')
      
      expect(config.defaultSrc).toContain("'self'")
      expect(config.upgradeInsecureRequests).toBe(false)
      expect(config.blockAllMixedContent).toBe(false)
    })
    
    it('should fallback to development config for unknown environment', () => {
      const config = getCSPConfig('unknown')
      const devConfig = getCSPConfig('development')
      
      expect(config).toEqual(devConfig)
    })
  })
  
  describe('buildCSPHeader', () => {
    it('should build valid CSP header string', () => {
      const config = getCSPConfig('production')
      const header = buildCSPHeader(config)
      
      expect(header).toContain("default-src 'self'")
      expect(header).toContain("object-src 'none'")
      expect(header).toContain("frame-ancestors 'none'")
      expect(header).toContain('upgrade-insecure-requests')
    })
    
    it('should replace nonce placeholders with actual nonce', () => {
      const config = getCSPConfig('development')
      const nonce = 'test-nonce-123'
      const header = buildCSPHeader(config, nonce)
      
      expect(header).toContain(`'nonce-${nonce}'`)
      expect(header).not.toContain("'nonce-{nonce}'")
    })
    
    it('should include external connections for business scraper', () => {
      const config = getCSPConfig('production')
      const header = buildCSPHeader(config)
      
      expect(header).toContain('https://nominatim.openstreetmap.org')
      expect(header).toContain('https://api.opencagedata.com')
      expect(header).toContain('https://*.googleapis.com')
      expect(header).toContain('https://api.duckduckgo.com')
    })
  })
  
  describe('generateCSPNonce', () => {
    it('should generate unique nonces', () => {
      const nonce1 = generateCSPNonce()
      const nonce2 = generateCSPNonce()
      
      expect(nonce1).not.toBe(nonce2)
      expect(nonce1).toMatch(/^[A-Za-z0-9+/]+=*$/) // Base64 pattern
      expect(nonce2).toMatch(/^[A-Za-z0-9+/]+=*$/)
    })
    
    it('should generate nonces of consistent length', () => {
      const nonce1 = generateCSPNonce()
      const nonce2 = generateCSPNonce()
      
      expect(nonce1.length).toBe(nonce2.length)
      expect(nonce1.length).toBeGreaterThan(10) // Should be reasonably long
    })
  })
  
  describe('validateCSPConfig', () => {
    it('should validate correct CSP configuration', () => {
      const config = getCSPConfig('production')
      const result = validateCSPConfig(config)
      
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })
    
    it('should detect missing default-src', () => {
      const config = getCSPConfig('production')
      config.defaultSrc = []
      
      const result = validateCSPConfig(config)
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('default-src directive is required')
    })
    
    it('should detect unsafe object-src', () => {
      const config = getCSPConfig('production')
      config.objectSrc = ["'self'"]
      
      const result = validateCSPConfig(config)
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('object-src should be set to none for security')
    })
  })
})

describe('CSP Utilities', () => {
  describe('isCSPSafe', () => {
    it('should detect safe content', () => {
      const safeContent = 'console.log("Hello World");'
      expect(isCSPSafe(safeContent)).toBe(true)
    })
    
    it('should detect unsafe eval usage', () => {
      const unsafeContent = 'eval("console.log(1)");'
      expect(isCSPSafe(unsafeContent)).toBe(false)
    })
    
    it('should detect unsafe Function constructor', () => {
      const unsafeContent = 'new Function("return 1")();'
      expect(isCSPSafe(unsafeContent)).toBe(false)
    })
    
    it('should detect unsafe setTimeout with string', () => {
      const unsafeContent = 'setTimeout("alert(1)", 1000);'
      expect(isCSPSafe(unsafeContent)).toBe(false)
    })
    
    it('should detect inline event handlers', () => {
      const unsafeContent = '<div onclick="alert(1)">Click me</div>'
      expect(isCSPSafe(unsafeContent)).toBe(false)
    })
    
    it('should detect javascript: URLs', () => {
      const unsafeContent = '<a href="javascript:alert(1)">Link</a>'
      expect(isCSPSafe(unsafeContent)).toBe(false)
    })
  })
  
  describe('sanitizeForCSP', () => {
    it('should remove eval calls', () => {
      const input = 'eval("console.log(1)");'
      const output = sanitizeForCSP(input)
      
      expect(output).not.toContain('eval(')
      expect(output).toContain('/* eval removed */')
    })
    
    it('should remove Function constructor calls', () => {
      const input = 'new Function("return 1")();'
      const output = sanitizeForCSP(input)
      
      expect(output).not.toContain('Function(')
      expect(output).toContain('/* Function constructor removed */')
    })
    
    it('should remove unsafe setTimeout calls', () => {
      const input = 'setTimeout("alert(1)", 1000);'
      const output = sanitizeForCSP(input)
      
      expect(output).toContain('/* unsafe setTimeout removed */')
    })
    
    it('should remove inline event handlers', () => {
      const input = '<div onclick="alert(1)">Click me</div>'
      const output = sanitizeForCSP(input)
      
      expect(output).not.toContain('onclick=')
      expect(output).toContain('/* inline handler removed */')
    })
    
    it('should preserve safe content', () => {
      const input = 'console.log("Hello World");'
      const output = sanitizeForCSP(input)
      
      expect(output).toBe(input)
    })
  })
})

describe('CSP Violation Reporting', () => {
  describe('logCSPViolation', () => {
    it('should log CSP violation without throwing', () => {
      const mockReport: CSPViolationReport = {
        'csp-report': {
          'document-uri': 'https://example.com',
          'referrer': '',
          'violated-directive': 'script-src',
          'effective-directive': 'script-src',
          'original-policy': "default-src 'self'",
          'disposition': 'enforce',
          'blocked-uri': 'https://evil.com/script.js',
          'line-number': 1,
          'column-number': 1,
          'source-file': 'https://example.com',
          'status-code': 200,
          'script-sample': ''
        }
      }
      
      expect(() => logCSPViolation(mockReport)).not.toThrow()
    })
  })
  
  describe('CSPReporter', () => {
    let reporter: CSPReporter

    beforeEach(() => {
      reporter = CSPReporter.getInstance()
      reporter.clearViolations()

      // Mock fetch for testing
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: 'received' })
      })
    })

    afterEach(() => {
      jest.restoreAllMocks()
    })
    
    it('should be a singleton', () => {
      const reporter1 = CSPReporter.getInstance()
      const reporter2 = CSPReporter.getInstance()
      
      expect(reporter1).toBe(reporter2)
    })
    
    it('should track violations', () => {
      reporter.reportViolation('script-src', 'https://evil.com/script.js')
      
      const violations = reporter.getViolations()
      expect(violations).toHaveLength(1)
      expect(violations[0].directive).toBe('script-src')
      expect(violations[0].blockedUri).toBe('https://evil.com/script.js')
    })
    
    it('should filter violations by time', () => {
      const now = Date.now()
      const oneHourAgo = now - 60 * 60 * 1000
      
      reporter.reportViolation('script-src', 'https://evil.com/script.js')
      
      const recentViolations = reporter.getViolations(oneHourAgo)
      expect(recentViolations).toHaveLength(1)
      
      const futureViolations = reporter.getViolations(now + 1000)
      expect(futureViolations).toHaveLength(0)
    })
    
    it('should clear violations', () => {
      reporter.reportViolation('script-src', 'https://evil.com/script.js')
      expect(reporter.getViolations()).toHaveLength(1)
      
      reporter.clearViolations()
      expect(reporter.getViolations()).toHaveLength(0)
    })
  })
})

describe('CSP Integration', () => {
  it('should maintain required external connections', () => {
    const config = getCSPConfig('production')
    const header = buildCSPHeader(config)
    
    // Business scraper requires these external connections
    const requiredConnections = [
      'https://nominatim.openstreetmap.org',
      'https://api.opencagedata.com',
      'https://*.googleapis.com',
      'https://*.cognitiveservices.azure.com',
      'https://api.duckduckgo.com',
      'https://duckduckgo.com'
    ]
    
    requiredConnections.forEach(connection => {
      expect(header).toContain(connection)
    })
  })
  
  it('should be stricter in production than development', () => {
    const devConfig = getCSPConfig('development')
    const prodConfig = getCSPConfig('production')
    
    // Production should have stricter policies
    expect(prodConfig.upgradeInsecureRequests).toBe(true)
    expect(devConfig.upgradeInsecureRequests).toBe(false)
    
    expect(prodConfig.blockAllMixedContent).toBe(true)
    expect(devConfig.blockAllMixedContent).toBe(false)
    
    // Development should allow more connections for local development
    expect(devConfig.connectSrc).toContain('ws://localhost:*')
    expect(prodConfig.connectSrc).not.toContain('ws://localhost:*')
  })
})
