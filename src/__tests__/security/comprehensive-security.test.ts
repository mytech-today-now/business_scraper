/**
 * Comprehensive Security Test Suite
 * 
 * Tests the enhanced security testing infrastructure including vulnerability scanning,
 * penetration testing, and security monitoring capabilities.
 */

import { SecurityTestRunner } from '@/lib/security-test-runner'
import { 
  getSecurityTestingConfig, 
  validateSecurityTestingConfig,
  SecurityTestSeverity 
} from '@/lib/security-testing-config'
import { logger } from '@/utils/logger'

// Mock external dependencies for testing
jest.mock('child_process', () => ({
  exec: jest.fn()
}))

jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn()
  }
}))

describe('Comprehensive Security Testing Infrastructure', () => {
  let securityTestRunner: SecurityTestRunner
  let originalEnv: NodeJS.ProcessEnv
  let mockExec: jest.Mock
  let mockLogger: any

  beforeAll(() => {
    originalEnv = { ...process.env }
    mockExec = require('child_process').exec as jest.Mock
    mockLogger = require('@/utils/logger').logger
  })

  afterAll(() => {
    process.env = originalEnv
  })

  beforeEach(() => {
    jest.clearAllMocks()
    mockExec.mockClear()
    securityTestRunner = new SecurityTestRunner()
  })

  describe('Security Testing Configuration', () => {
    test('should load default security testing configuration', () => {
      const config = getSecurityTestingConfig()
      
      expect(config).toBeDefined()
      expect(config.vulnerabilityScanning.enabled).toBe(true)
      expect(config.penetrationTesting.enabled).toBe(true)
      expect(config.securityMonitoring.enabled).toBe(true)
      expect(config.complianceTesting.enabled).toBe(true)
    })

    test('should validate security testing configuration', () => {
      const config = getSecurityTestingConfig()
      const errors = validateSecurityTestingConfig(config)
      
      // Should have warning about missing SNYK_TOKEN in test environment
      expect(errors).toContain('SNYK_TOKEN is required when vulnerability scanning is enabled')
    })

    test('should handle environment variable overrides', () => {
      process.env.SECURITY_SCAN_ENABLED = 'false'
      process.env.VULNERABILITY_THRESHOLD = 'critical'
      process.env.SNYK_TOKEN = 'test-token'

      const config = getSecurityTestingConfig()
      
      expect(config.vulnerabilityScanning.enabled).toBe(false)
      expect(config.vulnerabilityScanning.severityThreshold).toBe('critical')
      expect(config.vulnerabilityScanning.snykToken).toBe('test-token')
    })
  })

  describe('Security Test Runner', () => {
    test('should initialize with default configuration', () => {
      expect(securityTestRunner).toBeDefined()
      expect(securityTestRunner.getResults()).toEqual([])
    })

    test('should handle configuration validation warnings', () => {
      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.snykToken = undefined

      new SecurityTestRunner(config)

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'SecurityTestRunner',
        'Configuration validation warnings:',
        expect.arrayContaining(['SNYK_TOKEN is required when vulnerability scanning is enabled'])
      )
    })

    test('should generate comprehensive security metrics', async () => {
      // Mock successful test execution
      mockExec.mockImplementation((command: string, callback: Function) => {
        if (command.includes('npm audit')) {
          callback(null, {
            stdout: JSON.stringify({
              metadata: { vulnerabilities: { total: 0, high: 0, critical: 0 } }
            }),
            stderr: ''
          })
        } else if (command.includes('snyk test')) {
          callback(null, {
            stdout: JSON.stringify({ vulnerabilities: [] }),
            stderr: ''
          })
        }
      })

      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.snykToken = 'test-token'

      const runner = new SecurityTestRunner(config)
      const metrics = await runner.runAllTests()

      expect(metrics).toBeDefined()
      expect(metrics.totalTests).toBeGreaterThan(0)
      expect(metrics.testDuration).toBeGreaterThan(0)
      expect(metrics.lastRunTimestamp).toBeInstanceOf(Date)
    })
  })

  describe('Vulnerability Scanning', () => {
    test('should handle npm audit results', async () => {
      mockExec.mockImplementation((command: string, callback: Function) => {
        if (command.includes('npm audit')) {
          callback(null, {
            stdout: JSON.stringify({
              metadata: {
                vulnerabilities: {
                  total: 2,
                  high: 1,
                  critical: 1
                }
              }
            }),
            stderr: ''
          })
        }
      })

      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.snykToken = undefined // Disable Snyk for this test

      const runner = new SecurityTestRunner(config)
      await runner.runAllTests()

      const results = runner.getResults()
      const npmAuditResult = results.find(r => r.testName === 'NPM Audit')

      expect(npmAuditResult).toBeDefined()
      expect(npmAuditResult?.passed).toBe(false)
      expect(npmAuditResult?.vulnerabilityFound).toBe(true)
      expect(npmAuditResult?.severity).toBe(SecurityTestSeverity.CRITICAL)
    })

    test('should handle Snyk scan results', async () => {
      mockExec.mockImplementation((command: string, callback: Function) => {
        if (command.includes('npm audit')) {
          callback(null, {
            stdout: JSON.stringify({
              metadata: { vulnerabilities: { total: 0 } }
            }),
            stderr: ''
          })
        } else if (command.includes('snyk test')) {
          callback(null, {
            stdout: JSON.stringify({ vulnerabilities: [] }),
            stderr: ''
          })
        }
      })

      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.snykToken = 'test-token'

      const runner = new SecurityTestRunner(config)
      await runner.runAllTests()

      const results = runner.getResults()
      const snykResult = results.find(r => r.testName === 'Snyk Vulnerability Scan')

      expect(snykResult).toBeDefined()
      expect(snykResult?.passed).toBe(true)
      expect(snykResult?.vulnerabilityFound).toBe(false)
    })

    test('should handle Snyk scan failures gracefully', async () => {
      mockExec.mockImplementation((command: string, callback: Function) => {
        if (command.includes('npm audit')) {
          callback(null, {
            stdout: JSON.stringify({
              metadata: { vulnerabilities: { total: 0 } }
            }),
            stderr: ''
          })
        } else if (command.includes('snyk test')) {
          callback(new Error('Snyk authentication failed'))
        }
      })

      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.snykToken = 'invalid-token'

      const runner = new SecurityTestRunner(config)
      await runner.runAllTests()

      const results = runner.getResults()
      const snykResult = results.find(r => r.testName === 'Snyk Vulnerability Scan')

      expect(snykResult).toBeDefined()
      expect(snykResult?.passed).toBe(false)
      expect(snykResult?.description).toContain('failed to complete')
      expect(snykResult?.recommendation).toContain('Check Snyk token configuration')
    })
  })

  describe('Security Test Categories', () => {
    test('should run all enabled security test categories', async () => {
      mockExec.mockImplementation((command: string, callback: Function) => {
        callback(null, {
          stdout: JSON.stringify({
            metadata: { vulnerabilities: { total: 0 } }
          }),
          stderr: ''
        })
      })

      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.snykToken = undefined // Disable Snyk for this test

      const runner = new SecurityTestRunner(config)
      await runner.runAllTests()

      const results = runner.getResults()
      const categories = new Set(results.map(r => r.category))

      expect(categories).toContain('vulnerability-scanning')
      expect(categories).toContain('penetration-testing')
      expect(categories).toContain('security-headers')
      expect(categories).toContain('authentication')
      expect(categories).toContain('input-validation')
      expect(categories).toContain('compliance')
    })

    test('should skip disabled test categories', async () => {
      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.enabled = false
      config.penetrationTesting.enabled = false
      
      const runner = new SecurityTestRunner(config)
      await runner.runAllTests()

      const results = runner.getResults()
      const categories = new Set(results.map(r => r.category))
      
      expect(categories).not.toContain('vulnerability-scanning')
      expect(categories).not.toContain('penetration-testing')
    })
  })

  describe('Security Metrics Generation', () => {
    test('should calculate accurate security metrics', async () => {
      mockExec.mockImplementation((command: string, callback: Function) => {
        if (command.includes('npm audit')) {
          // Simulate vulnerabilities found
          const error = new Error('Vulnerabilities found') as any
          error.stdout = JSON.stringify({
            metadata: {
              vulnerabilities: {
                total: 3,
                high: 2,
                critical: 1
              }
            }
          })
          callback(error)
        }
      })

      const config = getSecurityTestingConfig()
      config.vulnerabilityScanning.snykToken = undefined

      const runner = new SecurityTestRunner(config)
      const metrics = await runner.runAllTests()

      expect(metrics.totalTests).toBeGreaterThan(0)
      expect(metrics.vulnerabilitiesFound).toBeGreaterThan(0)
      expect(metrics.failedTests).toBeGreaterThan(0)
      expect(metrics.testDuration).toBeGreaterThan(0)
    })
  })

  describe('Error Handling', () => {
    test('should handle test execution failures gracefully', async () => {
      mockExec.mockImplementation((command: string, callback: Function) => {
        callback(new Error('Command execution failed'))
      })

      const config = getSecurityTestingConfig()

      const runner = new SecurityTestRunner(config)

      // Should not throw, but handle errors gracefully
      await expect(runner.runAllTests()).resolves.toBeDefined()

      const results = runner.getResults()
      expect(results.some(r => !r.passed)).toBe(true)
    })
  })
})
