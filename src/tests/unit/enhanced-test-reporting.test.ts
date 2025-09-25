/**
 * Comprehensive Test Suite for Enhanced Test Reporting System
 * Tests all new test reporting components to ensure 99.9% success rate
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { EnhancedTestLogger } from '../../utils/TestLogger'
import { TestFailureIssueManager } from '../../lib/github/TestFailureIssueManager'
import { EnhancedBVTReporter } from '../../tests/bvt/enhanced-bvt-reporter'
import {
  TestStatus,
  TestCategory,
  TestPriority,
  ErrorSeverity,
  ErrorType,
  TestResult,
  TestMetadata,
  ComprehensiveTestReport
} from '../../types/TestReporting'
import * as fs from 'fs'
import * as path from 'path'

// Mock external dependencies
jest.mock('fs')
jest.mock('@octokit/rest')

const mockFs = fs as jest.Mocked<typeof fs>

describe('Enhanced Test Reporting System', () => {
  let enhancedLogger: EnhancedTestLogger
  let testReportsDir: string

  beforeEach(() => {
    testReportsDir = './test-logs-test'
    enhancedLogger = new EnhancedTestLogger(testReportsDir, { githubIntegration: false })
    
    // Mock file system operations
    mockFs.existsSync.mockReturnValue(true)
    mockFs.mkdirSync.mockReturnValue(undefined)
    mockFs.writeFileSync.mockReturnValue(undefined)
    mockFs.appendFileSync.mockReturnValue(undefined)
    mockFs.readFileSync.mockReturnValue(JSON.stringify({ version: '1.0.0' }))
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('EnhancedTestLogger', () => {
    it('should create test metadata with all required fields', () => {
      const metadata = enhancedLogger.createTestMetadata(
        'sample test',
        '/path/to/test.ts',
        'sample suite',
        {
          category: TestCategory.UNIT,
          priority: TestPriority.HIGH,
          description: 'A sample test case'
        }
      )

      expect(metadata).toMatchObject({
        testName: 'sample test',
        filePath: '/path/to/test.ts',
        suite: 'sample suite',
        category: TestCategory.UNIT,
        priority: TestPriority.HIGH,
        description: 'A sample test case'
      })
      expect(metadata.testId).toBeDefined()
      expect(metadata.relativePath).toBeDefined()
      expect(metadata.tags).toEqual([])
    })

    it('should create performance metrics with memory usage', () => {
      const startTime = 1000
      const endTime = 2000
      
      const metrics = enhancedLogger.createPerformanceMetrics(startTime, endTime)

      expect(metrics).toMatchObject({
        startTime,
        endTime,
        duration: 1000
      })
      expect(metrics.memoryUsage).toBeDefined()
      expect(metrics.memoryUsage.heapUsed).toBeGreaterThan(0)
      expect(metrics.memoryUsage.heapTotal).toBeGreaterThan(0)
    })

    it('should log test results with comprehensive metadata', () => {
      const testResult: TestResult = {
        metadata: enhancedLogger.createTestMetadata('test1', '/test.ts', 'suite1'),
        status: TestStatus.PASSED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        retryCount: 0
      }

      expect(() => {
        enhancedLogger.logTestResult(testResult)
      }).not.toThrow()
    })

    it('should generate comprehensive report with all sections', () => {
      // Add some test results
      const passedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('passed test', '/test1.ts', 'suite1'),
        status: TestStatus.PASSED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 1500),
        retryCount: 0
      }

      const failedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('failed test', '/test2.ts', 'suite1'),
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(2000, 3000),
        error: {
          message: 'Test assertion failed',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.HIGH,
          category: 'functional'
        },
        retryCount: 1
      }

      enhancedLogger.logTestResult(passedTest)
      enhancedLogger.logTestResult(failedTest)

      const report = enhancedLogger.generateComprehensiveReport()

      expect(report).toBeDefined()
      expect(report.metadata).toBeDefined()
      expect(report.executiveSummary).toBeDefined()
      expect(report.testInventory).toBeDefined()
      expect(report.detailedResults).toBeDefined()
      expect(report.issueTracking).toBeDefined()
      expect(report.performanceAnalysis).toBeDefined()
      expect(report.recommendations).toBeDefined()
      expect(report.historicalContext).toBeDefined()

      // Verify executive summary
      expect(report.executiveSummary.totalTests).toBe(2)
      expect(report.executiveSummary.successRate).toBe(50)
      expect(report.executiveSummary.criticalIssues).toBe(0)

      // Verify detailed results
      expect(report.detailedResults.failures).toHaveLength(1)
      expect(report.detailedResults.failures[0].metadata.testName).toBe('failed test')
    })

    it('should save comprehensive report in multiple formats', () => {
      const reportFiles = enhancedLogger.saveComprehensiveReport()

      expect(reportFiles).toBeDefined()
      expect(reportFiles.json).toBeDefined()
      expect(reportFiles.markdown).toBeDefined()
      expect(reportFiles.html).toBeDefined()

      // Verify file operations were called
      expect(mockFs.writeFileSync).toHaveBeenCalledTimes(3)
    })

    it('should categorize tests correctly by file path', () => {
      const unitTest = enhancedLogger.createTestMetadata('unit test', '/src/tests/unit/test.ts', 'unit suite')
      const integrationTest = enhancedLogger.createTestMetadata('integration test', '/src/tests/integration/test.ts', 'integration suite')
      const e2eTest = enhancedLogger.createTestMetadata('e2e test', '/src/tests/e2e/test.ts', 'e2e suite')

      expect(unitTest.category).toBe(TestCategory.UNIT)
      expect(integrationTest.category).toBe(TestCategory.INTEGRATION)
      expect(e2eTest.category).toBe(TestCategory.E2E)
    })

    it('should handle error categorization correctly', () => {
      const timeoutError = 'Test timeout after 5000ms'
      const assertionError = 'expect(received).toBe(expected)'
      const syntaxError = 'SyntaxError: Unexpected token'

      // Access private method for testing
      const categorizeError = (enhancedLogger as any).categorizeError.bind(enhancedLogger)

      expect(categorizeError(timeoutError)).toBe('timeout')
      expect(categorizeError(assertionError)).toBe('assertion')
      expect(categorizeError(syntaxError)).toBe('syntax')
    })
  })

  describe('TestFailureIssueManager', () => {
    let issueManager: TestFailureIssueManager
    let mockOctokit: any

    beforeEach(() => {
      mockOctokit = {
        rest: {
          issues: {
            create: jest.fn().mockResolvedValue({
              data: {
                number: 123,
                html_url: 'https://github.com/owner/repo/issues/123',
                created_at: '2023-01-01T00:00:00Z'
              }
            }),
            createComment: jest.fn().mockResolvedValue({}),
            update: jest.fn().mockResolvedValue({}),
            addLabels: jest.fn().mockResolvedValue({})
          },
          search: {
            issuesAndPullRequests: jest.fn().mockResolvedValue({
              data: { items: [] }
            })
          }
        }
      }

      // Mock Octokit constructor
      jest.doMock('@octokit/rest', () => ({
        Octokit: jest.fn().mockImplementation(() => mockOctokit)
      }))

      issueManager = new TestFailureIssueManager({
        token: 'test-token',
        owner: 'test-owner',
        repo: 'test-repo'
      }, {
        dryRun: false
      })

      // Replace the octokit instance
      ;(issueManager as any).octokit = mockOctokit
    })

    it('should create GitHub issue for test failure', async () => {
      const failedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('failed test', '/test.ts', 'suite1'),
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        error: {
          message: 'Test failed',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.HIGH,
          category: 'functional'
        },
        retryCount: 0
      }

      const issueRef = await issueManager.processTestFailure(failedTest)

      expect(issueRef).toBeDefined()
      expect(issueRef?.issueNumber).toBe(123)
      expect(issueRef?.status).toBe('open')
      expect(mockOctokit.rest.issues.create).toHaveBeenCalledTimes(1)
    })

    it('should not create issue for passing tests', async () => {
      const passedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('passed test', '/test.ts', 'suite1'),
        status: TestStatus.PASSED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        retryCount: 0
      }

      const issueRef = await issueManager.processTestFailure(passedTest)

      expect(issueRef).toBeNull()
      expect(mockOctokit.rest.issues.create).not.toHaveBeenCalled()
    })

    it('should handle dry run mode correctly', async () => {
      const dryRunManager = new TestFailureIssueManager({
        token: 'test-token',
        owner: 'test-owner',
        repo: 'test-repo'
      }, {
        dryRun: true
      })

      const failedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('failed test', '/test.ts', 'suite1'),
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        error: {
          message: 'Test failed',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.HIGH,
          category: 'functional'
        },
        retryCount: 0
      }

      const issueRef = await dryRunManager.processTestFailure(failedTest)

      expect(issueRef).toBeDefined()
      expect(issueRef?.status).toBe('pending')
    })

    it('should generate appropriate issue labels', () => {
      const failedTest: TestResult = {
        metadata: {
          testId: 'test-1',
          testName: 'critical test',
          testDescription: 'A critical test',
          filePath: '/test.ts',
          relativePath: 'test.ts',
          suite: 'suite1',
          category: TestCategory.UNIT,
          tags: [],
          priority: TestPriority.CRITICAL
        },
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        error: {
          message: 'Critical failure',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.CRITICAL,
          category: 'functional'
        },
        retryCount: 0
      }

      const labels = (issueManager as any).generateIssueLabels(failedTest)

      expect(labels).toContain('test-failure')
      expect(labels).toContain('bug')
      expect(labels).toContain('severity-critical')
      expect(labels).toContain('category-unit')
      expect(labels).toContain('priority-critical')
      expect(labels).toContain('critical')
      expect(labels).toContain('needs-immediate-attention')
    })
  })

  describe('EnhancedBVTReporter', () => {
    let bvtReporter: EnhancedBVTReporter

    beforeEach(() => {
      bvtReporter = new EnhancedBVTReporter('info')
    })

    it('should create execution context with environment details', () => {
      const context = (bvtReporter as any).createExecutionContext()

      expect(context).toBeDefined()
      expect(context.environment).toBeDefined()
      expect(context.nodeVersion).toBeDefined()
      expect(context.platform).toBeDefined()
      expect(context.timestamp).toBeDefined()
      expect(context.workingDirectory).toBeDefined()
      expect(context.configuration).toBeDefined()
      expect(context.dependencies).toBeDefined()
    })

    it('should log structured messages with metadata', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation()

      bvtReporter.logInfo('Test message', { key: 'value' })

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[BVT INFO]')
      )
      
      const logCall = consoleSpy.mock.calls[0][0]
      const logData = JSON.parse(logCall.replace('[BVT INFO] ', ''))
      
      expect(logData.level).toBe('INFO')
      expect(logData.message).toBe('Test message')
      expect(logData.data).toEqual({ key: 'value' })
      expect(logData.reportId).toBeDefined()
      expect(logData.timestamp).toBeDefined()

      consoleSpy.mockRestore()
    })

    it('should determine overall status correctly', () => {
      const determineOverallStatus = (bvtReporter as any).determineOverallStatus.bind(bvtReporter)

      expect(determineOverallStatus(100, 0)).toBe('passed')
      expect(determineOverallStatus(90, 0)).toBe('warning')
      expect(determineOverallStatus(100, 1)).toBe('failed')
      expect(determineOverallStatus(80, 2)).toBe('failed')
    })

    it('should determine quality gate correctly', () => {
      const determineQualityGate = (bvtReporter as any).determineQualityGate.bind(bvtReporter)

      expect(determineQualityGate(100, 0)).toBe('passed')
      expect(determineQualityGate(94, 0)).toBe('warning')
      expect(determineQualityGate(89, 0)).toBe('failed')
      expect(determineQualityGate(100, 1)).toBe('failed')
    })
  })

  describe('Integration Tests', () => {
    it('should integrate enhanced logger with BVT reporter', () => {
      const testResult: TestResult = {
        metadata: enhancedLogger.createTestMetadata('integration test', '/test.ts', 'integration suite'),
        status: TestStatus.PASSED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 1500),
        retryCount: 0
      }

      enhancedLogger.logTestResult(testResult)
      const report = enhancedLogger.generateComprehensiveReport()

      expect(report.executiveSummary.totalTests).toBe(1)
      expect(report.executiveSummary.successRate).toBe(100)
      expect(report.executiveSummary.overallStatus).toBe('passed')
    })

    it('should handle mixed test results correctly', () => {
      const tests: TestResult[] = [
        {
          metadata: enhancedLogger.createTestMetadata('test1', '/test1.ts', 'suite1'),
          status: TestStatus.PASSED,
          performance: enhancedLogger.createPerformanceMetrics(1000, 1200),
          retryCount: 0
        },
        {
          metadata: enhancedLogger.createTestMetadata('test2', '/test2.ts', 'suite1'),
          status: TestStatus.FAILED,
          performance: enhancedLogger.createPerformanceMetrics(2000, 2500),
          error: {
            message: 'Assertion failed',
            type: ErrorType.ASSERTION,
            severity: ErrorSeverity.MEDIUM,
            category: 'functional'
          },
          retryCount: 1
        },
        {
          metadata: enhancedLogger.createTestMetadata('test3', '/test3.ts', 'suite1'),
          status: TestStatus.SKIPPED,
          performance: enhancedLogger.createPerformanceMetrics(3000, 3000),
          retryCount: 0
        }
      ]

      tests.forEach(test => enhancedLogger.logTestResult(test))
      const report = enhancedLogger.generateComprehensiveReport()

      expect(report.executiveSummary.totalTests).toBe(3)
      expect(report.executiveSummary.successRate).toBeCloseTo(33.33, 1)
      expect(report.detailedResults.failures).toHaveLength(1)
      expect(report.executiveSummary.overallStatus).toBe('warning')
    })
  })

  describe('Error Handling and Edge Cases', () => {
    it('should handle empty test results gracefully', () => {
      const report = enhancedLogger.generateComprehensiveReport()

      expect(report.executiveSummary.totalTests).toBe(0)
      expect(report.executiveSummary.successRate).toBe(0)
      expect(report.detailedResults.failures).toHaveLength(0)
    })

    it('should handle file system errors gracefully', () => {
      mockFs.writeFileSync.mockImplementation(() => {
        throw new Error('File system error')
      })

      expect(() => {
        enhancedLogger.saveComprehensiveReport()
      }).not.toThrow()
    })

    it('should handle GitHub API errors gracefully', async () => {
      const failingIssueManager = new TestFailureIssueManager({
        token: 'invalid-token',
        owner: 'test-owner',
        repo: 'test-repo'
      })

      // Mock failing API call
      ;(failingIssueManager as any).octokit = {
        rest: {
          issues: {
            create: jest.fn().mockRejectedValue(new Error('API Error'))
          },
          search: {
            issuesAndPullRequests: jest.fn().mockRejectedValue(new Error('Search Error'))
          }
        }
      }

      const failedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('failed test', '/test.ts', 'suite1'),
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        error: {
          message: 'Test failed',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.HIGH,
          category: 'functional'
        },
        retryCount: 0
      }

      await expect(failingIssueManager.processTestFailure(failedTest)).rejects.toThrow('GitHub issue creation failed')
    })
  })
})
