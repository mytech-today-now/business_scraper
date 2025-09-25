/**
 * Build Verification Tests (BVT) for Enhanced Test Reporting System
 * Critical tests to ensure the enhanced test reporting system works correctly
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { EnhancedTestLogger } from '../../utils/TestLogger'
import { TestFailureIssueManager } from '../../lib/github/TestFailureIssueManager'
import { EnhancedBVTReporter } from './enhanced-bvt-reporter'
import {
  TestStatus,
  TestCategory,
  TestPriority,
  ErrorSeverity,
  ErrorType,
  TestResult
} from '../../types/TestReporting'
import * as fs from 'fs'

// Mock external dependencies for BVT
jest.mock('fs')
jest.mock('@octokit/rest')

const mockFs = fs as jest.Mocked<typeof fs>

describe('Enhanced Test Reporting BVT Suite', () => {
  let enhancedLogger: EnhancedTestLogger
  let bvtReporter: EnhancedBVTReporter

  beforeEach(() => {
    enhancedLogger = new EnhancedTestLogger('./test-logs-bvt', { githubIntegration: false })
    bvtReporter = new EnhancedBVTReporter('info')
    
    // Mock file system for BVT
    mockFs.existsSync.mockReturnValue(true)
    mockFs.mkdirSync.mockReturnValue(undefined)
    mockFs.writeFileSync.mockReturnValue(undefined)
    mockFs.appendFileSync.mockReturnValue(undefined)
    mockFs.readFileSync.mockReturnValue(JSON.stringify({ version: '1.0.0' }))
  })

  afterEach(() => {
    jest.clearAllMocks()
  })

  describe('Critical BVT: Core Functionality', () => {
    it('BVT-001: Enhanced logger must create valid test metadata', () => {
      const metadata = enhancedLogger.createTestMetadata(
        'BVT Test Case',
        '/src/tests/bvt/test.ts',
        'BVT Suite'
      )

      // Critical assertions for BVT
      expect(metadata.testId).toBeDefined()
      expect(metadata.testName).toBe('BVT Test Case')
      expect(metadata.filePath).toBe('/src/tests/bvt/test.ts')
      expect(metadata.suite).toBe('BVT Suite')
      expect(metadata.category).toBeDefined()
      expect(metadata.priority).toBeDefined()
      expect(metadata.relativePath).toBeDefined()
      expect(Array.isArray(metadata.tags)).toBe(true)
    })

    it('BVT-002: Enhanced logger must create valid performance metrics', () => {
      const startTime = performance.now()
      const endTime = startTime + 1000
      
      const metrics = enhancedLogger.createPerformanceMetrics(startTime, endTime)

      // Critical performance metrics validation
      expect(metrics.startTime).toBe(startTime)
      expect(metrics.endTime).toBe(endTime)
      expect(metrics.duration).toBe(1000)
      expect(metrics.memoryUsage).toBeDefined()
      expect(metrics.memoryUsage.heapUsed).toBeGreaterThan(0)
      expect(metrics.memoryUsage.heapTotal).toBeGreaterThan(0)
      expect(metrics.memoryUsage.external).toBeGreaterThanOrEqual(0)
      expect(metrics.memoryUsage.rss).toBeGreaterThan(0)
    })

    it('BVT-003: Enhanced logger must log test results without errors', () => {
      const testResult: TestResult = {
        metadata: enhancedLogger.createTestMetadata('BVT Test', '/test.ts', 'BVT Suite'),
        status: TestStatus.PASSED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        retryCount: 0
      }

      expect(() => {
        enhancedLogger.logTestResult(testResult)
      }).not.toThrow()
    })

    it('BVT-004: Enhanced logger must generate comprehensive report', () => {
      // Add test data
      const testResult: TestResult = {
        metadata: enhancedLogger.createTestMetadata('BVT Test', '/test.ts', 'BVT Suite'),
        status: TestStatus.PASSED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 1500),
        retryCount: 0
      }

      enhancedLogger.logTestResult(testResult)
      const report = enhancedLogger.generateComprehensiveReport()

      // Critical report structure validation
      expect(report).toBeDefined()
      expect(report.metadata).toBeDefined()
      expect(report.metadata.reportId).toBeDefined()
      expect(report.metadata.generatedAt).toBeDefined()
      expect(report.metadata.version).toBeDefined()
      expect(report.metadata.generator).toBe('EnhancedTestLogger')

      expect(report.executiveSummary).toBeDefined()
      expect(report.executiveSummary.totalTests).toBe(1)
      expect(report.executiveSummary.successRate).toBe(100)
      expect(report.executiveSummary.overallStatus).toBe('passed')

      expect(report.testInventory).toBeDefined()
      expect(report.detailedResults).toBeDefined()
      expect(report.issueTracking).toBeDefined()
      expect(report.performanceAnalysis).toBeDefined()
      expect(report.recommendations).toBeDefined()
      expect(report.historicalContext).toBeDefined()
    })

    it('BVT-005: Enhanced logger must save reports in multiple formats', () => {
      const reportFiles = enhancedLogger.saveComprehensiveReport()

      // Critical file generation validation
      expect(reportFiles).toBeDefined()
      expect(reportFiles.json).toBeDefined()
      expect(reportFiles.markdown).toBeDefined()
      expect(reportFiles.html).toBeDefined()

      // Verify all three formats were written
      expect(mockFs.writeFileSync).toHaveBeenCalledTimes(3)
    })
  })

  describe('Critical BVT: Error Handling', () => {
    it('BVT-006: System must handle test failures correctly', () => {
      const failedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('Failed BVT Test', '/test.ts', 'BVT Suite'),
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        error: {
          message: 'BVT test failure',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.CRITICAL,
          category: 'functional'
        },
        retryCount: 1
      }

      enhancedLogger.logTestResult(failedTest)
      const report = enhancedLogger.generateComprehensiveReport()

      // Critical failure handling validation
      expect(report.executiveSummary.totalTests).toBe(1)
      expect(report.executiveSummary.successRate).toBe(0)
      expect(report.executiveSummary.criticalIssues).toBe(1)
      expect(report.executiveSummary.overallStatus).toBe('failed')
      expect(report.detailedResults.failures).toHaveLength(1)
      expect(report.detailedResults.criticalFailures).toHaveLength(1)
    })

    it('BVT-007: System must categorize errors correctly', () => {
      const errorTypes = [
        { message: 'Test timeout after 5000ms', expectedCategory: 'timeout' },
        { message: 'expect(received).toBe(expected)', expectedCategory: 'assertion' },
        { message: 'SyntaxError: Unexpected token', expectedCategory: 'syntax' },
        { message: 'Promise rejected', expectedCategory: 'async' },
        { message: 'Cannot resolve module', expectedCategory: 'dependency' },
        { message: 'jest.fn() was called', expectedCategory: 'mock' }
      ]

      errorTypes.forEach(({ message, expectedCategory }) => {
        const categorizeError = (enhancedLogger as any).categorizeError.bind(enhancedLogger)
        expect(categorizeError(message)).toBe(expectedCategory)
      })
    })

    it('BVT-008: System must handle empty test results gracefully', () => {
      const report = enhancedLogger.generateComprehensiveReport()

      // Critical empty state validation
      expect(report.executiveSummary.totalTests).toBe(0)
      expect(report.executiveSummary.successRate).toBe(0)
      expect(report.executiveSummary.overallStatus).toBe('passed') // No failures = passed
      expect(report.detailedResults.failures).toHaveLength(0)
      expect(report.detailedResults.criticalFailures).toHaveLength(0)
    })
  })

  describe('Critical BVT: GitHub Integration', () => {
    let issueManager: TestFailureIssueManager
    let mockOctokit: any

    beforeEach(() => {
      mockOctokit = {
        rest: {
          issues: {
            create: jest.fn().mockResolvedValue({
              data: {
                number: 456,
                html_url: 'https://github.com/test/repo/issues/456',
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

      issueManager = new TestFailureIssueManager({
        token: 'bvt-test-token',
        owner: 'bvt-owner',
        repo: 'bvt-repo'
      })

      ;(issueManager as any).octokit = mockOctokit
    })

    it('BVT-009: GitHub integration must create issues for critical failures', async () => {
      const criticalFailure: TestResult = {
        metadata: enhancedLogger.createTestMetadata('Critical BVT Failure', '/test.ts', 'BVT Suite'),
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        error: {
          message: 'Critical system failure',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.CRITICAL,
          category: 'functional'
        },
        retryCount: 0
      }

      const issueRef = await issueManager.processTestFailure(criticalFailure)

      // Critical GitHub integration validation
      expect(issueRef).toBeDefined()
      expect(issueRef?.issueNumber).toBe(456)
      expect(issueRef?.status).toBe('open')
      expect(issueRef?.issueUrl).toBeDefined()
      expect(mockOctokit.rest.issues.create).toHaveBeenCalledTimes(1)

      // Verify issue creation parameters
      const createCall = mockOctokit.rest.issues.create.mock.calls[0][0]
      expect(createCall.title).toContain('CRITICAL')
      expect(createCall.title).toContain('Critical BVT Failure')
      expect(createCall.labels).toContain('test-failure')
      expect(createCall.labels).toContain('severity-critical')
    })

    it('BVT-010: GitHub integration must handle dry run mode', async () => {
      const dryRunManager = new TestFailureIssueManager({
        token: 'test-token',
        owner: 'test-owner',
        repo: 'test-repo'
      }, {
        dryRun: true
      })

      const failedTest: TestResult = {
        metadata: enhancedLogger.createTestMetadata('Dry Run Test', '/test.ts', 'BVT Suite'),
        status: TestStatus.FAILED,
        performance: enhancedLogger.createPerformanceMetrics(1000, 2000),
        error: {
          message: 'Test failure',
          type: ErrorType.ASSERTION,
          severity: ErrorSeverity.HIGH,
          category: 'functional'
        },
        retryCount: 0
      }

      const issueRef = await dryRunManager.processTestFailure(failedTest)

      // Critical dry run validation
      expect(issueRef).toBeDefined()
      expect(issueRef?.status).toBe('pending')
      expect(issueRef?.createdAt).toBeDefined()
    })
  })

  describe('Critical BVT: Enhanced BVT Reporter', () => {
    it('BVT-011: BVT Reporter must create execution context', () => {
      const context = (bvtReporter as any).createExecutionContext()

      // Critical execution context validation
      expect(context).toBeDefined()
      expect(context.environment).toBeDefined()
      expect(context.nodeVersion).toBeDefined()
      expect(context.platform).toBeDefined()
      expect(context.timestamp).toBeDefined()
      expect(context.workingDirectory).toBeDefined()
      expect(context.configuration).toBeDefined()
      expect(context.dependencies).toBeDefined()
      expect(context.dependencies.node).toBeDefined()
    })

    it('BVT-012: BVT Reporter must log structured messages', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation()

      bvtReporter.logInfo('BVT test message', { testData: 'value' })

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[BVT INFO]')
      )

      const logCall = consoleSpy.mock.calls[0][0]
      const logData = JSON.parse(logCall.replace('[BVT INFO] ', ''))

      // Critical log structure validation
      expect(logData.level).toBe('INFO')
      expect(logData.message).toBe('BVT test message')
      expect(logData.data).toEqual({ testData: 'value' })
      expect(logData.reportId).toBeDefined()
      expect(logData.timestamp).toBeDefined()

      consoleSpy.mockRestore()
    })

    it('BVT-013: BVT Reporter must determine status correctly', () => {
      const determineOverallStatus = (bvtReporter as any).determineOverallStatus.bind(bvtReporter)
      const determineQualityGate = (bvtReporter as any).determineQualityGate.bind(bvtReporter)

      // Critical status determination validation
      expect(determineOverallStatus(100, 0)).toBe('passed')
      expect(determineOverallStatus(94, 0)).toBe('warning')
      expect(determineOverallStatus(100, 1)).toBe('failed')

      expect(determineQualityGate(100, 0)).toBe('passed')
      expect(determineQualityGate(94, 0)).toBe('warning')
      expect(determineQualityGate(89, 0)).toBe('failed')
      expect(determineQualityGate(100, 1)).toBe('failed')
    })
  })

  describe('Critical BVT: Performance and Reliability', () => {
    it('BVT-014: System must handle large numbers of test results efficiently', () => {
      const startTime = performance.now()
      
      // Generate 1000 test results
      for (let i = 0; i < 1000; i++) {
        const testResult: TestResult = {
          metadata: enhancedLogger.createTestMetadata(`Test ${i}`, `/test${i}.ts`, 'Performance Suite'),
          status: i % 10 === 0 ? TestStatus.FAILED : TestStatus.PASSED,
          performance: enhancedLogger.createPerformanceMetrics(1000 + i, 1500 + i),
          retryCount: 0
        }

        if (testResult.status === TestStatus.FAILED) {
          testResult.error = {
            message: `Test ${i} failed`,
            type: ErrorType.ASSERTION,
            severity: ErrorSeverity.MEDIUM,
            category: 'functional'
          }
        }

        enhancedLogger.logTestResult(testResult)
      }

      const report = enhancedLogger.generateComprehensiveReport()
      const endTime = performance.now()

      // Critical performance validation
      expect(endTime - startTime).toBeLessThan(5000) // Should complete within 5 seconds
      expect(report.executiveSummary.totalTests).toBe(1000)
      expect(report.executiveSummary.successRate).toBe(90) // 100 failures out of 1000
      expect(report.detailedResults.failures).toHaveLength(100)
    })

    it('BVT-015: System must handle concurrent operations safely', async () => {
      const promises = []

      // Create 10 concurrent test logging operations
      for (let i = 0; i < 10; i++) {
        const promise = new Promise<void>((resolve) => {
          setTimeout(() => {
            const testResult: TestResult = {
              metadata: enhancedLogger.createTestMetadata(`Concurrent Test ${i}`, `/test${i}.ts`, 'Concurrent Suite'),
              status: TestStatus.PASSED,
              performance: enhancedLogger.createPerformanceMetrics(1000 + i * 100, 1500 + i * 100),
              retryCount: 0
            }
            enhancedLogger.logTestResult(testResult)
            resolve()
          }, Math.random() * 100)
        })
        promises.push(promise)
      }

      await Promise.all(promises)
      const report = enhancedLogger.generateComprehensiveReport()

      // Critical concurrency validation
      expect(report.executiveSummary.totalTests).toBe(10)
      expect(report.executiveSummary.successRate).toBe(100)
    })

    it('BVT-016: System must maintain data integrity under stress', () => {
      const testResults: TestResult[] = []

      // Create diverse test scenarios
      const scenarios = [
        { status: TestStatus.PASSED, category: TestCategory.UNIT, priority: TestPriority.HIGH },
        { status: TestStatus.FAILED, category: TestCategory.INTEGRATION, priority: TestPriority.CRITICAL },
        { status: TestStatus.SKIPPED, category: TestCategory.E2E, priority: TestPriority.MEDIUM },
        { status: TestStatus.TIMEOUT, category: TestCategory.PERFORMANCE, priority: TestPriority.LOW },
        { status: TestStatus.ERROR, category: TestCategory.SECURITY, priority: TestPriority.HIGH }
      ]

      scenarios.forEach((scenario, index) => {
        const testResult: TestResult = {
          metadata: {
            testId: `stress-test-${index}`,
            testName: `Stress Test ${index}`,
            testDescription: `Stress test scenario ${index}`,
            filePath: `/stress/test${index}.ts`,
            relativePath: `stress/test${index}.ts`,
            suite: 'Stress Suite',
            category: scenario.category,
            tags: ['stress', 'bvt'],
            priority: scenario.priority
          },
          status: scenario.status,
          performance: enhancedLogger.createPerformanceMetrics(1000 + index * 200, 1800 + index * 200),
          retryCount: scenario.status === TestStatus.FAILED ? 2 : 0
        }

        if (scenario.status === TestStatus.FAILED || scenario.status === TestStatus.ERROR) {
          testResult.error = {
            message: `Stress test ${index} failed`,
            type: ErrorType.ASSERTION,
            severity: ErrorSeverity.HIGH,
            category: 'functional'
          }
        }

        enhancedLogger.logTestResult(testResult)
        testResults.push(testResult)
      })

      const report = enhancedLogger.generateComprehensiveReport()

      // Critical data integrity validation
      expect(report.executiveSummary.totalTests).toBe(5)
      expect(report.testInventory.categories[TestCategory.UNIT]).toBe(1)
      expect(report.testInventory.categories[TestCategory.INTEGRATION]).toBe(1)
      expect(report.testInventory.categories[TestCategory.E2E]).toBe(1)
      expect(report.testInventory.categories[TestCategory.PERFORMANCE]).toBe(1)
      expect(report.testInventory.categories[TestCategory.SECURITY]).toBe(1)
      
      expect(report.testInventory.priorities[TestPriority.CRITICAL]).toBe(1)
      expect(report.testInventory.priorities[TestPriority.HIGH]).toBe(2)
      expect(report.testInventory.priorities[TestPriority.MEDIUM]).toBe(1)
      expect(report.testInventory.priorities[TestPriority.LOW]).toBe(1)

      expect(report.detailedResults.failures.length).toBeGreaterThan(0)
      expect(report.executiveSummary.successRate).toBeLessThan(100)
    })
  })
})
