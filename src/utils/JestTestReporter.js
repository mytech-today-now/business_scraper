/**
 * Enhanced Jest Test Reporter for Professional Test Reporting
 * Captures Jest test results with comprehensive metadata and GitHub integration
 */

const { testLogger, enhancedTestLogger } = require('./TestLogger')
const { performance } = require('perf_hooks')
const path = require('path')

// Conditional imports for enhanced features
let TestFailureIssueManager, TestStatus, TestCategory, TestPriority, ErrorSeverity, ErrorType

try {
  const githubModule = require('../lib/github/TestFailureIssueManager')
  TestFailureIssueManager = githubModule.TestFailureIssueManager
} catch (error) {
  console.warn('GitHub integration not available:', error.message)
  TestFailureIssueManager = null
}

try {
  const typesModule = require('../types/TestReporting')
  TestStatus = typesModule.TestStatus
  TestCategory = typesModule.TestCategory
  TestPriority = typesModule.TestPriority
  ErrorSeverity = typesModule.ErrorSeverity
  ErrorType = typesModule.ErrorType
} catch (error) {
  console.warn('Enhanced types not available:', error.message)
  // Fallback to basic enums
  TestStatus = { PASSED: 'passed', FAILED: 'failed', SKIPPED: 'skipped', PENDING: 'pending', ERROR: 'error', TIMEOUT: 'timeout' }
  TestCategory = { UNIT: 'unit', INTEGRATION: 'integration', E2E: 'e2e', PERFORMANCE: 'performance', SECURITY: 'security' }
  TestPriority = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }
  ErrorSeverity = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }
  ErrorType = { ASSERTION: 'assertion', TIMEOUT: 'timeout', SYNTAX: 'syntax', ASYNC: 'async', DEPENDENCY: 'dependency', MOCK: 'mock', UNKNOWN: 'unknown' }
}

class EnhancedJestTestReporter {
  constructor(globalConfig, options) {
    this.globalConfig = globalConfig
    this.options = options
    this.startTime = performance.now()
    this.testResults = new Map()

    // Initialize GitHub integration if configured and available
    this.githubIssueManager = null
    if (TestFailureIssueManager && process.env.GITHUB_TOKEN && process.env.GITHUB_REPO) {
      try {
        const [owner, repo] = process.env.GITHUB_REPO.split('/')
        this.githubIssueManager = new TestFailureIssueManager({
          token: process.env.GITHUB_TOKEN,
          owner,
          repo
        }, {
          labelPrefix: 'jest-test-failure',
          defaultAssignees: ['mytech-today-now']
        })
      } catch (error) {
        console.warn('Failed to initialize GitHub integration:', error.message)
      }
    }
  }

  /**
   * Called when all tests are complete - Enhanced version
   */
  async onRunComplete(contexts, results) {
    try {
      const endTime = performance.now()
      const totalDuration = endTime - this.startTime

      // Process each test suite with enhanced metadata
      for (const testResult of results.testResults) {
        await this.processTestSuite(testResult)
      }

      // Generate comprehensive report
      await this.generateComprehensiveReport(results, totalDuration)

      // Maintain backward compatibility
      this.processLegacyReporting(results)

    } catch (error) {
      console.error('Enhanced JestTestReporter error:', error)
    }
  }

  /**
   * Process individual test suite with enhanced metadata
   */
  async processTestSuite(testResult) {
    const suiteName = this.extractSuiteName(testResult.testFilePath)
    const suiteStartTime = testResult.perfStats.start
    const suiteEndTime = testResult.perfStats.end

    // Calculate suite statistics
    const total = testResult.numPassingTests + testResult.numFailingTests + testResult.numPendingTests
    const stats = {
      total: total,
      passed: testResult.numPassingTests,
      failed: testResult.numFailingTests,
      skipped: testResult.numPendingTests,
      successRate: total > 0 ? testResult.numPassingTests / total : 0,
      duration: suiteEndTime - suiteStartTime
    }

    // Log suite statistics to both loggers
    testLogger.logSuiteStats(suiteName, stats)

    // Process individual tests with enhanced metadata
    for (const test of testResult.testResults) {
      await this.processIndividualTest(test, testResult, suiteName)
    }
  }

  /**
   * Process individual test with comprehensive metadata
   */
  async processIndividualTest(test, testResult, suiteName) {
    // Check if enhanced logger is available
    if (!enhancedTestLogger || !enhancedTestLogger.createTestMetadata) {
      // Fallback to basic processing
      this.processBasicTest(test, testResult, suiteName)
      return
    }

    const testMetadata = enhancedTestLogger.createTestMetadata(
      test.title,
      testResult.testFilePath,
      suiteName,
      {
        category: this.inferTestCategory(testResult.testFilePath),
        priority: this.inferTestPriority(test.title),
        description: test.title
      }
    )

    const performanceMetrics = enhancedTestLogger.createPerformanceMetrics(
      testResult.perfStats.start,
      testResult.perfStats.end
    )

    const enhancedTestResult = {
      metadata: testMetadata,
      status: this.mapJestStatusToTestStatus(test.status),
      performance: performanceMetrics,
      retryCount: test.retryReasons?.length || 0
    }

    // Handle test failures with enhanced error information
    if (test.status === 'failed') {
      enhancedTestResult.error = this.createEnhancedError(test, testResult)

      // Create GitHub issue if configured
      if (this.githubIssueManager) {
        try {
          const githubIssue = await this.githubIssueManager.processTestFailure(enhancedTestResult)
          enhancedTestResult.githubIssue = githubIssue
        } catch (error) {
          console.error(`Failed to create GitHub issue for test ${test.title}:`, error)
        }
      }

      // Log to both old and new systems
      test.failureMessages.forEach(failureMessage => {
        testLogger.logError(
          suiteName,
          test.title,
          failureMessage,
          {
            file: testResult.testFilePath,
            category: this.categorizeTestError(failureMessage),
            severity: this.determineSeverity(failureMessage)
          }
        )
      })
    }

    // Log to enhanced test logger if available
    if (enhancedTestLogger && enhancedTestLogger.logTestResult) {
      enhancedTestLogger.logTestResult(enhancedTestResult)
    }

    // Store for comprehensive reporting
    const testKey = `${suiteName}::${test.title}`
    this.testResults.set(testKey, enhancedTestResult)
  }

  /**
   * Process basic test for fallback compatibility
   */
  processBasicTest(test, testResult, suiteName) {
    if (test.status === 'failed') {
      test.failureMessages.forEach(failureMessage => {
        testLogger.logError(
          suiteName,
          test.title,
          failureMessage,
          {
            file: testResult.testFilePath,
            category: this.categorizeTestError(failureMessage),
            severity: this.determineSeverity(failureMessage)
          }
        )
      })
    }
  }

  /**
   * Extract a clean suite name from file path
   */
  extractSuiteName(filePath) {
    // Extract filename without extension
    const fileName = filePath.split(/[/\\]/).pop().replace(/\.(test|spec)\.(js|jsx|ts|tsx)$/, '')
    
    // Convert to readable format
    return fileName
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .trim()
  }

  /**
   * Categorize test errors for better tracking
   */
  categorizeTestError(errorMessage) {
    if (errorMessage.includes('timeout') || errorMessage.includes('Timeout')) {
      return 'timeout'
    }
    if (errorMessage.includes('expect') || errorMessage.includes('toBe') || errorMessage.includes('toEqual')) {
      return 'assertion'
    }
    if (errorMessage.includes('mock') || errorMessage.includes('jest.fn') || errorMessage.includes('spy')) {
      return 'mock'
    }
    if (errorMessage.includes('async') || errorMessage.includes('Promise') || errorMessage.includes('await')) {
      return 'async'
    }
    if (errorMessage.includes('import') || errorMessage.includes('require') || errorMessage.includes('module')) {
      return 'dependency'
    }
    if (errorMessage.includes('SyntaxError') || errorMessage.includes('Unexpected token')) {
      return 'syntax'
    }
    return 'unknown'
  }

  /**
   * Determine error severity
   */
  determineSeverity(errorMessage) {
    if (
      errorMessage.includes('ReferenceError') ||
      errorMessage.includes('TypeError') ||
      errorMessage.includes('SyntaxError')
    ) {
      return 'critical'
    }
    if (errorMessage.includes('timeout') || errorMessage.includes('failed to run')) {
      return 'high'
    }
    if (errorMessage.includes('expect') || errorMessage.includes('assertion')) {
      return 'medium'
    }
    return 'low'
  }

  /**
   * Generate comprehensive test report
   */
  async generateComprehensiveReport(results, totalDuration) {
    try {
      if (enhancedTestLogger && enhancedTestLogger.generateComprehensiveReport) {
        const report = enhancedTestLogger.generateComprehensiveReport()
        const reportFiles = enhancedTestLogger.saveComprehensiveReport()

        console.log('\n🎯 Enhanced Test Report Generated:')
        console.log(`📊 JSON Report: ${reportFiles.json}`)
        console.log(`📝 Markdown Report: ${reportFiles.markdown}`)
        console.log(`🌐 HTML Report: ${reportFiles.html}`)

        // Generate GitHub Actions summary if in CI
        if (process.env.GITHUB_STEP_SUMMARY) {
          const summary = this.generateGitHubActionsSummary(report)
          require('fs').appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary)
        }
      } else {
        console.log('\n📊 Basic Test Report Generated (Enhanced features not available)')
      }
    } catch (error) {
      console.error('Failed to generate comprehensive report:', error)
    }
  }

  /**
   * Generate GitHub Actions summary
   */
  generateGitHubActionsSummary(report) {
    const status = report.executiveSummary.overallStatus === 'passed' ? '✅' : '❌'

    return `## ${status} Test Execution Summary

| Metric | Value |
|--------|-------|
| Overall Status | ${report.executiveSummary.overallStatus.toUpperCase()} |
| Total Tests | ${report.executiveSummary.totalTests} |
| Success Rate | ${report.executiveSummary.successRate.toFixed(2)}% |
| Critical Issues | ${report.executiveSummary.criticalIssues} |
| Quality Gate | ${report.executiveSummary.qualityGate.toUpperCase()} |

### Failed Tests
${report.detailedResults.failures.length > 0 ?
  report.detailedResults.failures.map(test =>
    `- **${test.metadata.testName}**: ${test.error?.message || 'Unknown error'}`
  ).join('\n') : 'No test failures ✅'
}

### GitHub Issues
- New Issues Created: ${report.issueTracking.newIssuesCreated.length}
- Existing Issues Updated: ${report.issueTracking.openIssues.length}
- Escalated Issues: ${report.issueTracking.escalatedIssues.length}

---
*Generated by Enhanced Jest Test Reporter*`
  }

  /**
   * Legacy reporting for backward compatibility
   */
  processLegacyReporting(results) {
    // This maintains the original functionality
    results.testResults.forEach(testResult => {
      const suiteName = this.extractSuiteName(testResult.testFilePath)

      const total = testResult.numPassingTests + testResult.numFailingTests + testResult.numPendingTests
      const stats = {
        total: total,
        passed: testResult.numPassingTests,
        failed: testResult.numFailingTests,
        skipped: testResult.numPendingTests,
        successRate: total > 0 ? testResult.numPassingTests / total : 0,
        duration: testResult.perfStats.end - testResult.perfStats.start
      }

      testLogger.logSuiteStats(suiteName, stats)
    })
  }

  /**
   * Create enhanced error object
   */
  createEnhancedError(test, testResult) {
    const failureMessage = test.failureMessages[0] || 'Unknown error'

    return {
      message: failureMessage,
      stack: test.failureMessages.join('\n'),
      type: this.mapErrorType(failureMessage),
      severity: this.mapErrorSeverity(failureMessage),
      category: 'functional',
      reproductionSteps: [
        `Run test: ${test.title}`,
        `In file: ${testResult.testFilePath}`,
        'Observe the failure'
      ],
      expectedBehavior: 'Test should pass without errors',
      actualBehavior: `Test failed with: ${failureMessage.split('\n')[0]}`
    }
  }

  /**
   * Map Jest status to TestStatus enum
   */
  mapJestStatusToTestStatus(jestStatus) {
    switch (jestStatus) {
      case 'passed': return TestStatus.PASSED
      case 'failed': return TestStatus.FAILED
      case 'skipped': return TestStatus.SKIPPED
      case 'pending': return TestStatus.PENDING
      case 'todo': return TestStatus.SKIPPED
      default: return TestStatus.ERROR
    }
  }

  /**
   * Map error message to ErrorType
   */
  mapErrorType(errorMessage) {
    if (errorMessage.includes('timeout')) return ErrorType.TIMEOUT
    if (errorMessage.includes('expect') || errorMessage.includes('toBe')) return ErrorType.ASSERTION
    if (errorMessage.includes('mock') || errorMessage.includes('spy')) return ErrorType.MOCK
    if (errorMessage.includes('async') || errorMessage.includes('Promise')) return ErrorType.ASYNC
    if (errorMessage.includes('import') || errorMessage.includes('require')) return ErrorType.DEPENDENCY
    if (errorMessage.includes('SyntaxError')) return ErrorType.SYNTAX
    return ErrorType.UNKNOWN
  }

  /**
   * Map error message to ErrorSeverity
   */
  mapErrorSeverity(errorMessage) {
    if (errorMessage.includes('ReferenceError') || errorMessage.includes('TypeError')) return ErrorSeverity.CRITICAL
    if (errorMessage.includes('timeout') || errorMessage.includes('failed to run')) return ErrorSeverity.HIGH
    if (errorMessage.includes('expect') || errorMessage.includes('assertion')) return ErrorSeverity.MEDIUM
    return ErrorSeverity.LOW
  }

  /**
   * Infer test category from file path
   */
  inferTestCategory(filePath) {
    const path = filePath.toLowerCase()
    if (path.includes('/unit/') || path.includes('.unit.')) return TestCategory.UNIT
    if (path.includes('/integration/') || path.includes('.integration.')) return TestCategory.INTEGRATION
    if (path.includes('/e2e/') || path.includes('.e2e.')) return TestCategory.E2E
    if (path.includes('/performance/') || path.includes('.performance.')) return TestCategory.PERFORMANCE
    if (path.includes('/security/') || path.includes('.security.')) return TestCategory.SECURITY
    return TestCategory.UNIT
  }

  /**
   * Infer test priority from test name
   */
  inferTestPriority(testName) {
    const name = testName.toLowerCase()
    if (name.includes('critical') || name.includes('essential')) return TestPriority.CRITICAL
    if (name.includes('important') || name.includes('high')) return TestPriority.HIGH
    if (name.includes('low') || name.includes('optional')) return TestPriority.LOW
    return TestPriority.MEDIUM
  }

  /**
   * Get reporter name
   */
  getLastError() {
    return this.lastError
  }
}

// Keep original class for backward compatibility
class JestTestReporter {
  constructor(globalConfig, options) {
    this.globalConfig = globalConfig
    this.options = options
  }

  onRunComplete(contexts, results) {
    try {
      results.testResults.forEach(testResult => {
        const suiteName = this.extractSuiteName(testResult.testFilePath)

        const total = testResult.numPassingTests + testResult.numFailingTests + testResult.numPendingTests
        const stats = {
          total: total,
          passed: testResult.numPassingTests,
          failed: testResult.numFailingTests,
          skipped: testResult.numPendingTests,
          successRate: total > 0 ? testResult.numPassingTests / total : 0,
          duration: testResult.perfStats.end - testResult.perfStats.start
        }

        testLogger.logSuiteStats(suiteName, stats)

        testResult.testResults.forEach(test => {
          if (test.status === 'failed') {
            test.failureMessages.forEach(failureMessage => {
              testLogger.logError(
                suiteName,
                test.title,
                failureMessage,
                {
                  file: testResult.testFilePath,
                  category: this.categorizeTestError(failureMessage),
                  severity: this.determineSeverity(failureMessage)
                }
              )
            })
          }
        })
      })
    } catch (error) {
      console.error('JestTestReporter error:', error)
    }
  }

  extractSuiteName(filePath) {
    const fileName = filePath.split(/[/\\]/).pop().replace(/\.(test|spec)\.(js|jsx|ts|tsx)$/, '')
    return fileName
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .trim()
  }

  categorizeTestError(errorMessage) {
    if (errorMessage.includes('timeout') || errorMessage.includes('Timeout')) return 'timeout'
    if (errorMessage.includes('expect') || errorMessage.includes('toBe') || errorMessage.includes('toEqual')) return 'assertion'
    if (errorMessage.includes('mock') || errorMessage.includes('jest.fn') || errorMessage.includes('spy')) return 'mock'
    if (errorMessage.includes('async') || errorMessage.includes('Promise') || errorMessage.includes('await')) return 'async'
    if (errorMessage.includes('import') || errorMessage.includes('require') || errorMessage.includes('module')) return 'dependency'
    if (errorMessage.includes('SyntaxError') || errorMessage.includes('Unexpected token')) return 'syntax'
    return 'unknown'
  }

  determineSeverity(errorMessage) {
    if (errorMessage.includes('ReferenceError') || errorMessage.includes('TypeError') || errorMessage.includes('SyntaxError')) return 'critical'
    if (errorMessage.includes('timeout') || errorMessage.includes('failed to run')) return 'high'
    if (errorMessage.includes('expect') || errorMessage.includes('assertion')) return 'medium'
    return 'low'
  }

  getLastError() {
    return this.lastError
  }
}

// Export both for backward compatibility
module.exports = EnhancedJestTestReporter
module.exports.JestTestReporter = JestTestReporter // Original class for backward compatibility
