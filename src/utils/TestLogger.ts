/**
 * TestLogger Utility for Enhanced Test Suite Management
 * Provides seamless error logging with metadata for test failures
 */

import { writeFileSync, appendFileSync, existsSync, mkdirSync } from 'fs'
import { join } from 'path'

export interface TestLogEntry {
  timestamp: string
  suite: string
  testCase: string
  error: string
  metadata: {
    file: string
    line?: number
    column?: number
    stack?: string
    category:
      | 'syntax'
      | 'async'
      | 'flaky'
      | 'dependency'
      | 'mock'
      | 'timeout'
      | 'assertion'
      | 'unknown'
    severity: 'critical' | 'high' | 'medium' | 'low'
    retryCount?: number
  }
}

export interface TestSuiteStats {
  total: number
  passed: number
  failed: number
  skipped: number
  successRate: number
  duration: number
}

export class TestLogger {
  private logDir: string
  private logFile: string
  private errorLog: TestLogEntry[] = []
  private suiteStats: Map<string, TestSuiteStats> = new Map()

  constructor(logDir: string = './test-logs') {
    this.logDir = logDir
    this.logFile = join(logDir, `test-run-${Date.now()}.json`)
    this.ensureLogDirectory()
  }

  private ensureLogDirectory(): void {
    if (!existsSync(this.logDir)) {
      mkdirSync(this.logDir, { recursive: true })
    }
  }

  /**
   * Log a test error with comprehensive metadata
   */
  logError(
    suite: string,
    testCase: string,
    error: Error | string,
    metadata: Partial<TestLogEntry['metadata']> = {}
  ): void {
    const errorString = error instanceof Error ? error.message : error
    const stack = error instanceof Error ? error.stack : undefined

    const logEntry: TestLogEntry = {
      timestamp: new Date().toISOString(),
      suite,
      testCase,
      error: errorString,
      metadata: {
        file: metadata.file || 'unknown',
        line: metadata.line,
        column: metadata.column,
        stack,
        category: this.categorizeError(errorString),
        severity: this.determineSeverity(errorString),
        retryCount: metadata.retryCount || 0,
        ...metadata,
      },
    }

    this.errorLog.push(logEntry)
    this.writeLogEntry(logEntry)
  }

  /**
   * Log test suite statistics
   */
  logSuiteStats(suite: string, stats: TestSuiteStats): void {
    this.suiteStats.set(suite, stats)
    this.writeSuiteStats(suite, stats)
  }

  /**
   * Categorize error type for better handling
   */
  private categorizeError(error: string): TestLogEntry['metadata']['category'] {
    if (error.includes('SyntaxError') || error.includes('Unexpected token')) {
      return 'syntax'
    }
    if (error.includes('timeout') || error.includes('Timeout')) {
      return 'timeout'
    }
    if (error.includes('async') || error.includes('Promise') || error.includes('await')) {
      return 'async'
    }
    if (error.includes('mock') || error.includes('jest.fn') || error.includes('spy')) {
      return 'mock'
    }
    if (error.includes('import') || error.includes('require') || error.includes('module')) {
      return 'dependency'
    }
    if (error.includes('expect') || error.includes('toBe') || error.includes('toEqual')) {
      return 'assertion'
    }
    if (error.includes('flaky') || error.includes('intermittent')) {
      return 'flaky'
    }
    return 'unknown'
  }

  /**
   * Determine error severity
   */
  private determineSeverity(error: string): TestLogEntry['metadata']['severity'] {
    if (
      error.includes('ReferenceError') ||
      error.includes('TypeError') ||
      error.includes('SyntaxError')
    ) {
      return 'critical'
    }
    if (error.includes('timeout') || error.includes('failed to run')) {
      return 'high'
    }
    if (error.includes('expect') || error.includes('assertion')) {
      return 'medium'
    }
    return 'low'
  }

  /**
   * Write individual log entry to file
   */
  private writeLogEntry(entry: TestLogEntry): void {
    try {
      const logLine = JSON.stringify(entry) + '\n'
      appendFileSync(this.logFile, logLine)
    } catch (error) {
      console.error('Failed to write test log entry:', error)
    }
  }

  /**
   * Write suite statistics
   */
  private writeSuiteStats(suite: string, stats: TestSuiteStats): void {
    try {
      const statsFile = join(this.logDir, 'suite-stats.json')
      const allStats = this.getAllSuiteStats()
      writeFileSync(statsFile, JSON.stringify(allStats, null, 2))
    } catch (error) {
      console.error('Failed to write suite stats:', error)
    }
  }

  /**
   * Get all logged errors
   */
  getErrors(): TestLogEntry[] {
    return [...this.errorLog]
  }

  /**
   * Get errors by category
   */
  getErrorsByCategory(category: TestLogEntry['metadata']['category']): TestLogEntry[] {
    return this.errorLog.filter(entry => entry.metadata.category === category)
  }

  /**
   * Get errors by severity
   */
  getErrorsBySeverity(severity: TestLogEntry['metadata']['severity']): TestLogEntry[] {
    return this.errorLog.filter(entry => entry.metadata.severity === severity)
  }

  /**
   * Get overall test statistics
   */
  getOverallStats(): {
    totalSuites: number
    passingSuites: number
    failingSuites: number
    overallSuccessRate: number
    criticalErrors: number
    highPriorityErrors: number
  } {
    const stats = Array.from(this.suiteStats.values())
    const totalSuites = stats.length
    const passingSuites = stats.filter(s => s.successRate >= 0.96).length
    const failingSuites = totalSuites - passingSuites
    const overallSuccessRate =
      totalSuites > 0 ? stats.reduce((sum, s) => sum + s.successRate, 0) / totalSuites : 0

    return {
      totalSuites,
      passingSuites,
      failingSuites,
      overallSuccessRate,
      criticalErrors: this.getErrorsBySeverity('critical').length,
      highPriorityErrors: this.getErrorsBySeverity('high').length,
    }
  }

  /**
   * Get all suite statistics
   */
  getAllSuiteStats(): Record<string, TestSuiteStats> {
    const result: Record<string, TestSuiteStats> = {}
    this.suiteStats.forEach((stats, suite) => {
      result[suite] = stats
    })
    return result
  }

  /**
   * Generate comprehensive test report
   */
  generateReport(): string {
    const overall = this.getOverallStats()
    const errorsByCategory = {
      syntax: this.getErrorsByCategory('syntax').length,
      async: this.getErrorsByCategory('async').length,
      flaky: this.getErrorsByCategory('flaky').length,
      dependency: this.getErrorsByCategory('dependency').length,
      mock: this.getErrorsByCategory('mock').length,
      timeout: this.getErrorsByCategory('timeout').length,
      assertion: this.getErrorsByCategory('assertion').length,
      unknown: this.getErrorsByCategory('unknown').length,
    }

    return `
# Test Suite Report - ${new Date().toISOString()}

## Overall Statistics
- Total Suites: ${overall.totalSuites}
- Passing Suites (≥96%): ${overall.passingSuites}
- Failing Suites: ${overall.failingSuites}
- Overall Success Rate: ${(overall.overallSuccessRate * 100).toFixed(2)}%
- Critical Errors: ${overall.criticalErrors}
- High Priority Errors: ${overall.highPriorityErrors}

## Error Categories
- Syntax Errors: ${errorsByCategory.syntax}
- Async/Promise Errors: ${errorsByCategory.async}
- Flaky Test Errors: ${errorsByCategory.flaky}
- Dependency Errors: ${errorsByCategory.dependency}
- Mock/Spy Errors: ${errorsByCategory.mock}
- Timeout Errors: ${errorsByCategory.timeout}
- Assertion Errors: ${errorsByCategory.assertion}
- Unknown Errors: ${errorsByCategory.unknown}

## Recommendations
${this.generateRecommendations(overall, errorsByCategory)}
    `.trim()
  }

  /**
   * Generate actionable recommendations
   */
  private generateRecommendations(
    overall: ReturnType<TestLogger['getOverallStats']>,
    errorsByCategory: Record<string, number>
  ): string {
    const recommendations: string[] = []

    if (overall.overallSuccessRate < 0.95) {
      recommendations.push(
        '- Overall success rate is below 95% target. Focus on critical and high-priority errors first.'
      )
    }

    if (errorsByCategory.syntax > 0) {
      recommendations.push('- Fix syntax errors immediately as they prevent test execution.')
    }

    if (errorsByCategory.dependency > 0) {
      recommendations.push(
        '- Review import/require statements and ensure all dependencies are properly mocked.'
      )
    }

    if (errorsByCategory.async > 0) {
      recommendations.push(
        '- Review async/await patterns and ensure proper promise handling in tests.'
      )
    }

    if (errorsByCategory.timeout > 0) {
      recommendations.push('- Increase test timeouts or optimize slow operations in tests.')
    }

    if (errorsByCategory.flaky > 0) {
      recommendations.push(
        '- Implement AutoRetry mechanism for flaky tests and improve test isolation.'
      )
    }

    if (errorsByCategory.mock > 0) {
      recommendations.push('- Review mock implementations and ensure proper cleanup between tests.')
    }

    return recommendations.length > 0
      ? recommendations.join('\n')
      : '- All tests are performing well!'
  }

  /**
   * Save final report to file
   */
  saveReport(): string {
    const report = this.generateReport()
    const reportFile = join(this.logDir, `test-report-${Date.now()}.md`)
    writeFileSync(reportFile, report)
    return reportFile
  }
}

// Export singleton instance
export const testLogger = new TestLogger()
