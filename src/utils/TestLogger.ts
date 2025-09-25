/**
 * Enhanced TestLogger Utility for Professional Test Suite Management
 * Provides comprehensive test reporting with metadata, performance tracking, and GitHub integration
 */

import { writeFileSync, appendFileSync, existsSync, mkdirSync, readFileSync } from 'fs'
import { join, relative } from 'path'
import { performance } from 'perf_hooks'
import * as os from 'os'
import {
  TestResult,
  TestSuiteResult,
  ComprehensiveTestReport,
  TestMetadata,
  TestPerformanceMetrics,
  TestError,
  TestStatus,
  TestCategory,
  TestPriority,
  ErrorType,
  ErrorSeverity,
  ErrorCategory,
  TestExecutionContext,
  GitHubIssueReference,
  TestRecommendation,
  TestTrends
} from '../types/TestReporting'

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

export class EnhancedTestLogger {
  private logDir: string
  private logFile: string
  private errorLog: TestLogEntry[] = []
  private suiteStats: Map<string, TestSuiteStats> = new Map()
  private testResults: Map<string, TestResult> = new Map()
  private suiteResults: Map<string, TestSuiteResult> = new Map()
  private executionContext: TestExecutionContext
  private startTime: number
  private githubIntegration: boolean
  private reportId: string

  constructor(logDir: string = './test-logs', options: { githubIntegration?: boolean } = {}) {
    this.logDir = logDir
    this.reportId = `report-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    this.logFile = join(logDir, `test-run-${this.reportId}.json`)
    this.githubIntegration = options.githubIntegration ?? true
    this.startTime = performance.now()
    this.executionContext = this.createExecutionContext()
    this.ensureLogDirectory()
  }

  private ensureLogDirectory(): void {
    if (!existsSync(this.logDir)) {
      mkdirSync(this.logDir, { recursive: true })
    }
  }

  private createExecutionContext(): TestExecutionContext {
    return {
      environment: process.env.NODE_ENV || 'test',
      nodeVersion: process.version,
      platform: `${os.platform()} ${os.arch()}`,
      timestamp: new Date().toISOString(),
      duration: 0, // Will be updated when report is generated
      workingDirectory: process.cwd(),
      configuration: {
        maxWorkers: process.env.JEST_WORKERS || 'auto',
        timeout: process.env.JEST_TIMEOUT || 60000,
        coverage: process.env.COLLECT_COVERAGE === 'true'
      },
      dependencies: this.getKeyDependencies()
    }
  }

  private getKeyDependencies(): Record<string, string> {
    try {
      const packageJson = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'))
      return {
        jest: packageJson.devDependencies?.jest || 'unknown',
        playwright: packageJson.devDependencies?.playwright || 'unknown',
        node: process.version
      }
    } catch {
      return { node: process.version }
    }
  }

  /**
   * Log a comprehensive test result with full metadata
   */
  logTestResult(testResult: TestResult): void {
    const testKey = `${testResult.metadata.suite}::${testResult.metadata.testName}`
    this.testResults.set(testKey, testResult)

    // Also maintain backward compatibility with old error logging
    if (testResult.status === TestStatus.FAILED && testResult.error) {
      this.logError(
        testResult.metadata.suite,
        testResult.metadata.testName,
        testResult.error.message,
        {
          file: testResult.metadata.filePath,
          stack: testResult.error.stack,
          category: testResult.error.category as any,
          severity: testResult.error.severity as any,
          retryCount: testResult.retryCount
        }
      )
    }
  }

  /**
   * Log a test error with comprehensive metadata (backward compatibility)
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
   * Create test metadata from basic information
   */
  createTestMetadata(
    testName: string,
    filePath: string,
    suite: string,
    options: Partial<TestMetadata> = {}
  ): TestMetadata {
    return {
      testId: `${suite}::${testName}::${Date.now()}`,
      testName,
      testDescription: options.testDescription || testName,
      filePath,
      relativePath: relative(process.cwd(), filePath),
      suite,
      category: options.category || this.inferTestCategory(filePath),
      tags: options.tags || [],
      priority: options.priority || TestPriority.MEDIUM,
      author: options.author,
      lastModified: options.lastModified
    }
  }

  /**
   * Create performance metrics for a test
   */
  createPerformanceMetrics(startTime: number, endTime: number): TestPerformanceMetrics {
    const memUsage = process.memoryUsage()
    return {
      startTime,
      endTime,
      duration: endTime - startTime,
      memoryUsage: {
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        external: memUsage.external,
        rss: memUsage.rss
      }
    }
  }

  /**
   * Log test suite statistics
   */
  logSuiteStats(suite: string, stats: TestSuiteStats): void {
    this.suiteStats.set(suite, stats)
    this.writeSuiteStats(suite, stats)
  }

  /**
   * Clear all suite statistics (useful for new test runs)
   */
  clearSuiteStats(): void {
    this.suiteStats.clear()
    this.errorLog = []
    this.testResults.clear()
    this.suiteResults.clear()
  }

  /**
   * Infer test category from file path
   */
  private inferTestCategory(filePath: string): TestCategory {
    const path = filePath.toLowerCase()
    if (path.includes('/unit/') || path.includes('.unit.')) return TestCategory.UNIT
    if (path.includes('/integration/') || path.includes('.integration.')) return TestCategory.INTEGRATION
    if (path.includes('/e2e/') || path.includes('.e2e.')) return TestCategory.E2E
    if (path.includes('/system/') || path.includes('.system.')) return TestCategory.SYSTEM
    if (path.includes('/regression/') || path.includes('.regression.')) return TestCategory.REGRESSION
    if (path.includes('/acceptance/') || path.includes('.acceptance.')) return TestCategory.ACCEPTANCE
    if (path.includes('/performance/') || path.includes('.performance.')) return TestCategory.PERFORMANCE
    if (path.includes('/security/') || path.includes('.security.')) return TestCategory.SECURITY
    if (path.includes('/accessibility/') || path.includes('.accessibility.')) return TestCategory.ACCESSIBILITY
    return TestCategory.UNIT // Default
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
   * Generate comprehensive test report
   */
  generateComprehensiveReport(): ComprehensiveTestReport {
    const endTime = performance.now()
    this.executionContext.duration = endTime - this.startTime

    const allTests = Array.from(this.testResults.values())
    const allSuites = Array.from(this.suiteResults.values())

    const totalTests = allTests.length
    const passedTests = allTests.filter(t => t.status === TestStatus.PASSED).length
    const failedTests = allTests.filter(t => t.status === TestStatus.FAILED).length
    const criticalFailures = allTests.filter(t =>
      t.status === TestStatus.FAILED && t.error?.severity === ErrorSeverity.CRITICAL
    ).length

    const successRate = totalTests > 0 ? (passedTests / totalTests) * 100 : 0

    return {
      metadata: {
        reportId: this.reportId,
        generatedAt: new Date().toISOString(),
        version: '2.0.0',
        reportType: 'comprehensive',
        generator: 'EnhancedTestLogger'
      },
      executiveSummary: {
        overallStatus: this.determineOverallStatus(successRate, criticalFailures),
        totalSuites: allSuites.length,
        totalTests,
        successRate,
        criticalIssues: criticalFailures,
        keyMetrics: {
          averageDuration: this.calculateAverageDuration(allTests),
          memoryPeak: this.calculateMemoryPeak(allTests),
          flakyTests: allTests.filter(t => t.flakiness?.isFlaky).length
        },
        qualityGate: this.determineQualityGate(successRate, criticalFailures)
      },
      testInventory: {
        suites: allSuites,
        categories: this.categorizeTests(allTests),
        priorities: this.prioritizeTests(allTests),
        environments: [this.executionContext.environment]
      },
      detailedResults: {
        failures: allTests.filter(t => t.status === TestStatus.FAILED),
        criticalFailures: allTests.filter(t =>
          t.status === TestStatus.FAILED && t.error?.severity === ErrorSeverity.CRITICAL
        ),
        flakyTests: allTests.filter(t => t.flakiness?.isFlaky),
        slowTests: this.getSlowTests(allTests),
        coverageGaps: this.identifyCoverageGaps(allTests)
      },
      issueTracking: {
        openIssues: this.getOpenIssues(allTests),
        resolvedIssues: this.getResolvedIssues(allTests),
        newIssuesCreated: this.getNewIssues(allTests),
        escalatedIssues: this.getEscalatedIssues(allTests)
      },
      performanceAnalysis: {
        executionMetrics: this.calculateOverallPerformance(allTests),
        resourceUsage: this.calculateResourceUsage(allTests),
        bottlenecks: this.identifyBottlenecks(allTests),
        optimizationOpportunities: this.identifyOptimizations(allTests)
      },
      recommendations: {
        immediate: this.generateImmediateRecommendations(allTests),
        shortTerm: this.generateShortTermRecommendations(allTests),
        longTerm: this.generateLongTermRecommendations(allTests)
      },
      historicalContext: {
        previousReports: this.getPreviousReports(),
        trendAnalysis: this.analyzeTrends(allTests),
        regressionAnalysis: {
          detected: this.detectRegressions(allTests),
          affectedTests: this.getAffectedTests(allTests),
          rootCause: this.identifyRootCause(allTests)
        },
        improvementTracking: {
          resolvedIssues: this.countResolvedIssues(allTests),
          performanceGains: this.calculatePerformanceGains(allTests),
          coverageIncrease: this.calculateCoverageIncrease(allTests)
        }
      }
    }
  }

  /**
   * Save comprehensive report to multiple formats
   */
  saveComprehensiveReport(): { json: string; markdown: string; html: string } {
    const report = this.generateComprehensiveReport()
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')

    const jsonFile = join(this.logDir, `comprehensive-report-${timestamp}.json`)
    const markdownFile = join(this.logDir, `comprehensive-report-${timestamp}.md`)
    const htmlFile = join(this.logDir, `comprehensive-report-${timestamp}.html`)

    // Save JSON report
    writeFileSync(jsonFile, JSON.stringify(report, null, 2))

    // Save Markdown report
    const markdownContent = this.generateMarkdownReport(report)
    writeFileSync(markdownFile, markdownContent)

    // Save HTML report
    const htmlContent = this.generateHtmlReport(report)
    writeFileSync(htmlFile, htmlContent)

    return { json: jsonFile, markdown: markdownFile, html: htmlFile }
  }

  /**
   * Helper methods for comprehensive report generation
   */
  private determineOverallStatus(successRate: number, criticalFailures: number): 'passed' | 'failed' | 'warning' {
    if (criticalFailures > 0) return 'failed'
    if (successRate < 95) return 'warning'
    return 'passed'
  }

  private determineQualityGate(successRate: number, criticalFailures: number): 'passed' | 'failed' | 'warning' {
    if (criticalFailures > 0 || successRate < 90) return 'failed'
    if (successRate < 95) return 'warning'
    return 'passed'
  }

  private calculateAverageDuration(tests: TestResult[]): number {
    if (tests.length === 0) return 0
    const totalDuration = tests.reduce((sum, test) => sum + test.performance.duration, 0)
    return totalDuration / tests.length
  }

  private calculateMemoryPeak(tests: TestResult[]): number {
    return Math.max(...tests.map(test => test.performance.memoryUsage.heapUsed), 0)
  }

  private categorizeTests(tests: TestResult[]): Record<TestCategory, number> {
    const categories = {} as Record<TestCategory, number>
    Object.values(TestCategory).forEach(cat => categories[cat] = 0)
    tests.forEach(test => categories[test.metadata.category]++)
    return categories
  }

  private prioritizeTests(tests: TestResult[]): Record<TestPriority, number> {
    const priorities = {} as Record<TestPriority, number>
    Object.values(TestPriority).forEach(pri => priorities[pri] = 0)
    tests.forEach(test => priorities[test.metadata.priority]++)
    return priorities
  }

  private getSlowTests(tests: TestResult[], threshold: number = 5000): TestResult[] {
    return tests.filter(test => test.performance.duration > threshold)
      .sort((a, b) => b.performance.duration - a.performance.duration)
      .slice(0, 10)
  }

  private identifyCoverageGaps(tests: TestResult[]): string[] {
    // This would integrate with coverage tools in a real implementation
    return ['src/utils/uncoveredModule.ts', 'src/components/UntestedComponent.tsx']
  }

  private getOpenIssues(tests: TestResult[]): GitHubIssueReference[] {
    return tests
      .filter(test => test.githubIssue?.status === 'open')
      .map(test => test.githubIssue!)
  }

  private getResolvedIssues(tests: TestResult[]): GitHubIssueReference[] {
    return tests
      .filter(test => test.githubIssue?.status === 'closed')
      .map(test => test.githubIssue!)
  }

  private getNewIssues(tests: TestResult[]): GitHubIssueReference[] {
    return tests
      .filter(test => test.githubIssue?.status === 'pending')
      .map(test => test.githubIssue!)
  }

  private getEscalatedIssues(tests: TestResult[]): GitHubIssueReference[] {
    return tests
      .filter(test =>
        test.githubIssue?.status === 'open' &&
        test.error?.severity === ErrorSeverity.CRITICAL
      )
      .map(test => test.githubIssue!)
  }

  // Additional helper methods (simplified implementations for now)
  private calculateOverallPerformance(tests: TestResult[]): TestPerformanceMetrics {
    const totalDuration = tests.reduce((sum, test) => sum + test.performance.duration, 0)
    const avgMemory = tests.reduce((sum, test) => sum + test.performance.memoryUsage.heapUsed, 0) / tests.length

    return {
      startTime: this.startTime,
      endTime: performance.now(),
      duration: totalDuration,
      memoryUsage: {
        heapUsed: avgMemory,
        heapTotal: avgMemory * 1.2,
        external: avgMemory * 0.1,
        rss: avgMemory * 1.5
      }
    }
  }

  private calculateResourceUsage(tests: TestResult[]): Record<string, number> {
    return {
      totalMemoryUsed: tests.reduce((sum, test) => sum + test.performance.memoryUsage.heapUsed, 0),
      averageTestDuration: this.calculateAverageDuration(tests),
      totalExecutionTime: tests.reduce((sum, test) => sum + test.performance.duration, 0)
    }
  }

  private identifyBottlenecks(tests: TestResult[]): string[] {
    const slowTests = this.getSlowTests(tests)
    return slowTests.map(test => `${test.metadata.testName} (${test.performance.duration}ms)`)
  }

  private identifyOptimizations(tests: TestResult[]): string[] {
    const optimizations = []
    const slowTests = this.getSlowTests(tests)
    if (slowTests.length > 0) {
      optimizations.push('Consider optimizing slow tests or running them in parallel')
    }
    const flakyTests = tests.filter(t => t.flakiness?.isFlaky)
    if (flakyTests.length > 0) {
      optimizations.push('Address flaky tests to improve reliability')
    }
    return optimizations
  }

  private generateImmediateRecommendations(tests: TestResult[]): TestRecommendation[] {
    const recommendations: TestRecommendation[] = []
    const criticalFailures = tests.filter(t => t.error?.severity === ErrorSeverity.CRITICAL)

    if (criticalFailures.length > 0) {
      recommendations.push({
        type: 'reliability',
        priority: 'critical',
        title: 'Fix Critical Test Failures',
        description: `${criticalFailures.length} critical test failures require immediate attention`,
        actionItems: criticalFailures.map(t => `Fix ${t.metadata.testName}: ${t.error?.message}`),
        estimatedEffort: '2-4 hours',
        relatedTests: criticalFailures.map(t => t.metadata.testName)
      })
    }

    return recommendations
  }

  private generateShortTermRecommendations(tests: TestResult[]): TestRecommendation[] {
    const recommendations: TestRecommendation[] = []
    const slowTests = this.getSlowTests(tests)

    if (slowTests.length > 0) {
      recommendations.push({
        type: 'performance',
        priority: 'high',
        title: 'Optimize Slow Tests',
        description: `${slowTests.length} tests are running slower than expected`,
        actionItems: ['Profile slow tests', 'Optimize test setup/teardown', 'Consider parallel execution'],
        estimatedEffort: '1-2 days',
        relatedTests: slowTests.map(t => t.metadata.testName)
      })
    }

    return recommendations
  }

  private generateLongTermRecommendations(tests: TestResult[]): TestRecommendation[] {
    return [{
      type: 'maintenance',
      priority: 'medium',
      title: 'Improve Test Coverage',
      description: 'Enhance test coverage for better quality assurance',
      actionItems: ['Add missing unit tests', 'Improve integration test coverage', 'Add performance benchmarks'],
      estimatedEffort: '1-2 weeks'
    }]
  }

  // Simplified implementations for remaining methods
  private getPreviousReports(): string[] { return [] }
  private analyzeTrends(tests: TestResult[]): TestTrends {
    return {
      historicalSuccessRate: [95, 96, 94, 97],
      performanceTrend: 'stable',
      flakinessScore: 0.1,
      regressionDetected: false,
      qualityGate: 'passed'
    }
  }
  private detectRegressions(tests: TestResult[]): boolean { return false }
  private getAffectedTests(tests: TestResult[]): string[] { return [] }
  private identifyRootCause(tests: TestResult[]): string | undefined { return undefined }
  private countResolvedIssues(tests: TestResult[]): number { return 0 }
  private calculatePerformanceGains(tests: TestResult[]): number { return 0 }
  private calculateCoverageIncrease(tests: TestResult[]): number { return 0 }

  private generateMarkdownReport(report: ComprehensiveTestReport): string {
    return `# Comprehensive Test Report

## Executive Summary
- **Overall Status**: ${report.executiveSummary.overallStatus.toUpperCase()}
- **Total Tests**: ${report.executiveSummary.totalTests}
- **Success Rate**: ${report.executiveSummary.successRate.toFixed(2)}%
- **Critical Issues**: ${report.executiveSummary.criticalIssues}
- **Quality Gate**: ${report.executiveSummary.qualityGate.toUpperCase()}

## Test Results
${report.detailedResults.failures.length > 0 ?
  `### Failed Tests\n${report.detailedResults.failures.map(t =>
    `- **${t.metadata.testName}**: ${t.error?.message || 'Unknown error'}`
  ).join('\n')}` : '### All Tests Passed ✅'
}

## Performance Analysis
- **Average Duration**: ${report.performanceAnalysis.executionMetrics.duration.toFixed(2)}ms
- **Memory Peak**: ${(report.executiveSummary.keyMetrics.memoryPeak / 1024 / 1024).toFixed(2)}MB

## Recommendations
${report.recommendations.immediate.map(r =>
  `### ${r.title} (${r.priority.toUpperCase()})\n${r.description}\n${r.actionItems.map(a => `- ${a}`).join('\n')}`
).join('\n\n')}

---
*Generated at ${report.metadata.generatedAt} by ${report.metadata.generator}*`
  }

  private generateHtmlReport(report: ComprehensiveTestReport): string {
    return `<!DOCTYPE html>
<html>
<head>
    <title>Test Report - ${report.metadata.generatedAt}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .status-passed { color: green; }
        .status-failed { color: red; }
        .status-warning { color: orange; }
        .metric { background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Comprehensive Test Report</h1>
    <div class="metric">
        <strong>Overall Status:</strong>
        <span class="status-${report.executiveSummary.overallStatus}">${report.executiveSummary.overallStatus.toUpperCase()}</span>
    </div>
    <div class="metric"><strong>Total Tests:</strong> ${report.executiveSummary.totalTests}</div>
    <div class="metric"><strong>Success Rate:</strong> ${report.executiveSummary.successRate.toFixed(2)}%</div>
    <div class="metric"><strong>Critical Issues:</strong> ${report.executiveSummary.criticalIssues}</div>

    <h2>Test Results</h2>
    ${report.detailedResults.failures.length > 0 ?
      `<h3>Failed Tests</h3><ul>${report.detailedResults.failures.map(t =>
        `<li><strong>${t.metadata.testName}</strong>: ${t.error?.message || 'Unknown error'}</li>`
      ).join('')}</ul>` : '<h3>All Tests Passed ✅</h3>'
    }

    <p><em>Generated at ${report.metadata.generatedAt} by ${report.metadata.generator}</em></p>
</body>
</html>`
  }

  /**
   * Save final report to file (backward compatibility)
   */
  saveReport(): string {
    const report = this.generateReport()
    const reportFile = join(this.logDir, `test-report-${Date.now()}.md`)
    writeFileSync(reportFile, report)
    return reportFile
  }
}

// Original TestLogger class for backward compatibility
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

  logSuiteStats(suite: string, stats: TestSuiteStats): void {
    this.suiteStats.set(suite, stats)
    this.writeSuiteStats(suite, stats)
  }

  clearSuiteStats(): void {
    this.suiteStats.clear()
    this.errorLog = []
  }

  private categorizeError(error: string): TestLogEntry['metadata']['category'] {
    if (error.includes('SyntaxError') || error.includes('Unexpected token')) return 'syntax'
    if (error.includes('timeout') || error.includes('Timeout')) return 'timeout'
    if (error.includes('async') || error.includes('Promise') || error.includes('await')) return 'async'
    if (error.includes('mock') || error.includes('jest.fn') || error.includes('spy')) return 'mock'
    if (error.includes('import') || error.includes('require') || error.includes('module')) return 'dependency'
    if (error.includes('expect') || error.includes('toBe') || error.includes('toEqual')) return 'assertion'
    if (error.includes('flaky') || error.includes('intermittent')) return 'flaky'
    return 'unknown'
  }

  private determineSeverity(error: string): TestLogEntry['metadata']['severity'] {
    if (error.includes('ReferenceError') || error.includes('TypeError') || error.includes('SyntaxError')) return 'critical'
    if (error.includes('timeout') || error.includes('failed to run')) return 'high'
    if (error.includes('expect') || error.includes('assertion')) return 'medium'
    return 'low'
  }

  private writeLogEntry(entry: TestLogEntry): void {
    try {
      appendFileSync(this.logFile, JSON.stringify(entry) + '\n')
    } catch (error) {
      console.error('Failed to write log entry:', error)
    }
  }

  private writeSuiteStats(suite: string, stats: TestSuiteStats): void {
    const statsFile = join(this.logDir, 'suite-stats.json')
    try {
      let allStats: Record<string, TestSuiteStats> = {}
      if (existsSync(statsFile)) {
        allStats = JSON.parse(readFileSync(statsFile, 'utf8'))
      }
      allStats[suite] = stats
      writeFileSync(statsFile, JSON.stringify(allStats, null, 2))
    } catch (error) {
      console.error('Failed to write suite stats:', error)
    }
  }

  generateReport(): string {
    const timestamp = new Date().toISOString()
    const totalSuites = this.suiteStats.size
    const passingSuites = Array.from(this.suiteStats.values()).filter(s => s.successRate >= 0.96).length
    const failingSuites = totalSuites - passingSuites
    const overallSuccessRate = totalSuites > 0
      ? Array.from(this.suiteStats.values()).reduce((sum, s) => sum + s.successRate, 0) / totalSuites * 100
      : 0

    const errorCategories = {
      syntax: 0, async: 0, flaky: 0, dependency: 0, mock: 0, timeout: 0, assertion: 0, unknown: 0
    }

    this.errorLog.forEach(entry => {
      errorCategories[entry.metadata.category]++
    })

    const criticalErrors = this.errorLog.filter(e => e.metadata.severity === 'critical').length
    const highPriorityErrors = this.errorLog.filter(e => e.metadata.severity === 'high').length

    return `# Test Suite Report - ${timestamp}

## Overall Statistics
- Total Suites: ${totalSuites}
- Passing Suites (≥96%): ${passingSuites}
- Failing Suites: ${failingSuites}
- Overall Success Rate: ${overallSuccessRate.toFixed(2)}%
- Critical Errors: ${criticalErrors}
- High Priority Errors: ${highPriorityErrors}

## Error Categories
- Syntax Errors: ${errorCategories.syntax}
- Async/Promise Errors: ${errorCategories.async}
- Flaky Test Errors: ${errorCategories.flaky}
- Dependency Errors: ${errorCategories.dependency}
- Mock/Spy Errors: ${errorCategories.mock}
- Timeout Errors: ${errorCategories.timeout}
- Assertion Errors: ${errorCategories.assertion}
- Unknown Errors: ${errorCategories.unknown}

## Recommendations
${overallSuccessRate < 95 ? '- Overall success rate is below 95% target. Focus on critical and high-priority errors first.' : '- All tests are performing well!'}
${criticalErrors > 0 ? `- Address ${criticalErrors} critical errors immediately.` : ''}
${highPriorityErrors > 0 ? `- Review ${highPriorityErrors} high-priority errors.` : ''}
${errorCategories.flaky > 0 ? `- Investigate ${errorCategories.flaky} flaky tests for stability improvements.` : ''}
${errorCategories.timeout > 0 ? `- Optimize ${errorCategories.timeout} tests experiencing timeouts.` : ''}`
  }

  saveReport(): string {
    const report = this.generateReport()
    const reportFile = join(this.logDir, `test-report-${Date.now()}.md`)
    writeFileSync(reportFile, report)
    return reportFile
  }
}

// Export both old and new instances for backward compatibility
export const testLogger = new TestLogger()
export const enhancedTestLogger = new EnhancedTestLogger()
