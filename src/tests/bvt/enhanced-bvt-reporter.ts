/**
 * Enhanced Build Verification Test (BVT) Reporter
 * Professional-grade BVT reporting with comprehensive metadata and GitHub integration
 */

import fs from 'fs'
import path from 'path'
import { performance } from 'perf_hooks'
import * as os from 'os'
import { TestFailureIssueManager } from '../../lib/github/TestFailureIssueManager'
import { 
  TestResult, 
  TestMetadata, 
  TestPerformanceMetrics, 
  TestStatus, 
  TestCategory, 
  TestPriority,
  ErrorSeverity,
  ErrorType,
  ComprehensiveTestReport,
  TestExecutionContext
} from '../../types/TestReporting'

export interface EnhancedBVTTestResult extends TestResult {
  bvtCategory: 'critical' | 'high' | 'medium' | 'low'
  testDescription: string
  reproductionSteps?: string[]
  expectedBehavior?: string
  actualBehavior?: string
  debugInfo?: Record<string, any>
}

export interface EnhancedBVTSuiteResult {
  metadata: {
    reportId: string
    generatedAt: string
    version: string
    environment: string
    nodeVersion: string
    platform: string
    workingDirectory: string
  }
  summary: {
    totalTests: number
    passed: number
    failed: number
    timeouts: number
    skipped: number
    criticalPassed: number
    criticalFailed: number
    successRate: number
    overallStatus: 'passed' | 'failed' | 'warning'
    qualityGate: 'passed' | 'failed' | 'warning'
  }
  performance: {
    totalDuration: number
    averageDuration: number
    slowestTest?: EnhancedBVTTestResult
    fastestTest?: EnhancedBVTTestResult
    memoryPeak: number
    resourceUsage: Record<string, number>
  }
  results: EnhancedBVTTestResult[]
  issueTracking: {
    newIssuesCreated: number
    existingIssuesUpdated: number
    escalatedIssues: number
    openIssues: number
    resolvedIssues: number
  }
  recommendations: {
    immediate: string[]
    shortTerm: string[]
    longTerm: string[]
  }
  trends: {
    historicalSuccessRate: number[]
    performanceTrend: 'improving' | 'degrading' | 'stable'
    regressionDetected: boolean
  }
}

export class EnhancedBVTReporter {
  private logLevel: 'debug' | 'info' | 'warn' | 'error'
  private outputDir: string
  private githubIssueManager?: TestFailureIssueManager
  private reportId: string
  private startTime: number
  private executionContext: TestExecutionContext

  constructor(
    logLevel: 'debug' | 'info' | 'warn' | 'error' = 'info',
    githubConfig?: { token: string; owner: string; repo: string }
  ) {
    this.logLevel = logLevel
    this.outputDir = path.join(process.cwd(), 'test-results', 'bvt')
    this.reportId = `bvt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    this.startTime = performance.now()
    this.ensureOutputDirectory()
    
    if (githubConfig) {
      this.githubIssueManager = new TestFailureIssueManager(githubConfig, {
        labelPrefix: 'bvt-failure',
        defaultAssignees: ['mytech-today-now']
      })
    }

    this.executionContext = this.createExecutionContext()
  }

  private createExecutionContext(): TestExecutionContext {
    return {
      environment: process.env.NODE_ENV || 'test',
      nodeVersion: process.version,
      platform: `${os.platform()} ${os.arch()}`,
      timestamp: new Date().toISOString(),
      duration: 0,
      workingDirectory: process.cwd(),
      configuration: {
        bvtMode: process.env.BVT_MODE || 'full',
        timeout: process.env.BVT_TIMEOUT || 30000,
        retries: process.env.BVT_RETRIES || 2
      },
      dependencies: this.getKeyDependencies()
    }
  }

  private getKeyDependencies(): Record<string, string> {
    try {
      const packageJson = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8'))
      return {
        node: process.version,
        npm: packageJson.engines?.npm || 'unknown',
        jest: packageJson.devDependencies?.jest || 'unknown'
      }
    } catch {
      return { node: process.version }
    }
  }

  private ensureOutputDirectory(): void {
    if (!fs.existsSync(this.outputDir)) {
      fs.mkdirSync(this.outputDir, { recursive: true })
    }
  }

  /**
   * Enhanced logging methods with structured output
   */
  logDebug(message: string, data?: any): void {
    if (this.shouldLog('debug')) {
      const logEntry = {
        timestamp: new Date().toISOString(),
        level: 'DEBUG',
        message,
        data,
        reportId: this.reportId
      }
      console.log(`[BVT DEBUG] ${JSON.stringify(logEntry)}`)
    }
  }

  logInfo(message: string, data?: any): void {
    if (this.shouldLog('info')) {
      const logEntry = {
        timestamp: new Date().toISOString(),
        level: 'INFO',
        message,
        data,
        reportId: this.reportId
      }
      console.log(`[BVT INFO] ${JSON.stringify(logEntry)}`)
    }
  }

  logWarning(message: string, data?: any): void {
    if (this.shouldLog('warn')) {
      const logEntry = {
        timestamp: new Date().toISOString(),
        level: 'WARNING',
        message,
        data,
        reportId: this.reportId
      }
      console.warn(`[BVT WARNING] ${JSON.stringify(logEntry)}`)
    }
  }

  logError(message: string, error?: any): void {
    if (this.shouldLog('error')) {
      const logEntry = {
        timestamp: new Date().toISOString(),
        level: 'ERROR',
        message,
        error: error?.message || error,
        stack: error?.stack,
        reportId: this.reportId
      }
      console.error(`[BVT ERROR] ${JSON.stringify(logEntry)}`)
    }
  }

  private shouldLog(level: string): boolean {
    const levels = ['debug', 'info', 'warn', 'error']
    const currentLevelIndex = levels.indexOf(this.logLevel)
    const messageLevelIndex = levels.indexOf(level)
    return messageLevelIndex >= currentLevelIndex
  }

  /**
   * Generate comprehensive BVT report with enhanced metadata
   */
  async generateEnhancedReport(results: EnhancedBVTTestResult[]): Promise<EnhancedBVTSuiteResult> {
    const endTime = performance.now()
    this.executionContext.duration = endTime - this.startTime

    const totalTests = results.length
    const passed = results.filter(r => r.status === TestStatus.PASSED).length
    const failed = results.filter(r => r.status === TestStatus.FAILED).length
    const timeouts = results.filter(r => r.status === TestStatus.TIMEOUT).length
    const skipped = results.filter(r => r.status === TestStatus.SKIPPED).length
    
    const criticalTests = results.filter(r => r.bvtCategory === 'critical')
    const criticalPassed = criticalTests.filter(r => r.status === TestStatus.PASSED).length
    const criticalFailed = criticalTests.filter(r => r.status === TestStatus.FAILED).length
    
    const successRate = totalTests > 0 ? (passed / totalTests) * 100 : 0

    // Process GitHub issues for failed tests
    const issueTracking = await this.processGitHubIssues(results.filter(r => r.status === TestStatus.FAILED))

    const report: EnhancedBVTSuiteResult = {
      metadata: {
        reportId: this.reportId,
        generatedAt: new Date().toISOString(),
        version: '2.0.0',
        environment: this.executionContext.environment,
        nodeVersion: this.executionContext.nodeVersion,
        platform: this.executionContext.platform,
        workingDirectory: this.executionContext.workingDirectory
      },
      summary: {
        totalTests,
        passed,
        failed,
        timeouts,
        skipped,
        criticalPassed,
        criticalFailed,
        successRate,
        overallStatus: this.determineOverallStatus(successRate, criticalFailed),
        qualityGate: this.determineQualityGate(successRate, criticalFailed)
      },
      performance: {
        totalDuration: this.executionContext.duration,
        averageDuration: this.calculateAverageDuration(results),
        slowestTest: this.getSlowestTest(results),
        fastestTest: this.getFastestTest(results),
        memoryPeak: this.calculateMemoryPeak(results),
        resourceUsage: this.calculateResourceUsage(results)
      },
      results,
      issueTracking,
      recommendations: {
        immediate: this.generateImmediateRecommendations(results),
        shortTerm: this.generateShortTermRecommendations(results),
        longTerm: this.generateLongTermRecommendations(results)
      },
      trends: {
        historicalSuccessRate: this.getHistoricalSuccessRates(),
        performanceTrend: this.analyzePerformanceTrend(results),
        regressionDetected: this.detectRegressions(results)
      }
    }

    return report
  }

  /**
   * Process GitHub issues for failed tests
   */
  private async processGitHubIssues(failedTests: EnhancedBVTTestResult[]): Promise<EnhancedBVTSuiteResult['issueTracking']> {
    let newIssuesCreated = 0
    let existingIssuesUpdated = 0
    let escalatedIssues = 0

    if (this.githubIssueManager) {
      for (const test of failedTests) {
        try {
          const issueRef = await this.githubIssueManager.processTestFailure(test)
          if (issueRef) {
            test.githubIssue = issueRef
            if (issueRef.status === 'pending') {
              newIssuesCreated++
            } else if (issueRef.status === 'open') {
              existingIssuesUpdated++
              if (test.retryCount >= 3) {
                escalatedIssues++
              }
            }
          }
        } catch (error) {
          this.logError(`Failed to process GitHub issue for test ${test.metadata.testName}`, error)
        }
      }
    }

    return {
      newIssuesCreated,
      existingIssuesUpdated,
      escalatedIssues,
      openIssues: failedTests.filter(t => t.githubIssue?.status === 'open').length,
      resolvedIssues: failedTests.filter(t => t.githubIssue?.status === 'closed').length
    }
  }

  /**
   * Save comprehensive report in multiple formats
   */
  async saveEnhancedReport(report: EnhancedBVTSuiteResult): Promise<{ json: string; markdown: string; html: string }> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    
    const jsonFile = path.join(this.outputDir, `enhanced-bvt-report-${timestamp}.json`)
    const markdownFile = path.join(this.outputDir, `enhanced-bvt-report-${timestamp}.md`)
    const htmlFile = path.join(this.outputDir, `enhanced-bvt-report-${timestamp}.html`)
    
    // Save JSON report
    fs.writeFileSync(jsonFile, JSON.stringify(report, null, 2))
    this.logInfo(`Enhanced JSON report saved to: ${jsonFile}`)
    
    // Save Markdown report
    const markdownContent = this.generateMarkdownReport(report)
    fs.writeFileSync(markdownFile, markdownContent)
    this.logInfo(`Enhanced Markdown report saved to: ${markdownFile}`)
    
    // Save HTML report
    const htmlContent = this.generateHtmlReport(report)
    fs.writeFileSync(htmlFile, htmlContent)
    this.logInfo(`Enhanced HTML report saved to: ${htmlFile}`)
    
    return { json: jsonFile, markdown: markdownFile, html: htmlFile }
  }

  // Helper methods (simplified implementations)
  private determineOverallStatus(successRate: number, criticalFailed: number): 'passed' | 'failed' | 'warning' {
    if (criticalFailed > 0) return 'failed'
    if (successRate < 95) return 'warning'
    return 'passed'
  }

  private determineQualityGate(successRate: number, criticalFailed: number): 'passed' | 'failed' | 'warning' {
    if (criticalFailed > 0 || successRate < 90) return 'failed'
    if (successRate < 95) return 'warning'
    return 'passed'
  }

  private calculateAverageDuration(results: EnhancedBVTTestResult[]): number {
    if (results.length === 0) return 0
    const totalDuration = results.reduce((sum, test) => sum + test.performance.duration, 0)
    return totalDuration / results.length
  }

  private getSlowestTest(results: EnhancedBVTTestResult[]): EnhancedBVTTestResult | undefined {
    return results.reduce((slowest, current) => 
      !slowest || current.performance.duration > slowest.performance.duration ? current : slowest
    , undefined as EnhancedBVTTestResult | undefined)
  }

  private getFastestTest(results: EnhancedBVTTestResult[]): EnhancedBVTTestResult | undefined {
    return results.reduce((fastest, current) => 
      !fastest || current.performance.duration < fastest.performance.duration ? current : fastest
    , undefined as EnhancedBVTTestResult | undefined)
  }

  private calculateMemoryPeak(results: EnhancedBVTTestResult[]): number {
    return Math.max(...results.map(test => test.performance.memoryUsage.heapUsed), 0)
  }

  private calculateResourceUsage(results: EnhancedBVTTestResult[]): Record<string, number> {
    return {
      totalMemoryUsed: results.reduce((sum, test) => sum + test.performance.memoryUsage.heapUsed, 0),
      averageTestDuration: this.calculateAverageDuration(results),
      totalExecutionTime: results.reduce((sum, test) => sum + test.performance.duration, 0)
    }
  }

  private generateImmediateRecommendations(results: EnhancedBVTTestResult[]): string[] {
    const recommendations = []
    const criticalFailures = results.filter(r => r.status === TestStatus.FAILED && r.bvtCategory === 'critical')
    
    if (criticalFailures.length > 0) {
      recommendations.push(`Fix ${criticalFailures.length} critical BVT failures immediately`)
    }
    
    const timeouts = results.filter(r => r.status === TestStatus.TIMEOUT)
    if (timeouts.length > 0) {
      recommendations.push(`Investigate ${timeouts.length} test timeouts`)
    }
    
    return recommendations
  }

  private generateShortTermRecommendations(results: EnhancedBVTTestResult[]): string[] {
    const recommendations = []
    const slowTests = results.filter(r => r.performance.duration > 10000) // > 10 seconds
    
    if (slowTests.length > 0) {
      recommendations.push(`Optimize ${slowTests.length} slow BVT tests`)
    }
    
    return recommendations
  }

  private generateLongTermRecommendations(results: EnhancedBVTTestResult[]): string[] {
    return [
      'Implement automated BVT performance monitoring',
      'Add more comprehensive BVT coverage for critical paths',
      'Establish BVT performance baselines and alerts'
    ]
  }

  private getHistoricalSuccessRates(): number[] {
    // In a real implementation, this would read from historical data
    return [95, 96, 94, 97, 98]
  }

  private analyzePerformanceTrend(results: EnhancedBVTTestResult[]): 'improving' | 'degrading' | 'stable' {
    // Simplified implementation
    return 'stable'
  }

  private detectRegressions(results: EnhancedBVTTestResult[]): boolean {
    // Simplified implementation
    return results.some(r => r.status === TestStatus.FAILED && r.bvtCategory === 'critical')
  }

  private generateMarkdownReport(report: EnhancedBVTSuiteResult): string {
    return `# Enhanced BVT Report - ${report.metadata.generatedAt}

## Executive Summary
- **Overall Status**: ${report.summary.overallStatus.toUpperCase()}
- **Quality Gate**: ${report.summary.qualityGate.toUpperCase()}
- **Success Rate**: ${report.summary.successRate.toFixed(2)}%
- **Total Tests**: ${report.summary.totalTests}
- **Critical Failures**: ${report.summary.criticalFailed}

## Performance Metrics
- **Total Duration**: ${(report.performance.totalDuration / 1000).toFixed(2)}s
- **Average Duration**: ${report.performance.averageDuration.toFixed(2)}ms
- **Memory Peak**: ${(report.performance.memoryPeak / 1024 / 1024).toFixed(2)}MB

## Test Results
${report.results.filter(r => r.status === TestStatus.FAILED).length > 0 ? 
  `### Failed Tests\n${report.results.filter(r => r.status === TestStatus.FAILED).map(t => 
    `- **${t.metadata.testName}** (${t.bvtCategory}): ${t.error?.message || 'Unknown error'}`
  ).join('\n')}` : '### All Tests Passed ✅'
}

## GitHub Issue Tracking
- **New Issues Created**: ${report.issueTracking.newIssuesCreated}
- **Existing Issues Updated**: ${report.issueTracking.existingIssuesUpdated}
- **Escalated Issues**: ${report.issueTracking.escalatedIssues}

## Immediate Recommendations
${report.recommendations.immediate.map(r => `- ${r}`).join('\n')}

---
*Generated by Enhanced BVT Reporter v${report.metadata.version} at ${report.metadata.generatedAt}*`
  }

  private generateHtmlReport(report: EnhancedBVTSuiteResult): string {
    return `<!DOCTYPE html>
<html>
<head>
    <title>Enhanced BVT Report - ${report.metadata.generatedAt}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .status-passed { color: green; font-weight: bold; }
        .status-failed { color: red; font-weight: bold; }
        .status-warning { color: orange; font-weight: bold; }
        .metric { background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 5px; }
        .critical { background: #ffebee; border-left: 4px solid #f44336; }
        .test-result { margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Enhanced BVT Report</h1>
    <div class="metric">
        <strong>Overall Status:</strong> 
        <span class="status-${report.summary.overallStatus}">${report.summary.overallStatus.toUpperCase()}</span>
    </div>
    <div class="metric"><strong>Success Rate:</strong> ${report.summary.successRate.toFixed(2)}%</div>
    <div class="metric"><strong>Total Tests:</strong> ${report.summary.totalTests}</div>
    <div class="metric"><strong>Critical Failures:</strong> ${report.summary.criticalFailed}</div>
    
    <h2>Performance Metrics</h2>
    <div class="metric"><strong>Total Duration:</strong> ${(report.performance.totalDuration / 1000).toFixed(2)}s</div>
    <div class="metric"><strong>Memory Peak:</strong> ${(report.performance.memoryPeak / 1024 / 1024).toFixed(2)}MB</div>
    
    <h2>Test Results</h2>
    ${report.results.filter(r => r.status === TestStatus.FAILED).map(test => 
      `<div class="test-result ${test.bvtCategory === 'critical' ? 'critical' : ''}">
        <strong>${test.metadata.testName}</strong> (${test.bvtCategory})<br>
        <em>Error:</em> ${test.error?.message || 'Unknown error'}<br>
        <em>Duration:</em> ${test.performance.duration}ms
      </div>`
    ).join('')}
    
    <p><em>Generated at ${report.metadata.generatedAt} by Enhanced BVT Reporter v${report.metadata.version}</em></p>
</body>
</html>`
  }
}
