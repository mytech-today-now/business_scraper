/**
 * Build Verification Test (BVT) Reporter
 * Handles logging, reporting, and result formatting
 */

import fs from 'fs'
import path from 'path'
import { BVTSuiteResult, BVTResult } from './bvt-runner'

export class BVTReporter {
  private logLevel: 'debug' | 'info' | 'warn' | 'error'
  private outputDir: string

  constructor(logLevel: 'debug' | 'info' | 'warn' | 'error' = 'info') {
    this.logLevel = logLevel
    this.outputDir = path.join(process.cwd(), 'test-results', 'bvt')
    this.ensureOutputDirectory()
  }

  /**
   * Ensure output directory exists
   */
  private ensureOutputDirectory(): void {
    if (!fs.existsSync(this.outputDir)) {
      fs.mkdirSync(this.outputDir, { recursive: true })
    }
  }

  /**
   * Log debug message
   */
  logDebug(message: string, data?: any): void {
    if (this.shouldLog('debug')) {
      console.log(`[BVT DEBUG] ${message}`, data || '')
    }
  }

  /**
   * Log info message
   */
  logInfo(message: string, data?: any): void {
    if (this.shouldLog('info')) {
      console.log(`[BVT INFO] ${message}`, data || '')
    }
  }

  /**
   * Log warning message
   */
  logWarning(message: string, data?: any): void {
    if (this.shouldLog('warn')) {
      console.warn(`[BVT WARN] ${message}`, data || '')
    }
  }

  /**
   * Log error message
   */
  logError(message: string, error?: any): void {
    if (this.shouldLog('error')) {
      console.error(`[BVT ERROR] ${message}`, error || '')
    }
  }

  /**
   * Log success message
   */
  logSuccess(message: string): void {
    if (this.shouldLog('info')) {
      console.log(`[BVT SUCCESS] ${message}`)
    }
  }

  /**
   * Check if should log at given level
   */
  private shouldLog(level: string): boolean {
    const levels = ['debug', 'info', 'warn', 'error']
    const currentLevelIndex = levels.indexOf(this.logLevel)
    const messageLevelIndex = levels.indexOf(level)
    return messageLevelIndex >= currentLevelIndex
  }

  /**
   * Generate comprehensive BVT report
   */
  generateReport(result: BVTSuiteResult): void {
    this.generateConsoleReport(result)
    this.generateJSONReport(result)
    this.generateMarkdownReport(result)
    this.generateJUnitReport(result)
  }

  /**
   * Generate console report
   */
  private generateConsoleReport(result: BVTSuiteResult): void {
    console.log('\n' + '='.repeat(80))
    console.log('BUILD VERIFICATION TEST (BVT) SUITE RESULTS')
    console.log('='.repeat(80))
    
    console.log(`\nExecution Summary:`)
    console.log(`  Start Time: ${result.startTime.toISOString()}`)
    console.log(`  End Time: ${result.endTime.toISOString()}`)
    console.log(`  Total Duration: ${(result.totalDuration / 1000).toFixed(2)}s`)
    console.log(`  Performance Target: ${result.summary.performanceWithinLimits ? '✓ PASS' : '✗ FAIL'} (< 10 minutes)`)
    
    console.log(`\nTest Results:`)
    console.log(`  Total Tests: ${result.totalTests}`)
    console.log(`  Passed: ${result.passed} (${((result.passed / result.totalTests) * 100).toFixed(1)}%)`)
    console.log(`  Failed: ${result.failed}`)
    console.log(`  Timeouts: ${result.timeouts}`)
    console.log(`  Skipped: ${result.skipped}`)
    
    console.log(`\nCritical Tests:`)
    console.log(`  Passed: ${result.summary.criticalPassed}`)
    console.log(`  Failed: ${result.summary.criticalFailed}`)
    
    console.log(`\nOverall Result: ${result.summary.overallSuccess ? '✓ PASS' : '✗ FAIL'}`)
    
    if (result.failed > 0 || result.timeouts > 0) {
      console.log(`\nFailed/Timeout Tests:`)
      result.results
        .filter(r => r.status === 'failed' || r.status === 'timeout')
        .forEach(r => {
          console.log(`  ✗ ${r.category}/${r.testName}: ${r.error || 'Unknown error'}`)
        })
    }
    
    console.log('\n' + '='.repeat(80))
  }

  /**
   * Generate JSON report
   */
  private generateJSONReport(result: BVTSuiteResult): void {
    const reportPath = path.join(this.outputDir, `bvt-report-${Date.now()}.json`)
    const jsonReport = {
      ...result,
      metadata: {
        generatedAt: new Date().toISOString(),
        version: '1.0.0',
        reportType: 'BVT'
      }
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(jsonReport, null, 2))
    this.logInfo(`JSON report saved to: ${reportPath}`)
  }

  /**
   * Generate Markdown report
   */
  private generateMarkdownReport(result: BVTSuiteResult): void {
    const reportPath = path.join(this.outputDir, `bvt-report-${Date.now()}.md`)
    
    let markdown = `# Build Verification Test (BVT) Report\n\n`
    markdown += `**Generated:** ${new Date().toISOString()}\n\n`
    
    markdown += `## Executive Summary\n\n`
    markdown += `| Metric | Value |\n`
    markdown += `|--------|-------|\n`
    markdown += `| Overall Result | ${result.summary.overallSuccess ? '✅ PASS' : '❌ FAIL'} |\n`
    markdown += `| Total Duration | ${(result.totalDuration / 1000).toFixed(2)}s |\n`
    markdown += `| Performance Target | ${result.summary.performanceWithinLimits ? '✅ PASS' : '❌ FAIL'} (< 10 minutes) |\n`
    markdown += `| Tests Passed | ${result.passed}/${result.totalTests} (${((result.passed / result.totalTests) * 100).toFixed(1)}%) |\n`
    markdown += `| Critical Tests | ${result.summary.criticalPassed} passed, ${result.summary.criticalFailed} failed |\n\n`
    
    markdown += `## Test Categories\n\n`
    const categories = [...new Set(result.results.map(r => r.category))]
    categories.forEach(category => {
      const categoryResults = result.results.filter(r => r.category === category)
      const passed = categoryResults.filter(r => r.status === 'passed').length
      const total = categoryResults.length
      
      markdown += `### ${category.charAt(0).toUpperCase() + category.slice(1)}\n\n`
      markdown += `**Status:** ${passed === total ? '✅ PASS' : '❌ FAIL'} (${passed}/${total})\n\n`
      
      categoryResults.forEach(test => {
        const status = test.status === 'passed' ? '✅' : 
                     test.status === 'failed' ? '❌' : 
                     test.status === 'timeout' ? '⏰' : '⏭️'
        markdown += `- ${status} **${test.testName}** (${test.duration}ms)\n`
        if (test.error) {
          markdown += `  - Error: ${test.error}\n`
        }
      })
      markdown += `\n`
    })
    
    if (result.failed > 0 || result.timeouts > 0) {
      markdown += `## Failed Tests\n\n`
      result.results
        .filter(r => r.status === 'failed' || r.status === 'timeout')
        .forEach(r => {
          markdown += `### ${r.category}/${r.testName}\n\n`
          markdown += `- **Status:** ${r.status}\n`
          markdown += `- **Duration:** ${r.duration}ms\n`
          markdown += `- **Error:** ${r.error || 'Unknown error'}\n\n`
        })
    }
    
    fs.writeFileSync(reportPath, markdown)
    this.logInfo(`Markdown report saved to: ${reportPath}`)
  }

  /**
   * Generate JUnit XML report for CI/CD integration
   */
  private generateJUnitReport(result: BVTSuiteResult): void {
    const reportPath = path.join(this.outputDir, `bvt-junit-${Date.now()}.xml`)
    
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`
    xml += `<testsuites name="BVT Suite" tests="${result.totalTests}" failures="${result.failed}" errors="${result.timeouts}" time="${(result.totalDuration / 1000).toFixed(3)}">\n`
    
    const categories = [...new Set(result.results.map(r => r.category))]
    categories.forEach(category => {
      const categoryResults = result.results.filter(r => r.category === category)
      const failures = categoryResults.filter(r => r.status === 'failed').length
      const errors = categoryResults.filter(r => r.status === 'timeout').length
      const time = categoryResults.reduce((sum, r) => sum + r.duration, 0) / 1000
      
      xml += `  <testsuite name="${category}" tests="${categoryResults.length}" failures="${failures}" errors="${errors}" time="${time.toFixed(3)}">\n`
      
      categoryResults.forEach(test => {
        xml += `    <testcase name="${test.testName}" classname="${category}" time="${(test.duration / 1000).toFixed(3)}">\n`
        
        if (test.status === 'failed') {
          xml += `      <failure message="${test.error || 'Test failed'}">${test.error || 'Test failed'}</failure>\n`
        } else if (test.status === 'timeout') {
          xml += `      <error message="Test timeout">${test.error || 'Test timeout'}</error>\n`
        } else if (test.status === 'skipped') {
          xml += `      <skipped/>\n`
        }
        
        xml += `    </testcase>\n`
      })
      
      xml += `  </testsuite>\n`
    })
    
    xml += `</testsuites>\n`
    
    fs.writeFileSync(reportPath, xml)
    this.logInfo(`JUnit report saved to: ${reportPath}`)
  }

  /**
   * Generate CI/CD summary for GitHub Actions
   */
  generateCISummary(result: BVTSuiteResult): void {
    if (process.env.GITHUB_STEP_SUMMARY) {
      const summary = this.generateGitHubSummary(result)
      fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary)
    }
  }

  /**
   * Generate GitHub Actions summary
   */
  private generateGitHubSummary(result: BVTSuiteResult): string {
    let summary = `## 🧪 Build Verification Test Results\n\n`
    
    const status = result.summary.overallSuccess ? '✅ PASSED' : '❌ FAILED'
    summary += `**Overall Status:** ${status}\n\n`
    
    summary += `| Metric | Value |\n`
    summary += `|--------|-------|\n`
    summary += `| Duration | ${(result.totalDuration / 1000).toFixed(2)}s |\n`
    summary += `| Tests Passed | ${result.passed}/${result.totalTests} |\n`
    summary += `| Success Rate | ${((result.passed / result.totalTests) * 100).toFixed(1)}% |\n`
    summary += `| Critical Tests | ${result.summary.criticalPassed} passed, ${result.summary.criticalFailed} failed |\n\n`
    
    if (!result.summary.overallSuccess) {
      summary += `### ❌ Failed Tests\n\n`
      result.results
        .filter(r => r.status === 'failed' || r.status === 'timeout')
        .forEach(r => {
          summary += `- **${r.category}/${r.testName}**: ${r.error || 'Unknown error'}\n`
        })
    }
    
    return summary
  }
}
