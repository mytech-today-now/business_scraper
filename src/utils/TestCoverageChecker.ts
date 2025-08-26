/**
 * TestCoverageChecker Utility
 * Ensures minimum coverage thresholds are maintained across all test categories
 */

import { execSync } from 'child_process'
import { readFileSync, writeFileSync, existsSync } from 'fs'
import { join } from 'path'
import { testLogger } from './TestLogger'

export interface CoverageThresholds {
  statements: number
  branches: number
  functions: number
  lines: number
}

export interface CoverageReport {
  total: CoverageThresholds
  files: Record<string, CoverageThresholds>
  uncoveredLines: Record<string, number[]>
  summary: {
    totalFiles: number
    coveredFiles: number
    overallCoverage: number
    meetingThreshold: boolean
  }
}

export interface TestCategoryConfig {
  name: string
  pattern: string
  requiredCoverage: number
  timeout: number
  retries: number
}

export class TestCoverageChecker {
  private projectRoot: string
  private coverageDir: string
  private thresholds: CoverageThresholds
  private testCategories: TestCategoryConfig[]

  constructor(
    projectRoot: string = process.cwd(),
    thresholds: Partial<CoverageThresholds> = {}
  ) {
    this.projectRoot = projectRoot
    this.coverageDir = join(projectRoot, 'coverage')
    this.thresholds = {
      statements: 85,
      branches: 80,
      functions: 85,
      lines: 85,
      ...thresholds
    }

    // Define the 12 test categories as per requirements
    this.testCategories = [
      {
        name: 'unit',
        pattern: 'src/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 90,
        timeout: 30000,
        retries: 1
      },
      {
        name: 'integration',
        pattern: 'src/tests/integration/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 85,
        timeout: 60000,
        retries: 2
      },
      {
        name: 'e2e',
        pattern: 'src/tests/e2e/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 75,
        timeout: 120000,
        retries: 3
      },
      {
        name: 'system',
        pattern: 'src/tests/system/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 80,
        timeout: 180000,
        retries: 2
      },
      {
        name: 'regression',
        pattern: 'src/tests/regression/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 85,
        timeout: 90000,
        retries: 2
      },
      {
        name: 'acceptance',
        pattern: 'src/tests/acceptance/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 80,
        timeout: 120000,
        retries: 2
      },
      {
        name: 'performance',
        pattern: 'src/tests/performance/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 70,
        timeout: 300000,
        retries: 3
      },
      {
        name: 'load',
        pattern: 'src/tests/load/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 70,
        timeout: 300000,
        retries: 3
      },
      {
        name: 'security',
        pattern: 'src/**/*security*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 95,
        timeout: 60000,
        retries: 1
      },
      {
        name: 'compatibility',
        pattern: 'src/tests/compatibility/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 75,
        timeout: 90000,
        retries: 2
      },
      {
        name: 'accessibility',
        pattern: 'src/tests/accessibility/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 85,
        timeout: 60000,
        retries: 2
      },
      {
        name: 'exploratory',
        pattern: 'src/tests/exploratory/**/*.{test,spec}.{js,ts,tsx}',
        requiredCoverage: 60,
        timeout: 120000,
        retries: 3
      }
    ]
  }

  /**
   * Run coverage analysis for all test categories
   */
  async checkAllCoverage(): Promise<{
    overall: CoverageReport
    categories: Record<string, CoverageReport>
    recommendations: string[]
  }> {
    const results: Record<string, CoverageReport> = {}
    const recommendations: string[] = []

    // Run overall coverage
    const overallCoverage = await this.runCoverageForPattern('src/**/*.{test,spec}.{js,ts,tsx}')
    
    // Run coverage for each category
    for (const category of this.testCategories) {
      try {
        const categoryResult = await this.runCoverageForPattern(category.pattern, category.name)
        results[category.name] = categoryResult

        // Check if category meets requirements
        if (categoryResult.summary.overallCoverage < category.requiredCoverage) {
          recommendations.push(
            `${category.name} tests: Coverage ${categoryResult.summary.overallCoverage.toFixed(1)}% ` +
            `is below required ${category.requiredCoverage}%`
          )
        }
      } catch (error) {
        testLogger.logError(
          'coverage-checker',
          `${category.name}-coverage`,
          error as Error,
          {
            category: 'dependency',
            severity: 'high',
            file: 'TestCoverageChecker.ts'
          }
        )
        
        recommendations.push(`${category.name} tests: Failed to run coverage analysis`)
      }
    }

    // Generate overall recommendations
    if (overallCoverage.summary.overallCoverage < 95) {
      recommendations.push(
        `Overall coverage ${overallCoverage.summary.overallCoverage.toFixed(1)}% is below 95% target`
      )
    }

    return {
      overall: overallCoverage,
      categories: results,
      recommendations
    }
  }

  /**
   * Run Jest coverage for a specific pattern
   */
  private async runCoverageForPattern(pattern: string, categoryName?: string): Promise<CoverageReport> {
    try {
      const command = `npx jest --coverage --testPathPattern="${pattern}" --coverageReporters=json-summary --coverageReporters=json --silent`
      
      execSync(command, {
        cwd: this.projectRoot,
        stdio: 'pipe'
      })

      return this.parseCoverageReport(categoryName)
    } catch (error) {
      // If coverage fails, return empty report
      return this.createEmptyReport()
    }
  }

  /**
   * Parse Jest coverage report
   */
  private parseCoverageReport(categoryName?: string): CoverageReport {
    const summaryPath = join(this.coverageDir, 'coverage-summary.json')
    const detailPath = join(this.coverageDir, 'coverage-final.json')

    if (!existsSync(summaryPath)) {
      return this.createEmptyReport()
    }

    try {
      const summary = JSON.parse(readFileSync(summaryPath, 'utf8'))
      const details = existsSync(detailPath) 
        ? JSON.parse(readFileSync(detailPath, 'utf8'))
        : {}

      const total = summary.total || {}
      const files: Record<string, CoverageThresholds> = {}
      const uncoveredLines: Record<string, number[]> = {}

      // Process file-level coverage
      Object.keys(details).forEach(filePath => {
        const fileData = details[filePath]
        if (fileData.s && fileData.b && fileData.f) {
          files[filePath] = {
            statements: this.calculateCoverage(fileData.s),
            branches: this.calculateCoverage(fileData.b),
            functions: this.calculateCoverage(fileData.f),
            lines: this.calculateCoverage(fileData.s) // Approximation
          }

          // Find uncovered lines
          uncoveredLines[filePath] = this.findUncoveredLines(fileData)
        }
      })

      const overallCoverage = (
        (total.statements?.pct || 0) +
        (total.branches?.pct || 0) +
        (total.functions?.pct || 0) +
        (total.lines?.pct || 0)
      ) / 4

      return {
        total: {
          statements: total.statements?.pct || 0,
          branches: total.branches?.pct || 0,
          functions: total.functions?.pct || 0,
          lines: total.lines?.pct || 0
        },
        files,
        uncoveredLines,
        summary: {
          totalFiles: Object.keys(files).length,
          coveredFiles: Object.keys(files).filter(f => 
            files[f].statements >= this.thresholds.statements
          ).length,
          overallCoverage,
          meetingThreshold: overallCoverage >= 85
        }
      }
    } catch (error) {
      testLogger.logError(
        'coverage-checker',
        'parse-coverage',
        error as Error,
        {
          category: 'dependency',
          severity: 'medium',
          file: 'TestCoverageChecker.ts'
        }
      )
      
      return this.createEmptyReport()
    }
  }

  /**
   * Calculate coverage percentage from Jest data
   */
  private calculateCoverage(coverageData: Record<string, number>): number {
    const values = Object.values(coverageData)
    if (values.length === 0) return 0
    
    const covered = values.filter(v => v > 0).length
    return (covered / values.length) * 100
  }

  /**
   * Find uncovered lines from Jest coverage data
   */
  private findUncoveredLines(fileData: any): number[] {
    const uncovered: number[] = []
    
    if (fileData.statementMap && fileData.s) {
      Object.keys(fileData.s).forEach(statementId => {
        if (fileData.s[statementId] === 0) {
          const statement = fileData.statementMap[statementId]
          if (statement && statement.start) {
            uncovered.push(statement.start.line)
          }
        }
      })
    }

    return [...new Set(uncovered)].sort((a, b) => a - b)
  }

  /**
   * Create empty coverage report
   */
  private createEmptyReport(): CoverageReport {
    return {
      total: { statements: 0, branches: 0, functions: 0, lines: 0 },
      files: {},
      uncoveredLines: {},
      summary: {
        totalFiles: 0,
        coveredFiles: 0,
        overallCoverage: 0,
        meetingThreshold: false
      }
    }
  }

  /**
   * Generate missing test files for uncovered code
   */
  async generateMissingTests(): Promise<string[]> {
    const generatedFiles: string[] = []
    
    try {
      const coverageResult = await this.checkAllCoverage()
      
      Object.keys(coverageResult.overall.uncoveredLines).forEach(filePath => {
        const uncoveredLines = coverageResult.overall.uncoveredLines[filePath]
        
        if (uncoveredLines.length > 0) {
          const testFilePath = this.generateTestFilePath(filePath)
          
          if (!existsSync(testFilePath)) {
            this.createBasicTestFile(filePath, testFilePath, uncoveredLines)
            generatedFiles.push(testFilePath)
          }
        }
      })
    } catch (error) {
      testLogger.logError(
        'coverage-checker',
        'generate-missing-tests',
        error as Error,
        {
          category: 'dependency',
          severity: 'medium',
          file: 'TestCoverageChecker.ts'
        }
      )
    }

    return generatedFiles
  }

  /**
   * Generate test file path from source file path
   */
  private generateTestFilePath(sourcePath: string): string {
    const relativePath = sourcePath.replace(this.projectRoot, '').replace(/^\//, '')
    const testPath = relativePath.replace(/\.(ts|tsx|js|jsx)$/, '.test.$1')
    return join(this.projectRoot, 'src', '__tests__', 'generated', testPath)
  }

  /**
   * Create basic test file for uncovered code
   */
  private createBasicTestFile(sourcePath: string, testPath: string, uncoveredLines: number[]): void {
    const fileName = sourcePath.split('/').pop()?.replace(/\.(ts|tsx|js|jsx)$/, '') || 'unknown'
    
    const testContent = `/**
 * Generated test file for ${fileName}
 * Covers previously uncovered lines: ${uncoveredLines.join(', ')}
 */

import { ${fileName} } from '${sourcePath.replace(this.projectRoot, '@')}'

describe('${fileName}', () => {
  test('should be defined', () => {
    expect(${fileName}).toBeDefined()
  })

  // TODO: Add specific tests for uncovered lines: ${uncoveredLines.join(', ')}
  test.todo('Add tests for uncovered functionality')
})
`

    // Ensure directory exists
    const testDir = testPath.substring(0, testPath.lastIndexOf('/'))
    execSync(`mkdir -p "${testDir}"`, { stdio: 'ignore' })
    
    writeFileSync(testPath, testContent)
  }

  /**
   * Validate that all test categories meet minimum requirements
   */
  async validateTestSuiteRequirements(): Promise<{
    valid: boolean
    issues: string[]
    recommendations: string[]
  }> {
    const issues: string[] = []
    const recommendations: string[] = []
    
    const coverageResult = await this.checkAllCoverage()
    
    // Check overall success rate requirement (≥95%)
    if (coverageResult.overall.summary.overallCoverage < 95) {
      issues.push(`Overall test success rate ${coverageResult.overall.summary.overallCoverage.toFixed(1)}% is below 95% requirement`)
      recommendations.push('Focus on fixing critical and high-priority test failures first')
    }

    // Check individual category requirements
    this.testCategories.forEach(category => {
      const categoryResult = coverageResult.categories[category.name]
      if (categoryResult && categoryResult.summary.overallCoverage < category.requiredCoverage) {
        issues.push(`${category.name} tests coverage ${categoryResult.summary.overallCoverage.toFixed(1)}% below required ${category.requiredCoverage}%`)
        recommendations.push(`Add more ${category.name} tests or fix existing failures`)
      }
    })

    // Check for missing test categories
    const missingCategories = this.testCategories.filter(cat => 
      !coverageResult.categories[cat.name] || 
      coverageResult.categories[cat.name].summary.totalFiles === 0
    )

    missingCategories.forEach(category => {
      issues.push(`Missing ${category.name} test category`)
      recommendations.push(`Create ${category.name} tests following pattern: ${category.pattern}`)
    })

    return {
      valid: issues.length === 0,
      issues,
      recommendations: [...recommendations, ...coverageResult.recommendations]
    }
  }
}

// Export singleton instance
export const testCoverageChecker = new TestCoverageChecker()

export default TestCoverageChecker
