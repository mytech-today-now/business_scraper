/**
 * Build Verification Test (BVT) Runner
 * Main orchestration engine for the BVT suite
 */

import { BVT_CONFIG, BVTTestCategory, BVTTest, validateBVTConfig } from './bvt-config'
import { BVTReporter } from './bvt-reporter'
import { BVTTestExecutor } from './bvt-test-executor'

export interface BVTResult {
  testName: string
  category: string
  status: 'passed' | 'failed' | 'skipped' | 'timeout'
  duration: number
  error?: string
  details?: any
}

export interface BVTSuiteResult {
  startTime: Date
  endTime: Date
  totalDuration: number
  totalTests: number
  passed: number
  failed: number
  skipped: number
  timeouts: number
  results: BVTResult[]
  summary: {
    criticalPassed: number
    criticalFailed: number
    overallSuccess: boolean
    performanceWithinLimits: boolean
  }
}

export class BVTRunner {
  private reporter: BVTReporter
  private executor: BVTTestExecutor
  private startTime: Date
  private results: BVTResult[] = []

  constructor() {
    this.reporter = new BVTReporter()
    this.executor = new BVTTestExecutor()
    this.startTime = new Date()
  }

  /**
   * Run the complete BVT suite
   */
  async runBVTSuite(): Promise<BVTSuiteResult> {
    this.startTime = new Date()
    this.results = []

    // Validate configuration
    const configValidation = validateBVTConfig()
    if (!configValidation.valid) {
      throw new Error(`BVT Configuration invalid: ${configValidation.errors.join(', ')}`)
    }

    this.reporter.logInfo('Starting Build Verification Test Suite')
    this.reporter.logInfo(`Max execution time: ${BVT_CONFIG.maxExecutionTime / 1000}s`)
    this.reporter.logInfo(`Total categories: ${BVT_CONFIG.categories.length}`)

    try {
      if (BVT_CONFIG.parallelExecution) {
        await this.runCategoriesInParallel()
      } else {
        await this.runCategoriesSequentially()
      }
    } catch (error) {
      this.reporter.logError('BVT Suite execution failed', error)
      throw error
    }

    const endTime = new Date()
    const totalDuration = endTime.getTime() - this.startTime.getTime()

    const suiteResult = this.generateSuiteResult(endTime, totalDuration)
    this.reporter.generateReport(suiteResult)

    return suiteResult
  }

  /**
   * Run categories in parallel for faster execution
   */
  private async runCategoriesInParallel(): Promise<void> {
    const categoryPromises = BVT_CONFIG.categories.map(category => 
      this.runCategory(category)
    )

    const categoryResults = await Promise.allSettled(categoryPromises)
    
    categoryResults.forEach((result, index) => {
      if (result.status === 'rejected') {
        const category = BVT_CONFIG.categories[index]
        this.reporter.logError(`Category ${category.name} failed`, result.reason)
      }
    })
  }

  /**
   * Run categories sequentially
   */
  private async runCategoriesSequentially(): Promise<void> {
    for (const category of BVT_CONFIG.categories) {
      try {
        await this.runCategory(category)
      } catch (error) {
        this.reporter.logError(`Category ${category.name} failed`, error)
        if (BVT_CONFIG.failFast) {
          throw error
        }
      }
    }
  }

  /**
   * Run all tests in a category
   */
  private async runCategory(category: BVTTestCategory): Promise<void> {
    this.reporter.logInfo(`Running category: ${category.name}`)
    
    const categoryStartTime = Date.now()
    const testPromises = category.tests.map(test => 
      this.runTest(test, category)
    )

    const testResults = await Promise.allSettled(testPromises)
    const categoryDuration = Date.now() - categoryStartTime

    this.reporter.logInfo(`Category ${category.name} completed in ${categoryDuration}ms`)
  }

  /**
   * Run a single test with timeout and retry logic
   */
  private async runTest(test: BVTTest, category: BVTTestCategory): Promise<void> {
    const testStartTime = Date.now()
    let lastError: any = null
    let attempts = 0
    const maxAttempts = category.retries + 1

    while (attempts < maxAttempts) {
      attempts++
      
      try {
        this.reporter.logDebug(`Running test: ${test.name} (attempt ${attempts}/${maxAttempts})`)
        
        const result = await Promise.race([
          this.executor.executeTest(test, category),
          this.createTimeoutPromise(test.timeout)
        ])

        const duration = Date.now() - testStartTime
        
        this.results.push({
          testName: test.name,
          category: category.name,
          status: 'passed',
          duration,
          details: result
        })

        this.reporter.logSuccess(`✓ ${test.name} passed (${duration}ms)`)
        return

      } catch (error) {
        lastError = error
        const duration = Date.now() - testStartTime

        if (error.message === 'Test timeout') {
          this.results.push({
            testName: test.name,
            category: category.name,
            status: 'timeout',
            duration,
            error: error.message
          })
          this.reporter.logError(`⏰ ${test.name} timed out after ${duration}ms`)
          return // Don't retry timeouts
        }

        if (attempts === maxAttempts) {
          this.results.push({
            testName: test.name,
            category: category.name,
            status: 'failed',
            duration,
            error: error.message
          })
          this.reporter.logError(`✗ ${test.name} failed after ${attempts} attempts: ${error.message}`)
        } else {
          this.reporter.logWarning(`⚠ ${test.name} failed (attempt ${attempts}), retrying...`)
          // Brief delay before retry
          await new Promise(resolve => setTimeout(resolve, 1000))
        }
      }
    }
  }

  /**
   * Create a timeout promise
   */
  private createTimeoutPromise(timeoutMs: number): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Test timeout')), timeoutMs)
    })
  }

  /**
   * Generate the final suite result
   */
  private generateSuiteResult(endTime: Date, totalDuration: number): BVTSuiteResult {
    const passed = this.results.filter(r => r.status === 'passed').length
    const failed = this.results.filter(r => r.status === 'failed').length
    const skipped = this.results.filter(r => r.status === 'skipped').length
    const timeouts = this.results.filter(r => r.status === 'timeout').length

    // Check critical tests
    const criticalCategories = ['functional', 'system', 'smoke', 'security', 'acceptance']
    const criticalResults = this.results.filter(r => criticalCategories.includes(r.category))
    const criticalPassed = criticalResults.filter(r => r.status === 'passed').length
    const criticalFailed = criticalResults.filter(r => r.status !== 'passed').length

    // Performance check
    const performanceWithinLimits = totalDuration <= BVT_CONFIG.maxExecutionTime

    // Overall success: all critical tests pass and within time limit
    const overallSuccess = criticalFailed === 0 && performanceWithinLimits

    return {
      startTime: this.startTime,
      endTime,
      totalDuration,
      totalTests: this.results.length,
      passed,
      failed,
      skipped,
      timeouts,
      results: this.results,
      summary: {
        criticalPassed,
        criticalFailed,
        overallSuccess,
        performanceWithinLimits
      }
    }
  }

  /**
   * Get current test results
   */
  getResults(): BVTResult[] {
    return [...this.results]
  }

  /**
   * Reset the runner for a new test run
   */
  reset(): void {
    this.results = []
    this.startTime = new Date()
  }
}

/**
 * Main entry point for running BVT suite
 */
export async function runBVT(): Promise<BVTSuiteResult> {
  const runner = new BVTRunner()
  return await runner.runBVTSuite()
}

/**
 * Quick health check - runs only critical tests
 */
export async function runBVTHealthCheck(): Promise<BVTSuiteResult> {
  const runner = new BVTRunner()
  
  // Temporarily modify config to run only critical tests
  const originalCategories = BVT_CONFIG.categories
  BVT_CONFIG.categories = BVT_CONFIG.categories.filter(cat => cat.priority === 'critical')
  
  try {
    const result = await runner.runBVTSuite()
    return result
  } finally {
    // Restore original config
    BVT_CONFIG.categories = originalCategories
  }
}
