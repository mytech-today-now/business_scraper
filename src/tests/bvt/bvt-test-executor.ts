/**
 * Build Verification Test (BVT) Test Executor
 * Executes individual BVT tests with proper isolation and error handling
 */

import { BVTTest, BVTTestCategory } from './bvt-config'
import { BVTTestImplementations } from './bvt-test-implementations'

export class BVTTestExecutor {
  private testImplementations: BVTTestImplementations

  constructor() {
    this.testImplementations = new BVTTestImplementations()
  }

  /**
   * Execute a single BVT test
   */
  async executeTest(test: BVTTest, category: BVTTestCategory): Promise<any> {
    // Validate test function exists
    if (!this.testImplementations.hasTest(test.testFunction)) {
      throw new Error(`Test function '${test.testFunction}' not found`)
    }

    // Check dependencies
    if (test.dependencies) {
      await this.checkDependencies(test.dependencies)
    }

    // Execute the test with proper error handling
    try {
      const result = await this.testImplementations.executeTest(test.testFunction, {
        testName: test.name,
        category: category.name,
        timeout: test.timeout,
        expectedDuration: test.expectedDuration
      })

      return result
    } catch (error) {
      // Enhance error with context
      const enhancedError = new Error(
        `Test '${test.name}' in category '${category.name}' failed: ${error.message}`
      )
      enhancedError.stack = error.stack
      throw enhancedError
    }
  }

  /**
   * Check if test dependencies are met
   */
  private async checkDependencies(dependencies: string[]): Promise<void> {
    for (const dependency of dependencies) {
      const isAvailable = await this.checkDependency(dependency)
      if (!isAvailable) {
        throw new Error(`Dependency '${dependency}' is not available`)
      }
    }
  }

  /**
   * Check a single dependency
   */
  private async checkDependency(dependency: string): Promise<boolean> {
    switch (dependency) {
      case 'database':
        return await this.testImplementations.checkDatabaseConnection()
      case 'redis':
        return await this.testImplementations.checkRedisConnection()
      case 'api':
        return await this.testImplementations.checkApiAvailability()
      case 'filesystem':
        return await this.testImplementations.checkFilesystemAccess()
      default:
        console.warn(`Unknown dependency: ${dependency}`)
        return true
    }
  }

  /**
   * Get available test functions
   */
  getAvailableTests(): string[] {
    return this.testImplementations.getAvailableTests()
  }

  /**
   * Validate all test functions exist
   */
  validateTestFunctions(tests: BVTTest[]): { valid: boolean; missing: string[] } {
    const missing: string[] = []
    const available = this.getAvailableTests()

    for (const test of tests) {
      if (!available.includes(test.testFunction)) {
        missing.push(test.testFunction)
      }
    }

    return {
      valid: missing.length === 0,
      missing
    }
  }
}

/**
 * Test execution context
 */
export interface TestExecutionContext {
  testName: string
  category: string
  timeout: number
  expectedDuration: number
  startTime?: Date
  environment?: {
    baseUrl?: string
    apiKey?: string
    databaseUrl?: string
    redisUrl?: string
  }
}

/**
 * Test result interface
 */
export interface TestExecutionResult {
  success: boolean
  duration: number
  data?: any
  metrics?: {
    responseTime?: number
    memoryUsage?: number
    cpuUsage?: number
  }
  warnings?: string[]
}

/**
 * Base test interface
 */
export interface BVTTestFunction {
  (context: TestExecutionContext): Promise<TestExecutionResult>
}

/**
 * Test registry for dynamic test loading
 */
export class BVTTestRegistry {
  private static instance: BVTTestRegistry
  private tests: Map<string, BVTTestFunction> = new Map()

  static getInstance(): BVTTestRegistry {
    if (!BVTTestRegistry.instance) {
      BVTTestRegistry.instance = new BVTTestRegistry()
    }
    return BVTTestRegistry.instance
  }

  /**
   * Register a test function
   */
  register(name: string, testFunction: BVTTestFunction): void {
    this.tests.set(name, testFunction)
  }

  /**
   * Get a test function
   */
  get(name: string): BVTTestFunction | undefined {
    return this.tests.get(name)
  }

  /**
   * Check if test exists
   */
  has(name: string): boolean {
    return this.tests.has(name)
  }

  /**
   * Get all registered test names
   */
  getTestNames(): string[] {
    return Array.from(this.tests.keys())
  }

  /**
   * Clear all tests (for testing purposes)
   */
  clear(): void {
    this.tests.clear()
  }
}

/**
 * Decorator for registering BVT tests
 */
export function BVTTestFunction(name: string) {
  return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
    const registry = BVTTestRegistry.getInstance()
    registry.register(name, descriptor.value)
  }
}

/**
 * Utility functions for test execution
 */
export class BVTTestUtils {
  /**
   * Measure execution time
   */
  static async measureTime<T>(fn: () => Promise<T>): Promise<{ result: T; duration: number }> {
    const startTime = Date.now()
    const result = await fn()
    const duration = Date.now() - startTime
    return { result, duration }
  }

  /**
   * Retry a function with exponential backoff
   */
  static async retry<T>(
    fn: () => Promise<T>,
    maxAttempts: number = 3,
    baseDelay: number = 1000
  ): Promise<T> {
    let lastError: any
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn()
      } catch (error) {
        lastError = error
        
        if (attempt === maxAttempts) {
          throw lastError
        }
        
        const delay = baseDelay * Math.pow(2, attempt - 1)
        await new Promise(resolve => setTimeout(resolve, delay))
      }
    }
    
    throw lastError
  }

  /**
   * Create a timeout promise
   */
  static createTimeout(ms: number): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`Operation timed out after ${ms}ms`)), ms)
    })
  }

  /**
   * Race a promise against a timeout
   */
  static async withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return Promise.race([
      promise,
      BVTTestUtils.createTimeout(timeoutMs)
    ])
  }

  /**
   * Check if a URL is reachable
   */
  static async isUrlReachable(url: string, timeoutMs: number = 5000): Promise<boolean> {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs)
      
      const response = await fetch(url, {
        method: 'HEAD',
        signal: controller.signal
      })
      
      clearTimeout(timeoutId)
      return response.ok
    } catch (error) {
      return false
    }
  }

  /**
   * Get system resource usage
   */
  static getResourceUsage(): { memoryUsage: number; cpuUsage?: number } {
    const memoryUsage = process.memoryUsage()
    return {
      memoryUsage: memoryUsage.heapUsed / 1024 / 1024, // MB
      // CPU usage would require additional monitoring
    }
  }

  /**
   * Validate environment variables
   */
  static validateEnvironment(requiredVars: string[]): { valid: boolean; missing: string[] } {
    const missing = requiredVars.filter(varName => !process.env[varName])
    return {
      valid: missing.length === 0,
      missing
    }
  }
}
