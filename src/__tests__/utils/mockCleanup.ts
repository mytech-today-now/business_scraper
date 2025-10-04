/**
 * Mock Cleanup Utilities
 * 
 * Comprehensive mock cleanup system to prevent state leakage between tests
 * and ensure consistent test isolation.
 */

import { jest } from '@jest/globals'
import { mockCleanup } from './standardizedMocks'
import { cleanupExternalServiceMocks } from './externalServiceMocks'

/**
 * Test Isolation Manager
 * Manages test isolation and cleanup to prevent state leakage
 */
export class TestIsolationManager {
  private static instance: TestIsolationManager
  private cleanupTasks: Array<{ name: string; cleanup: () => void | Promise<void> }> = []
  private globalState: Map<string, any> = new Map()
  private timers: Set<NodeJS.Timeout> = new Set()
  private intervals: Set<NodeJS.Timeout> = new Set()
  private eventListeners: Array<{ target: EventTarget; type: string; listener: EventListener }> = []

  static getInstance(): TestIsolationManager {
    if (!TestIsolationManager.instance) {
      TestIsolationManager.instance = new TestIsolationManager()
    }
    return TestIsolationManager.instance
  }

  /**
   * Register a cleanup task
   */
  registerCleanup(name: string, cleanup: () => void | Promise<void>): void {
    this.cleanupTasks.push({ name, cleanup })
  }

  /**
   * Store global state that should be restored after tests
   */
  storeGlobalState(key: string, value: any): void {
    this.globalState.set(key, value)
  }

  /**
   * Restore global state
   */
  restoreGlobalState(key: string): any {
    return this.globalState.get(key)
  }

  /**
   * Track timers for cleanup
   */
  trackTimer(timer: NodeJS.Timeout): void {
    this.timers.add(timer)
  }

  /**
   * Track intervals for cleanup
   */
  trackInterval(interval: NodeJS.Timeout): void {
    this.intervals.add(interval)
  }

  /**
   * Track event listeners for cleanup
   */
  trackEventListener(target: EventTarget, type: string, listener: EventListener): void {
    this.eventListeners.push({ target, type, listener })
  }

  /**
   * Execute all cleanup tasks
   */
  async executeCleanup(): Promise<void> {
    // Clear timers and intervals
    this.timers.forEach(timer => clearTimeout(timer))
    this.intervals.forEach(interval => clearInterval(interval))
    this.timers.clear()
    this.intervals.clear()

    // Remove event listeners
    this.eventListeners.forEach(({ target, type, listener }) => {
      try {
        target.removeEventListener(type, listener)
      } catch (error) {
        console.warn('Failed to remove event listener:', error)
      }
    })
    this.eventListeners.length = 0

    // Execute registered cleanup tasks
    for (const { name, cleanup } of this.cleanupTasks) {
      try {
        await cleanup()
      } catch (error) {
        console.warn(`Cleanup task "${name}" failed:`, error)
      }
    }

    // Clear Jest mocks
    jest.clearAllMocks()
    jest.resetAllMocks()

    // Clear global state
    this.globalState.clear()
  }

  /**
   * Reset the isolation manager
   */
  reset(): void {
    this.cleanupTasks.length = 0
    this.globalState.clear()
    this.timers.clear()
    this.intervals.clear()
    this.eventListeners.length = 0
  }
}

/**
 * Mock State Validator
 * Validates that mocks are properly reset between tests
 */
export class MockStateValidator {
  private static instance: MockStateValidator
  private mockRegistry: Map<string, jest.MockedFunction<any>> = new Map()
  private validationRules: Array<{ name: string; validate: () => boolean }> = []

  static getInstance(): MockStateValidator {
    if (!MockStateValidator.instance) {
      MockStateValidator.instance = new MockStateValidator()
    }
    return MockStateValidator.instance
  }

  /**
   * Register a mock for validation
   */
  registerMock(name: string, mock: jest.MockedFunction<any>): void {
    this.mockRegistry.set(name, mock)
  }

  /**
   * Add a validation rule
   */
  addValidationRule(name: string, validate: () => boolean): void {
    this.validationRules.push({ name, validate })
  }

  /**
   * Validate all registered mocks
   */
  validateMockState(): { isValid: boolean; errors: string[] } {
    const errors: string[] = []

    // Check that all mocks have been cleared
    for (const [name, mock] of this.mockRegistry) {
      if (mock.mock.calls.length > 0) {
        errors.push(`Mock "${name}" has ${mock.mock.calls.length} uncleaned calls`)
      }
      if (mock.mock.results.length > 0) {
        errors.push(`Mock "${name}" has ${mock.mock.results.length} uncleaned results`)
      }
    }

    // Run custom validation rules
    for (const { name, validate } of this.validationRules) {
      try {
        if (!validate()) {
          errors.push(`Validation rule "${name}" failed`)
        }
      } catch (error) {
        errors.push(`Validation rule "${name}" threw error: ${error}`)
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    }
  }

  /**
   * Reset all registered mocks
   */
  resetAllMocks(): void {
    for (const mock of this.mockRegistry.values()) {
      mock.mockReset()
    }
  }

  /**
   * Clear the validator
   */
  reset(): void {
    this.mockRegistry.clear()
    this.validationRules.length = 0
  }
}

/**
 * Memory Leak Detector
 * Detects potential memory leaks in test environment
 */
export class MemoryLeakDetector {
  private static instance: MemoryLeakDetector
  private initialMemory: NodeJS.MemoryUsage | null = null
  private memoryThreshold = 50 * 1024 * 1024 // 50MB
  private objectCounts: Map<string, number> = new Map()

  static getInstance(): MemoryLeakDetector {
    if (!MemoryLeakDetector.instance) {
      MemoryLeakDetector.instance = new MemoryLeakDetector()
    }
    return MemoryLeakDetector.instance
  }

  /**
   * Start memory monitoring
   */
  startMonitoring(): void {
    if (typeof process !== 'undefined' && process.memoryUsage) {
      this.initialMemory = process.memoryUsage()
    }
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc()
    }
  }

  /**
   * Check for memory leaks
   */
  checkForLeaks(): { hasLeaks: boolean; report: string } {
    if (!this.initialMemory || typeof process === 'undefined') {
      return { hasLeaks: false, report: 'Memory monitoring not available' }
    }

    const currentMemory = process.memoryUsage()
    const memoryIncrease = currentMemory.heapUsed - this.initialMemory.heapUsed

    const hasLeaks = memoryIncrease > this.memoryThreshold

    const report = `
Memory Usage Report:
- Initial heap: ${(this.initialMemory.heapUsed / 1024 / 1024).toFixed(2)} MB
- Current heap: ${(currentMemory.heapUsed / 1024 / 1024).toFixed(2)} MB
- Increase: ${(memoryIncrease / 1024 / 1024).toFixed(2)} MB
- Threshold: ${(this.memoryThreshold / 1024 / 1024).toFixed(2)} MB
- Status: ${hasLeaks ? 'POTENTIAL LEAK DETECTED' : 'OK'}
    `.trim()

    return { hasLeaks, report }
  }

  /**
   * Track object creation
   */
  trackObject(type: string): void {
    const current = this.objectCounts.get(type) || 0
    this.objectCounts.set(type, current + 1)
  }

  /**
   * Get object count report
   */
  getObjectCountReport(): string {
    const entries = Array.from(this.objectCounts.entries())
      .sort(([, a], [, b]) => b - a)
      .map(([type, count]) => `- ${type}: ${count}`)
      .join('\n')

    return `Object Counts:\n${entries}`
  }

  /**
   * Reset monitoring
   */
  reset(): void {
    this.initialMemory = null
    this.objectCounts.clear()
  }
}

// Export singleton instances
export const testIsolation = TestIsolationManager.getInstance()
export const mockValidator = MockStateValidator.getInstance()
export const memoryDetector = MemoryLeakDetector.getInstance()

/**
 * Comprehensive cleanup function for Jest setup
 */
export async function performComprehensiveCleanup(): Promise<void> {
  // Execute test isolation cleanup
  await testIsolation.executeCleanup()

  // Reset standardized mocks
  mockCleanup.cleanupAllMocks()

  // Reset external service mocks
  cleanupExternalServiceMocks()

  // Reset mock validator
  mockValidator.resetAllMocks()

  // Check for memory leaks (in development)
  if (process.env.NODE_ENV === 'test' && process.env.DETECT_MEMORY_LEAKS === 'true') {
    const { hasLeaks, report } = memoryDetector.checkForLeaks()
    if (hasLeaks) {
      console.warn('Memory leak detected:', report)
    }
  }
}

/**
 * Setup comprehensive cleanup for Jest
 */
export function setupComprehensiveCleanup(): void {
  beforeEach(async () => {
    // Start memory monitoring
    memoryDetector.startMonitoring()

    // Clear all mocks
    jest.clearAllMocks()
  })

  afterEach(async () => {
    // Perform comprehensive cleanup
    await performComprehensiveCleanup()

    // Validate mock state
    const validation = mockValidator.validateMockState()
    if (!validation.isValid) {
      console.warn('Mock state validation failed:', validation.errors)
    }
  })

  afterAll(async () => {
    // Final cleanup
    await performComprehensiveCleanup()
    
    // Reset all managers
    testIsolation.reset()
    mockValidator.reset()
    memoryDetector.reset()
  })
}

/**
 * Utility functions for test cleanup
 */
export const cleanupUtils = {
  // Register cleanup for a specific resource
  onCleanup: (name: string, cleanup: () => void | Promise<void>) => {
    testIsolation.registerCleanup(name, cleanup)
  },

  // Track a timer for cleanup
  trackTimer: (timer: NodeJS.Timeout) => {
    testIsolation.trackTimer(timer)
    return timer
  },

  // Track an interval for cleanup
  trackInterval: (interval: NodeJS.Timeout) => {
    testIsolation.trackInterval(interval)
    return interval
  },

  // Track an event listener for cleanup
  trackEventListener: (target: EventTarget, type: string, listener: EventListener) => {
    testIsolation.trackEventListener(target, type, listener)
    target.addEventListener(type, listener)
  },

  // Validate that cleanup was successful
  validateCleanup: () => {
    return mockValidator.validateMockState()
  },

  // Get memory usage report
  getMemoryReport: () => {
    return memoryDetector.checkForLeaks()
  },
}
