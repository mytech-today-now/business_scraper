/**
 * Rate Limiting Test Utility
 * Test the enhanced rate limiting and anti-bot measures
 */

import { logger } from '@/utils/logger'

export interface RateLimitTestConfig {
  baseDelay: number
  maxDelay: number
  maxFailures: number
  cooldownPeriod: number
}

export class RateLimitTester {
  private failures = 0
  private lastFailureTime = 0
  private lastRequestTime = 0
  private config: RateLimitTestConfig

  constructor(config: RateLimitTestConfig) {
    this.config = config
  }

  /**
   * Calculate delay with exponential backoff and jitter
   */
  calculateDelay(): number {
    const exponentialDelay = this.config.baseDelay * Math.pow(2, this.failures)
    const jitter = Math.random() * 0.3 * exponentialDelay // 30% jitter
    const finalDelay = Math.min(exponentialDelay + jitter, this.config.maxDelay)
    
    logger.debug('RateLimitTester', `Calculated delay: ${finalDelay}ms (failures: ${this.failures})`)
    return finalDelay
  }

  /**
   * Check if we should skip due to circuit breaker
   */
  shouldSkip(): boolean {
    if (this.failures >= this.config.maxFailures) {
      const timeSinceLastFailure = Date.now() - this.lastFailureTime
      if (timeSinceLastFailure < this.config.cooldownPeriod) {
        logger.warn('RateLimitTester', `Skipping due to circuit breaker (${this.failures} failures)`)
        return true
      } else {
        // Reset circuit breaker after cooldown
        this.failures = 0
        logger.info('RateLimitTester', 'Circuit breaker reset after cooldown')
      }
    }
    return false
  }

  /**
   * Record a failure
   */
  recordFailure(): void {
    this.failures++
    this.lastFailureTime = Date.now()
    logger.warn('RateLimitTester', `Failure recorded (${this.failures}/${this.config.maxFailures})`)
  }

  /**
   * Reset failures on success
   */
  resetFailures(): void {
    if (this.failures > 0) {
      logger.info('RateLimitTester', 'Failures reset after successful request')
      this.failures = 0
    }
  }

  /**
   * Wait with rate limiting
   */
  async waitWithRateLimit(): Promise<void> {
    const now = Date.now()
    const timeSinceLastRequest = now - this.lastRequestTime
    const requiredDelay = this.calculateDelay()

    if (timeSinceLastRequest < requiredDelay) {
      const waitTime = requiredDelay - timeSinceLastRequest
      logger.info('RateLimitTester', `Rate limiting: waiting ${waitTime}ms before next request`)
      await new Promise(resolve => setTimeout(resolve, waitTime))
    }

    this.lastRequestTime = Date.now()
  }

  /**
   * Simulate a request with rate limiting
   */
  async simulateRequest(shouldFail: boolean = false): Promise<boolean> {
    if (this.shouldSkip()) {
      return false
    }

    await this.waitWithRateLimit()

    if (shouldFail) {
      this.recordFailure()
      return false
    } else {
      this.resetFailures()
      return true
    }
  }

  /**
   * Get current status
   */
  getStatus() {
    return {
      failures: this.failures,
      lastFailureTime: this.lastFailureTime,
      lastRequestTime: this.lastRequestTime,
      isInCooldown: this.shouldSkip()
    }
  }
}

/**
 * Test the rate limiting system
 */
export async function testRateLimiting(): Promise<void> {
  logger.info('RateLimitTester', 'Starting rate limiting test')

  const tester = new RateLimitTester({
    baseDelay: 30000, // 30 seconds
    maxDelay: 300000, // 5 minutes
    maxFailures: 2,
    cooldownPeriod: 10 * 60 * 1000 // 10 minutes
  })

  // Test successful requests
  logger.info('RateLimitTester', 'Testing successful requests...')
  for (let i = 0; i < 3; i++) {
    const success = await tester.simulateRequest(false)
    logger.info('RateLimitTester', `Request ${i + 1}: ${success ? 'SUCCESS' : 'SKIPPED'}`)
  }

  // Test failed requests
  logger.info('RateLimitTester', 'Testing failed requests...')
  for (let i = 0; i < 3; i++) {
    const success = await tester.simulateRequest(true)
    logger.info('RateLimitTester', `Failed request ${i + 1}: ${success ? 'SUCCESS' : 'FAILED'}`)
  }

  // Test circuit breaker
  logger.info('RateLimitTester', 'Testing circuit breaker...')
  const success = await tester.simulateRequest(false)
  logger.info('RateLimitTester', `Circuit breaker test: ${success ? 'SUCCESS' : 'BLOCKED'}`)

  logger.info('RateLimitTester', 'Rate limiting test completed', tester.getStatus())
}
