/**
 * Build Verification Test (BVT) Suite Entry Point
 * Main entry point for running BVT tests
 */

export { BVTRunner, runBVT, runBVTHealthCheck } from './bvt-runner'
export { BVTReporter } from './bvt-reporter'
export { BVTTestExecutor } from './bvt-test-executor'
export { BVTTestImplementations } from './bvt-test-implementations'
export { BVT_CONFIG, validateBVTConfig, getTotalExpectedDuration, getTestsByPriority } from './bvt-config'
export type { 
  BVTConfig, 
  BVTTestCategory, 
  BVTTest, 
  BVTResult, 
  BVTSuiteResult 
} from './bvt-config'
export type { 
  TestExecutionContext, 
  TestExecutionResult, 
  BVTTestFunction 
} from './bvt-test-executor'

// CLI support
if (require.main === module) {
  const { runBVTCLI } = require('./bvt-cli')
  runBVTCLI().catch(console.error)
}
