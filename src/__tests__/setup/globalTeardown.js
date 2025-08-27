/**
 * Global Jest Teardown
 * Cleans up test environment and generates reports
 */

const { testLogger } = require('../../utils/TestLogger')

module.exports = async () => {
  console.log('🧹 Starting global test teardown...')

  // Calculate total test time
  const testDuration = Date.now() - (global.__TEST_START_TIME__ || 0)
  console.log(`⏱️  Total test duration: ${(testDuration / 1000).toFixed(2)}s`)

  // Generate test report
  try {
    console.log('📊 Generating test report...')
    const reportFile = testLogger.saveReport()
    console.log(`📄 Test report saved to: ${reportFile}`)

    // Log overall statistics
    const stats = testLogger.getOverallStats()
    console.log('📈 Test Statistics:')
    console.log(`   - Total Suites: ${stats.totalSuites}`)
    console.log(`   - Passing Suites: ${stats.passingSuites}`)
    console.log(`   - Failing Suites: ${stats.failingSuites}`)
    console.log(`   - Success Rate: ${(stats.overallSuccessRate * 100).toFixed(2)}%`)
    console.log(`   - Critical Errors: ${stats.criticalErrors}`)
    console.log(`   - High Priority Errors: ${stats.highPriorityErrors}`)

    // Check if we met the 95% target
    if (stats.overallSuccessRate >= 0.95) {
      console.log('🎉 SUCCESS: Test suite meets ≥95% success rate target!')
    } else {
      console.log('⚠️  WARNING: Test suite below 95% success rate target')
      console.log('   Please review the test report for recommendations')
    }
  } catch (error) {
    console.error('❌ Failed to generate test report:', error)
  }

  console.log('✅ Global test teardown complete')
}
