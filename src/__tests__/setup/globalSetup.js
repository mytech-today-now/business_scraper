/**
 * Global Jest Setup
 * Initializes test environment and utilities
 */

const { testLogger } = require('../../utils/TestLogger')
const { testCoverageChecker } = require('../../utils/TestCoverageChecker')

module.exports = async () => {
  console.log('🚀 Starting test suite with enhanced utilities...')
  
  // Initialize test logger
  console.log('📊 Initializing test logger...')
  
  // Set up test environment variables
  process.env.NODE_ENV = 'test'
  process.env.TEST_MODE = 'true'
  process.env.DISABLE_REAL_OPERATIONS = 'true'
  
  // Initialize coverage checker
  console.log('📈 Initializing coverage checker...')
  
  // Set global test start time
  global.__TEST_START_TIME__ = Date.now()
  
  console.log('✅ Global test setup complete')
}
