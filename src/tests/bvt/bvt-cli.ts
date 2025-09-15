#!/usr/bin/env node
/**
 * Build Verification Test (BVT) Command Line Interface
 * Provides CLI access to BVT functionality
 */

import { runBVT, runBVTHealthCheck } from './bvt-runner.js'
import { BVT_CONFIG, validateBVTConfig, getTotalExpectedDuration } from './bvt-config.js'

interface CLIOptions {
  mode: 'full' | 'health' | 'validate' | 'info'
  verbose: boolean
  output?: string
  timeout?: number
  parallel?: boolean
}

/**
 * Parse command line arguments
 */
function parseArgs(): CLIOptions {
  const args = process.argv.slice(2)
  const options: CLIOptions = {
    mode: 'full',
    verbose: false
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    
    switch (arg) {
      case '--mode':
      case '-m':
        const mode = args[++i]
        if (mode && ['full', 'health', 'validate', 'info'].includes(mode)) {
          options.mode = mode as CLIOptions['mode']
        } else {
          console.error(`Invalid mode: ${mode || 'undefined'}`)
          process.exit(1)
        }
        break
        
      case '--verbose':
      case '-v':
        options.verbose = true
        break
        
      case '--output':
      case '-o':
        options.output = args[++i]
        break
        
      case '--timeout':
      case '-t':
        const timeoutStr = args[++i]
        if (timeoutStr) {
          options.timeout = parseInt(timeoutStr)
        }
        break
        
      case '--parallel':
      case '-p':
        options.parallel = true
        break
        
      case '--help':
      case '-h':
        showHelp()
        process.exit(0)
        break
        
      default:
        console.error(`Unknown option: ${arg}`)
        showHelp()
        process.exit(1)
    }
  }

  return options
}

/**
 * Show help information
 */
function showHelp(): void {
  console.log(`
Build Verification Test (BVT) Suite

Usage: npm run test:bvt [options]

Options:
  -m, --mode <mode>     Test mode: full, health, validate, info (default: full)
  -v, --verbose         Enable verbose output
  -o, --output <path>   Output directory for reports
  -t, --timeout <ms>    Override default timeout
  -p, --parallel        Force parallel execution
  -h, --help            Show this help message

Modes:
  full      Run complete BVT suite (all 12 testing areas)
  health    Run only critical health checks (faster)
  validate  Validate BVT configuration without running tests
  info      Show BVT configuration information

Examples:
  npm run test:bvt                    # Run full BVT suite
  npm run test:bvt -- --mode health   # Run health check only
  npm run test:bvt -- --verbose       # Run with verbose output
  npm run test:bvt -- --mode validate # Validate configuration
`)
}

/**
 * Run BVT in validate mode
 */
async function runValidateMode(options: CLIOptions): Promise<void> {
  console.log('🔍 Validating BVT Configuration...\n')
  
  const validation = validateBVTConfig()
  
  if (validation.valid) {
    console.log('✅ BVT Configuration is valid')
    console.log(`📊 Total categories: ${BVT_CONFIG.categories.length}`)
    console.log(`⏱️  Expected duration: ${(getTotalExpectedDuration() / 1000).toFixed(2)}s`)
    console.log(`🎯 Max execution time: ${(BVT_CONFIG.maxExecutionTime / 1000).toFixed(2)}s`)
    
    if (options.verbose) {
      console.log('\n📋 Test Categories:')
      BVT_CONFIG.categories.forEach(category => {
        console.log(`  • ${category.name}: ${category.tests.length} tests (${category.priority} priority)`)
      })
    }
  } else {
    console.error('❌ BVT Configuration is invalid:')
    validation.errors.forEach(error => {
      console.error(`  • ${error}`)
    })
    process.exit(1)
  }
}

/**
 * Run BVT in info mode
 */
async function runInfoMode(options: CLIOptions): Promise<void> {
  console.log('📊 BVT Suite Information\n')
  
  console.log(`Configuration:`)
  console.log(`  • Max execution time: ${(BVT_CONFIG.maxExecutionTime / 1000).toFixed(2)}s`)
  console.log(`  • Parallel execution: ${BVT_CONFIG.parallelExecution ? 'enabled' : 'disabled'}`)
  console.log(`  • Fail fast: ${BVT_CONFIG.failFast ? 'enabled' : 'disabled'}`)
  console.log(`  • Retry failed tests: ${BVT_CONFIG.retryFailedTests ? 'enabled' : 'disabled'}`)
  console.log(`  • Reporting level: ${BVT_CONFIG.reportingLevel}`)
  
  console.log(`\nTest Categories (${BVT_CONFIG.categories.length} total):`)
  BVT_CONFIG.categories.forEach(category => {
    const totalDuration = category.tests.reduce((sum, test) => sum + test.expectedDuration, 0)
    console.log(`  • ${category.name.padEnd(15)} ${category.tests.length.toString().padStart(2)} tests  ${(totalDuration / 1000).toFixed(1).padStart(5)}s  ${category.priority}`)
  })
  
  const totalTests = BVT_CONFIG.categories.reduce((sum, cat) => sum + cat.tests.length, 0)
  const totalDuration = getTotalExpectedDuration()
  
  console.log(`\nSummary:`)
  console.log(`  • Total tests: ${totalTests}`)
  console.log(`  • Expected duration: ${(totalDuration / 1000).toFixed(2)}s`)
  console.log(`  • Performance target: ${totalDuration <= BVT_CONFIG.maxExecutionTime ? '✅ PASS' : '❌ FAIL'}`)
}

/**
 * Main CLI entry point
 */
export async function runBVTCLI(): Promise<void> {
  const options = parseArgs()
  
  // Set environment variables based on options
  if (options.verbose) {
    process.env.BVT_LOG_LEVEL = 'debug'
  }
  
  if (options.timeout) {
    BVT_CONFIG.maxExecutionTime = options.timeout
  }
  
  if (options.parallel !== undefined) {
    BVT_CONFIG.parallelExecution = options.parallel
  }

  try {
    switch (options.mode) {
      case 'validate':
        await runValidateMode(options)
        break
        
      case 'info':
        await runInfoMode(options)
        break
        
      case 'health':
        console.log('🏥 Running BVT Health Check...\n')
        const healthResult = await runBVTHealthCheck()
        
        if (healthResult.summary.overallSuccess) {
          console.log('\n✅ BVT Health Check PASSED')
          process.exit(0)
        } else {
          console.log('\n❌ BVT Health Check FAILED')
          process.exit(1)
        }
        break
        
      case 'full':
      default:
        console.log('🧪 Running Full BVT Suite...\n')
        const fullResult = await runBVT()
        
        if (fullResult.summary.overallSuccess) {
          console.log('\n✅ BVT Suite PASSED')
          process.exit(0)
        } else {
          console.log('\n❌ BVT Suite FAILED')
          process.exit(1)
        }
        break
    }
  } catch (error) {
    console.error('\n💥 BVT execution failed:', error.message)
    if (options.verbose) {
      console.error(error.stack)
    }
    process.exit(1)
  }
}

// Run CLI if this file is executed directly
if (require.main === module) {
  runBVTCLI().catch(error => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
}
