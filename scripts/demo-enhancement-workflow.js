#!/usr/bin/env node

/**
 * Demo Script for Self-Documenting Enhancement Workflow
 * 
 * This script demonstrates how to use the enhancement workflow with sample data
 * and provides examples of different console log scenarios.
 */

const fs = require('fs')
const path = require('path')
const { EnhancementWorkflow, ConsoleLogAnalyzer } = require('./console-log-enhancement-workflow')

// Sample console logs for demonstration
const SAMPLE_LOGS = {
  streamingIssues: `
6:36:58 PM [WARN] [06:36:58 PM] <useSearchStreaming> WARN: Streaming connection error {
  "readyState": 2,
  "url": "http://localhost:3000/api/stream-search?query=Insurance+Agencies&location=60047",
  "retryCount": 0,
  "timestamp": "2025-09-15T23:36:58.844Z"
}
6:36:58 PM [INFO] [06:36:58 PM] <useSearchStreaming> INFO: Retrying connection (1/3)
6:37:03 PM [WARN] [06:37:03 PM] <useSearchStreaming> WARN: Streaming connection error {
  "readyState": 2,
  "url": "http://localhost:3000/api/stream-search?query=Insurance+Agencies&location=60047",
  "retryCount": 0,
  "timestamp": "2025-09-15T23:37:03.219Z"
}
6:37:03 PM [INFO] [06:37:03 PM] <useSearchStreaming> INFO: Retrying connection (1/3)
6:37:07 PM [ERROR] [06:37:07 PM] <useSearchStreaming> ERROR: Max retries exceeded, connection failed
  `,

  excessiveLogging: `
6:36:58 PM [INFO] [06:36:58 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:00 PM [INFO] [06:37:00 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:03 PM [INFO] [06:37:03 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:05 PM [INFO] [06:37:05 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:07 PM [INFO] [06:37:07 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:09 PM [INFO] [06:37:09 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:11 PM [INFO] [06:37:11 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:13 PM [INFO] [06:37:13 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:14 PM [INFO] [06:37:14 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:16 PM [INFO] [06:37:16 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:18 PM [INFO] [06:37:18 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
6:37:20 PM [INFO] [06:37:20 PM] <AddressInputHandler> INFO: ZIP code input detected: 60047
  `,

  memoryIssues: `
6:37:12 PM [DEBUG] [06:37:12 PM] <Monitoring> DEBUG: Metric recorded: memory_heap_used = 317316886 bytes
6:37:12 PM [DEBUG] [06:37:12 PM] <Monitoring> DEBUG: Metric recorded: memory_heap_total = 346807774 bytes
6:37:12 PM [WARN] [06:37:12 PM] <MemoryMonitor> WARN: Memory usage above threshold: 91.5%
6:37:42 PM [DEBUG] [06:37:42 PM] <Monitoring> DEBUG: Metric recorded: memory_heap_used = 325144344 bytes
6:37:42 PM [ERROR] [06:37:42 PM] <MemoryMonitor> ERROR: Memory leak detected in component: SearchEngine
6:37:42 PM [INFO] [06:37:42 PM] <MemoryMonitor> INFO: Triggering garbage collection
  `,

  apiErrors: `
6:38:15 PM [ERROR] [06:38:15 PM] <SearchEngine> ERROR: API request failed {
  "url": "https://api.bing.microsoft.com/v7.0/search",
  "status": 429,
  "message": "Rate limit exceeded",
  "retryAfter": 60
}
6:38:15 PM [WARN] [06:38:15 PM] <RateLimiter> WARN: Rate limit hit for provider: bing
6:38:16 PM [INFO] [06:38:16 PM] <SearchEngine> INFO: Switching to fallback provider: google
6:38:20 PM [ERROR] [06:38:20 PM] <SearchEngine> ERROR: All providers exhausted, search failed
  `
}

class WorkflowDemo {
  constructor() {
    this.demoDir = path.join(process.cwd(), 'demo-results')
    this.ensureDemoDirectory()
  }

  ensureDemoDirectory() {
    if (!fs.existsSync(this.demoDir)) {
      fs.mkdirSync(this.demoDir, { recursive: true })
    }
  }

  async runDemo() {
    console.log('🎬 Starting Enhancement Workflow Demo...\n')

    // Demo 1: Console Log Analysis
    await this.demoConsoleLogAnalysis()

    // Demo 2: Pattern Detection
    await this.demoPatternDetection()

    // Demo 3: Recommendation Generation
    await this.demoRecommendationGeneration()

    // Demo 4: Full Workflow (dry run)
    await this.demoFullWorkflow()

    console.log('\n🎉 Demo completed! Check the demo-results/ directory for outputs.')
  }

  async demoConsoleLogAnalysis() {
    console.log('📊 Demo 1: Console Log Analysis')
    console.log('=' .repeat(50))

    for (const [scenario, logContent] of Object.entries(SAMPLE_LOGS)) {
      console.log(`\n🔍 Analyzing scenario: ${scenario}`)
      
      const analyzer = new ConsoleLogAnalyzer(logContent)
      const analysis = analyzer.analysis

      console.log(`  - INFO logs: ${analysis.infoLogs.length}`)
      console.log(`  - WARN logs: ${analysis.warnLogs.length}`)
      console.log(`  - ERROR logs: ${analysis.errorLogs.length}`)
      console.log(`  - DEBUG logs: ${analysis.debugLogs.length}`)
      console.log(`  - Patterns detected: ${Object.keys(analysis.patterns).length}`)
      console.log(`  - Recommendations: ${analysis.recommendations.length}`)

      // Save analysis to file
      const analysisFile = path.join(this.demoDir, `analysis-${scenario}.json`)
      fs.writeFileSync(analysisFile, JSON.stringify(analysis, null, 2))
      console.log(`  - Analysis saved to: ${analysisFile}`)
    }
  }

  async demoPatternDetection() {
    console.log('\n\n🔍 Demo 2: Pattern Detection')
    console.log('=' .repeat(50))

    const combinedLog = Object.values(SAMPLE_LOGS).join('\n')
    const analyzer = new ConsoleLogAnalyzer(combinedLog)
    const patterns = analyzer.analysis.patterns

    console.log('\nDetected patterns:')
    for (const [patternName, pattern] of Object.entries(patterns)) {
      console.log(`\n📋 ${patternName}:`)
      console.log(`  - Description: ${pattern.description}`)
      console.log(`  - Occurrences: ${pattern.count}`)
      console.log(`  - Affected components: ${pattern.affectedComponents.join(', ')}`)
    }

    // Save patterns to file
    const patternsFile = path.join(this.demoDir, 'detected-patterns.json')
    fs.writeFileSync(patternsFile, JSON.stringify(patterns, null, 2))
    console.log(`\nPatterns saved to: ${patternsFile}`)
  }

  async demoRecommendationGeneration() {
    console.log('\n\n💡 Demo 3: Recommendation Generation')
    console.log('=' .repeat(50))

    const combinedLog = Object.values(SAMPLE_LOGS).join('\n')
    const analyzer = new ConsoleLogAnalyzer(combinedLog)
    const recommendations = analyzer.analysis.recommendations

    console.log('\nGenerated recommendations:')
    recommendations.forEach((rec, index) => {
      console.log(`\n${index + 1}. ${rec.component} (Priority: ${rec.priority})`)
      console.log(`   Issue: ${rec.issue}`)
      console.log(`   Solution: ${rec.solution}`)
    })

    // Save recommendations to file
    const recommendationsFile = path.join(this.demoDir, 'recommendations.json')
    fs.writeFileSync(recommendationsFile, JSON.stringify(recommendations, null, 2))
    console.log(`\nRecommendations saved to: ${recommendationsFile}`)
  }

  async demoFullWorkflow() {
    console.log('\n\n🔄 Demo 4: Full Workflow (Dry Run)')
    console.log('=' .repeat(50))

    // Create a sample console log file
    const sampleLogFile = path.join(this.demoDir, 'sample-console.log')
    const combinedLog = Object.values(SAMPLE_LOGS).join('\n')
    fs.writeFileSync(sampleLogFile, combinedLog)

    console.log(`\n📝 Sample console log created: ${sampleLogFile}`)
    console.log('Log content preview:')
    console.log(combinedLog.split('\n').slice(0, 5).join('\n'))
    console.log('...')

    // Analyze the log
    const analyzer = new ConsoleLogAnalyzer(combinedLog)
    
    // Generate mock GitHub issue content
    const issueContent = this.generateMockIssueContent(analyzer.analysis)
    const issueFile = path.join(this.demoDir, 'mock-github-issue.md')
    fs.writeFileSync(issueFile, issueContent)

    console.log(`\n📋 Mock GitHub issue generated: ${issueFile}`)
    console.log('\nIssue preview:')
    console.log(issueContent.split('\n').slice(0, 10).join('\n'))
    console.log('...')

    // Generate mock test results
    const testResults = this.generateMockTestResults()
    const testResultsFile = path.join(this.demoDir, 'mock-test-results.json')
    fs.writeFileSync(testResultsFile, JSON.stringify(testResults, null, 2))

    console.log(`\n🧪 Mock test results generated: ${testResultsFile}`)
    console.log('Test results preview:')
    testResults.forEach(result => {
      console.log(`  - ${result.file}: ${result.result}`)
    })
  }

  generateMockIssueContent(analysis) {
    const infoLogs = analysis.infoLogs.slice(0, 5).join('\n')
    const warnLogs = analysis.warnLogs.slice(0, 5).join('\n')
    const errorLogs = analysis.errorLogs.slice(0, 5).join('\n')

    return `# [Enhancement] Console Log-Based Improvement

## Enhancement Summary
Enhancement derived from console log analysis.

## Key Logs
### INFO
\`\`\`
${infoLogs}
\`\`\`

### WARN
\`\`\`
${warnLogs}
\`\`\`

### ERROR
\`\`\`
${errorLogs}
\`\`\`

## Identified Patterns
${Object.entries(analysis.patterns).map(([key, pattern]) => 
  `- **${key}**: ${pattern.description} (${pattern.count} occurrences)`
).join('\n')}

## Recommendations
${analysis.recommendations.map(rec => 
  `- **${rec.component}** (${rec.priority}): ${rec.issue} - ${rec.solution}`
).join('\n')}

## Affected Files
- src/hooks/useSearchStreaming.ts
- src/components/AddressInputHandler.tsx
- src/lib/monitoring.ts
- src/app/api/stream-search/route.ts

## Expected Outcome
- Seamless functionality
- Errors and warnings resolved
- Analytics and metrics recorded correctly
`
  }

  generateMockTestResults() {
    return [
      {
        file: 'src/hooks/useSearchStreaming.ts',
        command: 'npm test -- src/hooks/useSearchStreaming.test.ts',
        result: 'PASS',
        output: 'Test Suites: 1 passed, 1 total\nTests: 5 passed, 5 total'
      },
      {
        file: 'src/components/AddressInputHandler.tsx',
        command: 'npm test -- src/components/AddressInputHandler.test.tsx',
        result: 'PASS',
        output: 'Test Suites: 1 passed, 1 total\nTests: 3 passed, 3 total'
      },
      {
        file: 'src/lib/monitoring.ts',
        command: 'npm test -- src/lib/monitoring.test.ts',
        result: 'FAIL',
        output: 'Test Suites: 1 failed, 1 total\nTests: 2 failed, 1 passed, 3 total'
      },
      {
        file: 'src/app/api/stream-search/route.ts',
        command: 'npm run test:integration -- --testPathPattern=stream-search',
        result: 'PASS',
        output: 'Test Suites: 1 passed, 1 total\nTests: 4 passed, 4 total'
      }
    ]
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2)
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Enhancement Workflow Demo

Usage: node scripts/demo-enhancement-workflow.js [options]

Options:
  --help, -h     Show this help message
  --scenario     Run specific scenario (streaming|logging|memory|api)
  --analyze      Only run analysis without full demo

Examples:
  node scripts/demo-enhancement-workflow.js
  node scripts/demo-enhancement-workflow.js --scenario streaming
  node scripts/demo-enhancement-workflow.js --analyze
    `)
    return
  }

  const demo = new WorkflowDemo()

  if (args.includes('--analyze')) {
    await demo.demoConsoleLogAnalysis()
  } else if (args.includes('--scenario')) {
    const scenarioIndex = args.indexOf('--scenario')
    const scenario = args[scenarioIndex + 1]
    
    if (SAMPLE_LOGS[scenario]) {
      console.log(`🎯 Running scenario: ${scenario}`)
      const analyzer = new ConsoleLogAnalyzer(SAMPLE_LOGS[scenario])
      console.log('Analysis:', JSON.stringify(analyzer.analysis, null, 2))
    } else {
      console.error(`❌ Unknown scenario: ${scenario}`)
      console.log('Available scenarios:', Object.keys(SAMPLE_LOGS).join(', '))
    }
  } else {
    await demo.runDemo()
  }
}

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('❌ Demo failed:', error)
    process.exit(1)
  })
}

module.exports = { WorkflowDemo, SAMPLE_LOGS }
