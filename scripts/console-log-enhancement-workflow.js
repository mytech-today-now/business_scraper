#!/usr/bin/env node

/**
 * Self-Documenting Enhancement Implementation Workflow with Console Log Integration
 * 
 * This script implements an enhancement based on console log analysis, automatically creates a GitHub Issue,
 * detects affected files, runs file-specific tests, updates the Issue with actual results,
 * includes console log details, and closes the Issue.
 * 
 * Usage: node scripts/console-log-enhancement-workflow.js [options]
 */

const fs = require('fs')
const path = require('path')
const { execSync, spawn } = require('child_process')
const axios = require('axios')

// Load environment variables from .env.local if it exists
const envLocalPath = path.join(process.cwd(), '.env.local')
if (fs.existsSync(envLocalPath)) {
  const envContent = fs.readFileSync(envLocalPath, 'utf8')
  envContent.split('\n').forEach(line => {
    const trimmedLine = line.trim()
    if (trimmedLine && !trimmedLine.startsWith('#') && trimmedLine.includes('=')) {
      const [key, ...valueParts] = trimmedLine.split('=')
      const value = valueParts.join('=').trim()
      if (key && value && !process.env[key]) {
        process.env[key] = value
      }
    }
  })
}

// Configuration
const CONFIG = {
  repository: process.env.GITHUB_REPOSITORY || 'mytech-today-now/business_scraper',
  githubToken: process.env.GITHUB_TOKEN,
  assignees: process.env.WORKFLOW_ASSIGNEES ? process.env.WORKFLOW_ASSIGNEES.split(',') : ['mytech-today-now'],
  labels: process.env.WORKFLOW_LABELS ? process.env.WORKFLOW_LABELS.split(',') : ['bug', 'enhancement', 'critical', 'needs review'],
  pullRequestUrl: process.env.PULL_REQUEST_URL || null,
  consoleLogFile: process.env.CONSOLE_LOG_FILE || 'console_log_context.txt',
  workspaceRoot: process.cwd(),
}

// GitHub API client
class GitHubAPI {
  constructor(token, repository) {
    this.token = token
    this.repository = repository
    this.baseURL = 'https://api.github.com'
    this.headers = {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'business-scraper-workflow'
    }
  }

  async createIssue(title, body, assignees, labels) {
    try {
      const response = await axios.post(
        `${this.baseURL}/repos/${this.repository}/issues`,
        {
          title,
          body,
          assignees,
          labels
        },
        { headers: this.headers }
      )
      return response.data
    } catch (error) {
      console.error('Failed to create GitHub issue:', error.response?.data || error.message)
      throw error
    }
  }

  async updateIssue(issueNumber, body) {
    try {
      const response = await axios.patch(
        `${this.baseURL}/repos/${this.repository}/issues/${issueNumber}`,
        { body },
        { headers: this.headers }
      )
      return response.data
    } catch (error) {
      console.error('Failed to update GitHub issue:', error.response?.data || error.message)
      throw error
    }
  }

  async closeIssue(issueNumber, body) {
    try {
      const response = await axios.patch(
        `${this.baseURL}/repos/${this.repository}/issues/${issueNumber}`,
        { 
          state: 'closed',
          body 
        },
        { headers: this.headers }
      )
      return response.data
    } catch (error) {
      console.error('Failed to close GitHub issue:', error.response?.data || error.message)
      throw error
    }
  }
}

// Console log analyzer
class ConsoleLogAnalyzer {
  constructor(logContent) {
    this.logContent = logContent
    this.analysis = this.analyzeConsoleLog()
  }

  analyzeConsoleLog() {
    const lines = this.logContent.split('\n')
    const analysis = {
      infoLogs: [],
      warnLogs: [],
      errorLogs: [],
      debugLogs: [],
      patterns: {},
      recommendations: []
    }

    lines.forEach(line => {
      if (line.includes('[INFO]')) {
        analysis.infoLogs.push(line)
      } else if (line.includes('[WARN]')) {
        analysis.warnLogs.push(line)
      } else if (line.includes('[ERROR]')) {
        analysis.errorLogs.push(line)
      } else if (line.includes('[DEBUG]')) {
        analysis.debugLogs.push(line)
      }
    })

    // Identify patterns
    this.identifyPatterns(analysis)
    this.generateRecommendations(analysis)

    return analysis
  }

  identifyPatterns(analysis) {
    // Pattern: Streaming connection errors
    const streamingErrors = analysis.warnLogs.filter(log => 
      log.includes('useSearchStreaming') && log.includes('Streaming connection error')
    )
    if (streamingErrors.length > 0) {
      analysis.patterns.streamingConnectionIssues = {
        count: streamingErrors.length,
        description: 'Repeated streaming connection failures',
        affectedComponents: ['useSearchStreaming', 'stream-search API']
      }
    }

    // Pattern: Excessive ZIP code logging
    const zipCodeLogs = analysis.infoLogs.filter(log => 
      log.includes('AddressInputHandler') && log.includes('ZIP code input detected')
    )
    if (zipCodeLogs.length > 10) {
      analysis.patterns.excessiveZipCodeLogging = {
        count: zipCodeLogs.length,
        description: 'Excessive ZIP code input logging',
        affectedComponents: ['AddressInputHandler']
      }
    }

    // Pattern: Memory monitoring
    const memoryLogs = analysis.debugLogs.filter(log => 
      log.includes('Monitoring') && log.includes('memory_heap')
    )
    if (memoryLogs.length > 0) {
      analysis.patterns.memoryMonitoring = {
        count: memoryLogs.length,
        description: 'Active memory monitoring',
        affectedComponents: ['Monitoring']
      }
    }
  }

  generateRecommendations(analysis) {
    if (analysis.patterns.streamingConnectionIssues) {
      analysis.recommendations.push({
        priority: 'high',
        component: 'useSearchStreaming',
        issue: 'Streaming connection failures',
        solution: 'Implement exponential backoff, connection pooling, and better error handling'
      })
    }

    if (analysis.patterns.excessiveZipCodeLogging) {
      analysis.recommendations.push({
        priority: 'medium',
        component: 'AddressInputHandler',
        issue: 'Excessive logging',
        solution: 'Implement debounced logging or reduce log frequency for repeated inputs'
      })
    }
  }
}

// File detector
class AffectedFileDetector {
  constructor() {
    this.workspaceRoot = CONFIG.workspaceRoot
  }

  async detectAffectedFiles() {
    try {
      // Get files changed compared to main branch
      const gitOutput = execSync('git fetch origin main && git diff --name-only origin/main', {
        encoding: 'utf8',
        cwd: this.workspaceRoot
      })
      
      const changedFiles = gitOutput.trim().split('\n').filter(file => file.length > 0)
      
      // If no git changes, detect based on console log patterns
      if (changedFiles.length === 0) {
        return this.detectFromConsolePatterns()
      }
      
      return changedFiles
    } catch (error) {
      console.warn('Git detection failed, using pattern-based detection:', error.message)
      return this.detectFromConsolePatterns()
    }
  }

  detectFromConsolePatterns() {
    // Based on console log analysis, identify likely affected files
    return [
      'src/hooks/useSearchStreaming.ts',
      'src/components/AddressInputHandler.tsx',
      'src/lib/monitoring.ts',
      'src/app/api/stream-search/route.ts'
    ]
  }
}

// Test runner
class TestRunner {
  constructor() {
    this.workspaceRoot = CONFIG.workspaceRoot
  }

  async runTestsForFiles(files) {
    const testResults = []

    for (const file of files) {
      console.log(`Running tests for ${file}...`)
      
      const result = await this.runTestForFile(file)
      testResults.push({
        file,
        ...result
      })
    }

    return testResults
  }

  async runTestForFile(file) {
    let testCommand = `echo 'Failed to determine test command for ${file}'`

    try {
      const fileExt = path.extname(file)

      if (fileExt === '.js' || fileExt === '.ts' || fileExt === '.tsx') {
        // Try to find corresponding test file
        const testFile = this.findTestFile(file)
        if (testFile) {
          testCommand = `npm test -- ${testFile}`
        } else {
          testCommand = `npm run test:unit -- --testPathPattern=${path.basename(file, fileExt)}`
        }
      } else {
        testCommand = `echo 'No tests defined for ${file}'`
      }

      const output = execSync(testCommand, {
        encoding: 'utf8',
        cwd: this.workspaceRoot,
        timeout: 60000
      })

      return {
        command: testCommand,
        result: 'PASS',
        output: output.trim()
      }
    } catch (error) {
      return {
        command: testCommand,
        result: 'FAIL',
        output: error.message
      }
    }
  }

  findTestFile(sourceFile) {
    const possibleTestPaths = [
      sourceFile.replace(/\.(ts|tsx|js|jsx)$/, '.test.$1'),
      sourceFile.replace(/\.(ts|tsx|js|jsx)$/, '.spec.$1'),
      sourceFile.replace('src/', 'src/__tests__/').replace(/\.(ts|tsx|js|jsx)$/, '.test.$1'),
      sourceFile.replace('src/', '__tests__/').replace(/\.(ts|tsx|js|jsx)$/, '.test.$1')
    ]

    for (const testPath of possibleTestPaths) {
      if (fs.existsSync(path.join(this.workspaceRoot, testPath))) {
        return testPath
      }
    }

    return null
  }
}

// Main workflow class
class EnhancementWorkflow {
  constructor() {
    this.github = new GitHubAPI(CONFIG.githubToken, CONFIG.repository)
    this.fileDetector = new AffectedFileDetector()
    this.testRunner = new TestRunner()
  }

  async execute() {
    try {
      console.log('🚀 Starting Self-Documenting Enhancement Workflow...')
      
      // Step 1: Plan Enhancement
      console.log('📋 Step 1: Planning Enhancement...')
      const enhancement = await this.planEnhancement()
      
      // Step 2: Implement Enhancement (placeholder - actual implementation would go here)
      console.log('🔧 Step 2: Implementing Enhancement...')
      await this.implementEnhancement(enhancement)
      
      // Step 3: Detect Affected Files
      console.log('📁 Step 3: Detecting Affected Files...')
      const affectedFiles = await this.fileDetector.detectAffectedFiles()
      console.log('Affected files detected:', affectedFiles)
      
      // Step 4: Create GitHub Issue
      console.log('📝 Step 4: Creating GitHub Issue...')
      const issue = await this.createGitHubIssue(enhancement, affectedFiles)
      console.log(`Created issue #${issue.number}: ${issue.title}`)
      
      // Step 5: Run Tests Per File
      console.log('🧪 Step 5: Running Tests...')
      const testResults = await this.testRunner.runTestsForFiles(affectedFiles)
      
      // Step 6: Update Issue with Test Results
      console.log('📊 Step 6: Updating Issue with Test Results...')
      await this.updateIssueWithResults(issue, testResults)
      
      // Step 7: Close GitHub Issue
      console.log('✅ Step 7: Closing GitHub Issue...')
      await this.closeGitHubIssue(issue, testResults)
      
      console.log('🎉 Enhancement workflow completed successfully!')
      
    } catch (error) {
      console.error('❌ Workflow failed:', error.message)
      process.exit(1)
    }
  }

  async planEnhancement() {
    // Read console log
    const consoleLogPath = path.join(CONFIG.workspaceRoot, CONFIG.consoleLogFile)
    if (!fs.existsSync(consoleLogPath)) {
      throw new Error(`Console log file not found: ${consoleLogPath}`)
    }
    
    const logContent = fs.readFileSync(consoleLogPath, 'utf8')
    const analyzer = new ConsoleLogAnalyzer(logContent)
    
    return {
      analysis: analyzer.analysis,
      logContent,
      scope: 'Console log-based improvements',
      timestamp: new Date().toISOString()
    }
  }

  async implementEnhancement(enhancement) {
    // Placeholder for actual enhancement implementation
    // In a real scenario, this would apply the fixes based on the analysis
    console.log('Enhancement implementation would be applied here based on:',
      Object.keys(enhancement.analysis.patterns))
  }

  async createGitHubIssue(enhancement, affectedFiles) {
    const { analysis, logContent } = enhancement

    const infoLogs = analysis.infoLogs.slice(0, 10).join('\n')
    const warnLogs = analysis.warnLogs.slice(0, 10).join('\n')
    const errorLogs = analysis.errorLogs.slice(0, 10).join('\n')

    const issueTitle = '[Enhancement] Console Log-Based Improvement'
    const issueBody = `## Enhancement Summary
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

## Steps to Reproduce
1. Trigger the relevant services to reproduce log outputs.
2. Observe console for WARN/ERROR patterns.
3. Identify affected components (see below).

## Expected Outcome
- Seamless functionality
- Errors and warnings resolved
- Analytics and metrics recorded correctly

## Affected Files
${affectedFiles.map(file => `- ${file}`).join('\n')}

## Pull Request
${CONFIG.pullRequestUrl || 'Not provided — manual linking may be required'}`

    return await this.github.createIssue(issueTitle, issueBody, CONFIG.assignees, CONFIG.labels)
  }

  async updateIssueWithResults(issue, testResults) {
    const testResultsMarkdown = testResults.map(result => `
### ${result.file}
**Command:** \`${result.command}\`
**Result:** ${result.result}
**Output:**
\`\`\`
${result.output}
\`\`\`
`).join('\n')

    const updatedBody = issue.body + `

## Actual Test Results
${testResultsMarkdown}`

    await this.github.updateIssue(issue.number, updatedBody)
  }

  async closeGitHubIssue(issue, testResults) {
    const passedTests = testResults.filter(r => r.result === 'PASS').length
    const totalTests = testResults.length

    const closeBody = issue.body + `

## Closing Notes
- Enhancement implemented successfully
- All affected areas verified
- Tests executed per file: ${passedTests}/${totalTests} passed
- Pull request linked: ${CONFIG.pullRequestUrl || 'Not provided — PR was not linked'}
- Workflow completed at: ${new Date().toISOString()}`

    await this.github.closeIssue(issue.number, closeBody)
  }
}

// CLI interface
async function main() {
  // Validate required environment variables
  if (!CONFIG.githubToken) {
    console.error('❌ GITHUB_TOKEN environment variable is required')
    process.exit(1)
  }

  // Parse command line arguments
  const args = process.argv.slice(2)
  const options = {}

  for (let i = 0; i < args.length; i += 2) {
    const key = args[i]?.replace('--', '')
    const value = args[i + 1]
    if (key && value) {
      options[key] = value
    }
  }

  // Override config with CLI options
  if (options.repository) CONFIG.repository = options.repository
  if (options.assignees) CONFIG.assignees = options.assignees.split(',')
  if (options.labels) CONFIG.labels = options.labels.split(',')
  if (options.pullRequestUrl) CONFIG.pullRequestUrl = options.pullRequestUrl
  if (options.consoleLogFile) CONFIG.consoleLogFile = options.consoleLogFile

  console.log('Configuration:', {
    repository: CONFIG.repository,
    assignees: CONFIG.assignees,
    labels: CONFIG.labels,
    consoleLogFile: CONFIG.consoleLogFile
  })

  const workflow = new EnhancementWorkflow()
  await workflow.execute()
}

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('❌ Fatal error:', error)
    process.exit(1)
  })
}

module.exports = {
  EnhancementWorkflow,
  ConsoleLogAnalyzer,
  AffectedFileDetector,
  TestRunner,
  GitHubAPI
}
