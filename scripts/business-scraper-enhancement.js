#!/usr/bin/env node

/**
 * Business Scraper Enhancement Implementation Script
 * Adapted for the business_scraper project structure and testing framework
 * 
 * This script provides local enhancement implementation with automatic
 * documentation updates and comprehensive testing.
 */

const fs = require('fs')
const path = require('path')
const { execSync } = require('child_process')

class BusinessScraperEnhancement {
  constructor(options = {}) {
    this.projectRoot = process.cwd()
    this.enhancementDescription = options.enhancement || 'General enhancement'
    this.dryRun = options.dryRun || false
    this.verbose = options.verbose || false
    
    // Business scraper specific paths
    this.paths = {
      src: path.join(this.projectRoot, 'src'),
      docs: path.join(this.projectRoot, 'docs'),
      tests: path.join(this.projectRoot, 'src', 'tests'),
      testResults: path.join(this.projectRoot, 'test-results'),
      logs: path.join(this.projectRoot, 'logs'),
      backups: path.join(this.projectRoot, 'backups')
    }
    
    // Documentation files specific to business_scraper
    this.docFiles = [
      'docs/UX-ToDo.html',
      'docs/Remaining-Work.html',
      'docs/MVP2.html', 
      'docs/MVP.html',
      'docs/MVP_REFACTOR_SUMMARY.html',
      'docs/MVP_IMPLEMENTATION_GUIDE.html',
      'docs/API_DOCUMENTATION.html',
      'docs/FEATURE_GUIDE.html',
      'docs/TESTING.md',
      'README.md',
      'CHANGELOG.md'
    ]
    
    this.ensureDirectories()
  }

  ensureDirectories() {
    const dirs = [this.paths.testResults, path.join(this.paths.testResults, 'enhancement')]
    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true })
      }
    })
  }

  log(message, level = 'INFO') {
    const timestamp = new Date().toISOString()
    const logMessage = `[${timestamp}] [${level}] ${message}`
    console.log(logMessage)
    
    if (this.verbose) {
      const logFile = path.join(this.paths.logs, 'enhancement.log')
      fs.appendFileSync(logFile, logMessage + '\n')
    }
  }

  async detectAffectedFiles() {
    this.log('🔍 Detecting affected files...')
    
    try {
      // Try to detect files changed from main branch
      const gitDiff = execSync('git diff --name-only origin/main 2>/dev/null || echo ""', { 
        encoding: 'utf8',
        cwd: this.projectRoot 
      }).trim()
      
      if (gitDiff) {
        const files = gitDiff.split('\n').filter(f => f.trim())
        this.log(`Found ${files.length} files changed from main branch`)
        return files
      }
      
      // Fallback: detect files that might be affected based on common patterns
      this.log('Using heuristic detection for potentially affected files...')
      
      const patterns = [
        'src/view/components/**/*.{ts,tsx}',
        'src/lib/**/*.ts',
        'src/app/api/**/*.ts',
        'src/model/**/*.ts',
        'src/controller/**/*.ts'
      ]
      
      const files = []
      patterns.forEach(pattern => {
        try {
          const found = execSync(`find ${this.paths.src} -path "${pattern.replace('**/', '')}" -type f 2>/dev/null || echo ""`, {
            encoding: 'utf8',
            cwd: this.projectRoot
          }).trim().split('\n').filter(f => f.trim())
          
          files.push(...found.slice(0, 5)) // Limit to 5 files per pattern
        } catch (error) {
          // Ignore find errors
        }
      })
      
      return [...new Set(files)] // Remove duplicates
      
    } catch (error) {
      this.log(`Error detecting files: ${error.message}`, 'WARN')
      return []
    }
  }

  async runTestsForFile(filePath) {
    this.log(`🧪 Running tests for: ${filePath}`)
    
    const fileName = path.basename(filePath, path.extname(filePath))
    const fileDir = path.dirname(filePath)
    
    let testCommand = ''
    let testType = 'unit'
    
    // Determine appropriate test command based on file location and type
    if (filePath.includes('src/view/') && filePath.endsWith('.tsx')) {
      // React component
      testCommand = `npm run test:unit -- --testPathPattern=${fileName}`
      testType = 'component'
    } else if (filePath.includes('src/lib/') && filePath.endsWith('.ts')) {
      // Service/library
      testCommand = `npm run test:unit -- --testPathPattern=${fileName}`
      testType = 'service'
    } else if (filePath.includes('src/app/api/')) {
      // API endpoint
      testCommand = `npm run test:integration -- --testPathPattern=api`
      testType = 'api'
    } else if (filePath.includes('src/model/')) {
      // Data model
      testCommand = `npm run test:unit -- --testPathPattern=${fileName}`
      testType = 'model'
    } else if (filePath.includes('src/controller/')) {
      // Controller
      testCommand = `npm run test:unit -- --testPathPattern=${fileName}`
      testType = 'controller'
    } else {
      // Generic test
      testCommand = `npm run test:unit -- --testPathPattern=${fileName}`
      testType = 'generic'
    }
    
    const logFile = path.join(this.paths.testResults, 'enhancement', `${fileName}-test.log`)
    
    try {
      if (this.dryRun) {
        this.log(`[DRY RUN] Would run: ${testCommand}`)
        return {
          file: filePath,
          command: testCommand,
          result: 'DRY_RUN',
          output: 'Dry run - no actual test execution',
          type: testType
        }
      }
      
      const output = execSync(testCommand, {
        encoding: 'utf8',
        cwd: this.projectRoot,
        timeout: 60000 // 1 minute timeout
      })
      
      fs.writeFileSync(logFile, output)
      
      this.log(`✅ Tests passed for ${filePath}`)
      return {
        file: filePath,
        command: testCommand,
        result: 'PASS',
        output: output.split('\n').slice(0, 5).join('\n'), // First 5 lines
        type: testType
      }
      
    } catch (error) {
      const errorOutput = error.stdout || error.message
      fs.writeFileSync(logFile, errorOutput)
      
      this.log(`❌ Tests failed for ${filePath}: ${error.message}`, 'ERROR')
      return {
        file: filePath,
        command: testCommand,
        result: 'FAIL',
        output: errorOutput.split('\n').slice(0, 5).join('\n'),
        type: testType,
        error: error.message
      }
    }
  }

  async updateDocumentation(affectedFiles) {
    this.log('📚 Updating project documentation...')
    
    const timestamp = new Date().toISOString()
    const backupDir = path.join(this.paths.backups, `docs-${Date.now()}`)
    
    if (!this.dryRun) {
      fs.mkdirSync(backupDir, { recursive: true })
    }
    
    for (const docFile of this.docFiles) {
      const fullPath = path.join(this.projectRoot, docFile)
      
      if (!fs.existsSync(fullPath)) {
        continue
      }
      
      if (this.dryRun) {
        this.log(`[DRY RUN] Would update documentation: ${docFile}`)
        continue
      }
      
      // Backup original
      const backupPath = path.join(backupDir, path.basename(docFile))
      fs.copyFileSync(fullPath, backupPath)
      
      // Create enhancement note
      const enhancementNote = this.createEnhancementNote(affectedFiles, timestamp)
      
      try {
        let content = fs.readFileSync(fullPath, 'utf8')
        
        if (docFile.endsWith('.html')) {
          // For HTML files, inject before closing body tag
          if (content.includes('</body>')) {
            content = content.replace('</body>', `${enhancementNote}\n</body>`)
          } else {
            content += enhancementNote
          }
        } else if (docFile.endsWith('.md')) {
          // For Markdown files, append at the end
          content += `\n\n## Recent Enhancement\n\n${enhancementNote}\n`
        }
        
        fs.writeFileSync(fullPath, content)
        this.log(`✅ Updated documentation: ${docFile}`)
        
      } catch (error) {
        this.log(`❌ Failed to update ${docFile}: ${error.message}`, 'ERROR')
      }
    }
    
    this.log(`📁 Documentation backups saved to: ${backupDir}`)
  }

  createEnhancementNote(affectedFiles, timestamp) {
    const fileList = affectedFiles.map(f => `- \`${f}\``).join('\n')
    
    return `
<!-- Enhancement Update: ${timestamp} -->
<div class="enhancement-note" style="border: 1px solid #e1e5e9; border-radius: 6px; padding: 16px; margin: 16px 0; background-color: #f6f8fa;">
  <h4>🔄 Enhancement Applied</h4>
  <p><strong>Description:</strong> ${this.enhancementDescription}</p>
  <p><strong>Date:</strong> ${timestamp}</p>
  <p><strong>Affected Files:</strong></p>
  <ul>
    ${affectedFiles.map(f => `<li><code>${f}</code></li>`).join('\n    ')}
  </ul>
  <p><em>Please review related sections and verify functionality.</em></p>
</div>`
  }

  async runComprehensiveTests() {
    this.log('🧪 Running comprehensive test suite...')
    
    const testSuites = [
      { name: 'Unit Tests', command: 'npm run test:unit' },
      { name: 'Integration Tests', command: 'npm run test:integration' },
      { name: 'Security Tests', command: 'npm run test:security' },
      { name: 'Performance Tests', command: 'npm run test:performance' },
      { name: 'Coverage Report', command: 'npm run test:coverage' }
    ]
    
    const results = []
    
    for (const suite of testSuites) {
      const logFile = path.join(this.paths.testResults, 'enhancement', `${suite.name.toLowerCase().replace(' ', '-')}.log`)
      
      try {
        if (this.dryRun) {
          this.log(`[DRY RUN] Would run: ${suite.command}`)
          results.push({
            name: suite.name,
            command: suite.command,
            result: 'DRY_RUN',
            output: 'Dry run - no actual test execution'
          })
          continue
        }
        
        this.log(`Running ${suite.name}...`)
        const output = execSync(suite.command, {
          encoding: 'utf8',
          cwd: this.projectRoot,
          timeout: 300000 // 5 minute timeout
        })
        
        fs.writeFileSync(logFile, output)
        
        results.push({
          name: suite.name,
          command: suite.command,
          result: 'PASS',
          output: output.split('\n').slice(-10).join('\n') // Last 10 lines
        })
        
        this.log(`✅ ${suite.name} completed successfully`)
        
      } catch (error) {
        const errorOutput = error.stdout || error.message
        fs.writeFileSync(logFile, errorOutput)
        
        results.push({
          name: suite.name,
          command: suite.command,
          result: 'FAIL',
          output: errorOutput.split('\n').slice(-10).join('\n'),
          error: error.message
        })
        
        this.log(`❌ ${suite.name} failed: ${error.message}`, 'ERROR')
      }
    }
    
    return results
  }

  async generateReport(affectedFiles, testResults, comprehensiveResults) {
    this.log('📊 Generating enhancement report...')
    
    const reportPath = path.join(this.paths.testResults, 'enhancement', 'enhancement-report.md')
    const timestamp = new Date().toISOString()
    
    const report = `# Business Scraper Enhancement Report

## Enhancement Summary
**Description:** ${this.enhancementDescription}
**Date:** ${timestamp}
**Mode:** ${this.dryRun ? 'DRY RUN' : 'LIVE EXECUTION'}

## Affected Files (${affectedFiles.length})
${affectedFiles.map(f => `- \`${f}\``).join('\n')}

## File-Specific Test Results
${testResults.map(result => `
### ${result.file}
- **Type:** ${result.type}
- **Command:** \`${result.command}\`
- **Result:** ${result.result}
- **Output:**
\`\`\`
${result.output}
\`\`\`
${result.error ? `- **Error:** ${result.error}` : ''}
`).join('\n')}

## Comprehensive Test Results
${comprehensiveResults.map(result => `
### ${result.name}
- **Command:** \`${result.command}\`
- **Result:** ${result.result}
- **Output:**
\`\`\`
${result.output}
\`\`\`
${result.error ? `- **Error:** ${result.error}` : ''}
`).join('\n')}

## Summary
- **Total Files Affected:** ${affectedFiles.length}
- **File Tests Passed:** ${testResults.filter(r => r.result === 'PASS').length}
- **File Tests Failed:** ${testResults.filter(r => r.result === 'FAIL').length}
- **Comprehensive Tests Passed:** ${comprehensiveResults.filter(r => r.result === 'PASS').length}
- **Comprehensive Tests Failed:** ${comprehensiveResults.filter(r => r.result === 'FAIL').length}

## Next Steps
1. Review failed tests and address issues
2. Verify enhanced functionality in development environment
3. Update any additional documentation as needed
4. Consider creating a pull request for the changes

---
*Report generated by Business Scraper Enhancement Script*
`
    
    if (!this.dryRun) {
      fs.writeFileSync(reportPath, report)
    }
    
    this.log(`📄 Enhancement report ${this.dryRun ? 'would be' : ''} saved to: ${reportPath}`)
    return report
  }

  async execute() {
    this.log(`🚀 Starting Business Scraper Enhancement: ${this.enhancementDescription}`)
    this.log(`Mode: ${this.dryRun ? 'DRY RUN' : 'LIVE EXECUTION'}`)
    
    try {
      // Step 1: Detect affected files
      const affectedFiles = await this.detectAffectedFiles()
      this.log(`📁 Detected ${affectedFiles.length} potentially affected files`)
      
      // Step 2: Run tests for each affected file
      const testResults = []
      for (const file of affectedFiles) {
        const result = await this.runTestsForFile(file)
        testResults.push(result)
      }
      
      // Step 3: Update documentation
      await this.updateDocumentation(affectedFiles)
      
      // Step 4: Run comprehensive test suite
      const comprehensiveResults = await this.runComprehensiveTests()
      
      // Step 5: Generate report
      const report = await this.generateReport(affectedFiles, testResults, comprehensiveResults)
      
      this.log('✅ Enhancement workflow completed successfully!')
      
      return {
        affectedFiles,
        testResults,
        comprehensiveResults,
        report
      }
      
    } catch (error) {
      this.log(`❌ Enhancement workflow failed: ${error.message}`, 'ERROR')
      throw error
    }
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2)
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Business Scraper Enhancement Script

Usage: node scripts/business-scraper-enhancement.js [options]

Options:
  --enhancement <description>  Enhancement description (required)
  --dry-run                   Run in dry-run mode (no actual changes)
  --verbose                   Enable verbose logging
  --help, -h                  Show this help message

Examples:
  node scripts/business-scraper-enhancement.js --enhancement "Improve search performance"
  node scripts/business-scraper-enhancement.js --enhancement "Fix memory leaks" --dry-run
  node scripts/business-scraper-enhancement.js --enhancement "Add new API endpoint" --verbose
    `)
    return
  }
  
  const enhancementIndex = args.indexOf('--enhancement')
  const enhancement = enhancementIndex !== -1 ? args[enhancementIndex + 1] : null
  
  if (!enhancement) {
    console.error('❌ Enhancement description is required. Use --enhancement "description"')
    process.exit(1)
  }
  
  const options = {
    enhancement,
    dryRun: args.includes('--dry-run'),
    verbose: args.includes('--verbose')
  }
  
  const enhancer = new BusinessScraperEnhancement(options)
  
  try {
    await enhancer.execute()
    console.log('\n🎉 Enhancement workflow completed successfully!')
  } catch (error) {
    console.error('\n❌ Enhancement workflow failed:', error.message)
    process.exit(1)
  }
}

// Run if called directly
if (require.main === module) {
  main()
}

module.exports = { BusinessScraperEnhancement }
