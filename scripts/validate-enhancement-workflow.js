#!/usr/bin/env node

/**
 * Business Scraper Enhancement Workflow Validation Script
 * 
 * This script validates that the enhancement workflow is properly configured
 * and all required dependencies are available.
 */

const fs = require('fs')
const path = require('path')
const { execSync } = require('child_process')

class WorkflowValidator {
  constructor() {
    this.projectRoot = process.cwd()
    this.errors = []
    this.warnings = []
    this.info = []
  }

  log(message, level = 'INFO') {
    const timestamp = new Date().toISOString()
    const logMessage = `[${timestamp}] [${level}] ${message}`
    
    switch (level) {
      case 'ERROR':
        this.errors.push(message)
        console.error(`❌ ${logMessage}`)
        break
      case 'WARN':
        this.warnings.push(message)
        console.warn(`⚠️  ${logMessage}`)
        break
      case 'INFO':
        this.info.push(message)
        console.log(`ℹ️  ${logMessage}`)
        break
      case 'SUCCESS':
        console.log(`✅ ${logMessage}`)
        break
    }
  }

  checkFileExists(filePath, required = true) {
    const fullPath = path.join(this.projectRoot, filePath)
    const exists = fs.existsSync(fullPath)
    
    if (exists) {
      this.log(`File exists: ${filePath}`, 'SUCCESS')
    } else if (required) {
      this.log(`Required file missing: ${filePath}`, 'ERROR')
    } else {
      this.log(`Optional file missing: ${filePath}`, 'WARN')
    }
    
    return exists
  }

  checkDirectoryExists(dirPath, required = true) {
    const fullPath = path.join(this.projectRoot, dirPath)
    const exists = fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory()
    
    if (exists) {
      this.log(`Directory exists: ${dirPath}`, 'SUCCESS')
    } else if (required) {
      this.log(`Required directory missing: ${dirPath}`, 'ERROR')
    } else {
      this.log(`Optional directory missing: ${dirPath}`, 'WARN')
    }
    
    return exists
  }

  checkCommand(command, required = true) {
    try {
      execSync(`${command} --version`, { stdio: 'pipe' })
      this.log(`Command available: ${command}`, 'SUCCESS')
      return true
    } catch (error) {
      if (required) {
        this.log(`Required command missing: ${command}`, 'ERROR')
      } else {
        this.log(`Optional command missing: ${command}`, 'WARN')
      }
      return false
    }
  }

  checkNpmScript(scriptName, required = true) {
    try {
      const packageJson = JSON.parse(fs.readFileSync(path.join(this.projectRoot, 'package.json'), 'utf8'))
      const exists = packageJson.scripts && packageJson.scripts[scriptName]
      
      if (exists) {
        this.log(`NPM script exists: ${scriptName}`, 'SUCCESS')
      } else if (required) {
        this.log(`Required NPM script missing: ${scriptName}`, 'ERROR')
      } else {
        this.log(`Optional NPM script missing: ${scriptName}`, 'WARN')
      }
      
      return exists
    } catch (error) {
      this.log(`Error checking NPM script ${scriptName}: ${error.message}`, 'ERROR')
      return false
    }
  }

  checkGitRepository() {
    try {
      execSync('git status', { stdio: 'pipe', cwd: this.projectRoot })
      this.log('Git repository detected', 'SUCCESS')
      
      // Check for remote origin
      try {
        const remote = execSync('git remote get-url origin', { 
          encoding: 'utf8', 
          cwd: this.projectRoot 
        }).trim()
        this.log(`Git remote origin: ${remote}`, 'SUCCESS')
        
        // Validate it's the expected repository
        if (remote.includes('mytech-today-now/business_scraper')) {
          this.log('Repository matches expected business_scraper repo', 'SUCCESS')
        } else {
          this.log('Repository does not match expected business_scraper repo', 'WARN')
        }
      } catch (error) {
        this.log('No git remote origin configured', 'WARN')
      }
      
      return true
    } catch (error) {
      this.log('Not a git repository or git not available', 'ERROR')
      return false
    }
  }

  checkProjectStructure() {
    this.log('Validating project structure...', 'INFO')
    
    // Required directories
    const requiredDirs = [
      'src',
      'src/view',
      'src/lib', 
      'src/app',
      'src/model',
      'src/controller',
      'docs',
      'scripts',
      '.github/workflows'
    ]
    
    requiredDirs.forEach(dir => this.checkDirectoryExists(dir, true))
    
    // Optional directories
    const optionalDirs = [
      'src/tests',
      'src/hooks',
      'test-results',
      'logs',
      'backups'
    ]
    
    optionalDirs.forEach(dir => this.checkDirectoryExists(dir, false))
  }

  checkRequiredFiles() {
    this.log('Validating required files...', 'INFO')
    
    // Core project files
    const requiredFiles = [
      'package.json',
      'next.config.js',
      'tsconfig.json',
      'jest.config.js',
      'playwright.config.ts',
      '.github/workflows/business-scraper-enhancement.yml',
      'scripts/business-scraper-enhancement.js',
      'config/enhancement-workflow.env.example'
    ]
    
    requiredFiles.forEach(file => this.checkFileExists(file, true))
    
    // Documentation files
    const docFiles = [
      'README.md',
      'CHANGELOG.md',
      'docs/BUSINESS_SCRAPER_ENHANCEMENT_WORKFLOW.md'
    ]
    
    docFiles.forEach(file => this.checkFileExists(file, true))
  }

  checkNpmScripts() {
    this.log('Validating NPM scripts...', 'INFO')
    
    // Required test scripts
    const requiredScripts = [
      'test',
      'test:unit',
      'test:integration',
      'test:coverage',
      'build',
      'dev'
    ]
    
    requiredScripts.forEach(script => this.checkNpmScript(script, true))
    
    // Optional test scripts
    const optionalScripts = [
      'test:e2e',
      'test:security',
      'test:performance',
      'test:accessibility'
    ]
    
    optionalScripts.forEach(script => this.checkNpmScript(script, false))
  }

  checkSystemCommands() {
    this.log('Validating system commands...', 'INFO')
    
    // Required commands
    const requiredCommands = [
      'node',
      'npm',
      'git'
    ]
    
    requiredCommands.forEach(cmd => this.checkCommand(cmd, true))
    
    // Optional commands
    const optionalCommands = [
      'yarn',
      'docker'
    ]
    
    optionalCommands.forEach(cmd => this.checkCommand(cmd, false))
  }

  checkConfiguration() {
    this.log('Validating configuration...', 'INFO')
    
    // Check if configuration file exists
    const configExists = this.checkFileExists('config/enhancement-workflow.env', false)
    
    if (!configExists) {
      this.log('Configuration file not found. Copy config/enhancement-workflow.env.example to config/enhancement-workflow.env', 'WARN')
    }
    
    // Validate package.json structure
    try {
      const packageJson = JSON.parse(fs.readFileSync(path.join(this.projectRoot, 'package.json'), 'utf8'))
      
      if (packageJson.name === 'business-scraper-app') {
        this.log('Package name matches expected value', 'SUCCESS')
      } else {
        this.log(`Package name mismatch: expected 'business-scraper-app', got '${packageJson.name}'`, 'WARN')
      }
      
      if (packageJson.scripts) {
        this.log(`Found ${Object.keys(packageJson.scripts).length} NPM scripts`, 'SUCCESS')
      } else {
        this.log('No NPM scripts found in package.json', 'ERROR')
      }
      
    } catch (error) {
      this.log(`Error reading package.json: ${error.message}`, 'ERROR')
    }
  }

  checkDependencies() {
    this.log('Validating dependencies...', 'INFO')
    
    try {
      const packageJson = JSON.parse(fs.readFileSync(path.join(this.projectRoot, 'package.json'), 'utf8'))
      
      // Check for key dependencies
      const keyDependencies = [
        'next',
        'react',
        'typescript'
      ]
      
      const keyDevDependencies = [
        'jest',
        '@playwright/test',
        '@testing-library/react'
      ]
      
      keyDependencies.forEach(dep => {
        if (packageJson.dependencies && packageJson.dependencies[dep]) {
          this.log(`Dependency found: ${dep}`, 'SUCCESS')
        } else {
          this.log(`Missing dependency: ${dep}`, 'ERROR')
        }
      })
      
      keyDevDependencies.forEach(dep => {
        if (packageJson.devDependencies && packageJson.devDependencies[dep]) {
          this.log(`Dev dependency found: ${dep}`, 'SUCCESS')
        } else {
          this.log(`Missing dev dependency: ${dep}`, 'WARN')
        }
      })
      
    } catch (error) {
      this.log(`Error checking dependencies: ${error.message}`, 'ERROR')
    }
  }

  async runValidation() {
    this.log('🔍 Starting Business Scraper Enhancement Workflow Validation', 'INFO')
    this.log('=' .repeat(80), 'INFO')
    
    // Run all validation checks
    this.checkGitRepository()
    this.checkProjectStructure()
    this.checkRequiredFiles()
    this.checkNpmScripts()
    this.checkSystemCommands()
    this.checkConfiguration()
    this.checkDependencies()
    
    // Generate summary
    this.generateSummary()
    
    return {
      errors: this.errors,
      warnings: this.warnings,
      info: this.info,
      isValid: this.errors.length === 0
    }
  }

  generateSummary() {
    this.log('=' .repeat(80), 'INFO')
    this.log('🎯 Validation Summary', 'INFO')
    this.log('=' .repeat(80), 'INFO')
    
    if (this.errors.length === 0) {
      this.log('✅ All critical validations passed!', 'SUCCESS')
      this.log('The enhancement workflow is ready to use.', 'SUCCESS')
    } else {
      this.log(`❌ Found ${this.errors.length} critical error(s):`, 'ERROR')
      this.errors.forEach(error => console.log(`   - ${error}`))
    }
    
    if (this.warnings.length > 0) {
      this.log(`⚠️  Found ${this.warnings.length} warning(s):`, 'WARN')
      this.warnings.forEach(warning => console.log(`   - ${warning}`))
    }
    
    this.log(`ℹ️  Total checks performed: ${this.info.length}`, 'INFO')
    
    // Recommendations
    if (this.errors.length > 0) {
      this.log('🔧 Recommendations:', 'INFO')
      this.log('1. Fix all critical errors before using the workflow', 'INFO')
      this.log('2. Review the Business Scraper Enhancement Workflow documentation', 'INFO')
      this.log('3. Ensure all required dependencies are installed', 'INFO')
    }
    
    if (this.warnings.length > 0) {
      this.log('💡 Suggestions:', 'INFO')
      this.log('1. Address warnings to improve workflow reliability', 'INFO')
      this.log('2. Copy and configure config/enhancement-workflow.env', 'INFO')
      this.log('3. Install optional dependencies for full functionality', 'INFO')
    }
  }
}

// CLI interface
async function main() {
  const args = process.argv.slice(2)
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Business Scraper Enhancement Workflow Validator

Usage: node scripts/validate-enhancement-workflow.js [options]

Options:
  --help, -h     Show this help message
  --quiet        Suppress info messages
  --json         Output results in JSON format

Examples:
  node scripts/validate-enhancement-workflow.js
  node scripts/validate-enhancement-workflow.js --quiet
  node scripts/validate-enhancement-workflow.js --json
    `)
    return
  }
  
  const validator = new WorkflowValidator()
  const results = await validator.runValidation()
  
  if (args.includes('--json')) {
    console.log(JSON.stringify(results, null, 2))
  }
  
  // Exit with error code if validation failed
  process.exit(results.isValid ? 0 : 1)
}

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('❌ Validation failed:', error.message)
    process.exit(1)
  })
}

module.exports = { WorkflowValidator }
