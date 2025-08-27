#!/usr/bin/env node

/**
 * Documentation Validation Script
 * Validates documentation files for consistency, accuracy, and quality
 */

const fs = require('fs')
const path = require('path')
const { execSync } = require('child_process')

// Configuration
const CONFIG = {
  docsDir: path.join(__dirname, '..', 'docs'),
  rootDir: path.join(__dirname, '..'),
  requiredFiles: [
    'README.md',
    'CHANGELOG.md',
    'VERSION',
    'docs/README.md',
    'docs/API_DOCUMENTATION.md',
    'docs/CRM_EXPORT_GUIDE.md',
    'docs/DOCUMENTATION_STANDARDS.md',
    'docs/CONTRIBUTING_DOCUMENTATION.md',
  ],
  versionFiles: [
    'VERSION',
    'package.json',
    'README.md',
    'docs/README.md',
    'docs/API_DOCUMENTATION.md',
  ],
  linkPatterns: [
    /\[([^\]]+)\]\(([^)]+)\)/g, // Markdown links
    /href="([^"]+)"/g, // HTML links
    /src="([^"]+)"/g, // Image sources
  ],
}

class DocumentationValidator {
  constructor() {
    this.errors = []
    this.warnings = []
    this.currentVersion = null
  }

  /**
   * Main validation function
   */
  async validate() {
    console.log('🔍 Starting documentation validation...\n')

    try {
      this.loadCurrentVersion()
      await this.validateRequiredFiles()
      await this.validateVersionConsistency()
      await this.validateMarkdownFiles()
      await this.validateLinks()
      await this.validateCodeExamples()
      await this.generateReport()
    } catch (error) {
      this.errors.push(`Validation failed: ${error.message}`)
    }

    this.printResults()
    return this.errors.length === 0
  }

  /**
   * Load current version from VERSION file
   */
  loadCurrentVersion() {
    try {
      const versionPath = path.join(__dirname, '..', 'VERSION')
      this.currentVersion = fs.readFileSync(versionPath, 'utf8').trim()
      console.log(`📋 Current version: ${this.currentVersion}`)
    } catch (error) {
      this.errors.push(`VERSION file not found or unreadable: ${error.message}`)
    }
  }

  /**
   * Validate that all required documentation files exist
   */
  async validateRequiredFiles() {
    console.log('📁 Validating required files...')

    for (const file of CONFIG.requiredFiles) {
      const filePath = path.join(__dirname, '..', file)
      if (!fs.existsSync(filePath)) {
        this.errors.push(`Required file missing: ${file}`)
      } else {
        const stats = fs.statSync(filePath)
        if (stats.size === 0) {
          this.warnings.push(`Required file is empty: ${file}`)
        }
      }
    }
  }

  /**
   * Validate version consistency across files
   */
  async validateVersionConsistency() {
    console.log('🔢 Validating version consistency...')

    if (!this.currentVersion) {
      this.errors.push('Cannot validate version consistency without current version')
      return
    }

    for (const file of CONFIG.versionFiles) {
      const filePath = path.join(__dirname, '..', file)
      if (!fs.existsSync(filePath)) continue

      try {
        const content = fs.readFileSync(filePath, 'utf8')

        if (file === 'package.json') {
          const packageData = JSON.parse(content)
          if (packageData.version !== this.currentVersion) {
            this.errors.push(
              `Version mismatch in ${file}: expected ${this.currentVersion}, found ${packageData.version}`
            )
          }
        } else {
          // Check for version badges and references
          const versionPattern = new RegExp(
            `version-${this.currentVersion.replace(/\./g, '\\.')}`,
            'g'
          )
          const badgePattern = /version-(\d+\.\d+\.\d+)/g

          const badges = content.match(badgePattern)
          if (badges) {
            badges.forEach(badge => {
              const foundVersion = badge.replace('version-', '')
              if (foundVersion !== this.currentVersion) {
                this.errors.push(
                  `Version badge mismatch in ${file}: expected ${this.currentVersion}, found ${foundVersion}`
                )
              }
            })
          }
        }
      } catch (error) {
        this.warnings.push(`Could not validate version in ${file}: ${error.message}`)
      }
    }
  }

  /**
   * Validate Markdown files for formatting and structure
   */
  async validateMarkdownFiles() {
    console.log('📝 Validating Markdown files...')

    const markdownFiles = this.findMarkdownFiles()

    for (const file of markdownFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8')
        this.validateMarkdownStructure(file, content)
        this.validateMarkdownFormatting(file, content)
      } catch (error) {
        this.errors.push(`Error reading ${file}: ${error.message}`)
      }
    }
  }

  /**
   * Find all Markdown files in the project
   */
  findMarkdownFiles() {
    const files = []

    const searchDir = dir => {
      const items = fs.readdirSync(dir)

      for (const item of items) {
        const fullPath = path.join(dir, item)
        const stats = fs.statSync(fullPath)

        if (stats.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
          searchDir(fullPath)
        } else if (item.endsWith('.md')) {
          files.push(fullPath)
        }
      }
    }

    searchDir(path.join(__dirname, '..'))
    return files
  }

  /**
   * Validate Markdown structure
   */
  validateMarkdownStructure(file, content) {
    const lines = content.split('\n')
    const relativePath = path.relative(path.join(__dirname, '..'), file)

    // Check for title (H1)
    const h1Count = (content.match(/^# /gm) || []).length
    if (h1Count === 0) {
      this.warnings.push(`${relativePath}: No H1 title found`)
    } else if (h1Count > 1) {
      this.warnings.push(`${relativePath}: Multiple H1 titles found (${h1Count})`)
    }

    // Check for proper heading hierarchy
    const headings = lines
      .map((line, index) => ({ line: line.trim(), number: index + 1 }))
      .filter(({ line }) => line.match(/^#{1,6} /))

    let previousLevel = 0
    for (const { line, number } of headings) {
      const level = line.match(/^(#{1,6})/)[1].length

      if (level > previousLevel + 1) {
        this.warnings.push(
          `${relativePath}:${number}: Heading level skipped (H${previousLevel} to H${level})`
        )
      }

      previousLevel = level
    }
  }

  /**
   * Validate Markdown formatting
   */
  validateMarkdownFormatting(file, content) {
    const relativePath = path.relative(path.join(__dirname, '..'), file)

    // Check for common formatting issues
    const issues = [
      {
        pattern: /\t/g,
        message: 'Contains tabs (use spaces instead)',
      },
      {
        pattern: /[ ]+$/gm,
        message: 'Contains trailing whitespace',
      },
      {
        pattern: /\n{3,}/g,
        message: 'Contains multiple consecutive empty lines',
      },
    ]

    for (const { pattern, message } of issues) {
      if (pattern.test(content)) {
        this.warnings.push(`${relativePath}: ${message}`)
      }
    }
  }

  /**
   * Validate links in documentation
   */
  async validateLinks() {
    console.log('🔗 Validating links...')

    const markdownFiles = this.findMarkdownFiles()

    for (const file of markdownFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8')
        const relativePath = path.relative(path.join(__dirname, '..'), file)

        this.validateLinksInFile(relativePath, content)
      } catch (error) {
        this.errors.push(`Error validating links in ${file}: ${error.message}`)
      }
    }
  }

  /**
   * Validate links in a specific file
   */
  validateLinksInFile(relativePath, content) {
    for (const pattern of CONFIG.linkPatterns) {
      let match
      while ((match = pattern.exec(content)) !== null) {
        const linkText = match[1] || 'link'
        const linkUrl = match[2] || match[1]

        // Skip external links and anchors
        if (
          linkUrl.startsWith('http') ||
          linkUrl.startsWith('#') ||
          linkUrl.startsWith('mailto:')
        ) {
          continue
        }

        // Validate internal links
        const linkPath = path.resolve(
          path.dirname(path.join(__dirname, '..', relativePath)),
          linkUrl
        )

        if (!fs.existsSync(linkPath)) {
          this.errors.push(`${relativePath}: Broken link "${linkText}" -> ${linkUrl}`)
        }
      }
    }
  }

  /**
   * Validate code examples in documentation
   */
  async validateCodeExamples() {
    console.log('💻 Validating code examples...')

    const markdownFiles = this.findMarkdownFiles()

    for (const file of markdownFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8')
        const relativePath = path.relative(path.join(__dirname, '..'), file)

        this.validateCodeExamplesInFile(relativePath, content)
      } catch (error) {
        this.warnings.push(`Error validating code examples in ${file}: ${error.message}`)
      }
    }
  }

  /**
   * Validate code examples in a specific file
   */
  validateCodeExamplesInFile(relativePath, content) {
    // Find code blocks
    const codeBlockPattern = /```(\w+)?\n([\s\S]*?)```/g
    let match

    while ((match = codeBlockPattern.exec(content)) !== null) {
      const language = match[1]
      const code = match[2]

      // Check for common issues
      if (!language) {
        this.warnings.push(`${relativePath}: Code block without language specification`)
      }

      if (code.trim().length === 0) {
        this.warnings.push(`${relativePath}: Empty code block`)
      }

      // Validate specific languages
      if (language === 'json') {
        try {
          JSON.parse(code)
        } catch (error) {
          this.errors.push(`${relativePath}: Invalid JSON in code block: ${error.message}`)
        }
      }
    }
  }

  /**
   * Generate validation report
   */
  async generateReport() {
    const reportPath = path.join(__dirname, '..', 'docs', 'VALIDATION_REPORT.md')
    const timestamp = new Date().toISOString()

    const report = `# Documentation Validation Report

Generated: ${timestamp}
Version: ${this.currentVersion}

## Summary

- **Errors**: ${this.errors.length}
- **Warnings**: ${this.warnings.length}
- **Status**: ${this.errors.length === 0 ? '✅ PASSED' : '❌ FAILED'}

## Errors

${this.errors.length === 0 ? 'No errors found.' : this.errors.map(error => `- ❌ ${error}`).join('\n')}

## Warnings

${this.warnings.length === 0 ? 'No warnings found.' : this.warnings.map(warning => `- ⚠️ ${warning}`).join('\n')}

## Validation Checks Performed

- ✅ Required files existence
- ✅ Version consistency across files
- ✅ Markdown structure and formatting
- ✅ Internal link validation
- ✅ Code example validation

## Next Steps

${this.errors.length > 0 ? '1. Fix all errors listed above\n2. Re-run validation\n3. Address warnings for improved quality' : '1. Address warnings for improved quality\n2. Continue with regular documentation maintenance'}

---
*This report was generated automatically by the documentation validation script.*
`

    fs.writeFileSync(reportPath, report)
    console.log(`📊 Validation report generated: ${reportPath}`)
  }

  /**
   * Print validation results
   */
  printResults() {
    console.log('\n📊 Validation Results:')
    console.log(`   Errors: ${this.errors.length}`)
    console.log(`   Warnings: ${this.warnings.length}`)

    if (this.errors.length > 0) {
      console.log('\n❌ Errors:')
      this.errors.forEach(error => console.log(`   - ${error}`))
    }

    if (this.warnings.length > 0) {
      console.log('\n⚠️  Warnings:')
      this.warnings.forEach(warning => console.log(`   - ${warning}`))
    }

    if (this.errors.length === 0 && this.warnings.length === 0) {
      console.log('\n✅ All documentation validation checks passed!')
    }

    console.log(
      `\n${this.errors.length === 0 ? '✅' : '❌'} Validation ${this.errors.length === 0 ? 'PASSED' : 'FAILED'}`
    )
  }
}

// Run validation if called directly
if (require.main === module) {
  const validator = new DocumentationValidator()
  validator
    .validate()
    .then(success => {
      process.exit(success ? 0 : 1)
    })
    .catch(error => {
      console.error('Validation failed:', error)
      process.exit(1)
    })
}

module.exports = DocumentationValidator
