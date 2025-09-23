#!/usr/bin/env node

/**
 * Quick Analysis Script for Console Log Enhancement
 * 
 * This script runs a quick analysis of the console_log_context.txt file
 * and shows what the enhancement workflow would do without actually
 * creating GitHub issues.
 */

const fs = require('fs')
const path = require('path')
const { ConsoleLogAnalyzer, AffectedFileDetector } = require('./console-log-enhancement-workflow')

async function runAnalysis() {
  console.log('🔍 Console Log Enhancement Analysis')
  console.log('=' .repeat(50))

  // Check if console log file exists
  const consoleLogPath = path.join(process.cwd(), 'console_log_context.txt')
  if (!fs.existsSync(consoleLogPath)) {
    console.error('❌ Console log file not found: console_log_context.txt')
    console.log('💡 Create this file with your console logs to run the analysis')
    return
  }

  // Read and analyze console log
  console.log('📖 Reading console log file...')
  const logContent = fs.readFileSync(consoleLogPath, 'utf8')
  const logLines = logContent.split('\n').length
  console.log(`   - File size: ${logContent.length} characters`)
  console.log(`   - Lines: ${logLines}`)

  console.log('\n🧠 Analyzing console logs...')
  const analyzer = new ConsoleLogAnalyzer(logContent)
  const analysis = analyzer.analysis

  // Display log statistics
  console.log('\n📊 Log Statistics:')
  console.log(`   - INFO logs: ${analysis.infoLogs.length}`)
  console.log(`   - WARN logs: ${analysis.warnLogs.length}`)
  console.log(`   - ERROR logs: ${analysis.errorLogs.length}`)
  console.log(`   - DEBUG logs: ${analysis.debugLogs.length}`)

  // Display detected patterns
  console.log('\n🔍 Detected Patterns:')
  if (Object.keys(analysis.patterns).length === 0) {
    console.log('   - No significant patterns detected')
  } else {
    for (const [patternName, pattern] of Object.entries(analysis.patterns)) {
      console.log(`   - ${patternName}:`)
      console.log(`     * Description: ${pattern.description}`)
      console.log(`     * Occurrences: ${pattern.count}`)
      console.log(`     * Components: ${pattern.affectedComponents.join(', ')}`)
    }
  }

  // Display recommendations
  console.log('\n💡 Recommendations:')
  if (analysis.recommendations.length === 0) {
    console.log('   - No specific recommendations generated')
  } else {
    analysis.recommendations.forEach((rec, index) => {
      console.log(`   ${index + 1}. ${rec.component} (Priority: ${rec.priority})`)
      console.log(`      Issue: ${rec.issue}`)
      console.log(`      Solution: ${rec.solution}`)
    })
  }

  // Detect affected files
  console.log('\n📁 Affected Files Detection:')
  const detector = new AffectedFileDetector()
  try {
    const affectedFiles = await detector.detectAffectedFiles()
    console.log('   Files that would be tested:')
    affectedFiles.forEach(file => {
      console.log(`   - ${file}`)
    })
  } catch (error) {
    console.log('   - Using pattern-based detection (git not available)')
    const patternFiles = detector.detectFromConsolePatterns()
    patternFiles.forEach(file => {
      console.log(`   - ${file}`)
    })
  }

  // Show sample GitHub issue content
  console.log('\n📝 Sample GitHub Issue Content:')
  console.log('   Title: [Enhancement] Console Log-Based Improvement')
  console.log('   Labels: bug, enhancement, critical, needs review')
  console.log('   Body preview:')
  
  const infoPreview = analysis.infoLogs.slice(0, 3).map(log => `     ${log}`).join('\n')
  const warnPreview = analysis.warnLogs.slice(0, 3).map(log => `     ${log}`).join('\n')
  
  console.log('     ## Key Logs')
  console.log('     ### INFO')
  console.log(infoPreview || '     (no INFO logs)')
  console.log('     ### WARN')
  console.log(warnPreview || '     (no WARN logs)')
  console.log('     ...')

  // Summary
  console.log('\n📋 Summary:')
  console.log(`   - Total log entries analyzed: ${logLines}`)
  console.log(`   - Patterns detected: ${Object.keys(analysis.patterns).length}`)
  console.log(`   - Recommendations generated: ${analysis.recommendations.length}`)
  console.log(`   - Priority issues: ${analysis.recommendations.filter(r => r.priority === 'high').length}`)

  // Next steps
  console.log('\n🚀 Next Steps:')
  console.log('   1. Review the detected patterns and recommendations')
  console.log('   2. Set up GITHUB_TOKEN environment variable')
  console.log('   3. Run the full workflow: npm run workflow:enhancement')
  console.log('   4. Or use GitHub Actions for automated execution')

  console.log('\n✅ Analysis complete!')
}

// Run the analysis
if (require.main === module) {
  runAnalysis().catch(error => {
    console.error('❌ Analysis failed:', error.message)
    process.exit(1)
  })
}

module.exports = { runAnalysis }
