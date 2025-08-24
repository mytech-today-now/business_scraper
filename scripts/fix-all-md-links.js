#!/usr/bin/env node

/**
 * Fix All MD Links Script
 * Comprehensive script to find and fix ALL .md references in documentation files
 */

const fs = require('fs')
const path = require('path')

/**
 * Fix all .md references in a file
 */
function fixAllMdReferences(filePath) {
  try {
    console.log(`Processing: ${filePath}`)
    
    let content = fs.readFileSync(filePath, 'utf8')
    let changeCount = 0
    
    // Pattern 1: href="filename.md" -> href="filename.html" target="_blank"
    content = content.replace(/href="([^"]+\.md)"/g, (match, filename) => {
      changeCount++
      const htmlFilename = filename.replace(/\.md$/, '.html')
      return `href="${htmlFilename}" target="_blank"`
    })
    
    // Pattern 2: >filename.md< -> >filename.html<
    content = content.replace(/>([^<]*\.md)</g, (match, filename) => {
      changeCount++
      const htmlFilename = filename.replace(/\.md$/, '.html')
      return `>${htmlFilename}<`
    })
    
    // Pattern 3: href="filename.html" without target="_blank"
    content = content.replace(/href="([^"]+\.html)"(?!\s+target="_blank")/g, (match, filename) => {
      changeCount++
      return `href="${filename}" target="_blank"`
    })
    
    // Write the updated content back
    fs.writeFileSync(filePath, content, 'utf8')
    
    console.log(`✓ Fixed ${changeCount} references in ${path.basename(filePath)}`)
    return changeCount
  } catch (error) {
    console.error(`✗ Error processing ${filePath}:`, error.message)
    return 0
  }
}

/**
 * Main function
 */
function main() {
  const docsDir = 'docs'
  
  console.log('🔧 Fixing ALL .md references in documentation files...\n')
  
  const filesToProcess = [
    path.join(docsDir, 'README.md'),
    path.join(docsDir, 'readme.html')
  ]
  
  let totalChanges = 0
  
  filesToProcess.forEach(filePath => {
    if (fs.existsSync(filePath)) {
      totalChanges += fixAllMdReferences(filePath)
    } else {
      console.log(`⚠️  File not found: ${filePath}`)
    }
  })
  
  console.log(`\n📊 Final Summary:`)
  console.log(`✓ Total references fixed: ${totalChanges}`)
  console.log(`📁 Files processed: ${filesToProcess.length}`)
  
  if (totalChanges > 0) {
    console.log(`\n🎉 All .md references have been fixed!`)
  } else {
    console.log(`\n✨ No changes needed - all references are already correct!`)
  }
}

// Run the script
if (require.main === module) {
  main()
}

module.exports = {
  fixAllMdReferences
}
