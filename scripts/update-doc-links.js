#!/usr/bin/env node

/**
 * Update Documentation Links Script
 * Updates all .md links to .html links with target="_blank" in documentation files
 */

const fs = require('fs')
const path = require('path')

/**
 * Update links in a file from .md to .html with target="_blank"
 */
function updateLinksInFile(filePath) {
  try {
    console.log(`Updating links in: ${filePath}`)
    
    let content = fs.readFileSync(filePath, 'utf8')
    let changeCount = 0
    
    // Pattern to match href="filename.md" and replace with href="filename.html" target="_blank"
    const linkPattern = /href="([^"]+\.md)"/g
    content = content.replace(linkPattern, (match, filename) => {
      changeCount++
      const htmlFilename = filename.replace(/\.md$/, '.html')
      return `href="${htmlFilename}" target="_blank"`
    })

    // Also update any remaining .md references in link text
    const linkTextPattern = />([^<]+\.md)</g
    content = content.replace(linkTextPattern, (match, filename) => {
      if (filename.endsWith('.md')) {
        changeCount++
        const htmlFilename = filename.replace(/\.md$/, '.html')
        return `>${htmlFilename}<`
      }
      return match
    })
    
    // Also update any remaining .md references that might not have target="_blank"
    const existingHtmlPattern = /href="([^"]+\.html)"(?!\s+target="_blank")/g
    content = content.replace(existingHtmlPattern, (match, filename) => {
      if (!match.includes('target="_blank"')) {
        changeCount++
        return `href="${filename}" target="_blank"`
      }
      return match
    })
    
    // Write the updated content back to the file
    fs.writeFileSync(filePath, content, 'utf8')
    
    console.log(`✓ Updated ${changeCount} links in ${path.basename(filePath)}`)
    return changeCount
  } catch (error) {
    console.error(`✗ Error updating ${filePath}:`, error.message)
    return 0
  }
}

/**
 * Main function
 */
function main() {
  const docsDir = 'docs'
  
  if (!fs.existsSync(docsDir)) {
    console.error(`Error: Directory "${docsDir}" does not exist`)
    process.exit(1)
  }
  
  console.log('🔗 Updating documentation links...\n')
  
  // Files to update
  const filesToUpdate = [
    path.join(docsDir, 'README.md'),
    path.join(docsDir, 'readme.html')
  ]
  
  let totalChanges = 0
  
  filesToUpdate.forEach(filePath => {
    if (fs.existsSync(filePath)) {
      totalChanges += updateLinksInFile(filePath)
    } else {
      console.log(`⚠️  File not found: ${filePath}`)
    }
  })
  
  console.log(`\n📊 Summary:`)
  console.log(`✓ Total links updated: ${totalChanges}`)
  console.log(`📁 Files processed: ${filesToUpdate.length}`)
  
  if (totalChanges > 0) {
    console.log(`\n🎉 All documentation links have been updated to use HTML files with target="_blank"!`)
  } else {
    console.log(`\n✨ No changes needed - all links are already up to date!`)
  }
}

// Run the script
if (require.main === module) {
  main()
}

module.exports = {
  updateLinksInFile
}
