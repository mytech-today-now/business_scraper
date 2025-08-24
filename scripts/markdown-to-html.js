#!/usr/bin/env node

/**
 * Markdown to HTML Converter Script
 * Converts Markdown files to HTML with external CSS styling
 */

const fs = require('fs')
const path = require('path')
const { marked } = require('marked')

// Configure marked options for better HTML output
marked.setOptions({
  gfm: true, // GitHub Flavored Markdown
  breaks: true, // Convert line breaks to <br>
  headerIds: true, // Add IDs to headers
  mangle: false, // Don't mangle autolinks
  sanitize: false, // Don't sanitize HTML (we trust our content)
})

/**
 * Generate HTML template with the converted content
 */
function generateHTMLTemplate(title, content, relativePath = '') {
  const cssPath = relativePath ? `${relativePath}/styles.css` : 'styles.css'
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - Business Scraper Documentation</title>
    <link rel="stylesheet" href="${cssPath}">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism.min.css">
    <style>
        .header-link {
            text-decoration: none;
            color: inherit;
        }
        .header-link:hover {
            text-decoration: underline;
        }
        .code-block {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 0.375rem;
            padding: 1rem;
            margin: 1rem 0;
        }
        .table-responsive {
            margin: 1rem 0;
        }
        .nav-breadcrumb {
            background-color: #f8f9fa;
            padding: 0.75rem 1rem;
            border-radius: 0.375rem;
            margin-bottom: 1rem;
        }
        .back-to-docs {
            margin-bottom: 2rem;
        }
        .content-wrapper {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        .alert {
            border-radius: 0.375rem;
            padding: 1rem;
            margin: 1rem 0;
        }
        .alert-info {
            background-color: #d1ecf1;
            border-color: #bee5eb;
            color: #0c5460;
        }
        .alert-warning {
            background-color: #fff3cd;
            border-color: #ffecb5;
            color: #664d03;
        }
        .alert-success {
            background-color: #d1e7dd;
            border-color: #badbcc;
            color: #0f5132;
        }
        .alert-danger {
            background-color: #f8d7da;
            border-color: #f5c2c7;
            color: #842029;
        }
    </style>
</head>
<body>
    <div class="content-wrapper">
        <div class="back-to-docs">
            <a href="${relativePath ? `${relativePath}/readme.html` : 'readme.html'}" class="btn btn-outline-primary">
                ← Back to Documentation Hub
            </a>
        </div>
        
        <div class="nav-breadcrumb">
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb mb-0">
                    <li class="breadcrumb-item">
                        <a href="${relativePath ? `${relativePath}/readme.html` : 'readme.html'}">Documentation</a>
                    </li>
                    <li class="breadcrumb-item active" aria-current="page">${title}</li>
                </ol>
            </nav>
        </div>

        <main class="documentation-content">
            ${content}
        </main>

        <footer class="text-center mt-5 pt-4 border-top">
            <p class="text-muted">
                <strong>Business Scraper Application v3.0.0</strong> - Enterprise Multi-User Collaboration Platform
            </p>
            <p class="text-muted">
                <a href="${relativePath ? `${relativePath}/readme.html` : 'readme.html'}">Documentation Hub</a> | 
                <a href="https://github.com/mytech-today-now/business_scraper">GitHub Repository</a>
            </p>
            <p class="text-muted small">Last updated: ${new Date().toLocaleDateString()}</p>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-core.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js"></script>
</body>
</html>`
}

/**
 * Extract title from markdown content
 */
function extractTitle(content) {
  // Try to find the first H1 heading
  const h1Match = content.match(/^#\s+(.+)$/m)
  if (h1Match) {
    return h1Match[1].replace(/[#*`]/g, '').trim()
  }
  
  // Try to find any heading
  const headingMatch = content.match(/^#{1,6}\s+(.+)$/m)
  if (headingMatch) {
    return headingMatch[1].replace(/[#*`]/g, '').trim()
  }
  
  // Fallback to filename
  return 'Documentation'
}

/**
 * Convert a single markdown file to HTML
 */
function convertMarkdownToHTML(inputPath, outputPath, relativePath = '') {
  try {
    console.log(`Converting: ${inputPath} -> ${outputPath}`)
    
    // Read the markdown file
    const markdownContent = fs.readFileSync(inputPath, 'utf8')
    
    // Extract title
    const title = extractTitle(markdownContent)
    
    // Convert markdown to HTML
    const htmlContent = marked(markdownContent)
    
    // Generate complete HTML document
    const fullHTML = generateHTMLTemplate(title, htmlContent, relativePath)
    
    // Write the HTML file
    fs.writeFileSync(outputPath, fullHTML, 'utf8')
    
    console.log(`✓ Successfully converted: ${path.basename(inputPath)}`)
    return true
  } catch (error) {
    console.error(`✗ Error converting ${inputPath}:`, error.message)
    return false
  }
}

/**
 * Process all markdown files in a directory
 */
function processDirectory(dirPath) {
  console.log(`\nProcessing directory: ${dirPath}`)
  
  try {
    const files = fs.readdirSync(dirPath)
    const markdownFiles = files.filter(file => 
      file.toLowerCase().endsWith('.md') && 
      !file.toLowerCase().startsWith('readme.md') // Skip readme.md as it's already HTML
    )
    
    console.log(`Found ${markdownFiles.length} markdown files to convert`)
    
    let successCount = 0
    let failCount = 0
    
    markdownFiles.forEach(file => {
      const inputPath = path.join(dirPath, file)
      const outputPath = path.join(dirPath, file.replace(/\.md$/i, '.html'))
      
      if (convertMarkdownToHTML(inputPath, outputPath)) {
        successCount++
      } else {
        failCount++
      }
    })
    
    console.log(`\n📊 Conversion Summary:`)
    console.log(`✓ Successfully converted: ${successCount} files`)
    console.log(`✗ Failed conversions: ${failCount} files`)
    console.log(`📁 Total files processed: ${successCount + failCount} files`)
    
    return { success: successCount, failed: failCount }
  } catch (error) {
    console.error(`Error processing directory ${dirPath}:`, error.message)
    return { success: 0, failed: 0 }
  }
}

/**
 * Main function
 */
function main() {
  const args = process.argv.slice(2)
  
  if (args.length === 0) {
    console.log(`
📚 Markdown to HTML Converter

Usage:
  node scripts/markdown-to-html.js <directory>
  node scripts/markdown-to-html.js <input.md> <output.html>

Examples:
  node scripts/markdown-to-html.js docs/
  node scripts/markdown-to-html.js docs/API_DOCUMENTATION.md docs/API_DOCUMENTATION.html

Features:
  ✓ GitHub Flavored Markdown support
  ✓ Syntax highlighting with Prism.js
  ✓ Bootstrap styling
  ✓ Responsive design
  ✓ Navigation breadcrumbs
  ✓ Automatic anchor links for headings
`)
    process.exit(1)
  }
  
  const inputPath = args[0]
  
  if (!fs.existsSync(inputPath)) {
    console.error(`Error: Path "${inputPath}" does not exist`)
    process.exit(1)
  }
  
  const stats = fs.statSync(inputPath)
  
  if (stats.isDirectory()) {
    // Process entire directory
    const result = processDirectory(inputPath)
    
    if (result.failed > 0) {
      console.log(`\n⚠️  Some files failed to convert. Check the error messages above.`)
      process.exit(1)
    } else {
      console.log(`\n🎉 All files converted successfully!`)
    }
  } else if (stats.isFile() && inputPath.toLowerCase().endsWith('.md')) {
    // Process single file
    const outputPath = args[1] || inputPath.replace(/\.md$/i, '.html')
    
    if (convertMarkdownToHTML(inputPath, outputPath)) {
      console.log(`\n🎉 File converted successfully!`)
    } else {
      console.log(`\n❌ File conversion failed!`)
      process.exit(1)
    }
  } else {
    console.error(`Error: "${inputPath}" is not a markdown file or directory`)
    process.exit(1)
  }
}

// Run the script
if (require.main === module) {
  main()
}

module.exports = {
  convertMarkdownToHTML,
  processDirectory,
  generateHTMLTemplate,
  extractTitle
}
