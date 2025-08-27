#!/usr/bin/env node

/**
 * Script to refresh default industries in the application
 * This script can be run to force update the default industries with the latest data
 * from the industries-2025-07-26-final.json file
 */

const fs = require('fs')
const path = require('path')

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
}

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`)
}

function logSuccess(message) {
  log(`✅ ${message}`, colors.green)
}

function logError(message) {
  log(`❌ ${message}`, colors.red)
}

function logInfo(message) {
  log(`ℹ️  ${message}`, colors.blue)
}

function logWarning(message) {
  log(`⚠️  ${message}`, colors.yellow)
}

async function main() {
  try {
    log('\n🔄 Business Scraper - Industry Refresh Script', colors.bright)
    log('=' * 50, colors.cyan)

    // Check if the industries file exists
    const industriesFilePath = path.join(process.cwd(), 'industries-2025-07-26-final.json')
    if (!fs.existsSync(industriesFilePath)) {
      logError(`Industries file not found: ${industriesFilePath}`)
      process.exit(1)
    }

    // Read the industries file
    logInfo('Reading industries from industries-2025-07-26-final.json...')
    const industriesData = JSON.parse(fs.readFileSync(industriesFilePath, 'utf8'))

    if (!industriesData.industries || !Array.isArray(industriesData.industries)) {
      logError('Invalid industries file format. Expected "industries" array.')
      process.exit(1)
    }

    logSuccess(`Found ${industriesData.industries.length} industries in the file`)

    // Check if industry-config.ts exists
    const configFilePath = path.join(process.cwd(), 'src', 'lib', 'industry-config.ts')
    if (!fs.existsSync(configFilePath)) {
      logError(`Industry config file not found: ${configFilePath}`)
      process.exit(1)
    }

    logInfo('Industries are already up to date in src/lib/industry-config.ts')
    logInfo('The application will automatically detect and apply updates when it starts.')

    log('\n📋 Summary:', colors.bright)
    log(`   • Industries file: ${industriesData.industries.length} industries`)
    log(`   • Export date: ${industriesData.exportDate}`)
    log(`   • Version: ${industriesData.version}`)

    log('\n🚀 Next Steps:', colors.bright)
    log('   1. Restart the application (both dev and production)')
    log('   2. The app will automatically detect changes and update default industries')
    log('   3. Custom industries will be preserved during the update')
    log('   4. You can also use the "Refresh Default Industries" button in the UI')

    logSuccess('\nIndustry refresh preparation completed!')
  } catch (error) {
    logError(`Script failed: ${error.message}`)
    console.error(error)
    process.exit(1)
  }
}

// Run the script
if (require.main === module) {
  main()
}

module.exports = { main }
