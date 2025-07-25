#!/usr/bin/env node

/**
 * Configuration loader script
 * Loads environment-specific configuration files and validates settings
 */

const fs = require('fs')
const path = require('path')
const dotenv = require('dotenv')

// Configuration file paths
const CONFIG_DIR = path.join(__dirname, '..', 'config')
const ROOT_DIR = path.join(__dirname, '..')

/**
 * Load configuration for a specific environment
 */
function loadConfig(environment = 'development') {
  console.log(`🔧 Loading configuration for ${environment} environment...`)
  
  const configFile = path.join(CONFIG_DIR, `${environment}.env`)
  
  if (!fs.existsSync(configFile)) {
    console.error(`❌ Configuration file not found: ${configFile}`)
    process.exit(1)
  }
  
  // Load the environment-specific config
  const result = dotenv.config({ path: configFile })
  
  if (result.error) {
    console.error(`❌ Error loading configuration: ${result.error.message}`)
    process.exit(1)
  }
  
  console.log(`✅ Configuration loaded from ${configFile}`)
  
  // Also load .env.local if it exists (for local overrides)
  const localEnvFile = path.join(ROOT_DIR, '.env.local')
  if (fs.existsSync(localEnvFile)) {
    const localResult = dotenv.config({ path: localEnvFile })
    if (!localResult.error) {
      console.log(`✅ Local overrides loaded from ${localEnvFile}`)
    }
  }
  
  return result.parsed
}

/**
 * Validate required configuration
 */
function validateConfig() {
  console.log('🔍 Validating configuration...')
  
  const requiredVars = [
    'NODE_ENV',
    'NEXT_PUBLIC_APP_NAME',
    'NEXT_PUBLIC_APP_VERSION'
  ]
  
  const missingVars = []
  
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      missingVars.push(varName)
    }
  }
  
  if (missingVars.length > 0) {
    console.error(`❌ Missing required environment variables: ${missingVars.join(', ')}`)
    return false
  }
  
  // Environment-specific validation
  const env = process.env.NODE_ENV
  
  if (env === 'production') {
    const productionRequiredVars = [
      'DB_PASSWORD',
      'ADMIN_PASSWORD_HASH',
      'ADMIN_PASSWORD_SALT'
    ]
    
    const missingProdVars = productionRequiredVars.filter(varName => 
      !process.env[varName] || 
      process.env[varName].includes('CHANGE_ME') ||
      process.env[varName].includes('GENERATE_')
    )
    
    if (missingProdVars.length > 0) {
      console.error(`❌ Production environment missing or has placeholder values for: ${missingProdVars.join(', ')}`)
      return false
    }
  }
  
  console.log('✅ Configuration validation passed')
  return true
}

/**
 * Display configuration summary
 */
function displayConfigSummary() {
  console.log('\n📋 Configuration Summary:')
  console.log('========================')
  console.log(`Environment: ${process.env.NODE_ENV}`)
  console.log(`App Name: ${process.env.NEXT_PUBLIC_APP_NAME}`)
  console.log(`App Version: ${process.env.NEXT_PUBLIC_APP_VERSION}`)
  console.log(`Debug Mode: ${process.env.NEXT_PUBLIC_DEBUG}`)
  console.log(`Port: ${process.env.PORT}`)
  console.log(`Database: ${process.env.DB_NAME}@${process.env.DB_HOST}:${process.env.DB_PORT}`)
  console.log(`Authentication: ${process.env.ENABLE_AUTH === 'true' ? 'Enabled' : 'Disabled'}`)
  console.log(`Cache Type: ${process.env.CACHE_TYPE}`)
  console.log(`Log Level: ${process.env.LOG_LEVEL}`)
  console.log(`Log Format: ${process.env.LOG_FORMAT}`)
  
  // Feature flags
  console.log('\n🚩 Feature Flags:')
  console.log(`  Caching: ${process.env.FEATURE_ENABLE_CACHING === 'true' ? 'Enabled' : 'Disabled'}`)
  console.log(`  Rate Limiting: ${process.env.FEATURE_ENABLE_RATE_LIMITING === 'true' ? 'Enabled' : 'Disabled'}`)
  console.log(`  Metrics: ${process.env.FEATURE_ENABLE_METRICS === 'true' ? 'Enabled' : 'Disabled'}`)
  console.log(`  Experimental: ${process.env.FEATURE_ENABLE_EXPERIMENTAL === 'true' ? 'Enabled' : 'Disabled'}`)
}

/**
 * Generate .env file from template
 */
function generateEnvFile(environment, outputPath = '.env') {
  console.log(`📝 Generating ${outputPath} from ${environment} template...`)
  
  const configFile = path.join(CONFIG_DIR, `${environment}.env`)
  const outputFile = path.join(ROOT_DIR, outputPath)
  
  if (!fs.existsSync(configFile)) {
    console.error(`❌ Template file not found: ${configFile}`)
    process.exit(1)
  }
  
  // Read template
  const template = fs.readFileSync(configFile, 'utf8')
  
  // Add header comment
  const header = `# Generated from ${environment}.env template
# Generated on: ${new Date().toISOString()}
# 
# IMPORTANT: Review and update all values marked with CHANGE_ME or GENERATE_
# before deploying to production.
#

`
  
  const content = header + template
  
  // Write to output file
  fs.writeFileSync(outputFile, content)
  
  console.log(`✅ Generated ${outputFile}`)
  
  // Check for placeholder values
  const placeholders = content.match(/(CHANGE_ME|GENERATE_[A-Z_]+|YOUR_[A-Z_]+)/g)
  if (placeholders) {
    console.log('\n⚠️  Please update the following placeholder values:')
    [...new Set(placeholders)].forEach(placeholder => {
      console.log(`  - ${placeholder}`)
    })
  }
}

/**
 * Main function
 */
function main() {
  const args = process.argv.slice(2)
  const command = args[0]
  
  switch (command) {
    case 'load':
      const environment = args[1] || process.env.NODE_ENV || 'development'
      loadConfig(environment)
      if (validateConfig()) {
        displayConfigSummary()
      } else {
        process.exit(1)
      }
      break
      
    case 'validate':
      if (!validateConfig()) {
        process.exit(1)
      }
      break
      
    case 'generate':
      const sourceEnv = args[1] || 'development'
      const outputFile = args[2] || '.env'
      generateEnvFile(sourceEnv, outputFile)
      break
      
    case 'summary':
      displayConfigSummary()
      break
      
    default:
      console.log('Configuration Loader Script')
      console.log('')
      console.log('Usage:')
      console.log('  node scripts/load-config.js load [environment]     # Load and validate config')
      console.log('  node scripts/load-config.js validate              # Validate current config')
      console.log('  node scripts/load-config.js generate [env] [file] # Generate .env from template')
      console.log('  node scripts/load-config.js summary               # Show config summary')
      console.log('')
      console.log('Examples:')
      console.log('  node scripts/load-config.js load production')
      console.log('  node scripts/load-config.js generate production .env.production')
      console.log('  node scripts/load-config.js validate')
      break
  }
}

// Run if called directly
if (require.main === module) {
  main()
}

module.exports = {
  loadConfig,
  validateConfig,
  displayConfigSummary,
  generateEnvFile
}
