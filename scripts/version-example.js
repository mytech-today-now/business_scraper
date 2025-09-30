#!/usr/bin/env node

/**
 * Version Utility Example Script
 * 
 * Demonstrates the new versioning pattern: 1-999.0-10.0-9999
 * Run with: node scripts/version-example.js
 */

const path = require('path')

// Import the version utility directly
const {
  parseVersion,
  validateVersion,
  formatVersion,
  compareVersions,
  incrementVersion,
  isValidVersionString,
  convertFromSemanticVersion,
  getCurrentVersion,
  VERSION_CONSTRAINTS
} = require('../src/utils/version.ts')

console.log('🔢 Application Version Utility Demo')
console.log('=====================================\n')

// Display version constraints
console.log('📋 Version Constraints:')
console.log(`   Major: ${VERSION_CONSTRAINTS.MAJOR.min}-${VERSION_CONSTRAINTS.MAJOR.max}`)
console.log(`   Minor: ${VERSION_CONSTRAINTS.MINOR.min}-${VERSION_CONSTRAINTS.MINOR.max}`)
console.log(`   Patch: ${VERSION_CONSTRAINTS.PATCH.min}-${VERSION_CONSTRAINTS.PATCH.max}\n`)

// Example 1: Parse and validate versions
console.log('1️⃣  Parsing and Validating Versions:')
const testVersions = ['6.10.1', '1.0.0', '999.10.9999', '1000.0.0', 'v6.5.123', 'invalid']

testVersions.forEach(versionStr => {
  console.log(`   Testing: "${versionStr}"`)
  const parsed = parseVersion(versionStr)
  
  if (parsed) {
    const validation = validateVersion(parsed)
    console.log(`     ✅ Parsed: ${JSON.stringify(parsed)}`)
    console.log(`     📊 Valid: ${validation.isValid}`)
    if (validation.errors.length > 0) {
      console.log(`     ❌ Errors: ${validation.errors.join(', ')}`)
    }
    if (validation.warnings.length > 0) {
      console.log(`     ⚠️  Warnings: ${validation.warnings.join(', ')}`)
    }
  } else {
    console.log(`     ❌ Failed to parse`)
  }
  console.log()
})

// Example 2: Version comparison
console.log('2️⃣  Version Comparison:')
const v1 = parseVersion('6.5.100')
const v2 = parseVersion('6.5.200')
const v3 = parseVersion('6.6.0')

if (v1 && v2 && v3) {
  console.log(`   Comparing ${formatVersion(v1)} vs ${formatVersion(v2)}:`)
  const comp1 = compareVersions(v1, v2)
  console.log(`     Result: ${comp1.comparison} (${comp1.comparison < 0 ? 'less than' : comp1.comparison > 0 ? 'greater than' : 'equal'})`)
  
  console.log(`   Comparing ${formatVersion(v1)} vs ${formatVersion(v3)}:`)
  const comp2 = compareVersions(v1, v3)
  console.log(`     Result: ${comp2.comparison} (${comp2.comparison < 0 ? 'less than' : comp2.comparison > 0 ? 'greater than' : 'equal'})`)
}
console.log()

// Example 3: Version incrementing
console.log('3️⃣  Version Incrementing:')
const baseVersion = parseVersion('6.5.100')

if (baseVersion) {
  console.log(`   Base version: ${formatVersion(baseVersion)}`)
  
  const majorIncrement = incrementVersion(baseVersion, 'major')
  if (majorIncrement) {
    console.log(`   Major increment: ${formatVersion(majorIncrement)}`)
  }
  
  const minorIncrement = incrementVersion(baseVersion, 'minor')
  if (minorIncrement) {
    console.log(`   Minor increment: ${formatVersion(minorIncrement)}`)
  }
  
  const patchIncrement = incrementVersion(baseVersion, 'patch')
  if (patchIncrement) {
    console.log(`   Patch increment: ${formatVersion(patchIncrement)}`)
  }
}
console.log()

// Example 4: Converting from semantic versioning
console.log('4️⃣  Converting from Semantic Versioning:')
const semanticVersions = ['1.2.3', '6.8.3', '999.10.9999', '1000.0.0', '1.11.0']

semanticVersions.forEach(semver => {
  console.log(`   Converting "${semver}":`)
  const converted = convertFromSemanticVersion(semver)
  
  if (converted) {
    console.log(`     ✅ Converted to: ${formatVersion(converted)}`)
  } else {
    console.log(`     ❌ Cannot convert (outside constraints or invalid format)`)
  }
})
console.log()

// Example 5: Current application version
console.log('5️⃣  Current Application Version:')
const currentVersion = getCurrentVersion()

if (currentVersion) {
  console.log(`   Current version: ${formatVersion(currentVersion, true)}`)
  console.log(`   Components: Major=${currentVersion.major}, Minor=${currentVersion.minor}, Patch=${currentVersion.patch}`)
  
  const validation = validateVersion(currentVersion)
  console.log(`   Status: ${validation.isValid ? '✅ Valid' : '❌ Invalid'}`)
  
  if (validation.warnings.length > 0) {
    console.log(`   Warnings: ${validation.warnings.join(', ')}`)
  }
} else {
  console.log('   ❌ Could not determine current version')
}
console.log()

// Example 6: Validation examples
console.log('6️⃣  Validation Examples:')
const validationTests = [
  '1.0.0',      // Valid minimum
  '999.10.9999', // Valid maximum
  '0.0.0',      // Invalid: major too low
  '1000.0.0',   // Invalid: major too high
  '1.11.0',     // Invalid: minor too high
  '1.0.10000'   // Invalid: patch too high
]

validationTests.forEach(version => {
  const isValid = isValidVersionString(version)
  console.log(`   "${version}": ${isValid ? '✅ Valid' : '❌ Invalid'}`)
})

console.log('\n🎉 Version utility demo complete!')
console.log('\nUsage in your code:')
console.log('```javascript')
console.log('import { parseVersion, formatVersion, isValidVersionString } from "@/utils/version"')
console.log('')
console.log('// Parse a version string')
console.log('const version = parseVersion("6.10.1")')
console.log('')
console.log('// Validate a version string')
console.log('const isValid = isValidVersionString("6.10.1")')
console.log('')
console.log('// Format a version with prefix')
console.log('const formatted = formatVersion(version, true) // "v6.10.1"')
console.log('```')
