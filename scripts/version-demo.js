#!/usr/bin/env node

/**
 * Version Utility Demo Script (Pure JavaScript)
 * 
 * Demonstrates the new versioning pattern: 1-999.0-10.0-9999
 * Run with: node scripts/version-demo.js
 */

console.log('🔢 Application Version Utility Demo')
console.log('=====================================\n')

// Version constraints
const VERSION_CONSTRAINTS = {
  MAJOR: { min: 1, max: 999 },
  MINOR: { min: 0, max: 10 },
  PATCH: { min: 0, max: 9999 }
}

// Version pattern regex
const VERSION_PATTERN = /^(\d{1,3})\.(\d{1,2})\.(\d{1,4})$/

/**
 * Parse a version string into components
 */
function parseVersion(versionString) {
  if (!versionString || typeof versionString !== 'string') {
    return null
  }

  // Remove 'v' prefix if present
  const cleanVersion = versionString.replace(/^v/, '')
  
  const match = cleanVersion.match(VERSION_PATTERN)
  if (!match) {
    return null
  }

  const major = parseInt(match[1], 10)
  const minor = parseInt(match[2], 10)
  const patch = parseInt(match[3], 10)

  // Validate constraints during parsing
  if (major < VERSION_CONSTRAINTS.MAJOR.min || major > VERSION_CONSTRAINTS.MAJOR.max) {
    return null
  }
  if (minor < VERSION_CONSTRAINTS.MINOR.min || minor > VERSION_CONSTRAINTS.MINOR.max) {
    return null
  }
  if (patch < VERSION_CONSTRAINTS.PATCH.min || patch > VERSION_CONSTRAINTS.PATCH.max) {
    return null
  }

  return {
    major,
    minor,
    patch,
    raw: cleanVersion
  }
}

/**
 * Validate a version object
 */
function validateVersion(version) {
  const result = {
    isValid: true,
    errors: [],
    warnings: []
  }

  // Validate major version
  if (version.major < VERSION_CONSTRAINTS.MAJOR.min || version.major > VERSION_CONSTRAINTS.MAJOR.max) {
    result.isValid = false
    result.errors.push(
      `Major version must be between ${VERSION_CONSTRAINTS.MAJOR.min} and ${VERSION_CONSTRAINTS.MAJOR.max}, got ${version.major}`
    )
  }

  // Validate minor version
  if (version.minor < VERSION_CONSTRAINTS.MINOR.min || version.minor > VERSION_CONSTRAINTS.MINOR.max) {
    result.isValid = false
    result.errors.push(
      `Minor version must be between ${VERSION_CONSTRAINTS.MINOR.min} and ${VERSION_CONSTRAINTS.MINOR.max}, got ${version.minor}`
    )
  }

  // Validate patch version
  if (version.patch < VERSION_CONSTRAINTS.PATCH.min || version.patch > VERSION_CONSTRAINTS.PATCH.max) {
    result.isValid = false
    result.errors.push(
      `Patch version must be between ${VERSION_CONSTRAINTS.PATCH.min} and ${VERSION_CONSTRAINTS.PATCH.max}, got ${version.patch}`
    )
  }

  // Add warnings for edge cases
  if (version.major === VERSION_CONSTRAINTS.MAJOR.max) {
    result.warnings.push('Major version is at maximum value (999)')
  }

  if (version.minor === VERSION_CONSTRAINTS.MINOR.max) {
    result.warnings.push('Minor version is at maximum value (10)')
  }

  if (version.patch === VERSION_CONSTRAINTS.PATCH.max) {
    result.warnings.push('Patch version is at maximum value (9999)')
  }

  return result
}

/**
 * Format a version object to string
 */
function formatVersion(version, includePrefix = false) {
  const versionString = `${version.major}.${version.minor}.${version.patch}`
  return includePrefix ? `v${versionString}` : versionString
}

/**
 * Compare two versions
 */
function compareVersions(version1, version2) {
  const majorDiff = version1.major - version2.major
  const minorDiff = version1.minor - version2.minor
  const patchDiff = version1.patch - version2.patch

  let comparison = 0

  if (majorDiff !== 0) {
    comparison = majorDiff > 0 ? 1 : -1
  } else if (minorDiff !== 0) {
    comparison = minorDiff > 0 ? 1 : -1
  } else if (patchDiff !== 0) {
    comparison = patchDiff > 0 ? 1 : -1
  }

  return {
    comparison,
    difference: {
      major: majorDiff,
      minor: minorDiff,
      patch: patchDiff
    }
  }
}

/**
 * Check if a version string is valid
 */
function isValidVersionString(versionString) {
  const parsed = parseVersion(versionString)
  if (!parsed) return false
  
  const validation = validateVersion(parsed)
  return validation.isValid
}

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

// Example 3: Validation examples
console.log('3️⃣  Validation Examples:')
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
console.log('\nThe new versioning pattern (1-999.0-10.0-9999) has been successfully implemented!')
console.log('\nKey features:')
console.log('• Major version: 1-999 (application major version)')
console.log('• Minor version: 0-10 (minor version number)')
console.log('• Patch version: 0-9999 (changes between minor releases)')
console.log('• Full validation and constraint checking')
console.log('• Version parsing, formatting, and comparison')
console.log('• Integration with existing configuration system')
