'use strict'

/**
 * Application Version Utility
 * 
 * Handles the custom versioning pattern: 1-999.0-10.0-9999
 * - Major: 1-999 (application major version)
 * - Minor: 0-10 (minor version number)
 * - Patch: 0-9999 (changes between minor releases)
 */

export interface AppVersion {
  major: number
  minor: number
  patch: number
  raw: string
}

export interface VersionValidationResult {
  isValid: boolean
  errors: string[]
  warnings: string[]
}

export interface VersionComparisonResult {
  comparison: -1 | 0 | 1 // -1: less than, 0: equal, 1: greater than
  difference: {
    major: number
    minor: number
    patch: number
  }
}

/**
 * Version validation constants
 */
export const VERSION_CONSTRAINTS = {
  MAJOR: { min: 1, max: 999 },
  MINOR: { min: 0, max: 10 },
  PATCH: { min: 0, max: 9999 }
} as const

/**
 * Regular expression for version pattern validation
 */
const VERSION_PATTERN = /^(\d{1,3})\.(\d{1,2})\.(\d{1,4})$/

/**
 * Parse a version string into components
 * @param versionString - Version string to parse (e.g., "6.5.1234")
 * @returns Parsed version object or null if invalid
 */
export function parseVersion(versionString: string): AppVersion | null {
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
 * Validate a version object against constraints
 * @param version - Version object to validate
 * @returns Validation result with errors and warnings
 */
export function validateVersion(version: AppVersion): VersionValidationResult {
  const result: VersionValidationResult = {
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
 * @param version - Version object to format
 * @param includePrefix - Whether to include 'v' prefix
 * @returns Formatted version string
 */
export function formatVersion(version: AppVersion, includePrefix: boolean = false): string {
  const versionString = `${version.major}.${version.minor}.${version.patch}`
  return includePrefix ? `v${versionString}` : versionString
}

/**
 * Compare two versions
 * @param version1 - First version to compare
 * @param version2 - Second version to compare
 * @returns Comparison result
 */
export function compareVersions(version1: AppVersion, version2: AppVersion): VersionComparisonResult {
  const majorDiff = version1.major - version2.major
  const minorDiff = version1.minor - version2.minor
  const patchDiff = version1.patch - version2.patch

  let comparison: -1 | 0 | 1 = 0

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
 * Increment version components
 * @param version - Current version
 * @param component - Component to increment ('major', 'minor', 'patch')
 * @param resetLower - Whether to reset lower components to 0
 * @returns New version object or null if increment would exceed constraints
 */
export function incrementVersion(
  version: AppVersion, 
  component: 'major' | 'minor' | 'patch',
  resetLower: boolean = true
): AppVersion | null {
  const newVersion = { ...version }

  switch (component) {
    case 'major':
      if (newVersion.major >= VERSION_CONSTRAINTS.MAJOR.max) {
        return null // Cannot increment beyond max
      }
      newVersion.major++
      if (resetLower) {
        newVersion.minor = 0
        newVersion.patch = 0
      }
      break

    case 'minor':
      if (newVersion.minor >= VERSION_CONSTRAINTS.MINOR.max) {
        return null // Cannot increment beyond max
      }
      newVersion.minor++
      if (resetLower) {
        newVersion.patch = 0
      }
      break

    case 'patch':
      if (newVersion.patch >= VERSION_CONSTRAINTS.PATCH.max) {
        return null // Cannot increment beyond max
      }
      newVersion.patch++
      break

    default:
      return null
  }

  newVersion.raw = formatVersion(newVersion)
  return newVersion
}

/**
 * Check if a version string is valid
 * @param versionString - Version string to check
 * @returns True if valid, false otherwise
 */
export function isValidVersionString(versionString: string): boolean {
  const parsed = parseVersion(versionString)
  if (!parsed) return false
  
  const validation = validateVersion(parsed)
  return validation.isValid
}

/**
 * Convert semantic version to new format
 * @param semver - Semantic version string (e.g., "1.2.3")
 * @returns Converted version or null if conversion not possible
 */
export function convertFromSemanticVersion(semver: string): AppVersion | null {
  // Use strict pattern that doesn't allow pre-release or build metadata
  const match = semver.match(/^v?(\d+)\.(\d+)\.(\d+)$/)
  if (!match) return null

  const major = parseInt(match[1], 10)
  const minor = parseInt(match[2], 10)
  const patch = parseInt(match[3], 10)

  // Check if conversion is possible within constraints
  if (major < VERSION_CONSTRAINTS.MAJOR.min || major > VERSION_CONSTRAINTS.MAJOR.max) {
    return null
  }
  if (minor > VERSION_CONSTRAINTS.MINOR.max) {
    return null
  }
  if (patch > VERSION_CONSTRAINTS.PATCH.max) {
    return null
  }

  const version: AppVersion = {
    major,
    minor,
    patch,
    raw: `${major}.${minor}.${patch}`
  }

  return version
}

/**
 * Get current application version from various sources
 * @returns Current version object or null if not found/invalid
 */
export function getCurrentVersion(): AppVersion | null {
  try {
    // Try to read from VERSION file first
    if (typeof window === 'undefined') {
      const fs = require('fs')
      const path = require('path')
      try {
        const versionFile = fs.readFileSync(path.join(process.cwd(), 'VERSION'), 'utf8').trim()
        const parsed = parseVersion(versionFile)
        if (parsed && validateVersion(parsed).isValid) {
          return parsed
        }
      } catch {
        // Fall through to other methods
      }
    }

    // Try environment variable
    const envVersion = process.env.NEXT_PUBLIC_APP_VERSION
    if (envVersion) {
      const parsed = parseVersion(envVersion)
      if (parsed && validateVersion(parsed).isValid) {
        return parsed
      }
    }

    // Try package.json (convert from semantic version)
    try {
      const packageJson = require('../../../package.json')
      return convertFromSemanticVersion(packageJson.version)
    } catch {
      // Fall through
    }

    return null
  } catch {
    return null
  }
}
