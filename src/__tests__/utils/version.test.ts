import {
  parseVersion,
  validateVersion,
  formatVersion,
  compareVersions,
  incrementVersion,
  isValidVersionString,
  convertFromSemanticVersion,
  getCurrentVersion,
  VERSION_CONSTRAINTS,
  AppVersion
} from '@/utils/version'

describe('Version Utility', () => {
  describe('parseVersion', () => {
    it('should parse valid version strings', () => {
      const testCases = [
        { input: '1.0.0', expected: { major: 1, minor: 0, patch: 0, raw: '1.0.0' } },
        { input: '999.10.9999', expected: { major: 999, minor: 10, patch: 9999, raw: '999.10.9999' } },
        { input: '6.5.1234', expected: { major: 6, minor: 5, patch: 1234, raw: '6.5.1234' } },
        { input: 'v1.2.3', expected: { major: 1, minor: 2, patch: 3, raw: '1.2.3' } }
      ]

      testCases.forEach(({ input, expected }) => {
        const result = parseVersion(input)
        expect(result).toEqual(expected)
      })
    })

    it('should return null for invalid version strings', () => {
      const invalidVersions = [
        '',
        'invalid',
        '1.2',
        '1.2.3.4',
        '1000.0.0', // Major too high
        '1.11.0', // Minor too high
        '1.0.10000', // Patch too high
        'a.b.c',
        '1.2.3-alpha',
        null,
        undefined
      ]

      invalidVersions.forEach(version => {
        expect(parseVersion(version as any)).toBeNull()
      })
    })
  })

  describe('validateVersion', () => {
    it('should validate versions within constraints', () => {
      const validVersion: AppVersion = { major: 1, minor: 0, patch: 0, raw: '1.0.0' }
      const result = validateVersion(validVersion)
      
      expect(result.isValid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should reject versions outside constraints', () => {
      const testCases = [
        { version: { major: 0, minor: 0, patch: 0, raw: '0.0.0' }, expectedError: 'Major version must be between 1 and 999' },
        { version: { major: 1000, minor: 0, patch: 0, raw: '1000.0.0' }, expectedError: 'Major version must be between 1 and 999' },
        { version: { major: 1, minor: 11, patch: 0, raw: '1.11.0' }, expectedError: 'Minor version must be between 0 and 10' },
        { version: { major: 1, minor: 0, patch: 10000, raw: '1.0.10000' }, expectedError: 'Patch version must be between 0 and 9999' }
      ]

      testCases.forEach(({ version, expectedError }) => {
        const result = validateVersion(version)
        expect(result.isValid).toBe(false)
        expect(result.errors.some(error => error.includes(expectedError.split(' ')[0]))).toBe(true)
      })
    })

    it('should provide warnings for edge cases', () => {
      const edgeCases = [
        { version: { major: 999, minor: 0, patch: 0, raw: '999.0.0' }, expectedWarning: 'Major version is at maximum' },
        { version: { major: 1, minor: 10, patch: 0, raw: '1.10.0' }, expectedWarning: 'Minor version is at maximum' },
        { version: { major: 1, minor: 0, patch: 9999, raw: '1.0.9999' }, expectedWarning: 'Patch version is at maximum' }
      ]

      edgeCases.forEach(({ version, expectedWarning }) => {
        const result = validateVersion(version)
        expect(result.isValid).toBe(true)
        expect(result.warnings.some(warning => warning.includes(expectedWarning.split(' ')[0]))).toBe(true)
      })
    })
  })

  describe('formatVersion', () => {
    it('should format version without prefix', () => {
      const version: AppVersion = { major: 1, minor: 2, patch: 3, raw: '1.2.3' }
      expect(formatVersion(version)).toBe('1.2.3')
    })

    it('should format version with prefix', () => {
      const version: AppVersion = { major: 1, minor: 2, patch: 3, raw: '1.2.3' }
      expect(formatVersion(version, true)).toBe('v1.2.3')
    })
  })

  describe('compareVersions', () => {
    it('should compare versions correctly', () => {
      const v1: AppVersion = { major: 1, minor: 0, patch: 0, raw: '1.0.0' }
      const v2: AppVersion = { major: 1, minor: 0, patch: 1, raw: '1.0.1' }
      const v3: AppVersion = { major: 1, minor: 1, patch: 0, raw: '1.1.0' }
      const v4: AppVersion = { major: 2, minor: 0, patch: 0, raw: '2.0.0' }

      // Test less than
      expect(compareVersions(v1, v2).comparison).toBe(-1)
      expect(compareVersions(v1, v3).comparison).toBe(-1)
      expect(compareVersions(v1, v4).comparison).toBe(-1)

      // Test greater than
      expect(compareVersions(v2, v1).comparison).toBe(1)
      expect(compareVersions(v3, v1).comparison).toBe(1)
      expect(compareVersions(v4, v1).comparison).toBe(1)

      // Test equal
      expect(compareVersions(v1, v1).comparison).toBe(0)
    })

    it('should calculate differences correctly', () => {
      const v1: AppVersion = { major: 1, minor: 2, patch: 3, raw: '1.2.3' }
      const v2: AppVersion = { major: 2, minor: 3, patch: 4, raw: '2.3.4' }

      const result = compareVersions(v2, v1)
      expect(result.difference).toEqual({
        major: 1,
        minor: 1,
        patch: 1
      })
    })
  })

  describe('incrementVersion', () => {
    it('should increment major version and reset lower components', () => {
      const version: AppVersion = { major: 1, minor: 2, patch: 3, raw: '1.2.3' }
      const result = incrementVersion(version, 'major')
      
      expect(result).toEqual({
        major: 2,
        minor: 0,
        patch: 0,
        raw: '2.0.0'
      })
    })

    it('should increment minor version and reset patch', () => {
      const version: AppVersion = { major: 1, minor: 2, patch: 3, raw: '1.2.3' }
      const result = incrementVersion(version, 'minor')
      
      expect(result).toEqual({
        major: 1,
        minor: 3,
        patch: 0,
        raw: '1.3.0'
      })
    })

    it('should increment patch version only', () => {
      const version: AppVersion = { major: 1, minor: 2, patch: 3, raw: '1.2.3' }
      const result = incrementVersion(version, 'patch')
      
      expect(result).toEqual({
        major: 1,
        minor: 2,
        patch: 4,
        raw: '1.2.4'
      })
    })

    it('should not reset lower components when resetLower is false', () => {
      const version: AppVersion = { major: 1, minor: 2, patch: 3, raw: '1.2.3' }
      const result = incrementVersion(version, 'major', false)
      
      expect(result).toEqual({
        major: 2,
        minor: 2,
        patch: 3,
        raw: '2.2.3'
      })
    })

    it('should return null when increment exceeds constraints', () => {
      const maxMajor: AppVersion = { major: 999, minor: 0, patch: 0, raw: '999.0.0' }
      const maxMinor: AppVersion = { major: 1, minor: 10, patch: 0, raw: '1.10.0' }
      const maxPatch: AppVersion = { major: 1, minor: 0, patch: 9999, raw: '1.0.9999' }

      expect(incrementVersion(maxMajor, 'major')).toBeNull()
      expect(incrementVersion(maxMinor, 'minor')).toBeNull()
      expect(incrementVersion(maxPatch, 'patch')).toBeNull()
    })
  })

  describe('isValidVersionString', () => {
    it('should validate correct version strings', () => {
      const validVersions = ['1.0.0', '999.10.9999', '6.5.1234', 'v1.2.3']
      
      validVersions.forEach(version => {
        expect(isValidVersionString(version)).toBe(true)
      })
    })

    it('should reject invalid version strings', () => {
      const invalidVersions = ['', '1.2', '1000.0.0', '1.11.0', '1.0.10000', 'invalid']
      
      invalidVersions.forEach(version => {
        expect(isValidVersionString(version)).toBe(false)
      })
    })
  })

  describe('convertFromSemanticVersion', () => {
    it('should convert valid semantic versions', () => {
      const testCases = [
        { input: '1.0.0', expected: { major: 1, minor: 0, patch: 0, raw: '1.0.0' } },
        { input: 'v6.5.123', expected: { major: 6, minor: 5, patch: 123, raw: '6.5.123' } },
        { input: '999.10.9999', expected: { major: 999, minor: 10, patch: 9999, raw: '999.10.9999' } }
      ]

      testCases.forEach(({ input, expected }) => {
        const result = convertFromSemanticVersion(input)
        expect(result).toEqual(expected)
      })
    })

    it('should return null for incompatible semantic versions', () => {
      const incompatibleVersions = [
        '1000.0.0', // Major too high
        '1.11.0', // Minor too high
        '1.0.10000', // Patch too high
        'invalid',
        '1.2.3-alpha'
      ]

      incompatibleVersions.forEach(version => {
        expect(convertFromSemanticVersion(version)).toBeNull()
      })
    })
  })

  describe('VERSION_CONSTRAINTS', () => {
    it('should have correct constraint values', () => {
      expect(VERSION_CONSTRAINTS.MAJOR).toEqual({ min: 1, max: 999 })
      expect(VERSION_CONSTRAINTS.MINOR).toEqual({ min: 0, max: 10 })
      expect(VERSION_CONSTRAINTS.PATCH).toEqual({ min: 0, max: 9999 })
    })
  })
})
