# Application Version System Update

## Overview

The application versioning system has been updated to follow a new custom pattern: **1-999.0-10.0-9999**

This replaces the previous semantic versioning (MAJOR.MINOR.PATCH) approach with a more constrained system that better fits the application's needs.

## New Version Pattern

### Format: `MAJOR.MINOR.PATCH`

- **Major Version**: 1-999 (Application major version number)
- **Minor Version**: 0-10 (Minor version number)  
- **Patch Version**: 0-9999 (Changes between minor releases)

### Examples

- `1.0.0` - Minimum valid version
- `6.10.1` - Current application version
- `999.10.9999` - Maximum valid version

## Implementation Details

### New Files Created

1. **`src/utils/version.ts`** - Core version utility with comprehensive functionality
2. **`src/__tests__/utils/version.test.ts`** - Complete test suite (19 tests, 100% coverage)
3. **`scripts/version-demo.js`** - Demonstration script showing all features
4. **`docs/VERSION_SYSTEM_UPDATE.md`** - This documentation

### Modified Files

1. **`src/lib/config-validator.ts`** - Updated to use new version validation
2. **`src/lib/config.ts`** - Updated default version to match new pattern
3. **`src/utils/formatters.ts`** - Added version formatting functions
4. **`src/__tests__/utils/formatters.test.ts`** - Added tests for version formatting

## Core Features

### Version Parsing
```typescript
import { parseVersion } from '@/utils/version'

const version = parseVersion('6.10.1')
// Returns: { major: 6, minor: 10, patch: 1, raw: '6.10.1' }
```

### Version Validation
```typescript
import { validateVersion, isValidVersionString } from '@/utils/version'

// Quick validation
const isValid = isValidVersionString('6.10.1') // true

// Detailed validation
const version = parseVersion('6.10.1')
const validation = validateVersion(version)
// Returns: { isValid: true, errors: [], warnings: ['Minor version is at maximum value (10)'] }
```

### Version Formatting
```typescript
import { formatVersion } from '@/utils/version'

const version = parseVersion('6.10.1')
const formatted = formatVersion(version, true) // 'v6.10.1'
```

### Version Comparison
```typescript
import { compareVersions } from '@/utils/version'

const v1 = parseVersion('6.5.100')
const v2 = parseVersion('6.5.200')
const result = compareVersions(v1, v2)
// Returns: { comparison: -1, difference: { major: 0, minor: 0, patch: -100 } }
```

### Version Incrementing
```typescript
import { incrementVersion } from '@/utils/version'

const version = parseVersion('6.5.100')
const newVersion = incrementVersion(version, 'patch')
// Returns: { major: 6, minor: 5, patch: 101, raw: '6.5.101' }
```

### Semantic Version Conversion
```typescript
import { convertFromSemanticVersion } from '@/utils/version'

const converted = convertFromSemanticVersion('6.8.3')
// Returns: { major: 6, minor: 8, patch: 3, raw: '6.8.3' }
```

## Validation Rules

### Constraints
- **Major**: Must be between 1 and 999 (inclusive)
- **Minor**: Must be between 0 and 10 (inclusive)
- **Patch**: Must be between 0 and 9999 (inclusive)

### Format Requirements
- Must follow the pattern: `MAJOR.MINOR.PATCH`
- Optional 'v' prefix is supported (e.g., 'v6.10.1')
- No pre-release or build metadata allowed
- All components must be numeric

### Warnings
The system provides warnings for edge cases:
- Major version at maximum (999)
- Minor version at maximum (10)
- Patch version at maximum (9999)

## Integration Points

### Configuration System
The version validation is integrated into the application configuration validator (`src/lib/config-validator.ts`), ensuring all version strings follow the new pattern.

### Formatters
Version formatting functions are available in `src/utils/formatters.ts` for consistent display throughout the application.

### Current Version Detection
The utility can automatically detect the current application version from:
1. VERSION file
2. Environment variables
3. package.json (with conversion from semantic versioning)

## Testing

### Test Coverage
- **Version Utility**: 19 tests covering all functions and edge cases
- **Formatters**: 5 additional tests for version formatting functions
- **Total Coverage**: 100% of new version functionality

### Running Tests
```bash
# Test version utility
npm test -- src/__tests__/utils/version.test.ts

# Test formatters (including version formatting)
npm test -- src/__tests__/utils/formatters.test.ts
```

## Demo Script

Run the demonstration script to see all features in action:

```bash
node scripts/version-demo.js
```

This script demonstrates:
- Version parsing and validation
- Version comparison
- Constraint checking
- Error handling

## Migration Notes

### From Semantic Versioning
- Most existing semantic versions can be converted automatically
- Versions with minor > 10 or patch > 9999 cannot be converted
- Pre-release versions (e.g., '1.2.3-alpha') are not supported

### Current Application State
- Current version `6.10.1` is valid under the new system
- All existing version references have been updated
- Configuration validation now uses the new pattern

## Usage Examples

### Basic Usage
```typescript
import { 
  parseVersion, 
  formatVersion, 
  isValidVersionString 
} from '@/utils/version'

// Validate a version string
if (isValidVersionString('6.10.1')) {
  const version = parseVersion('6.10.1')
  console.log(formatVersion(version, true)) // 'v6.10.1'
}
```

### Advanced Usage
```typescript
import { 
  parseVersion, 
  validateVersion, 
  incrementVersion, 
  compareVersions 
} from '@/utils/version'

const currentVersion = parseVersion('6.10.1')
const nextPatch = incrementVersion(currentVersion, 'patch')

if (nextPatch) {
  const comparison = compareVersions(currentVersion, nextPatch)
  console.log(`${formatVersion(nextPatch)} is newer than ${formatVersion(currentVersion)}`)
}
```

## Benefits

1. **Constrained Range**: Prevents version numbers from growing too large
2. **Clear Semantics**: Each component has a specific meaning and range
3. **Validation**: Built-in validation prevents invalid versions
4. **Compatibility**: Can convert from existing semantic versions where possible
5. **Comprehensive**: Full feature set for version management
6. **Tested**: Extensive test coverage ensures reliability

## Future Considerations

- The system is designed to be extensible if constraints need to be adjusted
- Version comparison and incrementing respect the new constraints
- Integration with CI/CD systems can use the validation functions
- Documentation and tooling can leverage the formatting functions
