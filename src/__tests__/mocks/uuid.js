/**
 * Mock for uuid package to handle ESM import issues in Jest
 */

// Simple UUID v4 mock implementation
function v4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

// Simple UUID v1 mock implementation
function v1() {
  const timestamp = Date.now()
  return `${timestamp.toString(16)}-xxxx-1xxx-yxxx-xxxxxxxxxxxx`.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

// Validate UUID format
function validate(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  return uuidRegex.test(uuid)
}

// Version detection
function version(uuid) {
  if (!validate(uuid)) {
    throw new Error('Invalid UUID')
  }
  return parseInt(uuid.charAt(14), 16)
}

// Export both CommonJS and ES module style
module.exports = {
  v1,
  v4,
  validate,
  version,
  // Default export for compatibility
  default: {
    v1,
    v4,
    validate,
    version,
  }
}

// Support for named imports
module.exports.v1 = v1
module.exports.v4 = v4
module.exports.validate = validate
module.exports.version = version
