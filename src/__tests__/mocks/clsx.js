/**
 * Mock implementation of clsx for Jest tests
 * Provides both named and default exports to handle different import patterns
 */

function clsxImpl(...args) {
  const classes = []
  
  args.forEach(arg => {
    if (!arg) return
    
    if (typeof arg === 'string' || typeof arg === 'number') {
      classes.push(arg)
    } else if (Array.isArray(arg)) {
      classes.push(clsxImpl(...arg))
    } else if (typeof arg === 'object') {
      Object.keys(arg).forEach(key => {
        if (arg[key]) classes.push(key)
      })
    }
  })
  
  return classes.join(' ')
}

// Export as both named and default export to handle different import patterns
module.exports = clsxImpl
module.exports.clsx = clsxImpl
module.exports.default = clsxImpl
