/**
 * Simple Mock for lucide-react - Direct component exports
 */

const React = require('react')

// Create a simple mock icon component
const createMockIcon = (name) => {
  const MockIcon = React.forwardRef((props, ref) => {
    const {
      size,
      width,
      height,
      strokeWidth = 2,
      className = '',
      'data-testid': testId,
      'aria-label': ariaLabel,
      ...restProps
    } = props

    return React.createElement('svg', {
      ...restProps,
      ref,
      'data-testid': testId || `${name.toLowerCase()}-icon`,
      'aria-label': ariaLabel || name,
      'aria-hidden': ariaLabel ? 'false' : 'true',
      role: 'img',
      width: size || width || 24,
      height: size || height || 24,
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
      className: `lucide lucide-${name.toLowerCase().replace(/([A-Z])/g, '-$1').toLowerCase()} ${className}`.trim(),
    })
  })

  MockIcon.displayName = `${name}Icon`
  return MockIcon
}

// Create all the icons directly
const X = createMockIcon('X')
const Menu = createMockIcon('Menu')
const Settings = createMockIcon('Settings')
const FileText = createMockIcon('FileText')
const Moon = createMockIcon('Moon')
const Sun = createMockIcon('Sun')
const AlertCircle = createMockIcon('AlertCircle')
const CheckCircle = createMockIcon('CheckCircle')
const Info = createMockIcon('Info')
const XCircle = createMockIcon('XCircle')
const AlertTriangle = createMockIcon('AlertTriangle')
const RefreshCw = createMockIcon('RefreshCw')
const Home = createMockIcon('Home')
const Bug = createMockIcon('Bug')
const Brain = createMockIcon('Brain')
const BarChart3 = createMockIcon('BarChart3')
const RotateCcw = createMockIcon('RotateCcw')

// Export all icons directly
module.exports = {
  X,
  Menu,
  Settings,
  FileText,
  Moon,
  Sun,
  AlertCircle,
  CheckCircle,
  Info,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Home,
  Bug,
  Brain,
  BarChart3,
  RotateCcw,
  default: createMockIcon('Default'),
  __esModule: true
}



// Handle nested imports (e.g., from 'lucide-react/dist/esm/icons/AlertCircle')
// This is used when Next.js modularizeImports transforms the imports
if (typeof module !== 'undefined' && module.exports) {
  // If this file is being imported as a specific icon, return that icon
  const filename = typeof __filename !== 'undefined' ? __filename : ''
  const iconMatch = filename.match(/icons[\/\\]([^\/\\]+)\.js$/)
  if (iconMatch) {
    const iconName = iconMatch[1]
    const specificIcon = createDynamicIcon(iconName)
    module.exports = specificIcon
    module.exports.default = specificIcon
  }
}
