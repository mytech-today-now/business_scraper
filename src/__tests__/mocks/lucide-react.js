/**
 * Mock for lucide-react to handle ESM import issues in Jest
 */

const React = require('react')

// Create a mock component factory
const createMockIcon = (name) => {
  const MockIcon = React.forwardRef((props, ref) => {
    return React.createElement('svg', {
      ...props,
      ref,
      'data-testid': `${name}-icon`,
      'aria-label': name,
      width: props.size || props.width || 24,
      height: props.size || props.height || 24,
      viewBox: '0 0 24 24',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: props.strokeWidth || 2,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
    })
  })
  
  MockIcon.displayName = `${name}Icon`
  return MockIcon
}

// Export all the icons used in the application
module.exports = {
  // Navigation and UI icons
  Home: createMockIcon('Home'),
  Search: createMockIcon('Search'),
  Settings: createMockIcon('Settings'),
  User: createMockIcon('User'),
  Menu: createMockIcon('Menu'),
  X: createMockIcon('X'),
  ChevronDown: createMockIcon('ChevronDown'),
  ChevronUp: createMockIcon('ChevronUp'),
  ChevronLeft: createMockIcon('ChevronLeft'),
  ChevronRight: createMockIcon('ChevronRight'),
  
  // Action icons
  Plus: createMockIcon('Plus'),
  Minus: createMockIcon('Minus'),
  Edit: createMockIcon('Edit'),
  Trash: createMockIcon('Trash'),
  Trash2: createMockIcon('Trash2'),
  Save: createMockIcon('Save'),
  Download: createMockIcon('Download'),
  Upload: createMockIcon('Upload'),
  Copy: createMockIcon('Copy'),
  
  // Status and feedback icons
  Check: createMockIcon('Check'),
  CheckCircle: createMockIcon('CheckCircle'),
  AlertCircle: createMockIcon('AlertCircle'),
  AlertTriangle: createMockIcon('AlertTriangle'),
  Info: createMockIcon('Info'),
  HelpCircle: createMockIcon('HelpCircle'),
  
  // Media and content icons
  Play: createMockIcon('Play'),
  Pause: createMockIcon('Pause'),
  Stop: createMockIcon('Stop'),
  RefreshCw: createMockIcon('RefreshCw'),
  RotateCcw: createMockIcon('RotateCcw'),
  
  // Communication icons
  Mail: createMockIcon('Mail'),
  Phone: createMockIcon('Phone'),
  MessageSquare: createMockIcon('MessageSquare'),
  
  // Business and data icons
  Building: createMockIcon('Building'),
  MapPin: createMockIcon('MapPin'),
  Globe: createMockIcon('Globe'),
  Database: createMockIcon('Database'),
  BarChart: createMockIcon('BarChart'),
  PieChart: createMockIcon('PieChart'),
  TrendingUp: createMockIcon('TrendingUp'),
  
  // Security icons
  Lock: createMockIcon('Lock'),
  Unlock: createMockIcon('Unlock'),
  Shield: createMockIcon('Shield'),
  Key: createMockIcon('Key'),
  
  // File and document icons
  File: createMockIcon('File'),
  FileText: createMockIcon('FileText'),
  Folder: createMockIcon('Folder'),
  FolderOpen: createMockIcon('FolderOpen'),
  
  // Technology icons
  Brain: createMockIcon('Brain'),
  Cpu: createMockIcon('Cpu'),
  Server: createMockIcon('Server'),
  Cloud: createMockIcon('Cloud'),
  
  // Utility icons
  Calendar: createMockIcon('Calendar'),
  Clock: createMockIcon('Clock'),
  Filter: createMockIcon('Filter'),
  Sort: createMockIcon('Sort'),
  Eye: createMockIcon('Eye'),
  EyeOff: createMockIcon('EyeOff'),
  
  // Export default for compatibility
  default: createMockIcon('Default'),
}

// Also support named exports for individual icons
Object.keys(module.exports).forEach(iconName => {
  if (iconName !== 'default') {
    module.exports[iconName] = module.exports[iconName]
  }
})
