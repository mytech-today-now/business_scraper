# Changelog

All notable changes to the Business Scraper App will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **🖼️ Next.js Image Optimization** (v1.2.0)
  - Replaced all `<img>` elements with Next.js `<Image>` components
  - Automatic WebP and AVIF format conversion for 25-50% smaller file sizes
  - Responsive image delivery with device-specific sizing
  - Priority loading for above-the-fold images to improve LCP
  - Explicit dimensions to prevent Cumulative Layout Shift (CLS)
  - Enhanced CSP configuration for Next.js image optimization endpoints
  - Created public directory structure with optimized favicon assets
  - Added PWA manifest.json for enhanced mobile experience
  - Comprehensive test suites for image optimization validation
  - Improved Core Web Vitals scores and SEO performance
- **🎯 Smart Industry Expansion System** (v1.1.0)
  - Automatic expansion of industry categories into specific business types
  - Professional Services → consulting, legal, accounting, financial, insurance
  - Healthcare → medical, healthcare, clinic, hospital, dental
  - 11 predefined industry categories with comprehensive keyword mappings
  - Case-insensitive matching with partial phrase support
  - Prioritizes quoted phrases over industry expansion
  - Comprehensive test coverage with 10 test cases

- **🏢 Advanced BBB Business Discovery** (v1.1.0)
  - Real-time BBB website scraping using Puppeteer
  - Anti-bot countermeasures with realistic browser fingerprinting
  - Extracts actual business websites from BBB profiles
  - Rate limiting with 1-second minimum delays between requests
  - Exponential backoff retry logic (up to 3 attempts)
  - Graceful fallback to directory search URLs
  - Dedicated BBBScrapingService with comprehensive error handling

- **📐 Precise ZIP Radius Validation** (v1.1.0)
  - Geolocation-based distance calculation using Haversine formula
  - ZIP code lookup service with API integration
  - Fallback geolocation data for major US cities
  - Accurate filtering of businesses within specified radius
  - Support for ZIP+4 codes and address parsing
  - ZipCodeService with caching and error recovery

- **🔍 Enhanced Search Engine Architecture** (v1.1.0)
  - Multi-strategy search with DuckDuckGo SERP scraping
  - Individual criteria parsing for comma-separated terms
  - Server-side proxy to avoid CORS issues
  - Comprehensive search result validation
  - Automatic failover between search providers
  - Real business website discovery instead of generic results

### Fixed
- **Industry Search Logic**: Fixed critical issue where system searched for industry category names instead of individual business types
- **BBB 500 Errors**: Resolved anti-scraping issues with proper Puppeteer implementation
- **Export Functionality**: Fixed data export in preview table
  - Implemented proper export handler in App component
  - Added loading states and user feedback
  - Fixed coordinate property mapping in formatters
  - Added comprehensive test coverage for all export formats
  - Export now works for CSV, XLSX, PDF, and JSON formats

### Changed
- **Search Query Processing**: Now expands "Professional Services businesses" into individual searches for consulting, legal, accounting, etc.
- **BBB Integration**: Replaced simplified URL generation with actual website scraping
- **Error Handling**: Enhanced with graceful degradation and detailed logging
- **Performance**: Improved with better rate limiting and resource management

### Technical Improvements
- **New Services**: BBBScrapingService, ZipCodeService, enhanced search engine
- **Test Coverage**: Added comprehensive test suites for industry expansion and BBB integration
- **Code Quality**: Improved error handling, logging, and resource cleanup
- **Architecture**: Better separation of concerns with dedicated service classes

### Planned Features
- Advanced filtering options for scraped data
- Bulk editing capabilities for business records
- Integration with CRM systems
- Advanced analytics and reporting
- API endpoints for external integrations
- Scheduled scraping jobs
- Data deduplication algorithms
- Enhanced geocoding accuracy

## [1.0.0] - 2024-01-XX

### Added
- **Core Scraping Engine**
  - Puppeteer-based web scraping with intelligent page navigation
  - Multi-provider search engine integration (DuckDuckGo, Bing, Yandex)
  - Automatic contact page discovery using keyword matching
  - Business data extraction (name, email, phone, address, website)
  - Configurable scraping depth and page limits
  - Real-time progress tracking with detailed statistics

- **Industry Management**
  - Predefined industry categories with associated keywords
  - Custom industry creation and management
  - Bulk selection/deselection of industries
  - Industry-specific search query generation

- **Location-Based Search**
  - ZIP code-centered search with configurable radius
  - Multi-provider geocoding service with fallback support
  - Address normalization and validation
  - Coordinate extraction and validation

- **Data Management**
  - IndexedDB-based local storage for offline capability
  - Business record CRUD operations
  - Session management for organizing scraping runs
  - Data validation and integrity checks
  - Duplicate detection and handling

- **User Interface**
  - Responsive design with mobile support
  - Dark mode toggle with system preference detection
  - Interactive data table with sorting and filtering
  - Real-time scraping progress visualization
  - Comprehensive error and warning displays
  - Intuitive configuration panels

- **Export Capabilities** ✅ **FULLY IMPLEMENTED & TESTED**
  - Multiple export formats: CSV, XLSX, XLS, ODS, PDF, JSON
  - Customizable export options (headers, encoding, formatting)
  - Batch export with progress indication
  - File size estimation for large datasets
  - One-click export from results table
  - Automatic file download with proper naming
  - Comprehensive test coverage (9 test cases)

- **Performance & Reliability**
  - Retry logic with exponential backoff
  - Request rate limiting to prevent blocking
  - Caching for search results and geocoding
  - Memory-efficient data processing
  - Error recovery and graceful degradation

- **Security & Privacy**
  - Input sanitization and XSP protection
  - CSP headers for enhanced security
  - Local-only data storage (no external transmission)
  - Ethical scraping practices with robots.txt respect

### Technical Implementation
- **Architecture**: Adapted MVC pattern with clear separation of concerns
- **Frontend**: Next.js 14 with React 18 and TypeScript
- **Styling**: Tailwind CSS with custom design system
- **State Management**: React Context with useReducer for complex state
- **Data Layer**: IndexedDB with idb wrapper for modern async/await API
- **Testing**: Jest with React Testing Library and comprehensive coverage
- **Build System**: Next.js with optimized production builds
- **Code Quality**: ESLint, TypeScript strict mode, and automated formatting

### Dependencies
- **Core Framework**: Next.js ^14.0.0, React ^18.2.0, TypeScript ^5.0.0
- **Scraping**: Puppeteer ^21.0.0, Playwright ^1.40.0
- **HTTP Client**: Axios ^1.6.0 with retry and timeout configuration
- **Data Export**: XLSX ^0.18.5, jsPDF ^2.5.1 with autoTable plugin
- **Storage**: idb ^8.0.0 for IndexedDB operations
- **Validation**: Zod ^3.22.0 for runtime type checking
- **UI Components**: Lucide React ^0.292.0 for icons
- **Styling**: Tailwind CSS ^3.3.0 with custom configuration
- **Notifications**: React Hot Toast ^2.4.1 for user feedback

### Development Tools
- **Testing**: Jest ^29.0.0, @testing-library/react ^14.0.0
- **Documentation**: Documentation.js ^14.0.0 for API docs
- **Linting**: ESLint ^8.0.0 with Next.js configuration
- **Type Checking**: TypeScript compiler with strict settings
- **Build Tools**: PostCSS, Autoprefixer for CSS processing

### Configuration
- **Environment Variables**: Comprehensive .env.example with all options
- **TypeScript**: Strict configuration with path mapping
- **Tailwind**: Custom design system with CSS variables
- **Jest**: Configured for Next.js with coverage reporting
- **ESLint**: Extended Next.js rules with custom overrides

### Documentation
- **README**: Comprehensive setup and usage instructions
- **API Docs**: JSDoc comments throughout codebase
- **Architecture**: Detailed explanation of MVC implementation
- **Contributing**: Guidelines for development and contributions
- **Deployment**: Instructions for various hosting platforms

### Performance Optimizations
- **Code Splitting**: Automatic route-based splitting with Next.js
- **Image Optimization**: Next.js Image component with lazy loading
- **Bundle Analysis**: Webpack bundle analyzer integration
- **Caching**: Strategic caching for API responses and computed data
- **Memory Management**: Efficient data structures and cleanup

### Accessibility
- **WCAG Compliance**: Level AA compliance for core functionality
- **Keyboard Navigation**: Full keyboard accessibility
- **Screen Reader Support**: Proper ARIA labels and semantic HTML
- **Color Contrast**: High contrast ratios in both light and dark modes
- **Focus Management**: Visible focus indicators and logical tab order

### Browser Support
- **Modern Browsers**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **Mobile Browsers**: iOS Safari 14+, Chrome Mobile 90+
- **Progressive Enhancement**: Graceful degradation for older browsers
- **Feature Detection**: Runtime feature detection for optional capabilities

### Known Limitations
- **Search Engines**: Limited by free API quotas and rate limits
- **Geocoding**: Accuracy depends on address quality and API availability
- **Scraping**: Subject to website structure changes and anti-bot measures
- **Performance**: Large datasets may impact browser performance
- **Storage**: IndexedDB size limits vary by browser and device

### Security Considerations
- **Data Privacy**: All data stored locally, no external transmission
- **Input Validation**: Comprehensive sanitization of user inputs
- **XSS Protection**: CSP headers and React's built-in protections
- **Rate Limiting**: Prevents overwhelming target websites
- **Error Handling**: Secure error messages without sensitive information

## [0.9.0] - Development Phase

### Added
- Initial project setup and architecture design
- Core component development and testing
- Basic scraping functionality implementation
- UI/UX design and responsive layout
- Data storage and export capabilities

### Changed
- Refined user interface based on testing feedback
- Optimized scraping algorithms for better accuracy
- Improved error handling and user notifications
- Enhanced data validation and sanitization

### Fixed
- Memory leaks in long-running scraping sessions
- Race conditions in concurrent data operations
- UI responsiveness issues on mobile devices
- Export formatting inconsistencies

## [0.1.0] - Initial Concept

### Added
- Project conception and requirements gathering
- Technology stack selection and evaluation
- Initial prototyping and proof of concept
- Architecture planning and design decisions

---

## Release Notes Format

Each release includes:
- **Added**: New features and capabilities
- **Changed**: Modifications to existing functionality
- **Deprecated**: Features marked for removal in future versions
- **Removed**: Features removed in this version
- **Fixed**: Bug fixes and issue resolutions
- **Security**: Security-related changes and improvements

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible functionality additions
- **PATCH**: Backward-compatible bug fixes

## Support Policy

- **Current Version**: Full support with regular updates
- **Previous Major**: Security fixes and critical bug fixes
- **Older Versions**: Community support only

For detailed information about specific changes, see the commit history and pull request discussions.
