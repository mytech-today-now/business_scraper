# Business Scraper App - API Documentation

This document provides comprehensive documentation for the Business Scraper App's internal APIs, services, and components.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Model Layer APIs](#model-layer-apis)
3. [Controller Layer APIs](#controller-layer-apis)
4. [View Layer Components](#view-layer-components)
5. [Utility Services](#utility-services)
6. [Type Definitions](#type-definitions)
7. [Configuration](#configuration)
8. [Error Handling](#error-handling)

## Architecture Overview

The application follows an **Adapted MVC (Model-View-Controller)** pattern:

```
src/
├── model/          # Data layer and business logic
├── view/           # UI components and presentation
├── controller/     # State management and workflow orchestration
├── utils/          # Utility functions and services
└── types/          # TypeScript type definitions
```

## Model Layer APIs

### ScraperService

**Location**: `src/model/scraperService.ts`

Core web scraping functionality using Puppeteer.

#### Methods

##### `initialize(): Promise<void>`
Initializes the browser instance for scraping operations.

```typescript
await scraperService.initialize()
```

##### `searchForWebsites(query: string, zipCode: string, maxResults?: number): Promise<string[]>`
Searches for business websites based on industry and location.

**Parameters:**
- `query`: Industry or business type to search for
- `zipCode`: ZIP code for location-based search
- `maxResults`: Maximum number of URLs to return (default: 50)

**Returns:** Array of website URLs

```typescript
const urls = await scraperService.searchForWebsites(
  'restaurants', 
  '90210', 
  25
)
```

##### `scrapeWebsite(url: string, depth?: number): Promise<BusinessRecord[]>`
Scrapes a website for business information.

**Parameters:**
- `url`: Website URL to scrape
- `depth`: Maximum crawl depth (default: 2)

**Returns:** Array of business records found on the website

```typescript
const businesses = await scraperService.scrapeWebsite(
  'https://example.com',
  3
)
```

##### `cleanup(): Promise<void>`
Closes the browser instance and cleans up resources.

```typescript
await scraperService.cleanup()
```

### GeocoderService

**Location**: `src/model/geocoder.ts`

Address geocoding with multiple provider fallbacks.

#### Methods

##### `geocodeAddress(address: string): Promise<GeocodingResult | null>`
Converts an address to coordinates.

**Parameters:**
- `address`: Street address to geocode

**Returns:** Geocoding result with lat/lng coordinates

```typescript
const result = await geocoder.geocodeAddress('123 Main St, Anytown, CA 12345')
if (result) {
  console.log(`Coordinates: ${result.lat}, ${result.lng}`)
}
```

##### `clearCache(): void`
Clears the geocoding cache.

```typescript
geocoder.clearCache()
```

### SearchEngineService

**Location**: `src/model/searchEngine.ts`

Search engine integration for finding business websites.

#### Methods

##### `searchBusinesses(query: string, location: string, maxResults?: number): Promise<SearchResult[]>`
Searches for businesses using multiple search providers.

**Parameters:**
- `query`: Search query
- `location`: Location (ZIP code or city)
- `maxResults`: Maximum results to return

**Returns:** Array of search results

```typescript
const results = await searchEngine.searchBusinesses(
  'coffee shops',
  'Seattle, WA',
  20
)
```

### StorageService

**Location**: `src/model/storage.ts`

IndexedDB operations for data persistence.

#### Methods

##### `saveBusiness(business: BusinessRecord): Promise<void>`
Saves a business record to storage.

```typescript
await storage.saveBusiness(businessRecord)
```

##### `getAllBusinesses(): Promise<BusinessRecord[]>`
Retrieves all business records.

```typescript
const businesses = await storage.getAllBusinesses()
```

##### `saveConfig(config: ScrapingConfig & { id: string }): Promise<void>`
Saves scraping configuration.

```typescript
await storage.saveConfig({ id: 'default', ...config })
```

## Controller Layer APIs

### ConfigContext

**Location**: `src/controller/ConfigContext.tsx`

Global configuration state management using React Context.

#### Hook: `useConfig()`

Returns configuration state and methods:

```typescript
const {
  state,
  updateConfig,
  addCustomIndustry,
  toggleIndustry,
  selectAllIndustries,
  toggleDarkMode,
  isConfigValid
} = useConfig()
```

#### State Properties

- `config`: Current scraping configuration
- `industries`: Available industry categories
- `selectedIndustries`: Currently selected industry IDs
- `isDarkMode`: Dark mode preference
- `isLoading`: Loading state
- `isInitialized`: Initialization status

#### Methods

- `updateConfig(config: Partial<ScrapingConfig>)`: Update configuration
- `addCustomIndustry(industry)`: Add custom industry category
- `toggleIndustry(id: string)`: Toggle industry selection
- `selectAllIndustries()`: Select all available industries
- `toggleDarkMode()`: Toggle dark/light mode

### useScraperController

**Location**: `src/controller/useScraperController.ts`

Scraping workflow orchestration hook.

#### Returns

```typescript
const {
  scrapingState,
  startScraping,
  stopScraping,
  clearResults,
  removeBusiness,
  updateBusiness,
  canStartScraping,
  hasResults
} = useScraperController()
```

#### State Properties

- `isScrapingActive`: Whether scraping is currently running
- `currentUrl`: Currently being scraped URL
- `progress`: Scraping progress information
- `results`: Array of scraped business records
- `stats`: Scraping statistics
- `errors`: Array of error messages

#### Methods

- `startScraping()`: Begin the scraping process
- `stopScraping()`: Stop the current scraping process
- `clearResults()`: Clear all scraped results
- `removeBusiness(id)`: Remove a specific business record
- `updateBusiness(id, updates)`: Update business information

## View Layer Components

### App

**Location**: `src/view/components/App.tsx`

Main application component that orchestrates the entire interface.

#### Props

No props - uses context for state management.

### CategorySelector

**Location**: `src/view/components/CategorySelector.tsx`

Industry category selection interface.

#### Features

- Display available industry categories
- Select/deselect individual categories
- Bulk select/deselect all categories
- Add custom industry categories
- Remove custom categories

### ResultsTable

**Location**: `src/view/components/ResultsTable.tsx`

Data display and management table for scraped business data.

#### Props

```typescript
interface ResultsTableProps {
  businesses: BusinessRecord[]
  onEdit?: (business: BusinessRecord) => void
  onDelete?: (businessId: string) => void
  onExport?: (format: string) => void
  isLoading?: boolean
}
```

#### Features

- Sortable columns
- Advanced filtering
- Inline editing
- Bulk operations
- Column visibility controls
- Export functionality

## Utility Services

### ExportService

**Location**: `src/utils/exportService.ts`

Multi-format data export functionality.

#### Methods

##### `exportBusinesses(businesses, format, options): Promise<{blob: Blob, filename: string}>`

Exports business data to specified format.

**Supported Formats:**
- `csv`: Comma-separated values
- `xlsx`: Excel workbook
- `xls`: Legacy Excel format
- `ods`: OpenDocument spreadsheet
- `pdf`: PDF document
- `json`: JSON format

```typescript
const { blob, filename } = await exportService.exportBusinesses(
  businesses,
  'xlsx',
  { filename: 'my-export' }
)
exportService.downloadBlob(blob, filename)
```

### ValidationService

**Location**: `src/utils/validation.ts`

Data validation and sanitization.

#### Methods

##### `validateBusinessRecord(business): ValidationResult`
Validates a business record against the schema.

##### `validateScrapingConfig(config): ValidationResult`
Validates scraping configuration.

##### `sanitizeInput(input: string): string`
Sanitizes user input for security.

```typescript
const result = validationService.validateBusinessRecord(business)
if (!result.isValid) {
  console.log('Validation errors:', result.errors)
}
```

### Logger

**Location**: `src/utils/logger.ts`

Structured logging system.

#### Methods

```typescript
logger.info('Component', 'Message', optionalData)
logger.warn('Component', 'Warning message')
logger.error('Component', 'Error message', errorObject)
logger.debug('Component', 'Debug info')
```

#### Features

- Multiple log levels (DEBUG, INFO, WARN, ERROR)
- Component-based logging
- In-memory log storage
- Export capabilities
- Console and storage output

## Type Definitions

### BusinessRecord

**Location**: `src/types/business.d.ts`

```typescript
interface BusinessRecord {
  id: string
  businessName: string
  email: string[]
  phone?: string
  websiteUrl: string
  address: {
    street: string
    suite?: string
    city: string
    state: string
    zipCode: string
  }
  contactPerson?: string
  coordinates?: {
    lat: number
    lng: number
  }
  industry: string
  scrapedAt: Date
}
```

### ScrapingConfig

```typescript
interface ScrapingConfig {
  industries: string[]
  zipCode: string
  searchRadius: number
  searchDepth: number
  pagesPerSite: number
}
```

### IndustryCategory

```typescript
interface IndustryCategory {
  id: string
  name: string
  keywords: string[]
  isCustom: boolean
}
```

## Configuration

### Environment Variables

```env
# Optional API keys for enhanced functionality
GOOGLE_MAPS_API_KEY=your_key_here
OPENCAGE_API_KEY=your_key_here
BING_SEARCH_API_KEY=your_key_here

# Scraping configuration
SCRAPING_TIMEOUT=30000
SCRAPING_MAX_RETRIES=3
SCRAPING_DELAY_MS=1000

# Application settings
NODE_ENV=development
NEXT_PUBLIC_DEBUG=false
```

### Default Configuration

```typescript
const DEFAULT_CONFIG = {
  timeout: 30000,
  maxRetries: 3,
  retryDelay: 1000,
  searchRadius: 25,
  searchDepth: 2,
  pagesPerSite: 5
}
```

## Error Handling

### Error Types

1. **Network Errors**: Connection timeouts, DNS failures
2. **Scraping Errors**: Website blocking, parsing failures
3. **Validation Errors**: Invalid data format, missing required fields
4. **Storage Errors**: IndexedDB failures, quota exceeded
5. **Configuration Errors**: Invalid settings, missing API keys

### Error Recovery

- Automatic retry with exponential backoff
- Graceful degradation for optional features
- User-friendly error messages
- Detailed logging for debugging

### Example Error Handling

```typescript
try {
  const result = await scraperService.scrapeWebsite(url)
  return result
} catch (error) {
  logger.error('Scraper', 'Failed to scrape website', error)
  
  if (error.code === 'TIMEOUT') {
    // Retry with longer timeout
    return await scraperService.scrapeWebsite(url, { timeout: 60000 })
  }
  
  throw new Error(`Scraping failed: ${error.message}`)
}
```

## Performance Considerations

### Optimization Strategies

1. **Lazy Loading**: Components and routes loaded on demand
2. **Caching**: Search results and geocoding cached locally
3. **Batch Processing**: Multiple operations grouped together
4. **Memory Management**: Cleanup of unused resources
5. **Rate Limiting**: Prevents overwhelming target servers

### Monitoring

- Real-time progress tracking
- Performance metrics collection
- Memory usage monitoring
- Error rate tracking

---

For more detailed information about specific implementations, refer to the JSDoc comments in the source code files.
