# Chamber of Commerce Processing (COCP)

## Overview

The Chamber of Commerce Processing (COCP) system automatically detects and processes `chamberofcommerce.com` URLs to extract business listings and their actual business websites. This provides comprehensive business contact information by navigating through Chamber of Commerce directory pages to find real business websites.

## Key Features

### 🔍 **Automatic Detection**
- Detects `chamberofcommerce.com` URLs in search results
- Automatically triggers specialized processing
- Seamlessly integrated into the main search flow

### 🎯 **Business Listing Extraction**
- Identifies business entries using specific CSS patterns:
  ```html
  <a href="/business-directory/illinois/barrington/tax-preparation-service/2024858709-g3-accounting-tax" 
     placeid="2024858709" 
     class="card white-card card-hover-shadow mb-2 p-3 p-lg-4 FeaturedPlacePreview">
  ```
- Extracts business profile URLs from Chamber directory pages
- Processes multiple businesses per Chamber page

### 🌐 **Business Website Discovery**
- Navigates to individual Chamber business profile pages
- Searches for external website links (non-chamberofcommerce.com domains)
- Extracts actual business website URLs
- Filters out social media and directory links

### 🔍 **Deep Website Scraping**
- Scrapes up to **20 pages per business website** (configurable)
- Extracts comprehensive contact information
- Uses enhanced scraping engine with anti-bot detection
- Collects detailed business records with full contact details

## Technical Implementation

### Automatic URL Detection

The system automatically detects Chamber of Commerce URLs during the search filtering process:

```typescript
// In filterValidBusinessResults()
if (domain.includes('chamberofcommerce.com')) {
  logger.info('ClientSearchEngine', `Detected Chamber of Commerce URL: ${result.url}`)
  const chamberResults = await this.processChamberOfCommerceUrl(result.url, 5)
  validResults.push(...chamberResults)
  continue
}
```

### Business Listing Extraction

```typescript
// Primary selectors for business entries
const businessSelectors = [
  'a[placeid][href*="/business-directory/"]',
  'a.card[href*="/business-directory/"]',
  'a.FeaturedPlacePreview[href*="/business-directory/"]',
  'a[href*="/business-directory/"]'
]
```

### Website URL Extraction

```typescript
// Extract external business websites (not chamberofcommerce.com)
const websiteSelectors = [
  'a[href*="http"]:not([href*="chamberofcommerce.com"]):not([href*="mailto:"]):not([href*="tel:"])',
  '.website a',
  '.business-website a',
  '.contact-info a[href*="http"]'
]
```

## Data Flow

### 1. **URL Detection**
```
Search Results → Filter → Detect chamberofcommerce.com URL
↓
Trigger Chamber of Commerce Processing
```

### 2. **Business Discovery**
```
Chamber Directory Page → Extract business listings using CSS selectors
↓
For each business: Extract Chamber profile URL
↓
Navigate to business profile page
```

### 3. **Website Extraction**
```
Business Profile Page → Find external website links
↓
Extract business website URL (non-chamberofcommerce.com)
↓
Validate and clean website URL
```

### 4. **Deep Scraping**
```
Business Website → Enhanced scraping engine
↓
Scrape up to 20 pages per site
↓
Extract contact information and business details
↓
Return comprehensive business records
```

## Configuration Options

### Processing Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | - | Chamber of Commerce URL to process |
| `maxBusinesses` | number | 10 | Maximum businesses to extract from Chamber page |
| `maxPagesPerSite` | number | 20 | Maximum pages to scrape per business website |

### API Request Format

```json
{
  "provider": "chamber-of-commerce",
  "url": "https://www.chamberofcommerce.com/business-directory/illinois/barrington/",
  "maxResults": 10,
  "maxPagesPerSite": 20
}
```

## Response Format

### ChamberOfCommerceBusinessResult

```typescript
interface ChamberOfCommerceBusinessResult {
  url: string                           // Business website URL
  title: string                         // Business name from Chamber
  snippet: string                       // Business description
  domain: string                        // Website domain
  address?: string                      // Business address
  phone?: string                        // Phone number
  chamberProfileUrl?: string            // Original Chamber profile URL
  businessRecords?: BusinessRecord[]    // Deep scraped data
}
```

### BusinessRecord (from Deep Scraping)

```typescript
interface BusinessRecord {
  id: string
  businessName: string
  email: string[]                       // All found email addresses
  phone?: string                        // Phone number
  websiteUrl: string                   // Source website
  address: {
    street: string
    suite?: string
    city: string
    state: string
    zipCode: string
  }
  contactPerson?: string               // Contact person name
  coordinates?: {
    lat: number
    lng: number
  }
  industry: string
  scrapedAt: Date
}
```

## Example Processing Flow

### Input URL
```
https://www.chamberofcommerce.com/business-directory/illinois/barrington/
```

### Step 1: Business Listing Extraction
```
Found business entries:
- G3 Accounting Tax (placeid: 2024858709)
- ABC Consulting (placeid: 2024858710)
- XYZ Services (placeid: 2024858711)
```

### Step 2: Profile URL Construction
```
https://www.chamberofcommerce.com/business-directory/illinois/barrington/tax-preparation-service/2024858709-g3-accounting-tax
https://www.chamberofcommerce.com/business-directory/illinois/barrington/consulting/2024858710-abc-consulting
https://www.chamberofcommerce.com/business-directory/illinois/barrington/services/2024858711-xyz-services
```

### Step 3: Website Extraction
```
G3 Accounting Tax → www.g3accounting.com
ABC Consulting → www.abcconsulting.net
XYZ Services → www.xyzservices.org
```

### Step 4: Deep Scraping Results
```
www.g3accounting.com → 3 business records with contact info
www.abcconsulting.net → 2 business records with contact info
www.xyzservices.org → 4 business records with contact info
```

## Error Handling

### Robust Fallback System
1. **Business Listing Fails**: Tries multiple CSS selectors
2. **Profile Navigation Fails**: Continues with next business
3. **Website Extraction Fails**: Keeps basic Chamber info
4. **Deep Scraping Fails**: Returns business info without detailed records
5. **Rate Limiting**: Implements delays and retry mechanisms

### Logging and Monitoring
- Detailed logging at each step of the process
- Performance metrics for deep scraping
- Success/failure rates for website extraction
- Processing time monitoring

## Performance Optimizations

### 1. **Concurrent Processing**
- Browser pool management for multiple simultaneous scrapes
- Parallel processing of business websites
- Resource cleanup and memory management

### 2. **Smart Rate Limiting**
- Respects Chamber of Commerce rate limits
- Implements delays between requests
- Uses multiple user agents and viewports

### 3. **Efficient Scraping**
- Stops scraping when sufficient contact info is found
- Prioritizes contact pages and about pages
- Skips irrelevant pages (images, downloads, etc.)

## Integration Points

### Automatic Integration
The COCP system is automatically triggered when:
1. Search results contain `chamberofcommerce.com` URLs
2. URLs are detected during the `filterValidBusinessResults` process
3. No manual configuration required

### Manual API Usage
```typescript
// Direct API call
const response = await fetch('/api/search', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    provider: 'chamber-of-commerce',
    url: 'https://www.chamberofcommerce.com/business-directory/illinois/barrington/',
    maxResults: 10,
    maxPagesPerSite: 20
  })
})
```

## Benefits

### 🎯 **Comprehensive Coverage**
- Extracts multiple businesses from single Chamber directory page
- Finds actual business websites, not just directory listings
- Provides deep contact information through website scraping

### 📊 **High-Quality Data**
- Real business websites with comprehensive contact information
- Multiple email addresses and phone numbers per business
- Complete address and contact person details

### ⚡ **Efficient Processing**
- Automatic detection and processing
- Concurrent scraping of multiple business websites
- Smart rate limiting prevents blocking

### 🔧 **Seamless Integration**
- No manual configuration required
- Automatically triggered during normal search operations
- Transparent to end users

## Usage Examples

### Automatic Processing (Recommended)
```typescript
// Chamber URLs are automatically detected and processed during normal searches
const results = await clientSearchEngine.searchBusinesses(
  "tax preparation services",
  "Barrington, IL",
  10
)
// If results include chamberofcommerce.com URLs, they are automatically processed
```

### Manual Processing
```typescript
const results = await chamberOfCommerceScrapingService.processChamberOfCommercePage({
  url: "https://www.chamberofcommerce.com/business-directory/illinois/barrington/",
  maxBusinesses: 10,
  maxPagesPerSite: 20
})
```

## Related Components

### **New Files:**
- `src/lib/chamberOfCommerceScrapingService.ts` - Main COCP service
- `CHAMBER_OF_COMMERCE_PROCESSING.md` - This documentation

### **Updated Files:**
- `src/app/api/search/route.ts` - Added COCP API endpoint
- `src/model/clientSearchEngine.ts` - Added automatic detection and processing

### **Dependencies:**
- Enhanced scraping engine for deep website analysis
- Browser pool for concurrent processing
- Anti-bot detection bypass for reliable scraping

The Chamber of Commerce Processing system provides a powerful, automated way to extract comprehensive business information from Chamber of Commerce directory pages, seamlessly integrated into the main search workflow.
