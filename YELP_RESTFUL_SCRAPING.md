# Yelp RESTful Scraping with Deep Website Analysis

## Overview

The Yelp processing system has been completely refactored to use **RESTful URLs** for searching Yelp and implement **deep website scraping** of discovered business websites. This provides more reliable search results and comprehensive contact information extraction.

## Key Features

### 🔗 **RESTful URL Search**
- Uses direct Yelp search URLs: `https://www.yelp.com/search?find_desc=Business+Consulting&find_loc=90274`
- More reliable than form-based searching
- Better compatibility with headless browsers
- Consistent URL structure for all searches

### 🎯 **YERP Processing** 
- **YERP**: Yelp Engine Results Pages
- Identifies business entries using specific CSS selector: `div.businessName__09f24__HG_pC.y-css-mhg9c5[data-traffic-crawl-id="SearchResultBizName"]`
- Extracts business profile URLs from search results
- Processes multiple businesses per search

### 🌐 **Business Website Extraction**
- Navigates to individual Yelp business profile pages
- Extracts actual business website URLs using the pattern:
  ```html
  <div class="y-css-1ilqd8r">
    <a href="/biz_redir?url=https%3A%2F%2Fwww.rscbusinessgroup.com&amp;cachebuster=1753494273&amp;website_link_type=website&amp;src_bizid=eUpRo6nbHjcljDWfBywe5w&amp;s=59cd957b85fab6b8d7bc735840330c0796095d7bad24a1d0cbbc13f95a716a3a" 
       class=" y-css-14ckas3" target="_blank">
  ```
- Decodes `biz_redir` URLs to extract actual business websites
- Handles both redirect URLs and direct website links

### 🔍 **Deep Website Scraping**
- Scrapes up to **20 pages per business website** (configurable)
- Extracts comprehensive contact information
- Follows internal links for thorough coverage
- Uses enhanced scraping engine with anti-bot detection
- Collects business records with full contact details

## Technical Implementation

### RESTful URL Construction

```typescript
const yelpSearchUrl = new URL('https://www.yelp.com/search')
yelpSearchUrl.searchParams.set('find_desc', query.replace(/\s+/g, '+'))
yelpSearchUrl.searchParams.set('find_loc', location)
```

**Example URLs:**
- Business Consulting in 90274: `https://www.yelp.com/search?find_desc=Business+Consulting&find_loc=90274`
- Legal Services in 10001: `https://www.yelp.com/search?find_desc=Legal+Services&find_loc=10001`
- Medical Clinics in 90210: `https://www.yelp.com/search?find_desc=Medical+Clinics&find_loc=90210`

### YERP Business Extraction

```typescript
// Primary selector for business entries
const businessNameSelectors = [
  'div.businessName__09f24__HG_pC.y-css-mhg9c5[data-traffic-crawl-id="SearchResultBizName"]',
  '.businessName__09f24__HG_pC[data-traffic-crawl-id="SearchResultBizName"]',
  '[data-traffic-crawl-id="SearchResultBizName"]'
]
```

### Website URL Extraction

```typescript
// Extract business website from biz_redir URLs
if (link.href.includes('biz_redir?url=')) {
  const urlParams = new URLSearchParams(link.href.split('?')[1])
  const actualUrl = decodeURIComponent(urlParams.get('url') || '')
  return actualUrl
}
```

### Deep Scraping Integration

```typescript
// Perform deep scraping of business websites
const scrapingResult = await scraperService.scrapeWebsiteEnhanced(
  business.url,
  2, // depth
  maxPagesPerSite // up to 20 pages
)
```

## Configuration Options

### Search Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | - | Search terms (e.g., "Business Consulting") |
| `location` | string | - | ZIP code or location (e.g., "90274") |
| `zipRadius` | number | 25 | Search radius in miles |
| `maxResults` | number | 10 | Maximum businesses to process |
| `maxPagesPerSite` | number | 20 | Maximum pages to scrape per website |

### API Request Format

```json
{
  "provider": "yelp-discovery",
  "query": "Business Consulting",
  "location": "90274",
  "maxResults": 10,
  "zipRadius": 25,
  "maxPagesPerSite": 20
}
```

## Data Flow

### 1. **RESTful Search**
```
Query: "Business Consulting" + Location: "90274"
↓
URL: https://www.yelp.com/search?find_desc=Business+Consulting&find_loc=90274
↓
Navigate to YERP (Yelp Engine Results Page)
```

### 2. **Business Discovery**
```
YERP → Extract business entries using CSS selector
↓
For each business: Extract Yelp profile URL
↓
Navigate to business profile page
```

### 3. **Website Extraction**
```
Business Profile Page → Find website link
↓
Extract from biz_redir URL or direct link
↓
Decode actual business website URL
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

## Response Format

### YelpBusinessResult

```typescript
interface YelpBusinessResult {
  url: string                    // Business website URL
  title: string                  // Business name from Yelp
  snippet: string               // Business description
  domain: string                // Website domain
  address?: string              // Business address
  phone?: string                // Phone number
  yelpProfileUrl?: string       // Original Yelp profile URL
  businessRecords?: BusinessRecord[]  // Deep scraped data
}
```

### BusinessRecord (from Deep Scraping)

```typescript
interface BusinessRecord {
  id: string
  businessName: string
  email: string[]               // All found email addresses
  phone?: string                // Phone number
  websiteUrl: string           // Source website
  address: {
    street: string
    suite?: string
    city: string
    state: string
    zipCode: string
  }
  contactPerson?: string        // Contact person name
  coordinates?: {
    lat: number
    lng: number
  }
  industry: string
  scrapedAt: Date
}
```

## Error Handling

### Robust Fallback System
1. **Primary Selector Fails**: Falls back to alternative CSS selectors
2. **biz_redir Parsing Fails**: Attempts direct URL extraction
3. **Deep Scraping Fails**: Returns basic business info without detailed records
4. **Rate Limiting**: Implements delays and retry mechanisms
5. **Anti-Bot Detection**: Uses browser pool and user agent rotation

### Logging and Monitoring
- Detailed logging at each step of the process
- Performance metrics for deep scraping
- Success/failure rates for website extraction
- Rate limiting compliance monitoring

## Performance Optimizations

### 1. **Concurrent Processing**
- Browser pool management for multiple simultaneous scrapes
- Parallel processing of business websites
- Resource cleanup and memory management

### 2. **Smart Rate Limiting**
- Respects Yelp's rate limits
- Implements delays between requests
- Uses multiple user agents and viewports

### 3. **Efficient Scraping**
- Stops scraping when sufficient contact info is found
- Prioritizes contact pages and about pages
- Skips irrelevant pages (images, downloads, etc.)

## Usage Examples

### Basic Search
```typescript
const results = await yelpScrapingService.searchBusinesses({
  query: "Business Consulting",
  location: "90274",
  zipRadius: 25,
  maxResults: 10,
  maxPagesPerSite: 20
})
```

### Industry-Specific Search
```typescript
const results = await yelpScrapingService.searchBusinesses({
  query: "Legal Services",
  location: "10001",
  zipRadius: 15,
  maxResults: 5,
  maxPagesPerSite: 15
})
```

## Benefits of the Refactored System

### 🎯 **Improved Reliability**
- RESTful URLs are more stable than form-based searches
- Specific CSS selectors reduce parsing errors
- Better handling of Yelp's dynamic content

### 📊 **Enhanced Data Quality**
- Deep website scraping provides comprehensive contact information
- Multiple email addresses and phone numbers per business
- Complete address and contact person details

### ⚡ **Better Performance**
- Concurrent processing of multiple businesses
- Efficient resource management with browser pooling
- Smart rate limiting prevents blocking

### 🔧 **Maintainability**
- Clear separation of concerns (search → extract → scrape)
- Modular design allows easy updates
- Comprehensive error handling and logging

This refactored Yelp processing system provides a robust, scalable solution for discovering and deeply analyzing business websites found through Yelp search results.
