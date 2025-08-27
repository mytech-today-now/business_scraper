# API Documentation

![Version](https://img.shields.io/badge/version-3.10.1-blue.svg)
![API](https://img.shields.io/badge/API-REST-blue.svg)
![Last Updated](https://img.shields.io/badge/updated-2025--08--25-green.svg)

## 📋 Overview

This document provides comprehensive API documentation for the Business Scraper
Application v3.7.0. The API follows REST principles and provides endpoints for
business search, data scraping, configuration management, and CRM export
functionality.

## 🔗 Base URL

```
Development: http://localhost:3000/api
Production: https://your-domain.com/api
```

## 🔐 Authentication

Currently, the API uses session-based authentication. Future versions will
include API key authentication for programmatic access.

```typescript
// Authentication headers (when implemented)
{
  "Authorization": "Bearer <api-key>",
  "Content-Type": "application/json"
}
```

## 📊 Response Format

All API responses follow a consistent format:

```typescript
interface APIResponse<T> {
  success: boolean
  data?: T
  message: string
  error?: string
  timestamp: string
  version: string
}
```

### Success Response

```json
{
  "success": true,
  "data": {
    /* response data */
  },
  "message": "Operation completed successfully",
  "timestamp": "2025-08-25T10:00:00.000Z",
  "version": "3.7.0"
}
```

### Error Response

```json
{
  "success": false,
  "error": "Detailed error message",
  "message": "Operation failed",
  "timestamp": "2025-08-25T10:00:00.000Z",
  "version": "3.7.0"
}
```

## 🔍 Business Search API

### Search Businesses

**Endpoint**: `POST /api/search` **Description**: Search for businesses using
various search engines and criteria

#### Request Body

```typescript
interface SearchRequest {
  query: string // Search query (e.g., "restaurants")
  location: string // Location (ZIP code or city, state)
  radius?: number // Search radius in miles (default: 25)
  limit?: number // Maximum results (default: 50, max: 500)
  engines?: string[] // Search engines to use
  filters?: SearchFilters // Additional search filters
}

interface SearchFilters {
  industry?: string[] // Industry categories
  minRating?: number // Minimum business rating
  hasWebsite?: boolean // Filter for businesses with websites
  hasPhone?: boolean // Filter for businesses with phone numbers
  hasEmail?: boolean // Filter for businesses with email addresses
}
```

#### Example Request

```bash
curl -X POST http://localhost:3000/api/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "restaurants",
    "location": "90210",
    "radius": 10,
    "limit": 25,
    "filters": {
      "hasWebsite": true,
      "minRating": 4.0
    }
  }'
```

#### Response

```typescript
interface SearchResponse {
  results: BusinessRecord[]
  metadata: {
    totalFound: number
    searchTime: number
    engines: string[]
    location: {
      query: string
      resolved: string
      coordinates?: [number, number]
    }
  }
}
```

#### Example Response

```json
{
  "success": true,
  "data": {
    "results": [
      {
        "id": "business-123",
        "businessName": "Example Restaurant",
        "url": "https://example-restaurant.com",
        "phone": "(555) 123-4567",
        "email": "contact@example-restaurant.com",
        "address": "123 Main St",
        "city": "Beverly Hills",
        "state": "CA",
        "zipCode": "90210",
        "industry": "restaurants",
        "confidence": 0.95,
        "source": "google",
        "scrapedAt": "2025-08-25T10:00:00.000Z"
      }
    ],
    "metadata": {
      "totalFound": 1,
      "searchTime": 2500,
      "engines": ["google", "yelp"],
      "location": {
        "query": "90210",
        "resolved": "Beverly Hills, CA 90210",
        "coordinates": [34.0901, -118.4065]
      }
    }
  },
  "message": "Search completed successfully",
  "timestamp": "2025-08-25T10:00:00.000Z",
  "version": "3.6.0"
}
```

## 🕷️ Web Scraping API

### Scrape Business Details

**Endpoint**: `POST /api/scrape` **Description**: Scrape detailed information
from business websites

#### Request Body

```typescript
interface ScrapeRequest {
  urls: string[] // URLs to scrape
  options?: ScrapeOptions // Scraping options
}

interface ScrapeOptions {
  timeout?: number // Request timeout in milliseconds
  waitFor?: string // CSS selector to wait for
  extractEmails?: boolean // Extract email addresses
  extractPhones?: boolean // Extract phone numbers
  extractSocial?: boolean // Extract social media links
  screenshot?: boolean // Take screenshot
}
```

#### Example Request

```bash
curl -X POST http://localhost:3000/api/scrape \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://example-business.com"],
    "options": {
      "extractEmails": true,
      "extractPhones": true,
      "timeout": 30000
    }
  }'
```

#### Response

```typescript
interface ScrapeResponse {
  results: ScrapedData[]
}

interface ScrapedData {
  url: string
  title?: string
  description?: string
  emails: string[]
  phones: string[]
  socialLinks: string[]
  screenshot?: string // Base64 encoded image
  error?: string
  scrapedAt: string
}
```

## ⚙️ Configuration API

### Get Configuration

**Endpoint**: `GET /api/config` **Description**: Retrieve current application
configuration

#### Response

```typescript
interface ConfigResponse {
  searchEngines: SearchEngineConfig[]
  industries: IndustryConfig[]
  settings: AppSettings
}
```

### Update Configuration

**Endpoint**: `PUT /api/config` **Description**: Update application
configuration

#### Request Body

```typescript
interface ConfigUpdateRequest {
  searchEngines?: SearchEngineConfig[]
  industries?: IndustryConfig[]
  settings?: Partial<AppSettings>
}
```

## 🔗 CRM Export API

### Get CRM Templates

**Endpoint**: `GET /api/crm/templates` **Description**: Retrieve available CRM
export templates

#### Query Parameters

- `platform`: Filter by CRM platform (salesforce, hubspot, pipedrive)
- `format`: Filter by export format (csv, json, xml)

#### Response

```typescript
interface CRMTemplatesResponse {
  templates: CRMTemplate[]
  platforms: string[]
}
```

### Export to CRM

**Endpoint**: `POST /api/crm/export` **Description**: Export business data using
CRM templates

#### Request Body

```typescript
interface CRMExportRequest {
  templateId: string
  businessIds: string[] // IDs of businesses to export
  options?: {
    includeHeaders?: boolean
    validateData?: boolean
    skipInvalidRecords?: boolean
  }
}
```

#### Response

```typescript
interface CRMExportResponse {
  downloadUrl: string // URL to download the export file
  statistics: {
    totalRecords: number
    exportedRecords: number
    skippedRecords: number
    errors: ValidationError[]
    processingTime: number
  }
  filename: string
  format: string
}
```

### Validate CRM Data

**Endpoint**: `POST /api/crm/validate` **Description**: Validate business data
against CRM template requirements

#### Request Body

```typescript
interface CRMValidateRequest {
  templateId: string
  businessIds: string[]
}
```

#### Response

```typescript
interface CRMValidateResponse {
  validCount: number
  invalidCount: number
  errors: ValidationError[]
  warnings: string[]
}
```

## 📊 Health and Status API

### Health Check

**Endpoint**: `GET /api/health` **Description**: Check application health and
status

#### Response

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "3.6.0",
    "uptime": 86400,
    "services": {
      "database": "connected",
      "scraper": "ready",
      "searchEngines": "operational"
    },
    "metrics": {
      "totalSearches": 1250,
      "totalBusinesses": 15000,
      "avgResponseTime": 250
    }
  },
  "message": "System is healthy",
  "timestamp": "2025-08-25T10:00:00.000Z",
  "version": "3.6.0"
}
```

### System Metrics

**Endpoint**: `GET /api/metrics` **Description**: Retrieve system performance
metrics

#### Response

```typescript
interface MetricsResponse {
  performance: {
    avgResponseTime: number
    requestsPerMinute: number
    errorRate: number
  }
  usage: {
    totalSearches: number
    totalBusinesses: number
    activeUsers: number
  }
  system: {
    memoryUsage: number
    cpuUsage: number
    diskUsage: number
  }
}
```

## ❌ Error Codes

| Code | Description           | Common Causes                      |
| ---- | --------------------- | ---------------------------------- |
| 400  | Bad Request           | Invalid request parameters or body |
| 401  | Unauthorized          | Missing or invalid authentication  |
| 403  | Forbidden             | Insufficient permissions           |
| 404  | Not Found             | Resource not found                 |
| 422  | Unprocessable Entity  | Validation errors                  |
| 429  | Too Many Requests     | Rate limit exceeded                |
| 500  | Internal Server Error | Server-side error                  |
| 503  | Service Unavailable   | Service temporarily unavailable    |

### Error Response Details

```json
{
  "success": false,
  "error": "Validation failed",
  "message": "Request validation failed",
  "details": {
    "field": "query",
    "code": "REQUIRED",
    "message": "Query parameter is required"
  },
  "timestamp": "2025-08-25T10:00:00.000Z",
  "version": "3.6.0"
}
```

## 🔄 Rate Limiting

The API implements rate limiting to ensure fair usage:

- **Search API**: 100 requests per hour per IP
- **Scraping API**: 50 requests per hour per IP
- **Configuration API**: 200 requests per hour per IP
- **CRM Export API**: 20 exports per hour per user

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## 📝 Request/Response Examples

### Complete Search Workflow

```bash
# 1. Search for businesses
curl -X POST http://localhost:3000/api/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "coffee shops",
    "location": "Seattle, WA",
    "limit": 10
  }'

# 2. Scrape additional details
curl -X POST http://localhost:3000/api/scrape \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://example-coffee.com"],
    "options": {
      "extractEmails": true,
      "extractPhones": true
    }
  }'

# 3. Export to CRM
curl -X POST http://localhost:3000/api/crm/export \
  -H "Content-Type: application/json" \
  -d '{
    "templateId": "salesforce-lead-basic",
    "businessIds": ["business-123", "business-456"],
    "options": {
      "includeHeaders": true,
      "validateData": true
    }
  }'
```

## 🔧 SDK and Client Libraries

### JavaScript/TypeScript SDK

```typescript
import { BusinessScraperAPI } from 'business-scraper-sdk'

const api = new BusinessScraperAPI({
  baseURL: 'http://localhost:3000/api',
  apiKey: 'your-api-key', // When authentication is implemented
})

// Search for businesses
const results = await api.search({
  query: 'restaurants',
  location: '90210',
  limit: 25,
})

// Export to CRM
const exportResult = await api.exportToCRM({
  templateId: 'salesforce-lead-basic',
  businessIds: results.data.results.map(b => b.id),
})
```

## 📚 Related Documentation

- **[User Guide](USER_GUIDE.md)**: End-user documentation
- **[CRM Export Guide](CRM_EXPORT_GUIDE.md)**: CRM export functionality
- **[Deployment Guide](DEPLOYMENT.md)**: Deployment and configuration
- **[Security Guide](SECURITY_GUIDE.md)**: Security best practices

## 🔄 Changelog

### v3.6.0

- Added CRM export API endpoints
- Enhanced search API with advanced filtering
- Improved error handling and validation
- Added comprehensive metrics and health endpoints

### v3.5.0

- Enhanced testing coverage and quality assurance
- Improved API response consistency
- Added comprehensive validation

### v3.4.0

- Added performance monitoring endpoints
- Enhanced metrics collection
- Improved error reporting
