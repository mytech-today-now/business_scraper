# Domain Blacklist Import/Export Format

## Overview

The Business Scraper application supports importing and exporting domain blacklist configurations as JSON files. This allows you to:

- **Backup** your domain blacklist configurations
- **Share** blacklist setups between different installations
- **Migrate** configurations when upgrading or moving systems
- **Collaborate** with team members using standardized domain filtering

## JSON File Format

### Structure

The domain blacklist export uses the same header format as industry exports for consistency:

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-26T15:30:45.123Z",
  "domainBlacklist": [
    "statefarm.com",
    "example.com",
    "unwanted-site.net",
    "spam-domain.org"
  ]
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | **Yes** | Application name - must be "Business Scraper" |
| `url` | string | **Yes** | GitHub repository URL |
| `version` | string | **Yes** | Application version number |
| `exportDate` | string | **Yes** | ISO timestamp of when the file was exported |
| `domainBlacklist` | array | **Yes** | Array of domain strings to exclude from search results |

## Usage Instructions

### Exporting Domain Blacklist

1. Navigate to **Settings** → **API Configuration**
2. Scroll to the **Domain Blacklist** section
3. Click the **Export** button
4. Save the generated JSON file

### Importing Domain Blacklist

1. Navigate to **Settings** → **API Configuration**
2. Scroll to the **Domain Blacklist** section
3. Click the **Import** button
4. Select your JSON file
5. The domains will be loaded into the blacklist

## Backward Compatibility

The import function supports both formats:

### New Format (Recommended)
```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-26T15:30:45.123Z",
  "domainBlacklist": [
    "statefarm.com",
    "example.com"
  ]
}
```

### Legacy Format (Still Supported)
```json
[
  "statefarm.com",
  "example.com"
]
```

## Domain Format Rules

- **Domain only**: Use just the domain name without protocol or www
  - ✅ Correct: `"statefarm.com"`
  - ❌ Incorrect: `"https://www.statefarm.com"`

- **Case insensitive**: Domains are automatically converted to lowercase
  - `"STATEFARM.COM"` becomes `"statefarm.com"`

- **Exact matching**: Exact domain matches are filtered
  - `"statefarm.com"` will block `statefarm.com` but not `agent.statefarm.com`

- **Wildcard support**: Use `*` for pattern matching
  - `"*.statefarm.com"` blocks `statefarm.com`, `agent.statefarm.com`, `www.statefarm.com`
  - `"statefarm.*"` blocks `statefarm.com`, `statefarm.net`, `statefarm.org`
  - `"*statefarm*"` blocks any domain containing "statefarm"

## Example Files

### 1. Insurance Companies Blacklist (with Wildcards)

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-26T15:30:45.123Z",
  "domainBlacklist": [
    "*.statefarm.com",
    "*.geico.com",
    "*.progressive.com",
    "*.allstate.com",
    "*.farmers.com"
  ]
}
```

### 2. Social Media and Directories

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-26T15:30:45.123Z",
  "domainBlacklist": [
    "facebook.com",
    "linkedin.com",
    "twitter.com",
    "instagram.com",
    "yelp.com",
    "yellowpages.com",
    "whitepages.com"
  ]
}
```

### 3. Generic Spam Domains

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-26T15:30:45.123Z",
  "domainBlacklist": [
    "example.com",
    "test.com",
    "placeholder.com",
    "sample.org",
    "demo.net"
  ]
}
```

### 4. Wildcard Pattern Examples

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-26T15:30:45.123Z",
  "domainBlacklist": [
    "*.statefarm.com",
    "statefarm.*",
    "*insurance*",
    "*.yellowpages.*",
    "*directory*"
  ]
}
```

**What each pattern blocks:**
- `"*.statefarm.com"` → `statefarm.com`, `agent.statefarm.com`, `www.statefarm.com`
- `"statefarm.*"` → `statefarm.com`, `statefarm.net`, `statefarm.org`
- `"*insurance*"` → `myinsurance.com`, `insurance-quotes.net`, `bestinsurance.org`
- `"*.yellowpages.*"` → `www.yellowpages.com`, `mobile.yellowpages.net`
- `"*directory*"` → `businessdirectory.com`, `local-directory.net`

## Wildcard Pattern Types

### 1. Subdomain Wildcards (`*.domain.com`)
Blocks the main domain and all its subdomains:
```json
"*.statefarm.com"
```
**Blocks:** `statefarm.com`, `agent.statefarm.com`, `www.statefarm.com`, `mobile.statefarm.com`
**Doesn't block:** `statefarminsurance.com`, `mystatefarm.net`

### 2. TLD Wildcards (`domain.*`)
Blocks a domain across all top-level domains:
```json
"statefarm.*"
```
**Blocks:** `statefarm.com`, `statefarm.net`, `statefarm.org`, `statefarm.co.uk`
**Doesn't block:** `agent.statefarm.com`, `statefarminsurance.com`

### 3. Substring Wildcards (`*keyword*`)
Blocks any domain containing the keyword:
```json
"*insurance*"
```
**Blocks:** `insurance.com`, `myinsurance.net`, `best-insurance.org`, `insurancequotes.com`
**Doesn't block:** `insure.com`, `coverage.net`

### 4. Complex Patterns
Multiple wildcards for advanced filtering:
```json
"*.insurance.*"
```
**Blocks:** `www.insurance.com`, `mobile.insurance.net`, `app.insurance.org`

## Integration with Search Providers

The domain blacklist is applied to all search providers:

- **Google Custom Search**: Filtered from API results
- **Azure AI Foundry**: Filtered from Bing Custom Search results  
- **DuckDuckGo SERP**: Filtered from scraped results
- **BBB Discovery**: Filtered from extracted business websites

## File Naming Convention

Exported files follow this naming pattern:
```
domain-blacklist-YYYY-MM-DD.json
```

Example: `domain-blacklist-2025-07-26.json`

## Validation

The application validates imported files to ensure:

1. Valid JSON format
2. Proper structure (either new format with headers or legacy array)
3. Domain strings are non-empty after trimming
4. Automatic conversion to lowercase for consistency

## Error Handling

Common import errors and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| "Failed to parse blacklist file" | Invalid JSON | Check file format and syntax |
| "Expected array of domains" | Wrong data type | Ensure domainBlacklist is an array |
| "Invalid blacklist format" | Missing required fields | Use proper format with headers |

## Best Practices

1. **Regular Updates**: Export your blacklist regularly as backup
2. **Team Sharing**: Share blacklist files with team members for consistency
3. **Version Control**: Keep blacklist files in version control for tracking changes
4. **Documentation**: Comment your blacklist choices in separate documentation
5. **Testing**: Test blacklist effectiveness with sample searches

## Migration from Legacy Format

To convert legacy array format to new format:

1. Export your current blacklist (will use new format automatically)
2. The exported file will include proper headers
3. Use the new file for future imports and sharing

This ensures consistency with other Business Scraper export formats and better metadata tracking.
