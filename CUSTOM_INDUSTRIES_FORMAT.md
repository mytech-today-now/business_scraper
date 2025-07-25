# Custom Industries Import/Export Format

## Overview

The Business Scraper application supports importing and exporting custom industry categories as JSON files. This allows you to:

- **Backup** your custom industry configurations
- **Share** industry setups between different installations
- **Migrate** configurations when upgrading or moving systems
- **Collaborate** with team members using standardized industry definitions

## JSON File Format

### Structure

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-25T20:35:47.780Z",
  "customIndustries": [
    {
      "name": "Pet Services",
      "keywords": [
        "pet",
        "veterinary",
        "grooming",
        "animal care",
        "pet supplies"
      ]
    },
    {
      "name": "Solar Energy",
      "keywords": [
        "solar",
        "renewable energy",
        "solar panels",
        "solar installation",
        "green energy"
      ]
    }
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
| `customIndustries` | array | **Yes** | Array of custom industry objects |
| `customIndustries[].name` | string | **Yes** | Display name of the industry category |
| `customIndustries[].keywords` | array | **Yes** | Array of search keywords for this industry |

## Usage Instructions

### Exporting Custom Industries

1. Navigate to the **Industry Categories** section
2. Click the **Export** button next to "Add Custom"
3. The file will be automatically downloaded as `custom-industries-YYYY-MM-DD.json`
4. Only custom industries are exported (default industries are not included)

### Importing Custom Industries

1. Click the **Import** button next to "Export"
2. Select a valid JSON file with the correct format
3. The system will:
   - Validate the file format
   - Skip industries with duplicate names
   - Import valid new industries
   - Show a summary of imported/skipped items

### Import Behavior

- **Duplicate Names**: Industries with names that already exist (case-insensitive) will be skipped
- **Invalid Data**: Industries missing required fields will be skipped
- **Empty Keywords**: Empty keyword strings will be filtered out
- **Error Handling**: Import continues even if individual industries fail

## Example Use Cases

### 1. Backup Configuration
```bash
# Export your custom industries before system updates
# File: custom-industries-2025-01-25.json
```

### 2. Team Collaboration

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-25T20:35:47.780Z",
  "customIndustries": [
    {
      "name": "Fintech Startups",
      "keywords": [
        "fintech",
        "financial technology",
        "digital banking",
        "payment processing",
        "cryptocurrency"
      ]
    }
  ]
}
```

### 3. Industry-Specific Templates

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper",
  "version": "1.0.0",
  "exportDate": "2025-07-25T20:35:47.780Z",
  "customIndustries": [
    {
      "name": "E-commerce Platforms",
      "keywords": [
        "e-commerce",
        "online store",
        "digital marketplace",
        "online retail",
        "shopping platform"
      ]
    },
    {
      "name": "SaaS Companies",
      "keywords": [
        "software as a service",
        "cloud software",
        "subscription software",
        "web application",
        "enterprise software"
      ]
    }
  ]
}
```

## Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "No custom industries to export" | No custom industries exist | Create custom industries first |
| "Invalid file format" | JSON structure is incorrect | Check file format against examples |
| "No industries imported" | All industries were duplicates/invalid | Check for name conflicts or data issues |
| "Failed to import industries" | File parsing error | Ensure valid JSON format |

## Best Practices

1. **Descriptive Names**: Use clear, descriptive industry names
2. **Comprehensive Keywords**: Include various search terms and synonyms
3. **Regular Backups**: Export configurations before major changes
4. **Version Control**: Keep dated backups of your industry configurations
5. **Team Standards**: Establish naming conventions for shared configurations

## Technical Notes

- File size limit: No explicit limit, but keep reasonable (< 1MB recommended)
- Character encoding: UTF-8
- Date format: ISO 8601 timestamps
- Case sensitivity: Industry names are compared case-insensitively during import
- Validation: Client-side validation with user-friendly error messages
