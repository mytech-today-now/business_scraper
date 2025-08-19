# Per-Industry Domain Blacklist Feature

## Overview

The Business Scraper application now supports **per-industry domain blacklists**, allowing you to configure specific domain filtering rules for each industry category. This provides much more granular control over search results and helps eliminate irrelevant domains based on the specific industry being searched.

## Key Features

### 🎯 **Industry-Specific Filtering**
- Each industry category can have its own domain blacklist
- Blacklists are automatically applied when searching for businesses in that industry
- Supports all wildcard patterns: `*.domain.com`, `domain.*`, `*keyword*`

### 🔧 **Enhanced Interface**
- Click on any industry criteria to open the expanded editor
- Two separate text areas: one for search keywords, one for domain blacklist
- **Theme-aware design**: Text areas automatically adapt to light/dark mode with proper contrast
- Visual indicators show how many domains are blocked per industry
- Edit button for quick access to the expanded editor
- Full-width expanded editor for better usability

### 📊 **Improved Export/Import**
- Export now includes ALL industries with their current settings (not just custom ones)
- Import overwrites all industry settings for complete configuration management
- Backward compatibility with legacy custom-only exports

## How to Use

### 1. **Editing Industry Settings**

#### Method 1: Click on Criteria Text
1. Navigate to the **Industry Categories** section
2. Click on the comma-separated criteria text for any industry
3. The expanded editor will open with two text areas:
   - **Top area**: Search keywords (one per line)
   - **Bottom area**: Domain blacklist (one per line, supports wildcards)

#### Method 2: Use Edit Button
1. Hover over any industry card
2. Click the blue **Edit** button (pencil icon) that appears
3. The expanded editor will open

### 2. **Configuring Domain Blacklists**

In the domain blacklist text area, you can add:

```
*.statefarm.com
*.geico.com
*insurance*
yellowpages.*
```

**Wildcard Patterns:**
- `*.statefarm.com` - Blocks statefarm.com and all subdomains
- `statefarm.*` - Blocks statefarm across all TLDs (.com, .net, .org)
- `*insurance*` - Blocks any domain containing "insurance"

### 3. **Visual Indicators**

Each industry card shows:
- **Keywords**: Comma-separated list of search terms
- **Blocked domains**: "🚫 X blocked domains" if blacklist is configured
- **Edit hint**: "Click criteria to edit keywords & blacklist"

### 4. **Export/Import Configuration**

#### Exporting
1. Go to **Industry Categories** section
2. Click **Export** button
3. Saves file as `industries-YYYY-MM-DD.json`
4. Includes ALL industries with their current settings

#### Importing
1. Click **Import** button
2. Select a JSON file
3. **Warning**: This will replace ALL current industry settings
4. Supports both new format and legacy custom-only format

## Technical Implementation

### Industry Data Structure

```json
{
  "id": "professional",
  "name": "Professional Services", 
  "keywords": ["consulting", "legal", "accounting"],
  "isCustom": false,
  "domainBlacklist": ["*.statefarm.*", "*.geico.*"]
}
```

### Export Format

```json
{
  "name": "Business Scraper",
  "url": "https://github.com/mytech-today-now/business_scraper", 
  "version": "1.0.0",
  "exportDate": "2025-07-26T...",
  "industries": [
    {
      "id": "professional",
      "name": "Professional Services",
      "keywords": ["consulting", "legal", "accounting"],
      "isCustom": false,
      "domainBlacklist": ["*.statefarm.*", "*.geico.*"]
    }
  ]
}
```

### Search Integration

The search engine automatically:
1. Extracts keywords from search queries
2. Matches keywords to industry categories
3. Applies relevant industry blacklists
4. Combines with global domain blacklist
5. Filters search results using all applicable patterns

### User Interface Design

The interface features a **theme-aware design** that provides optimal user experience:

#### Text Area Styling
- **Background**: Automatically adapts to light/dark mode using `bg-background`
- **Text Color**: Uses `text-foreground` for proper contrast in both themes
- **Placeholder Text**: Styled with `placeholder:text-muted-foreground` for readability
- **Focus States**: Maintains primary color ring for clear interaction feedback

#### Responsive Layout
- **Expanded Editor**: Full-width layout for better editing experience
- **Dual Text Areas**: Separate areas for keywords and domain blacklist
- **Visual Indicators**: Clear feedback showing blocked domain counts
- **Hover Actions**: Edit and delete buttons appear on hover for clean interface

## Pre-configured Examples

### Professional Services
- **Keywords**: consulting, legal, accounting, financial, insurance
- **Blacklist**: `*.statefarm.*`, `*.geico.*`, `*.progressive.*`, `*.allstate.*`

### Healthcare & Medical  
- **Keywords**: medical, healthcare, clinic, hospital, dental
- **Blacklist**: `*.webmd.*`, `*.mayoclinic.*`, `*.healthline.*`

## Migration from Global Blacklist

If you were using the global domain blacklist:

1. **Export** your current industries to backup settings
2. **Edit** each relevant industry to add domain-specific blacklists
3. **Remove** domains from global blacklist that are now industry-specific
4. **Keep** truly global domains (like social media) in global blacklist

## Best Practices

### 1. **Industry-Specific Blocking**
- Use industry blacklists for domains specific to that industry
- Example: Block insurance company sites only for insurance-related searches

### 2. **Global vs Industry Blacklists**
- **Global**: Social media, directories, generic spam domains
- **Industry**: Competitor sites, irrelevant industry-specific domains

### 3. **Wildcard Usage**
- `*.company.*` - Most comprehensive, blocks all subdomains and TLDs
- `*.company.com` - Blocks subdomains but allows other TLDs
- `*keyword*` - Blocks any domain containing the keyword

### 4. **Testing and Refinement**
- Start with broad patterns and refine based on results
- Monitor search results to identify new domains to block
- Regular export for backup before making major changes

## Troubleshooting

### Issue: Industry blacklist not working
- **Check**: Ensure keywords in search query match industry keywords
- **Verify**: Domain patterns are correctly formatted
- **Test**: Try exact domain match first, then add wildcards

### Issue: Too many results filtered
- **Review**: Check if wildcard patterns are too broad
- **Adjust**: Use more specific patterns
- **Balance**: Move overly broad patterns to global blacklist

### Issue: Import fails
- **Format**: Ensure JSON file has correct structure
- **Validation**: Check that all required fields are present
- **Backup**: Always export current settings before importing

## Advanced Configuration

### Custom Industry Creation
1. Click **Add Industry** button
2. Configure keywords and domain blacklist
3. Industry will be marked as "Custom"
4. Can be deleted (unlike pre-configured industries)

### Bulk Configuration
1. Export current settings
2. Edit JSON file with text editor
3. Add/modify domain blacklists for multiple industries
4. Import modified file

### Pattern Testing
Use the search functionality to test blacklist effectiveness:
1. Search for industry-specific terms
2. Review results for unwanted domains
3. Add patterns to block identified domains
4. Re-test to verify filtering

This per-industry blacklist feature provides powerful, granular control over search results while maintaining the simplicity and effectiveness of the original domain filtering system.
