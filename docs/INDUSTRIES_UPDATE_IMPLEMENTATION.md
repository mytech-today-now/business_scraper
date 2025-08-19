# Industries Update Implementation

## Overview

This document describes the implementation of automatic and manual industry updates to ensure that the default industries, criteria, and blacklists from `industries-2025-07-26-final.json` are properly synchronized with both development and production versions of the Business Scraper application.

## Problem Statement

Previously, the application would only initialize default industries if no industries were saved in the browser's IndexedDB storage. Once industries were saved, they would never be updated with new defaults, even if the `industry-config.ts` file was updated. This meant that users would not receive updates to:

- Industry keywords
- Domain blacklists
- New industries
- Industry name changes

## Solution Implementation

### 1. Automatic Update Detection

**File:** `src/controller/ConfigContext.tsx`

Added intelligent update detection that compares saved industries with current defaults:

- **`checkIfDefaultIndustriesNeedUpdate()`**: Compares saved industries with `DEFAULT_INDUSTRIES`
- Checks for changes in keywords, domain blacklists, names, and missing industries
- Preserves custom industries while updating defaults

### 2. Smart Industry Refresh

**Function:** `updateDefaultIndustries()`

- Separates custom industries from default ones
- Updates all default industries with latest data
- Preserves all custom industries created by users
- Logs the update process for debugging

### 3. Manual Refresh Capability

**UI Component:** Added "Refresh Defaults" button in CategorySelector
- Located next to Export/Import buttons
- Allows users to manually trigger industry updates
- Provides immediate feedback via toast notifications

**API Method:** `refreshDefaultIndustries()` in ConfigContext
- Can be called programmatically
- Forces update of default industries
- Preserves custom industries

### 4. Command Line Script

**File:** `scripts/refresh-industries.js`
**NPM Script:** `npm run industries:refresh`

- Validates the `industries-2025-07-26-final.json` file
- Provides status information about current industries
- Gives clear instructions for next steps

## Files Modified

### Core Logic
- `src/controller/ConfigContext.tsx` - Added update detection and refresh logic
- `src/view/components/CategorySelector.tsx` - Added refresh button UI

### Scripts
- `scripts/refresh-industries.js` - New refresh script
- `package.json` - Added `industries:refresh` script

## How It Works

### Automatic Updates (On App Start)

1. Application loads saved industries from IndexedDB
2. `checkIfDefaultIndustriesNeedUpdate()` compares with current defaults
3. If changes detected:
   - Custom industries are preserved
   - Default industries are updated with latest data
   - User sees success notification
   - Industries are saved back to storage

### Manual Updates (UI Button)

1. User clicks "Refresh Defaults" button
2. `refreshDefaultIndustries()` is called
3. Current industries are loaded from storage
4. Default industries are updated while preserving custom ones
5. UI is updated with new industry list
6. Success notification is shown

### Command Line Updates

1. Run `npm run industries:refresh`
2. Script validates the industries file
3. Provides status and instructions
4. Next app restart will apply updates

## Industry Data Structure

The system handles industries with the following structure:

```typescript
interface IndustryCategory {
  id: string
  name: string
  keywords: string[]
  isCustom: boolean
  domainBlacklist?: string[]
}
```

### Default vs Custom Industries

- **Default Industries**: `isCustom: false` - Updated automatically
- **Custom Industries**: `isCustom: true` - Always preserved during updates

## Testing the Implementation

### 1. Production Testing
```bash
npm run build
npm start
# Visit http://localhost:3000
```

### 2. Development Testing
```bash
npm run dev
# Visit http://localhost:3001
```

### 3. Script Testing
```bash
npm run industries:refresh
```

## Benefits

1. **Automatic Updates**: Users get latest industry data without manual intervention
2. **Preservation**: Custom industries are never lost during updates
3. **Manual Control**: Users can force refresh when needed
4. **Transparency**: Clear logging and notifications about updates
5. **Backward Compatibility**: Works with existing saved data

## Current Industry Data

The implementation uses data from `industries-2025-07-26-final.json`:

- **19 total industries** with updated keywords and blacklists
- **Export date**: 2025-07-26T16:00:00.000Z
- **Version**: 1.0.1

### Key Industries Included:
- Legal Services
- Accounting & Tax Services
- Architectural Services
- Medical Clinics
- Dental Offices
- Real Estate Agencies
- Insurance Agencies
- Financial Advisory Services
- Nonprofit Organizations
- Staffing & Recruiting Firms
- Event Planning & Management
- Hospitality & Hotel Management
- Engineering Firms
- Private & Charter Schools
- Marketing & Creative Agencies
- E-commerce Businesses
- Manufacturing Companies
- Logistics & Supply Chain
- Legal Tech SaaS

## Future Maintenance

To update industries in the future:

1. Update `src/lib/industry-config.ts` with new data
2. Users will automatically get updates on next app start
3. Or users can manually refresh using the UI button
4. Or run `npm run industries:refresh` script

This implementation ensures that industry data stays current while preserving user customizations.
