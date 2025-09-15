# Debug Mode Enhancement for Security Token Error Capture

## Overview

This enhancement addresses a critical debugging issue where the application immediately reloads after displaying "Loading Security Token..." message, preventing developers from capturing error messages in the console for debugging purposes.

## Problem Solved

**Original Issue**: After redeploying the application, the message "Loading Security Token..." is displayed and the console fills with content, but immediately the page is reloaded before any error messages can be captured for debugging purposes.

**Solution**: Implemented a comprehensive debug mode system that:
- Prevents automatic page reloads when debug mode is enabled
- Captures and persists detailed error information across page reloads
- Provides enhanced error logging with full context and stack traces
- Offers debugging utilities accessible via browser console

## How to Enable Debug Mode

### Method 1: Environment Variables (Recommended for Development)

Add to your `.env.development` file:
```env
DEBUG_MODE=true
DEBUG_PREVENT_AUTO_RELOAD=true
DEBUG_ENHANCED_ERROR_LOGGING=true
DEBUG_PERSIST_ERRORS=true
DEBUG_SHOW_STACK_TRACES=true
```

### Method 2: Runtime Enabling (For Testing/Debugging)

Open browser console and run:
```javascript
// Enable debug mode
debugUtils.enableDebugMode()

// Disable debug mode
debugUtils.disableDebugMode()
```

## Using Debug Mode for Security Token Issues

### Step 1: Enable Debug Mode
Enable debug mode using one of the methods above.

### Step 2: Reproduce the Issue
1. Clear browser cache and localStorage
2. Navigate to the login page
3. Observe the "Loading Security Token..." message
4. **Notice**: Page will NOT auto-reload (debug mode prevents this)

### Step 3: Capture Error Information
When debug mode is active, you'll see:
- 🐛 DEBUG MODE indicator in top-right corner
- Enhanced console logging with detailed error context
- Notification when auto-reload is prevented

### Step 4: Access Debugging Data
Use console utilities to examine captured errors:
```javascript
// Get error analytics
debugUtils.getErrorAnalytics()

// Export all error data
debugUtils.exportErrorData()

// Get current session errors
debugUtils.getPersistedErrors()

// Clear all error data
debugUtils.clearErrors()
```

## Technical Implementation

### Files Modified/Created

**New Files:**
- `src/utils/debugConfig.ts` - Debug mode configuration and utilities
- `src/utils/enhancedErrorLogger.ts` - Enhanced error logging system
- `src/utils/errorPersistence.ts` - Cross-reload error persistence
- `src/components/DebugSystemInitializer.tsx` - Debug system initialization
- `src/__tests__/debug-mode.test.tsx` - Debug mode tests
- `src/__tests__/error-persistence.test.ts` - Error persistence tests

**Modified Files:**
- `src/app/login/page.tsx` - Uses safeReload() instead of window.location.reload()
- `src/hooks/useCSRFProtection.ts` - Enhanced error logging integration
- `src/components/ErrorBoundary.tsx` - Debug mode integration
- `src/app/layout.tsx` - Added DebugSystemInitializer
- `config/development.env.example` - Debug mode configuration examples
- `config/production.env.example` - Production debug configuration

### Key Features

1. **Safe Reload Pattern**: `safeReload()` function prevents auto-reload in debug mode
2. **Enhanced Error Logging**: Detailed context, stack traces, and timing information
3. **Error Persistence**: Errors survive page reloads using localStorage
4. **Visual Indicators**: Debug mode indicator and reload prevention notifications
5. **Console Utilities**: Rich debugging tools accessible via browser console

## Configuration Options

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `DEBUG_MODE` | `false` | Enable/disable debug mode |
| `DEBUG_PREVENT_AUTO_RELOAD` | `false` | Prevent automatic page reloads |
| `DEBUG_ENHANCED_ERROR_LOGGING` | `false` | Enable detailed error logging |
| `DEBUG_PERSIST_ERRORS` | `false` | Persist errors across reloads |
| `DEBUG_SHOW_STACK_TRACES` | `false` | Include stack traces in logs |

## Testing Results

The enhancement has been thoroughly tested:

**Debug Mode Tests**: 18/18 passing (100%)
**Error Persistence Tests**: 11/11 passing (100%)
**Total Debug Tests**: 29/29 passing (100%)

Test coverage includes:
- Environment variable configuration
- LocalStorage override functionality
- Safe reload behavior
- Enhanced error logging
- Error persistence across sessions
- Debug utilities functionality

## Usage Examples

### Debugging CSRF Token Issues
```javascript
// After enabling debug mode and reproducing the issue:
const analytics = debugUtils.getErrorAnalytics()
console.log('Error patterns:', analytics.errorPatterns)
console.log('Total errors:', analytics.totalErrors)

// Export detailed error data
const errorData = debugUtils.exportErrorData()
console.log('Full error context:', errorData)
```

### Monitoring Security Token Loading
When debug mode is active, security token errors are automatically captured with:
- Request/response details
- Network timing information
- Stack traces
- Browser environment context
- Session correlation IDs

## Production Considerations

- Debug mode is disabled by default in production
- Error persistence uses localStorage (automatically cleaned up)
- Performance impact is minimal when debug mode is disabled
- All debug utilities are only available when debug mode is active

## Troubleshooting

**Q: Debug mode indicator not showing?**
A: Ensure `DEBUG_MODE=true` in your environment or run `debugUtils.enableDebugMode()`

**Q: Errors not being captured?**
A: Verify `DEBUG_ENHANCED_ERROR_LOGGING=true` and check browser console for debug logs

**Q: Page still reloading automatically?**
A: Confirm `DEBUG_PREVENT_AUTO_RELOAD=true` and debug mode is active

## Security Notes

- Debug mode should only be enabled in development/testing environments
- Error persistence data is stored locally and not transmitted
- Debug utilities are only exposed when debug mode is explicitly enabled
- Production builds should have debug mode disabled by default
