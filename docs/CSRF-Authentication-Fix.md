# CSRF Authentication System Fix

## Overview

This document describes the resolution of a critical authentication issue where CSRF token fetching was failing with 401 Unauthorized errors on the login page.

## Problem Description

### Issue
Users were experiencing authentication failures on the login screen with repeated 401 Unauthorized errors when attempting to fetch CSRF tokens.

**Error Messages:**
```
Failed to fetch CSRF token: 401
[05:44:25 AM] <CSRF> ERROR: Failed to fetch CSRF token Error: Failed to fetch CSRF token: 401
```

### Root Cause
The issue was caused by a **route conflict** between two authentication systems:

1. **NextAuth.js** uses a catch-all route at `/api/auth/[...nextauth]/route.ts` that intercepts ALL requests to `/api/auth/*`
2. **Custom CSRF system** had a route at `/api/auth/route.ts` for CSRF token management
3. When the frontend tried to GET `/api/auth` for CSRF tokens, NextAuth.js intercepted it instead of the custom route
4. NextAuth.js doesn't handle this request properly, resulting in 401 errors

## Solution Implementation

### 1. Route Separation
- **Moved CSRF endpoint** from `/api/auth` to `/api/csrf` to avoid NextAuth.js route conflicts
- **Enhanced CSRF endpoint** to handle both session-based and temporary tokens
- **Removed conflicting GET handler** from `/api/auth/route.ts`

### 2. Frontend Updates
- **Updated useCSRFProtection hook** to use `/api/csrf` endpoint exclusively
- **Removed fallback** to the conflicting `/api/auth` endpoint
- **Enhanced error handling** and retry mechanisms

### 3. Security Enhancements
- **Maintained CSRF protection** while fixing authentication flow
- **Added audit logging** for all CSRF operations
- **Enhanced session management** with proper cookie handling

## Technical Changes

### Files Modified

#### `/src/app/api/csrf/route.ts`
- Enhanced to handle both authenticated and unauthenticated users
- Provides session-based CSRF tokens for authenticated users
- Creates new sessions for unauthenticated users
- Includes POST endpoint for token refresh
- Comprehensive error handling and audit logging

#### `/src/hooks/useCSRFProtection.ts`
- Updated to use `/api/csrf` endpoint exclusively
- Removed fallback to conflicting `/api/auth` endpoint
- Enhanced logging and error messages

#### `/src/app/api/auth/route.ts`
- Removed GET handler that was conflicting with NextAuth.js
- Maintained POST (login) and DELETE (logout) handlers
- Preserved all authentication functionality

### API Endpoints

#### `GET /api/csrf`
**Purpose:** Fetch CSRF token for session protection

**Response:**
```json
{
  "authenticated": false,
  "sessionId": "session-id",
  "csrfToken": "csrf-token",
  "expiresAt": "2025-09-05T18:00:00.000Z",
  "temporary": false
}
```

**Headers:**
- `X-CSRF-Token`: The CSRF token value
- `X-CSRF-Expires`: Token expiration timestamp
- `X-CSRF-Temporary`: Whether token is temporary (always false now)

**Cookies Set:**
- `session-id`: HttpOnly session cookie
- `csrf-token`: CSRF token cookie (accessible to JavaScript)

#### `POST /api/csrf`
**Purpose:** Refresh CSRF token for existing session

**Requirements:** Valid session cookie

**Response:** Same as GET endpoint with refreshed token

## Security Considerations

### CSRF Protection Maintained
- Double-submit cookie pattern still enforced
- Session-based token validation
- Proper token expiration and refresh

### Audit Compliance
- All CSRF operations logged for SOC2 compliance
- Security events tracked for monitoring
- IP address and user agent logging

### Session Security
- HttpOnly session cookies
- Secure flag in production
- SameSite=Strict policy
- Proper session timeout handling

## Testing

### Unit Tests
- `src/__tests__/api/csrf.test.ts` - CSRF endpoint functionality
- Covers all scenarios: new sessions, existing sessions, invalid sessions, errors

### Integration Tests
- `src/__tests__/integration/csrf-auth-fix.test.ts` - End-to-end authentication flow
- Verifies complete login process without CSRF errors
- Tests security compliance and audit logging

## Deployment Notes

### Backward Compatibility
- No breaking changes to existing authentication
- Frontend automatically uses new CSRF endpoint
- Existing sessions remain valid

### Environment Requirements
- No additional environment variables required
- Works with existing security configuration
- Compatible with all deployment environments

## Monitoring

### Success Metrics
- Login page loads without console errors
- CSRF tokens fetch successfully (200 status)
- Authentication flow completes end-to-end
- No 401 errors in application logs

### Error Indicators
- 500 errors from `/api/csrf` endpoint
- Missing CSRF tokens in responses
- Session creation failures
- Audit log gaps

## Related Issues

- **GitHub Issue #149**: CSRF Token Authentication Failure: 401 Unauthorized on Login Screen
- **Resolution Date**: 2025-09-05
- **Version**: 6.6.6

## Future Considerations

### NextAuth.js Integration
- Consider migrating to NextAuth.js completely for unified authentication
- Evaluate custom adapter for postgres.js database integration
- Plan migration strategy for existing session management

### CSRF Enhancement
- Consider implementing CSRF token rotation
- Evaluate additional CSRF protection mechanisms
- Monitor for new security best practices
