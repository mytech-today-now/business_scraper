# Content Security Policy (CSP) Implementation Guide

## Overview

The Business Scraper application implements a comprehensive Content Security Policy (CSP) system to protect against XSS attacks, code injection, and other security vulnerabilities. This document outlines the implementation details and usage guidelines.

## Architecture

### Centralized Configuration
- **`src/lib/cspConfig.ts`**: Main CSP configuration module with environment-specific policies
- **`src/lib/cspUtils.ts`**: Client-side utilities and helpers
- **`src/components/CSPSafeComponents.tsx`**: React components for CSP-safe content loading

### Integration Points
- **`src/middleware.ts`**: Server-side CSP header injection with nonce generation
- **`next.config.js`**: Static CSP headers for build-time optimization
- **`src/app/api/csp-report/route.ts`**: CSP violation reporting endpoint

## Environment-Specific Policies

### Development Environment
```typescript
{
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'", "'nonce-{nonce}'"],
  styleSrc: ["'self'", "'unsafe-inline'", "'nonce-{nonce}'"],
  connectSrc: ["'self'", "ws://localhost:*", "http://localhost:*", ...externalAPIs],
  upgradeInsecureRequests: false,
  blockAllMixedContent: false
}
```

### Production Environment
```typescript
{
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-eval'", "'nonce-{nonce}'"],
  styleSrc: ["'self'", "'unsafe-inline'", "'nonce-{nonce}'"],
  connectSrc: ["'self'", ...externalAPIs],
  upgradeInsecureRequests: true,
  blockAllMixedContent: true
}
```

### Test Environment
```typescript
{
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-eval'", "'unsafe-inline'"],
  styleSrc: ["'self'", "'unsafe-inline'"],
  upgradeInsecureRequests: false,
  blockAllMixedContent: false
}
```

## External API Allowlist

The CSP configuration includes necessary external connections for business scraper functionality:

- **Geocoding Services**:
  - `https://nominatim.openstreetmap.org`
  - `https://api.opencagedata.com`

- **Cloud Services**:
  - `https://*.googleapis.com` (Google APIs)
  - `https://*.cognitiveservices.azure.com` (Azure services)

- **Search Services**:
  - `https://api.duckduckgo.com`
  - `https://duckduckgo.com`

## Usage Examples

### Basic CSP Header Generation
```typescript
import { getCSPHeader, generateCSPNonce } from '@/lib/cspConfig'

// Generate nonce for current request
const nonce = generateCSPNonce()

// Get CSP header with nonce
const cspHeader = getCSPHeader(nonce)

// Set header in response
response.headers.set('Content-Security-Policy', cspHeader)
```

### CSP-Safe React Components
```tsx
import { CSPScript, CSPStyle, CSPNonceProvider } from '@/components/CSPSafeComponents'

function MyComponent() {
  return (
    <CSPNonceProvider nonce={nonce}>
      <CSPStyle>
        {`.my-class { color: red; }`}
      </CSPStyle>
      
      <CSPScript>
        {`console.log('CSP-safe script');`}
      </CSPScript>
    </CSPNonceProvider>
  )
}
```

### Content Validation
```typescript
import { isCSPSafe, sanitizeForCSP } from '@/lib/cspUtils'

const userContent = `eval("malicious code")`

if (!isCSPSafe(userContent)) {
  const sanitized = sanitizeForCSP(userContent)
  // Use sanitized content
}
```

### Dynamic Script Loading
```typescript
import { loadScriptSafely } from '@/lib/cspUtils'

// Load external script with CSP compliance
await loadScriptSafely('https://example.com/script.js', nonce)
```

## CSP Violation Reporting

### Automatic Reporting
CSP violations are automatically reported to `/api/csp-report` endpoint and logged for monitoring.

### Manual Reporting
```typescript
import { CSPReporter } from '@/lib/cspUtils'

const reporter = CSPReporter.getInstance()
reporter.reportViolation('script-src', 'https://blocked-domain.com/script.js')
```

### Violation Monitoring
```typescript
// Get recent violations
const violations = reporter.getViolations()

// Clear violation history
reporter.clearViolations()
```

## Security Features

### Nonce-Based Script/Style Loading
- Cryptographically secure nonces generated per request
- Automatic nonce injection in middleware
- React components support nonce-based loading

### Content Sanitization
- Automatic detection of unsafe patterns
- Content sanitization for CSP compliance
- Removal of `eval()`, `Function()`, inline handlers

### Environment Awareness
- Stricter policies in production
- Development-friendly policies for local development
- Test-specific configurations

## Best Practices

### 1. Use CSP-Safe Components
```tsx
// ✅ Good - Use CSP-safe components
<CSPScript nonce={nonce}>
  {safeScriptContent}
</CSPScript>

// ❌ Bad - Direct script injection
<script dangerouslySetInnerHTML={{__html: unsafeContent}} />
```

### 2. Validate External Content
```typescript
// ✅ Good - Validate before use
if (isCSPSafe(externalContent)) {
  useContent(externalContent)
} else {
  useContent(sanitizeForCSP(externalContent))
}

// ❌ Bad - Use external content directly
useContent(externalContent)
```

### 3. Monitor Violations
```typescript
// ✅ Good - Monitor and respond to violations
useEffect(() => {
  const handleViolation = (event) => {
    console.warn('CSP Violation:', event.violatedDirective)
    // Take appropriate action
  }
  
  document.addEventListener('securitypolicyviolation', handleViolation)
  return () => document.removeEventListener('securitypolicyviolation', handleViolation)
}, [])
```

### 4. Environment-Specific Policies
```typescript
// ✅ Good - Use environment-specific configurations
const config = getCSPConfig(process.env.NODE_ENV)

// ❌ Bad - One-size-fits-all policy
const config = getCSPConfig('production') // Always production
```

## Troubleshooting

### Common Issues

1. **Script Blocked**: Add nonce to script tags or whitelist the source
2. **Style Blocked**: Use nonce-based styles or add to style-src
3. **External API Blocked**: Add domain to connect-src allowlist
4. **Inline Handler Blocked**: Replace with event listeners

### Debug Mode
In development, use the CSP status indicator:
```tsx
import { CSPStatusIndicator } from '@/components/CSPSafeComponents'

// Shows violation count and current nonce
<CSPStatusIndicator />
```

### Violation Analysis
Check browser console for CSP violation details:
```
Content Security Policy: The page's settings blocked the loading of a resource at https://example.com/script.js ("script-src").
```

## Testing

Run CSP tests to verify implementation:
```bash
npm test -- src/__tests__/csp.test.ts
```

The test suite covers:
- Configuration validation
- Header generation
- Content sanitization
- Violation reporting
- Environment-specific policies

## Migration Guide

### From Basic CSP to Enhanced CSP

1. **Update imports**:
   ```typescript
   // Old
   const csp = "default-src 'self'"
   
   // New
   import { getCSPHeader } from '@/lib/cspConfig'
   const csp = getCSPHeader()
   ```

2. **Replace inline scripts**:
   ```tsx
   // Old
   <script>{inlineScript}</script>
   
   // New
   <CSPScript nonce={nonce}>{inlineScript}</CSPScript>
   ```

3. **Add violation monitoring**:
   ```typescript
   // New
   import { initializeCSPReporting } from '@/lib/cspUtils'
   initializeCSPReporting()
   ```

## Security Considerations

- **Nonce Rotation**: Nonces are generated per request for maximum security
- **External Dependencies**: Only necessary external domains are whitelisted
- **Content Validation**: All dynamic content is validated before use
- **Violation Monitoring**: All violations are logged and can trigger alerts
- **Environment Isolation**: Production policies are stricter than development

## Future Enhancements

- **Strict CSP**: Gradual migration to remove `unsafe-inline` and `unsafe-eval`
- **Report-Only Mode**: Test new policies without breaking functionality
- **Automated Monitoring**: Integration with security monitoring services
- **Policy Optimization**: Regular review and tightening of CSP policies
