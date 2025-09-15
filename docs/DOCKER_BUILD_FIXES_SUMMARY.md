# Docker Build Fixes Summary

## Overview
This document summarizes the Docker build issues identified and fixed as part of GitHub Issue #162.

## Current Status: IN PROGRESS
**GitHub Issue**: #162 - Docker Build Failure: next.config.js Configuration Issues

## Issues Identified and Fixed

### 1. Next.js Configuration Issues ✅ FIXED
- **File**: `next.config.js`
- **Problem**: Circular reference in experimental configuration causing `ReferenceError: Cannot access 'nextConfig' before initialization`
- **Root Cause**: 
  - Line 160 had `...nextConfig.experimental` which referenced the object before it was fully initialized
  - Duplicate `experimental` properties (lines 159-162 and 165-177)
  - Package conflict between `serverComponentsExternalPackages` and `optimizePackageImports` for `@tensorflow/tfjs`
- **Solution**: 
  - Removed circular reference `...nextConfig.experimental`
  - Merged duplicate experimental properties into single configuration
  - Removed `@tensorflow/tfjs` from `optimizePackageImports` since it's in `serverComponentsExternalPackages`

### 2. Data Retention System Build Issues ✅ FIXED
- **File**: `src/lib/dataRetentionSystem.ts`
- **Problem**: System initializing and executing policies during Docker build process, causing excessive logging
- **Root Cause**: Constructor called `initializeDefaultPolicies()` which scheduled policies immediately
- **Solution**:
  - Added `isBuildMode()` method to detect build environment
  - Modified constructor to skip policy initialization during build
  - Updated `addPolicy()` and `enablePolicy()` methods to respect build mode
  - Added checks for `NODE_ENV=production`, `NEXT_PHASE=phase-production-build`, `DOCKER_BUILDKIT=1`, `CI=true`

### 3. Stripe Provider SSR Issues ✅ PARTIALLY FIXED
- **Files**: 
  - `src/view/components/payments/StripeProvider.tsx`
  - `src/components/ClientOnlyStripeProvider.tsx` (new)
  - `src/app/layout.tsx`
- **Problem**: Stripe initialization during server-side rendering causing circular references
- **Root Cause**: Module-level `getConfig()` call and Stripe promise initialization during SSR
- **Solution**:
  - Moved `getConfig()` call inside `loadStripeWithRetry()` function
  - Created `ClientOnlyStripeProvider` wrapper component
  - Added client-side only rendering with `useEffect` and `useState`
  - Updated layout to use client-only wrapper instead of direct StripeProvider

### 4. Remaining Issues 🔄 IN PROGRESS
- **Problem**: Still encountering `ReferenceError: Cannot access 's' before initialization` in chunk 6490.js
- **Status**: Different component causing similar circular reference issues
- **Affected Pages**: Multiple routes failing during static generation
  - `/` (home page)
  - `/login`
  - `/pricing`
  - `/payment/success`
  - `/payment/cancel`
  - `/_not-found`

## Progress Made

### Build Process Improvements
- ✅ Docker build process starts correctly
- ✅ Dependencies install successfully  
- ✅ Next.js configuration loads without errors
- ✅ Data retention system no longer causes build loops
- ✅ Stripe provider SSR issues resolved
- ✅ Static page generation progresses further (reaches 80/80 pages)

### Remaining Challenges
- ❌ Build still fails due to remaining circular reference in chunk 6490.js
- ❌ Static page generation fails for multiple routes
- ❌ Export process encounters errors on 6 pages

## Next Steps
1. ✅ ~~Fix next.config.js circular reference~~
2. ✅ ~~Fix data retention system build issues~~
3. ✅ ~~Fix Stripe provider SSR issues~~
4. 🔄 Identify and fix remaining circular reference in chunk 6490.js
5. 🔄 Test complete Docker build process
6. 🔄 Run comprehensive test suite (target: 90% success rate)
7. 🔄 Update documentation
8. 🔄 Close GitHub issue with resolution

## Files Modified
- `next.config.js` - Fixed circular references and duplicate properties
- `src/lib/dataRetentionSystem.ts` - Added build mode detection
- `src/view/components/payments/StripeProvider.tsx` - Fixed SSR issues
- `src/components/ClientOnlyStripeProvider.tsx` - New client-only wrapper
- `src/app/layout.tsx` - Updated to use client-only Stripe provider

## Technical Details

### Build Mode Detection Implementation
```typescript
private isBuildMode(): boolean {
  return (
    process.env.NODE_ENV === 'production' && 
    (
      process.env.NEXT_PHASE === 'phase-production-build' ||
      process.env.DOCKER_BUILDKIT === '1' ||
      process.env.CI === 'true' ||
      !process.env.DATABASE_URL // No database during build
    )
  )
}
```

### Client-Only Stripe Provider Pattern
```typescript
export function ClientOnlyStripeProvider({ children }: Props): JSX.Element {
  const [isClient, setIsClient] = useState(false)
  
  useEffect(() => {
    setIsClient(true)
  }, [])
  
  if (!isClient) {
    return <>{children}</>
  }
  
  return <StripeProvider>{children}</StripeProvider>
}
```

## Testing Commands
```bash
# Test Docker build
docker build -f Dockerfile.production -t business-scraper:fixed .

# Check build logs
docker build --progress=plain -f Dockerfile.production -t business-scraper:test .
```

## Related Documentation
- [GitHub Issue #162](https://github.com/mytech-today-now/business_scraper/issues/162)
- [Next.js Configuration Documentation](https://nextjs.org/docs/api-reference/next.config.js/introduction)
- [Docker Environment Configuration](./DOCKER_ENV_REFACTOR_SUMMARY.md)
