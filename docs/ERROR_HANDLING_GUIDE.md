# Error Handling Guide

This guide outlines the standardized error handling patterns implemented across the Business Scraper application.

## Overview

The application uses a comprehensive error handling strategy that includes:

1. **React Error Boundaries** for component-level error catching
2. **Standardized API Error Handling** for consistent server-side error responses
3. **Client-side Error Handling Hooks** for React components
4. **Structured Logging** for debugging and monitoring
5. **User-friendly Error Messages** with recovery options

## Components

### 1. React Error Boundary (`src/components/ErrorBoundary.tsx`)

The `ErrorBoundary` component catches JavaScript errors anywhere in the component tree and displays a fallback UI.

**Features:**
- Automatic error logging with unique error IDs
- Retry functionality with configurable limits
- Development vs production error details
- Copy error details to clipboard
- Different levels: page, section, component

**Usage:**
```tsx
import { ErrorBoundary } from '@/components/ErrorBoundary'

// Wrap components that might throw errors
<ErrorBoundary level="component" showDetails={isDevelopment}>
  <MyComponent />
</ErrorBoundary>

// Higher-order component wrapper
const SafeComponent = withErrorBoundary(MyComponent, {
  level: 'component',
  onError: (error, errorInfo) => {
    // Custom error handling
  }
})
```

### 2. Error Handling Hooks (`src/hooks/useErrorHandling.ts`)

Provides standardized error handling for React components and async operations.

**Available Hooks:**

#### `useErrorHandling(options)`
Basic error handling with retry functionality:
```tsx
const { error, isError, handleError, retry, canRetry, clearError } = useErrorHandling({
  maxRetries: 3,
  component: 'MyComponent',
  onError: (error, errorId) => {
    toast.error(`Operation failed: ${error.message}`)
  }
})
```

#### `useAsyncOperation(options)`
Handles async operations with loading states and error handling:
```tsx
const { data, loading, error, execute, retry, reset } = useAsyncOperation({
  component: 'DataLoader',
  maxRetries: 2
})

// Execute async operation
const result = await execute(async () => {
  return await fetchData()
})
```

#### `useFormErrorHandling(options)`
Specialized for form submissions with field-level error handling:
```tsx
const { 
  error, 
  fieldErrors, 
  handleSubmissionError, 
  setFieldError,
  clearAllErrors 
} = useFormErrorHandling({
  component: 'ContactForm'
})
```

### 3. API Error Handling (`src/utils/apiErrorHandling.ts`)

Standardized error handling for API routes and client-side API calls.

**Server-side (API Routes):**
```tsx
import { withStandardErrorHandling, handleAsyncApiOperation } from '@/utils/apiErrorHandling'

async function myApiHandler(request: NextRequest): Promise<NextResponse> {
  const result = await handleAsyncApiOperation(
    async () => {
      // Your API logic here
      return await performOperation()
    },
    {
      operationName: 'My Operation',
      endpoint: '/api/my-endpoint',
      request
    }
  )

  if (!result.success) {
    return result.error
  }

  return createSuccessResponse(result.data)
}

export const POST = withStandardErrorHandling(myApiHandler)
```

**Client-side API Calls:**
```tsx
import { makeApiCall } from '@/utils/apiErrorHandling'

const result = await makeApiCall('/api/data', {
  method: 'POST',
  body: JSON.stringify(data)
}, {
  operation: 'Save Data',
  component: 'DataForm'
})

if (result.success) {
  console.log('Data saved:', result.data)
} else {
  console.error('Save failed:', result.error.error)
}
```

### 4. Logging (`src/utils/logger.ts`)

Structured logging with different levels and automatic error context.

**Usage:**
```tsx
import { logger } from '@/utils/logger'

// Different log levels
logger.debug('Component', 'Debug message', { data })
logger.info('Component', 'Info message', { context })
logger.warn('Component', 'Warning message', { warning })
logger.error('Component', 'Error occurred', error)

// Scoped logger
const componentLogger = logger.createScope('MyComponent')
componentLogger.info('Operation completed')
```

## Best Practices

### 1. Consistent Error Logging

Always log errors with proper context:
```tsx
try {
  await riskyOperation()
} catch (error) {
  logger.error('ComponentName', 'Operation failed', {
    operation: 'riskyOperation',
    context: { userId, data },
    error: error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack
    } : error
  })
  
  // Handle the error appropriately
  handleError(error instanceof Error ? error : new Error(String(error)))
}
```

### 2. User-Friendly Error Messages

Provide actionable error messages to users:
```tsx
// Bad
toast.error('Error: 500 Internal Server Error')

// Good
toast.error('Failed to save your changes. Please try again or contact support if the problem persists.')
```

### 3. Error Recovery Options

Always provide ways for users to recover from errors:
```tsx
{error && (
  <div className="error-container">
    <p>Something went wrong: {error.message}</p>
    <div className="error-actions">
      {canRetry && (
        <Button onClick={() => retry()}>
          Try Again ({maxRetries - retryCount} left)
        </Button>
      )}
      <Button onClick={() => clearError()}>
        Dismiss
      </Button>
      <Button onClick={() => window.location.reload()}>
        Reload Page
      </Button>
    </div>
  </div>
)}
```

### 4. Error Boundaries Placement

Place error boundaries at strategic locations:
```tsx
// App level - catches all errors
<ErrorBoundary level="page">
  <App />
</ErrorBoundary>

// Section level - isolates major sections
<ErrorBoundary level="section">
  <Dashboard />
</ErrorBoundary>

// Component level - protects individual components
<ErrorBoundary level="component">
  <ComplexWidget />
</ErrorBoundary>
```

### 5. Async Error Handling

Use proper async error handling patterns:
```tsx
// Using the hook
const { execute, loading, error } = useAsyncOperation({
  component: 'DataLoader'
})

const loadData = useCallback(async () => {
  const result = await execute(async () => {
    const response = await fetch('/api/data')
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`)
    }
    return response.json()
  })
  
  if (result) {
    setData(result)
  }
}, [execute])

// Or using the wrapper function
const safeLoadData = withErrorHandling(async () => {
  const response = await fetch('/api/data')
  return response.json()
}, {
  component: 'DataLoader',
  onError: (error, errorId) => {
    toast.error(`Failed to load data: ${error.message}`)
  }
})
```

## Error Types and Status Codes

### Standard HTTP Status Codes
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (authentication required)
- `403` - Forbidden (access denied)
- `404` - Not Found
- `429` - Too Many Requests (rate limiting)
- `500` - Internal Server Error

### Custom Error Classes
- `ValidationError` - Input validation failures
- `AuthenticationError` - Authentication issues
- `AuthorizationError` - Permission issues
- `NotFoundError` - Resource not found
- `RateLimitError` - Rate limiting
- `ApiError` - General API errors

## Testing Error Handling

### Unit Tests
```tsx
import { render, screen } from '@testing-library/react'
import { ErrorBoundary } from '@/components/ErrorBoundary'

const ThrowError = () => {
  throw new Error('Test error')
}

test('error boundary catches and displays error', () => {
  render(
    <ErrorBoundary>
      <ThrowError />
    </ErrorBoundary>
  )
  
  expect(screen.getByTestId('error-boundary')).toBeInTheDocument()
  expect(screen.getByText(/test error/i)).toBeInTheDocument()
})
```

### E2E Tests
```tsx
test('handles network errors gracefully', async ({ page }) => {
  // Simulate network failure
  await page.route('**/api/**', route => route.abort())
  
  // Trigger action that requires API call
  await page.click('[data-testid="submit-btn"]')
  
  // Verify error handling
  await expect(page.locator('[data-testid="error-message"]')).toBeVisible()
  await expect(page.locator('[data-testid="retry-btn"]')).toBeVisible()
})
```

## Monitoring and Alerting

### Error Tracking
In production, errors are automatically reported to monitoring services:
```tsx
// In ErrorBoundary.tsx
if (process.env.NODE_ENV === 'production') {
  // Report to error tracking service
  Sentry.captureException(error, { 
    extra: errorInfo, 
    tags: { errorId } 
  })
}
```

### Metrics
Key error metrics to monitor:
- Error rate by component/page
- Error recovery success rate
- Most common error types
- User impact of errors

## Migration Guide

To update existing components to use the new error handling patterns:

1. **Wrap components with ErrorBoundary**
2. **Replace try-catch blocks with error handling hooks**
3. **Update API routes to use standardized error handling**
4. **Add proper error logging**
5. **Implement user-friendly error messages**

See the implementation examples in the codebase for detailed patterns.
