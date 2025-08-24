# Testing Guide

## Overview

This guide covers the comprehensive testing strategy for the Business Scraper application, including unit tests, integration tests, end-to-end tests, and performance testing.

## Testing Stack

- **Unit Tests**: Jest with TypeScript support
- **Integration Tests**: Jest with mocked dependencies
- **End-to-End Tests**: Playwright
- **Performance Tests**: Custom performance utilities
- **API Testing**: Supertest with Jest
- **Coverage**: Jest coverage reports

## Test Structure

```
src/
├── __tests__/
│   ├── lib/
│   │   ├── field-mapping/
│   │   │   ├── mapping-engine.test.ts
│   │   │   ├── transformations.test.ts
│   │   │   └── validators.test.ts
│   │   ├── export-templates/
│   │   │   ├── salesforce.test.ts
│   │   │   ├── hubspot.test.ts
│   │   │   ├── pipedrive.test.ts
│   │   │   ├── mailchimp.test.ts
│   │   │   └── constant-contact.test.ts
│   │   ├── integrations/
│   │   │   ├── api-framework.test.ts
│   │   │   ├── oauth2-service.test.ts
│   │   │   ├── webhook-service.test.ts
│   │   │   └── scheduling-service.test.ts
│   │   └── analytics/
│   │       ├── usage-analytics.test.ts
│   │       └── api-metrics.test.ts
│   ├── integration/
│   │   ├── api-endpoints.test.ts
│   │   ├── export-workflows.test.ts
│   │   └── webhook-delivery.test.ts
│   └── e2e/
│       ├── export-flow.spec.ts
│       ├── api-authentication.spec.ts
│       └── scheduling.spec.ts
```

## Running Tests

### All Tests
```bash
npm test
```

### Unit Tests Only
```bash
npm run test:unit
```

### Integration Tests Only
```bash
npm run test:integration
```

### End-to-End Tests
```bash
npm run test:e2e
```

### Coverage Report
```bash
npm run test:coverage
```

### Watch Mode
```bash
npm run test:watch
```

## Test Categories

### 1. Unit Tests

#### Field Mapping Engine Tests
- **File**: `src/__tests__/lib/field-mapping/mapping-engine.test.ts`
- **Coverage**: Schema management, transformation execution, validation
- **Key Test Cases**:
  - Schema registration and retrieval
  - Field mapping execution with various data types
  - Transformation application and error handling
  - Performance with large datasets

#### Export Template Tests
- **Files**: `src/__tests__/lib/export-templates/*.test.ts`
- **Coverage**: Template configuration, data transformation, platform-specific features
- **Key Test Cases**:
  - Template validation and configuration
  - Business data preprocessing and filtering
  - Field mapping accuracy
  - Platform-specific formatting (phone, email, address)
  - Lead scoring and data enrichment
  - Error handling and data quality control

#### API Framework Tests
- **File**: `src/__tests__/lib/integrations/api-framework.test.ts`
- **Coverage**: Request handling, authentication, rate limiting, CORS
- **Key Test Cases**:
  - Request processing and response formatting
  - Authentication (OAuth 2.0, API Key)
  - Authorization and permission checking
  - Rate limiting enforcement
  - Error handling and metrics recording

### 2. Integration Tests

#### API Endpoints Tests
- **File**: `src/__tests__/integration/api-endpoints.test.ts`
- **Coverage**: End-to-end API functionality with mocked services
- **Key Test Cases**:
  - Template listing and filtering
  - Export creation with various options
  - Analytics data retrieval
  - Error handling and validation
  - Response format consistency

#### Export Workflows Tests
- **Coverage**: Complete export workflows from data input to output
- **Key Test Cases**:
  - Multi-platform export execution
  - Export scheduling and delivery
  - Webhook notification delivery
  - Data quality validation across templates

### 3. End-to-End Tests

#### Export Flow Tests
- **Coverage**: Complete user workflows through the application
- **Key Test Cases**:
  - Business data import and validation
  - Template selection and configuration
  - Export execution and download
  - Scheduled export setup and monitoring

#### API Authentication Tests
- **Coverage**: OAuth 2.0 and API key authentication flows
- **Key Test Cases**:
  - OAuth authorization code flow
  - Token refresh and validation
  - API key authentication
  - Permission-based access control

## Test Data

### Sample Business Records
```typescript
const testBusinessData: BusinessRecord[] = [
  {
    businessName: 'Acme Corporation',
    email: ['contact@acme.com', 'sales@acme.com'],
    phone: ['5551234567', '5559876543'],
    website: 'https://acme.com',
    address: {
      street: '123 Main Street',
      city: 'Anytown',
      state: 'CA',
      zipCode: '12345',
      country: 'United States'
    },
    industry: 'Technology',
    description: 'Leading technology company'
  }
  // Additional test records...
]
```

### Mock Services
```typescript
// Mock export service
jest.mock('@/lib/enhanced-export-service', () => ({
  enhancedExportService: {
    listTemplates: jest.fn(() => mockTemplates),
    exportWithTemplate: jest.fn(() => mockExportResult),
    getTemplate: jest.fn(() => mockTemplate)
  }
}))

// Mock analytics service
jest.mock('@/lib/analytics/usage-analytics', () => ({
  usageAnalyticsService: {
    recordUsage: jest.fn(),
    getClientAnalytics: jest.fn(() => mockAnalytics),
    getRealTimeMetrics: jest.fn(() => mockMetrics)
  }
}))
```

## Performance Testing

### Load Testing
```typescript
describe('Performance Tests', () => {
  test('should handle large dataset export efficiently', async () => {
    const largeDataset = Array(1000).fill(null).map((_, index) => ({
      businessName: `Company ${index}`,
      email: [`contact${index}@company${index}.com`],
      industry: 'Technology'
    }))

    const startTime = Date.now()
    const result = await template.execute(largeDataset)
    const duration = Date.now() - startTime

    expect(result.success).toBe(true)
    expect(result.recordsExported).toBe(1000)
    expect(duration).toBeLessThan(10000) // Should complete within 10 seconds
    expect(result.metadata.averageProcessingTime).toBeLessThan(10) // < 10ms per record
  })
})
```

### Memory Usage Testing
```typescript
test('should not leak memory during large exports', async () => {
  const initialMemory = process.memoryUsage().heapUsed
  
  for (let i = 0; i < 10; i++) {
    await template.execute(largeDataset)
  }
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc()
  }
  
  const finalMemory = process.memoryUsage().heapUsed
  const memoryIncrease = finalMemory - initialMemory
  
  expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024) // Less than 50MB increase
})
```

## Security Testing

### Input Validation Tests
```typescript
describe('Security Tests', () => {
  test('should sanitize malicious input', async () => {
    const maliciousData = [{
      businessName: '<script>alert("xss")</script>',
      email: ['test@evil.com'],
      description: 'DROP TABLE users; --'
    }]

    const result = await template.execute(maliciousData)
    
    expect(result.exportData[0].Company).not.toContain('<script>')
    expect(result.exportData[0].Description).not.toContain('DROP TABLE')
  })

  test('should handle SQL injection attempts', async () => {
    const sqlInjectionData = [{
      businessName: "'; DROP TABLE businesses; --",
      email: ['test@test.com']
    }]

    const result = await template.execute(sqlInjectionData)
    
    expect(result.success).toBe(true)
    expect(result.exportData[0].Company).not.toContain('DROP TABLE')
  })
})
```

### Authentication Tests
```typescript
describe('Authentication Security', () => {
  test('should reject invalid tokens', async () => {
    const request = new NextRequest('https://example.com/api/v1/exports', {
      headers: { 'Authorization': 'Bearer invalid-token' }
    })

    const response = await handler(request)
    expect(response.status).toBe(401)
  })

  test('should enforce rate limits', async () => {
    // Simulate rapid requests
    const requests = Array(200).fill(null).map(() => 
      handler(new NextRequest('https://example.com/api/v1/exports'))
    )

    const responses = await Promise.all(requests)
    const rateLimitedResponses = responses.filter(r => r.status === 429)
    
    expect(rateLimitedResponses.length).toBeGreaterThan(0)
  })
})
```

## Test Configuration

### Jest Configuration
```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/__tests__/**/*'
  ],
  coverageThreshold: {
    global: {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85
    }
  },
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup.ts']
}
```

### Test Setup
```typescript
// src/__tests__/setup.ts
import { jest } from '@jest/globals'

// Global test setup
beforeAll(() => {
  // Set test environment variables
  process.env.NODE_ENV = 'test'
  process.env.API_BASE_URL = 'http://localhost:3000'
})

afterAll(() => {
  // Cleanup after all tests
  jest.clearAllMocks()
})

// Mock external dependencies
jest.mock('@/lib/security', () => ({
  getClientIP: jest.fn(() => '127.0.0.1')
}))
```

## Continuous Integration

### GitHub Actions Workflow
```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm run test:coverage
      - run: npm run test:e2e
      - uses: codecov/codecov-action@v3
        with:
          file: ./coverage/lcov.info
```

## Coverage Requirements

- **Minimum Coverage**: 85% for all metrics (lines, functions, branches, statements)
- **Critical Paths**: 95% coverage for export templates and API endpoints
- **New Code**: 90% coverage requirement for all new features

## Best Practices

1. **Test Isolation**: Each test should be independent and not rely on other tests
2. **Descriptive Names**: Test names should clearly describe what is being tested
3. **Arrange-Act-Assert**: Follow the AAA pattern for test structure
4. **Mock External Dependencies**: Use mocks for external services and APIs
5. **Test Edge Cases**: Include tests for error conditions and edge cases
6. **Performance Awareness**: Include performance assertions for critical paths
7. **Security Focus**: Test for common security vulnerabilities
8. **Documentation**: Keep tests well-documented and maintainable

## Debugging Tests

### Running Specific Tests
```bash
# Run specific test file
npm test -- mapping-engine.test.ts

# Run tests matching pattern
npm test -- --testNamePattern="should execute mapping"

# Run tests in debug mode
npm test -- --detectOpenHandles --forceExit
```

### Test Debugging
```typescript
// Add debugging output
test('should debug export process', async () => {
  console.log('Starting export test...')
  
  const result = await template.execute(testData)
  
  console.log('Export result:', JSON.stringify(result, null, 2))
  
  expect(result.success).toBe(true)
})
```

This comprehensive testing strategy ensures high-quality, reliable code with excellent coverage across all application components.
