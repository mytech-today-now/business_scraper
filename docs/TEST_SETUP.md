# Test Setup Guide

## Quick Start

### Prerequisites

- Node.js 18+ installed
- npm or yarn package manager
- Git for version control

### Installation

```bash
# Clone the repository
git clone https://github.com/mytech-today-now/business_scraper.git
cd business_scraper

# Install dependencies
npm install

# Run tests to verify setup
npm test
```

## Environment Setup

### Development Environment

```bash
# Copy environment template
cp .env.example .env.development

# Set test-specific variables
echo "NODE_ENV=test" >> .env.test
echo "TEST_MODE=true" >> .env.test
echo "DISABLE_REAL_OPERATIONS=true" >> .env.test
```

### Test Database Setup

```bash
# For integration tests requiring database
npm run db:setup:test
npm run db:migrate:test
npm run db:seed:test
```

## IDE Configuration

### VS Code Setup

Create `.vscode/settings.json`:

```json
{
  "jest.jestCommandLine": "npm test --",
  "jest.autoRun": {
    "watch": true,
    "onStartup": ["all-tests"]
  },
  "typescript.preferences.includePackageJsonAutoImports": "on",
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true
  }
}
```

### VS Code Extensions

Recommended extensions:

- Jest Runner
- Jest Snippets
- Testing Library Snippets
- ESLint
- Prettier

## Test Configuration Files

### jest.config.js

```javascript
module.exports = {
  preset: 'next/jest',
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  collectCoverageFrom: [
    'src/**/*.{js,jsx,ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.stories.{js,jsx,ts,tsx}',
  ],
  coverageThreshold: {
    global: {
      statements: 85,
      branches: 80,
      functions: 85,
      lines: 85,
    },
  },
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.{js,jsx,ts,tsx}',
    '<rootDir>/src/**/*.{test,spec}.{js,jsx,ts,tsx}',
    '<rootDir>/tests/**/*.{test,spec}.{js,jsx,ts,tsx}',
  ],
  moduleDirectories: ['node_modules', '<rootDir>/'],
  testTimeout: 30000,
}
```

### jest.setup.js

Key setup includes:

- Testing Library extensions
- Global mocks (fetch, localStorage, etc.)
- Browser API polyfills
- Custom matchers
- Environment variables

## Package Scripts

### Available Test Commands

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:ci": "jest --ci --coverage --watchAll=false",
    "test:unit": "jest --testPathPattern=unit",
    "test:integration": "jest --testPathPattern=integration",
    "test:e2e": "playwright test",
    "test:debug": "node --inspect-brk node_modules/.bin/jest --runInBand",
    "test:update-snapshots": "jest --updateSnapshot"
  }
}
```

## Mock Setup

### Global Mocks

Automatically mocked in `jest.setup.js`:

- `fetch` API
- `localStorage` and `sessionStorage`
- Browser APIs (ResizeObserver, IntersectionObserver)
- Crypto API
- File APIs
- Performance API

### Module Mocks

```javascript
// __mocks__/next/router.js
export const useRouter = () => ({
  push: jest.fn(),
  replace: jest.fn(),
  back: jest.fn(),
  query: {},
  pathname: '/',
})

// __mocks__/puppeteer.js
export default {
  launch: jest.fn(() =>
    Promise.resolve({
      newPage: jest.fn(() =>
        Promise.resolve({
          goto: jest.fn(),
          evaluate: jest.fn(),
          close: jest.fn(),
        })
      ),
      close: jest.fn(),
    })
  ),
}
```

## Test Utilities

### Custom Test Utilities

Located in `src/test/testUtils.ts`:

```typescript
// Mock context providers
export const mockConfigContext = {
  config: {},
  updateConfig: jest.fn(),
  resetConfig: jest.fn(),
}

// Mock scraper controller
export const mockScraperController = {
  isRunning: false,
  results: [],
  progress: { current: 0, total: 0, status: 'idle' },
  startScraping: jest.fn(),
  stopScraping: jest.fn(),
  clearResults: jest.fn(),
}

// Browser mock setup
export const setupBrowserMocks = () => {
  // Setup all browser-related mocks
}
```

### Test Factories

```typescript
// Create test data
export const createMockUser = (overrides = {}) => ({
  id: 'test-user-id',
  email: 'test@example.com',
  name: 'Test User',
  ...overrides,
})

export const createMockScrapingResult = (overrides = {}) => ({
  id: 'test-result-id',
  businessName: 'Test Business',
  email: 'business@example.com',
  phone: '555-0123',
  ...overrides,
})
```

## Debugging Tests

### Debug Configuration

```bash
# Debug specific test
npm run test:debug -- --testNamePattern="specific test name"

# Debug with VS Code
# Set breakpoints and use "Jest Debug" configuration
```

### Common Debug Scenarios

1. **Component not rendering**

   ```typescript
   // Add debug output
   const { debug } = render(<Component />)
   debug() // Prints current DOM
   ```

2. **Async operations not completing**

   ```typescript
   // Use waitFor with debugging
   await waitFor(
     () => {
       console.log('Current state:', screen.debug())
       expect(element).toBeInTheDocument()
     },
     { timeout: 5000 }
   )
   ```

3. **Mock not working**
   ```typescript
   // Verify mock setup
   console.log('Mock calls:', mockFunction.mock.calls)
   ```

## Performance Optimization

### Test Performance Tips

1. **Use `--maxWorkers`** to control parallelization
2. **Mock expensive operations** (API calls, file I/O)
3. **Use `--onlyChanged`** during development
4. **Avoid unnecessary DOM operations**
5. **Clean up after tests**

### Memory Management

```typescript
// Proper cleanup
afterEach(() => {
  jest.clearAllMocks()
  cleanup() // From @testing-library/react
})

// Avoid memory leaks
beforeEach(() => {
  jest.useFakeTimers()
})

afterEach(() => {
  jest.runOnlyPendingTimers()
  jest.useRealTimers()
})
```

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      - run: npm ci
      - run: npm run test:ci
      - uses: codecov/codecov-action@v3
```

### Quality Gates

- Minimum 85% test coverage
- All tests must pass
- No critical security vulnerabilities
- Performance benchmarks within limits

## Troubleshooting

### Common Issues

1. **Tests timing out**
   - Increase `testTimeout` in Jest config
   - Use proper async/await patterns
   - Mock slow operations

2. **Mocks not working**
   - Check mock placement (before imports)
   - Verify mock implementation
   - Clear mocks between tests

3. **DOM not updating**
   - Use `act()` for React updates
   - Wait for async operations
   - Check component lifecycle

4. **Memory leaks**
   - Clean up timers and subscriptions
   - Use `--detectOpenHandles`
   - Monitor test execution time

### Getting Help

1. Check test examples in codebase
2. Review Jest documentation
3. Use debugging tools
4. Ask team for guidance

## Best Practices

### Test Organization

- Group related tests with `describe`
- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)
- Keep tests focused and isolated

### Test Data

- Use factories for test data creation
- Avoid hardcoded values
- Clean up after tests
- Use realistic data

### Async Testing

- Always await async operations
- Use `waitFor` for DOM updates
- Handle promise rejections
- Set appropriate timeouts

### Error Handling

- Test both success and error cases
- Mock error scenarios
- Verify error messages
- Test error boundaries

---

For more information, see the main [Testing Guide](./TESTING.md).
