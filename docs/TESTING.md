# Testing Guide

## Overview

This document provides comprehensive guidelines for testing the Business Scraper
application. Our testing strategy follows industry best practices and ensures
high-quality, reliable software delivery.

## Testing Architecture

### Test Categories

1. **Unit Tests** - Individual function/component testing
2. **Integration Tests** - Service and API interaction testing
3. **End-to-End Tests** - Complete user workflow testing
4. **Performance Tests** - Load and stress testing
5. **Security Tests** - Vulnerability and penetration testing
6. **Accessibility Tests** - WCAG 2.1 AA compliance testing

### Test Structure

```
src/
├── __tests__/           # Component and integration tests
├── tests/
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   ├── e2e/           # End-to-end tests
│   ├── performance/   # Performance tests
│   └── security/      # Security tests
└── test/
    ├── testUtils.ts   # Test utilities and helpers
    ├── mocks/         # Mock implementations
    └── fixtures/      # Test data and fixtures
```

## Test Configuration

### Jest Configuration

Our Jest setup includes:

- TypeScript support
- React Testing Library integration
- Coverage reporting
- Custom matchers
- Mock implementations

### Key Configuration Files

- `jest.config.js` - Main Jest configuration
- `jest.setup.js` - Global test setup and mocks
- `src/test/testUtils.ts` - Reusable test utilities

## Running Tests

### Basic Commands

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test types
npm run test:unit
npm run test:integration
npm run test:e2e
```

### Test Execution Options

```bash
# Run specific test file
npm test -- src/__tests__/App.test.tsx

# Run tests matching pattern
npm test -- --testNamePattern="should render"

# Run tests with verbose output
npm test -- --verbose

# Run tests in parallel
npm test -- --maxWorkers=4
```

## Writing Tests

### Unit Tests

Unit tests should focus on individual functions, classes, or components in
isolation.

```typescript
// Example unit test
import { validateEmail } from '@/utils/validation'

describe('validateEmail', () => {
  it('should validate correct email format', () => {
    expect(validateEmail('test@example.com')).toBe(true)
  })

  it('should reject invalid email format', () => {
    expect(validateEmail('invalid-email')).toBe(false)
  })
})
```

### Component Tests

Component tests verify UI behavior and user interactions.

```typescript
import { render, screen, userEvent } from '@testing-library/react'
import { Button } from '@/components/Button'

describe('Button', () => {
  it('should call onClick when clicked', async () => {
    const handleClick = jest.fn()
    render(<Button onClick={handleClick}>Click me</Button>)

    await userEvent.click(screen.getByRole('button'))
    expect(handleClick).toHaveBeenCalledTimes(1)
  })
})
```

### Integration Tests

Integration tests verify interactions between multiple components or services.

```typescript
import { render, screen } from '@testing-library/react'
import { App } from '@/components/App'
import { mockConfigContext } from '@/test/testUtils'

describe('App Integration', () => {
  it('should integrate configuration and scraping services', () => {
    render(<App />)
    expect(screen.getByText('Business Scraper')).toBeInTheDocument()
  })
})
```

## Test Utilities

### Mock Implementations

We provide comprehensive mocks for:

- Browser APIs (localStorage, fetch, etc.)
- External services
- React hooks and contexts
- Node.js modules

### Test Helpers

```typescript
// Available test utilities
import {
  mockConfigContext,
  mockScraperController,
  setupBrowserMocks,
  createMockUser,
  waitForLoadingToFinish,
} from '@/test/testUtils'
```

### Custom Matchers

```typescript
// Custom Jest matchers
expect(element).toBeVisible()
expect(element).toHaveAccessibleName('Button')
expect(response).toHaveValidationError('email')
```

## Coverage Requirements

### Minimum Coverage Thresholds

- **Statements**: 85%
- **Branches**: 80%
- **Functions**: 85%
- **Lines**: 85%

### Coverage Reporting

```bash
# Generate coverage report
npm run test:coverage

# View coverage in browser
open coverage/lcov-report/index.html
```

## Best Practices

### Test Organization

1. **Group related tests** using `describe` blocks
2. **Use descriptive test names** that explain the expected behavior
3. **Follow AAA pattern** (Arrange, Act, Assert)
4. **Keep tests focused** on single behaviors
5. **Use setup and teardown** appropriately

### Test Data Management

1. **Use factories** for creating test data
2. **Avoid hardcoded values** when possible
3. **Clean up after tests** to prevent side effects
4. **Use realistic test data** that matches production scenarios

### Async Testing

```typescript
// Proper async test handling
it('should handle async operations', async () => {
  const result = await asyncFunction()
  expect(result).toBeDefined()
})

// Using waitFor for DOM updates
await waitFor(() => {
  expect(screen.getByText('Loaded')).toBeInTheDocument()
})
```

### Error Testing

```typescript
// Testing error scenarios
it('should handle errors gracefully', async () => {
  const consoleSpy = jest.spyOn(console, 'error').mockImplementation()

  render(<ComponentThatMightError />)

  expect(consoleSpy).not.toHaveBeenCalled()
  consoleSpy.mockRestore()
})
```

## Debugging Tests

### Common Issues

1. **Async timing issues** - Use `waitFor` and proper async/await
2. **Mock not working** - Ensure mocks are set up before imports
3. **DOM not updating** - Use `act()` for React state updates
4. **Memory leaks** - Clean up timers, subscriptions, and event listeners

### Debugging Tools

```bash
# Run tests with Node debugger
node --inspect-brk node_modules/.bin/jest --runInBand

# Debug specific test
npm test -- --testNamePattern="specific test" --runInBand
```

## Continuous Integration

### GitHub Actions

Our CI pipeline runs:

- All test suites
- Coverage analysis
- Performance benchmarks
- Security scans
- Accessibility audits

### Quality Gates

Tests must pass with:

- 85% minimum coverage
- No critical security vulnerabilities
- No accessibility violations
- Performance within acceptable thresholds

## Troubleshooting

### Common Test Failures

1. **Component not rendering** - Check mock setup and imports
2. **Events not firing** - Ensure proper user event simulation
3. **Async operations timing out** - Increase timeout or fix async handling
4. **Mock functions not called** - Verify mock implementation and timing

### Getting Help

1. Check existing test examples in the codebase
2. Review Jest and Testing Library documentation
3. Use debugging tools to inspect test execution
4. Ask team members for guidance on complex scenarios

## Performance Considerations

### Test Performance

- Use `--maxWorkers` to control parallelization
- Mock expensive operations
- Use `--onlyChanged` for faster feedback
- Consider test sharding for large suites

### Memory Management

- Clean up after tests
- Avoid memory leaks in mocks
- Use `--detectOpenHandles` to find leaks
- Monitor test execution time

## Security Testing

### Automated Security Scans

- Dependency vulnerability scanning
- Static code analysis
- Dynamic security testing
- Penetration testing simulation

### Security Test Examples

```typescript
// Testing input sanitization
it('should sanitize user input', () => {
  const maliciousInput = '<script>alert("xss")</script>'
  const sanitized = sanitizeInput(maliciousInput)
  expect(sanitized).not.toContain('<script>')
})
```

## Accessibility Testing

### Automated Accessibility Tests

```typescript
import { axe, toHaveNoViolations } from 'jest-axe'

expect.extend(toHaveNoViolations)

it('should have no accessibility violations', async () => {
  const { container } = render(<Component />)
  const results = await axe(container)
  expect(results).toHaveNoViolations()
})
```

### Manual Testing Guidelines

1. Test with screen readers
2. Verify keyboard navigation
3. Check color contrast ratios
4. Validate ARIA attributes
5. Test with assistive technologies

---

For more detailed information, see the individual test files and documentation
in the `docs/` directory.
