Implement the following enhancement to the application.  Do the enhancement first.  Follow the Rules and Guidelines for the project.  Plan out you actions.  Work logically through the process.  Be sure to cover all of the instances where the enhancement alters the application.  Handle errors and fallback to seamless solutions.
Log each enhancement as an Issue/Error on Github for the project with the required proper 'bug' documentation.
Be sure the Issue has the proper Assignees, Labels, bug, Something isn't working, critical, etc for the Issue.
If the changes are code related make sure the test cases run to 99.9% success.  Add the tests to the appropriate section of the test suite. Add the tests to the BVT test suite too.  After the resolution of the Issue, close the Issue on GitHub with the proper documentation.  If the changes are not code related, add the tests to the appropriate section of the test suite.  Add the tests to the BVT test suite too.  After the resolution of the Issue, close the Issue on GitHub with the proper documentation.
enhancement:

# Augment AI Code Review Remediation Prompts

This document contains a series of Augment AI prompts designed to address the critical issues and recommendations identified in the code review summary. Execute these prompts in order of priority.

## 🔴 CRITICAL SECURITY VULNERABILITIES - IMMEDIATE ACTION REQUIRED

### Prompt 1: Fix NPM Security Vulnerabilities
```
Analyze the current npm audit report and fix all security vulnerabilities in the Business Scraper application. Focus on:

1. Update typeORM to the latest secure version to resolve SQL injection vulnerability
2. Update xml2js to resolve prototype pollution vulnerability  
3. Update jose package to resolve moderate vulnerability
4. Update cookie package to resolve security vulnerability
5. Run npm audit fix and verify all critical and high-severity vulnerabilities are resolved
6. Update package.json and package-lock.json with secure dependency versions
7. Test the application after updates to ensure functionality is maintained

Provide a detailed report of what was updated and any breaking changes that need to be addressed.
```

### Prompt 2: Fix TypeScript Configuration Issues
```
Fix the TypeScript configuration issues in the Business Scraper application:

1. Rename JSX files with incorrect .ts extensions to .tsx:
   - src/hooks/useMemoryLeakDetection.ts → src/hooks/useMemoryLeakDetection.tsx
   - src/__tests__/utils/testHelpers.ts → src/__tests__/utils/testHelpers.tsx

2. Update all import statements that reference these files to use the new .tsx extensions

3. Verify that tsconfig.json properly handles JSX compilation for these files

4. Run TypeScript compilation to ensure no errors remain

5. Update any build scripts or configuration files that reference the old file names

Ensure the application builds successfully after these changes.
```

### Prompt 3: Enable TypeScript Strict Mode
```
Enable TypeScript strict mode in the Business Scraper application and fix all resulting type errors:

1. Update tsconfig.json to set "strict": true
2. Fix all type errors that arise from enabling strict mode
3. Add proper type annotations where implicit any types are detected
4. Ensure null/undefined checks are properly handled
5. Fix any issues with function parameter types and return types
6. Update any @ts-ignore comments to @ts-expect-error where appropriate
7. Verify the application compiles and runs correctly with strict mode enabled

Document any significant type changes made during this process.
```

### Prompt 4: Fix Crypto API Compatibility Issues
```
Resolve the crypto API compatibility issues in the Business Scraper application:

1. Implement proper polyfills for crypto.randomUUID in test environments
2. Configure Web Crypto API polyfills for Edge Runtime compatibility
3. Update test configuration to properly handle crypto APIs
4. Fix any failing tests related to crypto API usage
5. Ensure authentication tests pass with proper crypto API support
6. Add fallback implementations for environments that don't support native crypto APIs

Test thoroughly to ensure crypto functionality works across all environments.
```

## 🟠 HIGH PRIORITY ISSUES

### Prompt 5: Fix Failing Test Suites
```
Systematically fix all failing test suites in the Business Scraper application:

1. Fix useSearchStreaming connection error tests (8/9 failing)
2. Fix CSRF token validation tests (6/12 failing)  
3. Fix security monitoring tests (9/9 failing)
4. Fix authentication tests failing due to crypto API issues
5. Update test environment configuration to resolve compatibility issues
6. Ensure all test utilities and helpers are properly configured
7. Run the complete test suite and verify >95% pass rate

Provide detailed analysis of what was causing each test failure and how it was resolved.
```

### Prompt 6: Resolve ESLint Violations
```
Fix all ESLint violations in the Business Scraper application:

1. Replace all @ts-ignore comments with @ts-expect-error where appropriate
2. Replace all instances of 'var' with 'let' or 'const' as appropriate
3. Fix parsing errors in TypeScript files
4. Ensure consistent code formatting and style
5. Update ESLint configuration if needed to match project standards
6. Run ESLint with --fix flag to automatically resolve fixable issues
7. Manually address any remaining violations

Ensure the codebase passes all ESLint checks without warnings or errors.
```

### Prompt 7: Optimize Build Configuration
```
Optimize the build configuration for the Business Scraper application:

1. Review and update webpack configuration for optimal performance
2. Ensure proper JSX configuration for all TypeScript files
3. Optimize bundle splitting and code splitting strategies
4. Update build scripts to handle the new file extensions (.tsx)
5. Verify source maps are properly generated for debugging
6. Ensure development and production builds work correctly
7. Test hot module replacement and development server functionality

Document any changes made to build configuration and their impact.
```

## 🟡 MEDIUM PRIORITY IMPROVEMENTS

### Prompt 8: Enhance Error Handling Consistency
```
Improve error handling consistency across the Business Scraper application:

1. Audit all error handling patterns across different layers (Model, View, Controller)
2. Implement consistent error handling strategies
3. Ensure proper error propagation from services to controllers to views
4. Add structured error logging with appropriate log levels
5. Implement user-friendly error messages that don't expose sensitive information
6. Add error boundaries for React components where appropriate
7. Create standardized error response formats for API endpoints

Provide documentation on the new error handling patterns implemented.
```

### Prompt 9: Resolve Circular Dependencies
```
Identify and resolve circular dependencies in the Business Scraper application:

1. Analyze the codebase to identify all circular dependencies
2. Refactor service imports to eliminate circular references
3. Implement proper dependency injection patterns where needed
4. Create interface abstractions to break circular dependencies
5. Update import statements to follow a clear dependency hierarchy
6. Verify that the application still functions correctly after refactoring
7. Add ESLint rules to prevent future circular dependencies

Document the dependency structure and any architectural changes made.
```

### Prompt 10: Optimize Database Queries
```
Optimize database queries in the Business Scraper application:

1. Audit all database queries for performance issues
2. Add proper indexing for frequently queried fields
3. Implement query optimization techniques (eager loading, query batching)
4. Add database query logging and monitoring
5. Optimize N+1 query problems
6. Implement proper pagination for large datasets
7. Add query performance tests to prevent regressions

Provide performance benchmarks before and after optimization.
```

## 🟢 LONG-TERM ENHANCEMENTS

### Prompt 11: Improve Test Coverage
```
Enhance test coverage for the Business Scraper application to achieve >90% coverage:

1. Identify areas with low test coverage using coverage reports
2. Add unit tests for untested functions and methods
3. Expand integration tests for critical business logic
4. Add more comprehensive E2E tests for user workflows
5. Implement performance tests for critical operations
6. Add accessibility tests for UI components
7. Create test data factories and fixtures for consistent testing

Provide detailed coverage reports and testing strategy documentation.
```

### Prompt 12: Implement Additional Security Hardening
```
Implement additional security hardening measures for the Business Scraper application:

1. Review and enhance Content Security Policy (CSP) configuration
2. Implement additional input validation and sanitization
3. Add security headers for all HTTP responses
4. Enhance rate limiting and DDoS protection
5. Implement additional authentication security measures (2FA, session management)
6. Add security monitoring and alerting
7. Conduct security penetration testing

Document all security enhancements and provide security best practices guide.
```

## EXECUTION GUIDELINES

### Priority Order
1. Execute Critical Security prompts (1-4) immediately
2. Execute High Priority prompts (5-7) within 24-48 hours  
3. Execute Medium Priority prompts (8-10) within 1 week
4. Execute Long-term prompts (11-12) within 1 month

### Validation Steps
After each prompt execution:
1. Run the full test suite to ensure no regressions
2. Verify the application builds and runs correctly
3. Check that security vulnerabilities are resolved
4. Update documentation as needed
5. Commit changes with clear commit messages following conventional commit format

### Success Criteria
- All critical security vulnerabilities resolved
- TypeScript compilation successful with strict mode enabled
- Test suite achieving >95% pass rate
- ESLint passing without violations
- Application ready for production deployment
