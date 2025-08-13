# Code Review Actions for Augment AI

This document contains actionable prompts for Augment AI in VS Code to address the critical issues identified in the GitHub Code Review of the Business Scraper Application.

## 🔴 CRITICAL PRIORITY - Execute Immediately

### Action 1: Fix Security Vulnerabilities
```
Update all vulnerable npm dependencies to secure versions. Focus on these critical vulnerabilities:
- xlsx package (Prototype Pollution and ReDoS)
- ws package version 8.0.0-8.17.0 (DoS vulnerability)
- tar-fs package version 3.0.0-3.0.8 (Path traversal)
- dompurify package <3.2.4 (XSS vulnerability)
- vue-template-compiler (XSS vulnerability)

Run npm audit and fix all high and moderate severity issues. Handle any breaking changes that result from updates.
```

### Action 2: Fix Failing Test Suite
```
Fix the 73 failing tests in the test suite, focusing on:
1. Component tests in src/__tests__/view/components/CategorySelector.test.tsx - fix DOM element selection issues
2. Integration tests with API mocking problems
3. E2E tests that are timing out or failing to find elements

Ensure all tests pass and the test suite is stable for CI/CD.
```

### Action 3: Replace TypeScript 'any' Types
```
Replace all instances of 'any' type with proper TypeScript types in these critical files:
- src/lib/cache.ts
- src/lib/database.ts
- src/lib/dataValidationPipeline.ts
- src/utils/logger.ts
- src/model/clientSearchEngine.ts

Create proper interfaces and generic types where needed. Focus on type safety for core business logic.
```

## 🟡 HIGH PRIORITY - Execute This Week

### Action 4: Fix ESLint Violations
```
Systematically fix ESLint errors across the codebase:
1. Remove all unused variables and imports
2. Fix missing dependencies in React useEffect and useCallback hooks
3. Replace 'let' with 'const' where variables are not reassigned
4. Fix unescaped quotes in JSX components
5. Remove unused function parameters

Start with files that have the most errors and work systematically through the codebase.
```

### Action 5: Standardize Error Handling
```
Implement consistent error handling patterns across all API routes and services:
1. Ensure all catch blocks properly use the error variable or remove it
2. Add proper error logging using the logger utility
3. Return consistent error response formats
4. Add error boundaries for React components where missing

Focus on files in src/app/api/ and src/lib/ directories.
```

### Action 6: Fix React Hook Dependencies
```
Fix missing dependencies in React hooks throughout the application:
1. Add missing dependencies to useEffect hooks
2. Add missing dependencies to useCallback hooks
3. Add missing dependencies to useMemo hooks

Pay special attention to:
- src/controller/useScraperController.ts
- src/view/components/ directory
- Custom hooks in the application
```

## 🟢 MEDIUM PRIORITY - Execute Next Week

### Action 7: Improve Component Test Coverage
```
Add missing test cases and fix existing component tests:
1. Fix CategorySelector component tests to match actual DOM structure
2. Add tests for error states and edge cases
3. Improve test assertions to be more specific
4. Add accessibility testing for components

Focus on achieving 90%+ test coverage for critical components.
```

### Action 8: Clean Up Unused Code
```
Remove unused code and imports throughout the application:
1. Remove unused import statements
2. Remove unused function parameters
3. Remove unused variables and constants
4. Remove dead code paths

Use your code analysis to identify and safely remove unused code.
```

### Action 9: Improve Type Definitions
```
Create proper TypeScript interfaces and types for:
1. API request/response objects
2. Database entity types
3. Configuration objects
4. Business logic data structures

Replace remaining 'any' types with specific interfaces in non-critical files.
```

## 🔵 LOW PRIORITY - Execute When Time Permits

### Action 10: Add Missing Documentation
```
Add JSDoc comments and improve code documentation for:
1. Complex business logic functions
2. API endpoint handlers
3. Utility functions
4. Type definitions

Focus on functions that are not self-explanatory or have complex logic.
```

### Action 11: Improve Accessibility
```
Add accessibility improvements to React components:
1. Add ARIA labels where missing
2. Improve keyboard navigation
3. Add proper semantic HTML elements
4. Ensure color contrast compliance

Focus on user-facing components in src/view/components/.
```

### Action 12: Performance Optimizations
```
Implement performance improvements:
1. Add React.memo for expensive components
2. Optimize database queries
3. Implement proper caching strategies
4. Add lazy loading for heavy components

Focus on components that render large datasets or perform expensive operations.
```

## 📋 Execution Guidelines

### For Each Action:
1. **Analyze First**: Use codebase retrieval to understand the current implementation
2. **Plan Changes**: Identify all files that need modification
3. **Implement Incrementally**: Make small, focused changes
4. **Test After Changes**: Run tests to ensure no regressions
5. **Verify Success**: Confirm the issue is resolved

### Priority Order:
1. Execute all CRITICAL actions first (Actions 1-3)
2. Move to HIGH priority actions (Actions 4-6)
3. Complete MEDIUM priority actions (Actions 7-9)
4. Address LOW priority actions as time permits (Actions 10-12)

### Testing Strategy:
- Run `npm test` after each major change
- Run `npm run lint` to verify ESLint compliance
- Run `npm audit` to verify security improvements
- Test critical user workflows manually

### Success Criteria:
- ✅ Zero security vulnerabilities in npm audit
- ✅ All tests passing (478/478)
- ✅ ESLint errors reduced to <50
- ✅ TypeScript strict mode compliance
- ✅ Consistent error handling patterns

## 🚀 Getting Started

**Recommended first prompt to Augment AI:**
```
I need to fix critical security vulnerabilities in my Business Scraper application. Please analyze the package.json file and npm audit results, then update all vulnerable dependencies to secure versions. Handle any breaking changes that result from the updates and ensure the application still builds and runs correctly.
```

This will address the most critical issue first and establish a foundation for the remaining improvements.
