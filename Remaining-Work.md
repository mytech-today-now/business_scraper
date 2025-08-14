# Remaining Work - ESLint & Code Quality Improvements

This document contains a series of prompts for Augment AI in VS Code to systematically complete the remaining ESLint violations and code quality improvements in the business scraper application.

## Current Status
- **ESLint violations reduced from 1,079 to ~1,050**
- **All critical parsing errors fixed**
- **React hooks dependencies corrected**
- **JSX quote escaping completed**
- **Major unused imports/variables removed**

---

## Phase 1: Critical Error Fixes (High Priority)

### Prompt 1.1: Fix Security Violations in Production Code
```
Fix all security-related ESLint violations in production code (non-test files). Focus on:
1. Generic Object Injection Sink violations in src/lib/ and src/view/ files
2. Variable Assigned to Object Injection Sink issues
3. Script URL eval violations
4. Non-literal filesystem operations

Exclude test files from this fix. Ensure all fixes maintain functionality while improving security.
```

### Prompt 1.2: Remove Remaining Unused Variables in Production Code
```
Remove all unused variables, imports, and function parameters in production code (src/lib/, src/view/, src/model/, src/controller/, src/app/). Focus on:
1. Unused imports in component files
2. Unused function parameters (prefix with underscore if needed for API compatibility)
3. Unused variables in business logic files
4. Unused destructured properties

Do not modify test files in this pass.
```

### Prompt 1.3: Fix Require Import Violations
```
Replace all require() style imports with ES6 import statements in production code. Focus on:
1. Dynamic require() calls that can be converted to static imports
2. Conditional require() calls that need proper dynamic import() syntax
3. Test utility require() calls in production code

Maintain functionality while modernizing import syntax.
```

---

## Phase 2: React & TypeScript Improvements (Medium Priority)

### Prompt 2.1: Add Missing Return Type Annotations
```
Add explicit return type annotations to all functions missing them in production code. Focus on:
1. React component functions
2. Event handler functions
3. Utility functions in src/lib/ and src/utils/
4. API route handlers
5. Hook functions

Use proper TypeScript return types (JSX.Element, void, Promise<T>, etc.).
```

### Prompt 2.2: Fix Remaining React Hook Dependencies
```
Fix all remaining React hook dependency violations. Focus on:
1. useEffect hooks with missing dependencies
2. useCallback hooks with missing dependencies
3. useMemo hooks with missing dependencies
4. Custom hooks with dependency issues

Ensure all dependencies are properly included to prevent stale closures and bugs.
```

### Prompt 2.3: Replace Non-Null Assertions in Production Code
```
Replace all non-null assertions (!) in production code with proper null checks or optional chaining. Focus on:
1. Property access with ! operator
2. Array/object access with ! operator
3. Function call results with ! operator

Add proper error handling or default values instead of assertions.
```

---

## Phase 3: Code Quality & Standards (Lower Priority)

### Prompt 3.1: Fix Remaining 'any' Types in Production Code
```
Replace remaining 'any' types in production code with proper TypeScript types. Focus on:
1. Function parameters with 'any' type
2. Object properties with 'any' type
3. Array elements with 'any' type
4. Return types using 'any'

Create proper interfaces and type definitions where needed.
```

### Prompt 3.2: Optimize Image Usage
```
Replace <img> elements with Next.js <Image> components for better performance. Focus on:
1. Static images in components
2. Dynamic images with proper optimization
3. Add proper alt text and loading strategies
4. Implement responsive image sizing

Improve LCP and bandwidth usage across the application.
```

### Prompt 3.3: Improve Error Handling Patterns
```
Standardize error handling patterns across the application. Focus on:
1. Consistent error logging in try-catch blocks
2. Proper error propagation in async functions
3. User-friendly error messages in UI components
4. Error boundary implementation for React components

Ensure robust error handling throughout the application.
```

---

## Phase 4: Test File Cleanup (Optional)

### Prompt 4.1: Clean Up Test File ESLint Violations
```
Fix ESLint violations in test files that don't compromise test functionality. Focus on:
1. Unused imports in test files
2. Missing return types in test helper functions
3. Consistent test structure and formatting
4. Remove unused test variables

Maintain test coverage while improving code quality.
```

### Prompt 4.2: Improve Test Security Practices
```
Address security violations in test files where appropriate. Focus on:
1. Replace hardcoded file paths with proper test fixtures
2. Use mock data instead of real file system operations
3. Sanitize test inputs and outputs
4. Implement proper test isolation

Balance security with test functionality requirements.
```

---

## Phase 5: Performance & Optimization

### Prompt 5.1: Optimize Bundle Size
```
Analyze and optimize the application bundle size. Focus on:
1. Remove unused dependencies from package.json
2. Implement proper tree shaking for large libraries
3. Use dynamic imports for heavy components
4. Optimize icon imports (use specific imports instead of full libraries)

Improve application loading performance.
```

### Prompt 5.2: Implement Code Splitting
```
Implement strategic code splitting for better performance. Focus on:
1. Route-based code splitting for pages
2. Component-based splitting for heavy components
3. Lazy loading for non-critical features
4. Proper loading states and error boundaries

Improve initial page load times and user experience.
```

---

## Execution Guidelines

### For Each Prompt:
1. **Run ESLint first** to identify current violations
2. **Make targeted fixes** for the specific category
3. **Test functionality** after changes
4. **Run ESLint again** to verify improvements
5. **Commit changes** with descriptive messages

### Priority Order:
1. **Phase 1** - Critical errors that could cause runtime issues
2. **Phase 2** - React/TypeScript improvements for maintainability
3. **Phase 3** - Code quality and standards
4. **Phase 4** - Test file cleanup (optional)
5. **Phase 5** - Performance optimizations

### Success Metrics:
- **ESLint error count reduction**
- **No new runtime errors introduced**
- **Maintained test coverage**
- **Improved TypeScript strict mode compliance**
- **Better performance metrics**

---

## Final Verification

### Prompt: Final ESLint Cleanup Verification
```
Run a comprehensive ESLint check and create a final report showing:
1. Total violations remaining by category
2. Files with the most violations
3. Comparison with initial violation count
4. Recommendations for any remaining issues

Ensure the codebase meets production quality standards.
```

---

## Specific File Targets

### High-Priority Files (Most Violations)
Based on current ESLint output, focus on these files first:

#### API Routes:
- `src/app/api/upload/route.ts` - Security violations, unused variables
- `src/app/api/security/route.ts` - Unused functions, any types
- `src/app/api/security/monitoring/route.ts` - Any types, missing return types

#### View Components:
- `src/view/components/ApiConfigurationPage.tsx` - Security violations, unused variables
- `src/view/SettingsPanel.tsx` - Security violations, unused imports
- `src/view/UserExperienceProvider.tsx` - Security violations, any types
- `src/view/components/ResultsTable.tsx` - Non-null assertions, any types

#### Controllers:
- `src/controller/useScraperController.ts` - Security violations, hook dependencies
- `src/controller/ConfigContext.tsx` - Missing return types, unused variables

#### Library Files:
- `src/lib/advancedRateLimit.ts` - Security violations
- `src/hooks/useCSRFProtection.ts` - Any types, missing return types

### Test Files (Lower Priority):
- `src/__tests__/lib/config-validator.test.ts` - Multiple require() imports
- `src/__tests__/lib/cache.test.ts` - Require() imports
- `src/__tests__/model/clientSearchEngine.test.ts` - Any types, require() imports

---

## ESLint Configuration Improvements

### Prompt: Optimize ESLint Configuration
```
Review and optimize the ESLint configuration to:
1. Add more specific rules for React hooks
2. Configure proper TypeScript strict mode rules
3. Add security-focused rules for production code
4. Set up different rule sets for test vs production files
5. Configure auto-fix rules for consistent formatting

Update .eslintrc.json with improved rule configuration.
```

---

## Automation Scripts

### Prompt: Create ESLint Automation Scripts
```
Create npm scripts and automation tools for ESLint management:
1. Script to run ESLint with different configurations for prod vs test files
2. Pre-commit hook to prevent commits with ESLint errors
3. CI/CD integration script for ESLint checking
4. Script to generate ESLint violation reports
5. Auto-fix script for safe violations

Add these to package.json and document usage.
```

---

## Documentation Updates

### Prompt: Update Development Documentation
```
Update development documentation to reflect ESLint improvements:
1. Update README.md with ESLint setup and usage
2. Create CONTRIBUTING.md with code quality guidelines
3. Document ESLint rules and exceptions
4. Add code review checklist including ESLint compliance
5. Create troubleshooting guide for common ESLint issues

Ensure new developers can maintain code quality standards.
```

---

## Monitoring & Maintenance

### Prompt: Set Up Code Quality Monitoring
```
Implement ongoing code quality monitoring:
1. Set up automated ESLint reporting in CI/CD
2. Create dashboard for tracking code quality metrics
3. Implement alerts for regression in code quality
4. Set up periodic code quality reviews
5. Create metrics for tracking improvement over time

Ensure sustained code quality improvements.
```
