# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 13
- **Success Rate**: 38.46%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should handle configuration validation warnings**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"SecurityTestRunner"[39m, [32m"Configuration validation warnings:"[39m, [32mArrayContaining ["SNYK_TOKEN is required when vulnerability scanning is enabled"][39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:96:31)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should generate comprehensive security metrics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:129:36)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle npm audit results**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeDefined[2m()[22m

Received: [31mundefined[39m
    at Object.toBeDefined (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:162:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle Snyk scan results**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeDefined[2m()[22m

Received: [31mundefined[39m
    at Object.toBeDefined (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:194:26)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle Snyk scan failures gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeDefined[2m()[22m

Received: [31mundefined[39m
    at Object.toBeDefined (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:222:26)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should run all enabled security test categories**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected value: [32m"vulnerability-scanning"[39m
Received set:   [31mSet {"security-headers", "authentication", "input-validation", "compliance"}[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:249:26)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should calculate accurate security metrics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:299:44)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle test execution failures gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\comprehensive-security.test.ts:319:44)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 10946.00ms
- **Memory Peak**: 93.18MB

## Recommendations


---
*Generated at 2025-10-02T18:49:07.147Z by EnhancedTestLogger*