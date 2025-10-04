# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 138
- **Success Rate**: 92.03%
- **Critical Issues**: 6
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should authenticate valid user credentials**: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:253:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should generate MFA secret successfully**: Error: Failed to generate MFA secret
    at generateMFASecret (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\auth.ts:377:11)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:328:45)
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
- **should verify MFA through authentication flow**: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:375:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle authentication without MFA**: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:427:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should enable MFA for user with valid code**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:442:22)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should disable MFA for user**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:450:22)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should enforce password security requirements**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"password123"[39m, [32m"weak-hash"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:475:34)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle GDPR compliance flags**: TypeError: Cannot read properties of null (reading 'complianceFlags')
    at Object.complianceFlags (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:501:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should update last login timestamp**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mStringContaining "UPDATE users SET last_login = NOW()"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:529:28)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle authentication with MFA requirement**: TypeError: Cannot read properties of null (reading 'mfaEnabled')
    at Object.mfaEnabled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:558:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle concurrent authentication requests**: TypeError: Cannot read properties of null (reading 'id')
    at id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:614:23)
    at Array.forEach (<anonymous>)
    at Object.forEach (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:612:15)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 242979.00ms
- **Memory Peak**: 111.55MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
6 critical test failures require immediate attention
- Fix should authenticate valid user credentials: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:253:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- Fix should verify MFA through authentication flow: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:375:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- Fix should handle authentication without MFA: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:427:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- Fix should handle GDPR compliance flags: TypeError: Cannot read properties of null (reading 'complianceFlags')
    at Object.complianceFlags (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:501:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- Fix should handle authentication with MFA requirement: TypeError: Cannot read properties of null (reading 'mfaEnabled')
    at Object.mfaEnabled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:558:21)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- Fix should handle concurrent authentication requests: TypeError: Cannot read properties of null (reading 'id')
    at id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:614:23)
    at Array.forEach (<anonymous>)
    at Object.forEach (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:612:15)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

---
*Generated at 2025-10-03T22:35:40.821Z by EnhancedTestLogger*