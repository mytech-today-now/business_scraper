# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 19
- **Success Rate**: 57.89%
- **Critical Issues**: 1
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should prevent XSS in error messages**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:200:45)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should not expose session IDs in any response**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"sessionId": "[SESSION_ACTIVE]"}[39m, [32m200[39m, [32mAny<Object>[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:226:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should use secure session creation**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"sessionId": "[SESSION_CREATED]"}[39m, [32m200[39m, [32mAny<Object>[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:261:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize sensitive data in logs**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mStringContaining "password=secret123"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:357:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle password verification failures securely**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:489:45)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should set secure cookie attributes**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"sessionId": "[SESSION_CREATED]", "success": true}[39m, [32m200[39m, [32mObjectContaining {"context": "Auth Login Success", "sanitizeSession": true}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:563:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should log all authentication events securely**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a mock or spy function

Received has type:  function
Received has value: [31m[Function logSecurityEvent][39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:595:58)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize audit logs to prevent log injection**: TypeError: value is invalid
    at assertValue (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:20:11)
    at HeadersImpl.set (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:107:5)
    at Headers.set (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\generated\Headers.js:313:34)
    at Object.set (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:612:15)
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

## Performance Analysis
- **Average Duration**: 18430.00ms
- **Memory Peak**: 98.52MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
1 critical test failures require immediate attention
- Fix should sanitize audit logs to prevent log injection: TypeError: value is invalid
    at assertValue (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:20:11)
    at HeadersImpl.set (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:107:5)
    at Headers.set (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\generated\Headers.js:313:34)
    at Object.set (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:612:15)
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

---
*Generated at 2025-10-03T21:56:30.590Z by EnhancedTestLogger*