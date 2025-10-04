# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 19
- **Success Rate**: 52.63%
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
- **should handle password verification securely**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"correct-password"[39m, [32m"hashed-password"[39m, [32m"salt"[39m
Received: [2m"correct-password"[22m, [31m"50ea037a8c1f7365ce632efae5ff87e53010d9dbfa756c785cd33573994f7095fa07d4006dee2bb281aa727f7455f0c48d9e1d87c6262dd5bcc5b03004c8168c"[39m, [31m"5acf2b02b38f79fe378864ea702d1fa6"[39m

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:465:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle password verification failures securely**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:488:31)
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
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:595:45)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize audit logs to prevent log injection**: TypeError: value is invalid
    at assertValue (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:20:11)
    at HeadersImpl.append (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:71:5)
    at HeadersImpl._fill (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:49:14)
    at new HeadersImpl (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:35:12)
    at Object.exports.setup (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\generated\Headers.js:67:12)
    at new Headers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\generated\Headers.js:182:22)
    at new MockNextRequest (Q:\_kyle\temp_documents\GitHub\business_scraper\jest.setup.js:303:20)
    at new NextRequest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\next\src\server\web\spec-extension\request.ts:29:10)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:610:23)
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
- **Average Duration**: 17936.00ms
- **Memory Peak**: 103.35MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
1 critical test failures require immediate attention
- Fix should sanitize audit logs to prevent log injection: TypeError: value is invalid
    at assertValue (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:20:11)
    at HeadersImpl.append (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:71:5)
    at HeadersImpl._fill (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:49:14)
    at new HeadersImpl (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\fetch\Headers-impl.js:35:12)
    at Object.exports.setup (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\generated\Headers.js:67:12)
    at new Headers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\living\generated\Headers.js:182:22)
    at new MockNextRequest (Q:\_kyle\temp_documents\GitHub\business_scraper\jest.setup.js:303:20)
    at new NextRequest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\next\src\server\web\spec-extension\request.ts:29:10)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:610:23)
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
*Generated at 2025-10-03T21:54:10.266Z by EnhancedTestLogger*