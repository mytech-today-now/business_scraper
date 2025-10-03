# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 20
- **Success Rate**: 85.00%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should log errors securely without sensitive data**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"abc123"[39m
Received string:        [31m"{\"errorId\":\"err_mga844op_i7pvtx\",\"endpoint\":\"/api/secure\",\"method\":\"POST\",\"ip\":\"192.168.1.xxx\",\"userAgent\":\"Mozilla/5.0\",\"sessionId\":\"sess_123\",\"userId\":\"user_456\",\"error\":{\"name\":\"Error\",\"message\":\"API key [7mabc123[27m is invalid\"},\"timestamp\":\"2025-10-03T02:26:58.873Z\",\"classification\":\"internal\"}"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\error-handling\secure-error-handling.comprehensive.test.ts:115:27)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should generate unique error IDs for tracking**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoMatch[2m([22m[32mexpected[39m[2m)[22m

Expected pattern: [32m/^err_\d+_[a-z0-9]+$/[39m
Received string:  [31m"err_mga844sf_g7rbb2"[39m
    at Object.toMatch (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\error-handling\secure-error-handling.comprehensive.test.ts:422:29)
- **should provide error recovery suggestions**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeDefined[2m()[22m

Received: [31mundefined[39m
    at Object.toBeDefined (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\error-handling\secure-error-handling.comprehensive.test.ts:442:29)

## Performance Analysis
- **Average Duration**: 17840.00ms
- **Memory Peak**: 87.96MB

## Recommendations


---
*Generated at 2025-10-03T02:26:59.129Z by EnhancedTestLogger*