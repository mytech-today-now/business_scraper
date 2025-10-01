# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 40
- **Success Rate**: 87.50%
- **Critical Issues**: 2
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should check connectivity with ping**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

[32m- Expected[39m
[31m+ Received[39m

  [2m"/api/test"[22m,
[2m  Object {[22m
[2m    "cache": "no-cache",[22m
[31m+   "headers": Object {[39m
[31m+     "Cache-Control": "no-cache, no-store, must-revalidate",[39m
[31m+     "Expires": "0",[39m
[31m+     "Pragma": "no-cache",[39m
[31m+   },[39m
[2m    "method": "HEAD",[22m
[32m-   "signal": Any<AbortSignal>,[39m
[31m+   "signal": AbortSignal {},[39m
[2m  }[22m,

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useOfflineSupport.test.ts:115:19)
- **should handle ping failure**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useOfflineSupport.test.ts:133:33)
- **should retry connection with exponential backoff**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledTimes[2m([22m[32mexpected[39m[2m)[22m

Expected number of calls: [32m3[39m
Received number of calls: [31m1[39m
    at Object.toHaveBeenCalledTimes (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useOfflineSupport.test.ts:151:19)
- **should handle periodic connectivity checks**: TypeError: Cannot assign to read only property 'performance' of object '[object Window]'
    at hijackMethod (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@sinonjs\fake-timers\src\fake-timers-src.js:945:32)
    at Object.install (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@sinonjs\fake-timers\src\fake-timers-src.js:1754:17)
    at FakeTimers.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@jest\fake-timers\build\modernFakeTimers.js:118:36)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1980:38)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useOfflineSupport.test.ts:155:10)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should not ping when interval is disabled**: TypeError: Can't install fake timers twice on the same global object.
    at Object.install (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@sinonjs\fake-timers\src\fake-timers-src.js:1663:19)
    at FakeTimers.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@jest\fake-timers\build\modernFakeTimers.js:118:36)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1980:38)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useOfflineSupport.test.ts:173:10)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)

## Performance Analysis
- **Average Duration**: 35615.00ms
- **Memory Peak**: 117.95MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
2 critical test failures require immediate attention
- Fix should handle periodic connectivity checks: TypeError: Cannot assign to read only property 'performance' of object '[object Window]'
    at hijackMethod (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@sinonjs\fake-timers\src\fake-timers-src.js:945:32)
    at Object.install (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@sinonjs\fake-timers\src\fake-timers-src.js:1754:17)
    at FakeTimers.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@jest\fake-timers\build\modernFakeTimers.js:118:36)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1980:38)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useOfflineSupport.test.ts:155:10)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should not ping when interval is disabled: TypeError: Can't install fake timers twice on the same global object.
    at Object.install (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@sinonjs\fake-timers\src\fake-timers-src.js:1663:19)
    at FakeTimers.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@jest\fake-timers\build\modernFakeTimers.js:118:36)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1980:38)
    at Object.useFakeTimers (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useOfflineSupport.test.ts:173:10)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)

---
*Generated at 2025-09-30T14:42:58.933Z by EnhancedTestLogger*