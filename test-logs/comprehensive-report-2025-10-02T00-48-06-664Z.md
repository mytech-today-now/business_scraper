# Comprehensive Test Report

## Executive Summary
- **Overall Status**: PASSED
- **Total Tests**: 20
- **Success Rate**: 95.00%
- **Critical Issues**: 0
- **Quality Gate**: PASSED

## Test Results
### Failed Tests
- **should not expose internal configuration in scraping API**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoHaveProperty[2m([22m[32mpath[39m[2m)[22m

Expected path: not [32m"query"[39m

Received value: [31m"sensitive search query"[39m
    at Object.toHaveProperty (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\sensitive-data-exposure.test.ts:361:60)
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
- **Average Duration**: 17680.00ms
- **Memory Peak**: 86.50MB

## Recommendations


---
*Generated at 2025-10-02T00:48:06.663Z by EnhancedTestLogger*