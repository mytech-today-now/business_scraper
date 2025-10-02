# Comprehensive Test Report

## Executive Summary
- **Overall Status**: PASSED
- **Total Tests**: 20
- **Success Rate**: 95.00%
- **Critical Issues**: 0
- **Quality Gate**: PASSED

## Test Results
### Failed Tests
- **should not expose internal configuration in scraping API**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"sensitive_config"[39m
Received string:        [31m"{\"status\":\"operational\",\"capabilities\":{\"actions\":[\"search\",\"scrape\"],\"maxDepth\":10,\"maxPages\":50,\"internalConfig\":\"[7msensitive_config[27m\",\"databaseUrl\":\"postgresql://localhost:5432/db\"},\"recentSessions\":[{\"id\":\"session_123\",\"query\":\"sensitive search query\",\"url\":\"https://example.com\",\"status\":\"completed\"}]}"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\sensitive-data-exposure.test.ts:350:34)
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
- **Average Duration**: 15900.00ms
- **Memory Peak**: 85.42MB

## Recommendations


---
*Generated at 2025-10-02T00:47:32.480Z by EnhancedTestLogger*