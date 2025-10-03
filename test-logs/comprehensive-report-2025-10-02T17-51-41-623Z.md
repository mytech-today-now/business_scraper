# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 41
- **Success Rate**: 56.10%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should handle 50 concurrent page requests**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0.8[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\performance\browser-pool-load.test.ts:84:47)
- **should handle rapid page creation and destruction**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0.9[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\performance\browser-pool-load.test.ts:122:41)
- **should maintain performance under sustained load**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m50[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\performance\browser-pool-load.test.ts:167:30)
- **should handle memory-intensive operations without leaks**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\performance\browser-pool-load.test.ts:183:22)
- **should recover from memory pressure**: Error: No available pages in browser pool. Stats: {"browsers":4,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\performance\browser-pool-load.test.ts:279:25)
- **should handle timeout scenarios gracefully**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\performance\browser-pool-load.test.ts:332:22)
- **should detect browser memory leaks**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:70:22)
- **should properly cleanup pages with event listeners**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:140:20)
- **should cleanup browser instances with all resources**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:161:20)
- **should handle browser disconnect gracefully**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:178:20)
- **should update memory statistics periodically**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:224:20)
- **should handle concurrent page requests without memory leaks**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at listOnTimeout (node:internal/timers:549:9)
    at processTimers (node:internal/timers:523:7)
    at async Promise.all (index 1)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:245:21)
- **should maintain stable memory usage over time**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:262:22)
- **should cleanup resources even when errors occur**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:287:20)
- **should handle browser crash gracefully**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:303:20)
- **should handle timeout scenarios with proper cleanup**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:318:20)
- **should maintain stability over extended periods**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:346:22)
- **should provide accurate memory statistics via API**: Error: No available pages in browser pool. Stats: {"browsers":3,"pages":0,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:270:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:400:20)

## Performance Analysis
- **Average Duration**: 298254.00ms
- **Memory Peak**: 143.63MB

## Recommendations


---
*Generated at 2025-10-02T17:51:41.623Z by EnhancedTestLogger*