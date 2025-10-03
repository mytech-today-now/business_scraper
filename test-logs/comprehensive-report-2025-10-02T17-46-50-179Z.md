# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 17
- **Success Rate**: 29.41%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should detect browser memory leaks**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at listOnTimeout (node:internal/timers:549:9)
    at processTimers (node:internal/timers:523:7)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:70:22)
- **should properly cleanup pages with event listeners**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:140:20)
- **should cleanup browser instances with all resources**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:161:20)
- **should handle browser disconnect gracefully**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:178:20)
- **should update memory statistics periodically**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:224:20)
- **should handle concurrent page requests without memory leaks**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at listOnTimeout (node:internal/timers:549:9)
    at processTimers (node:internal/timers:523:7)
    at async Promise.all (index 1)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:245:21)
- **should maintain stable memory usage over time**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:262:22)
- **should cleanup resources even when errors occur**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:287:20)
- **should handle browser crash gracefully**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:303:20)
- **should handle timeout scenarios with proper cleanup**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:318:20)
- **should maintain stability over extended periods**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:346:22)
- **should provide accurate memory statistics via API**: Error: No available pages in browser pool. Stats: {"browsers":3,"availablePages":0,"activePages":0,"totalPages":0,"isShuttingDown":false}
    at BrowserPool.getPage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\browserPool.ts:266:13)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\memory\browser-pool-memory-leak.test.ts:400:20)

## Performance Analysis
- **Average Duration**: 177531.00ms
- **Memory Peak**: 98.73MB

## Recommendations


---
*Generated at 2025-10-02T17:46:50.179Z by EnhancedTestLogger*