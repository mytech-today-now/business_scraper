# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 26
- **Success Rate**: 61.54%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should handle health check failures**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"degraded"[39m
Received: [31m"unknown"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:99:31)
- **should retry health checks on failure**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledTimes[2m([22m[32mexpected[39m[2m)[22m

Expected number of calls: [32m3[39m
Received number of calls: [31m2[39m
    at Object.toHaveBeenCalledTimes (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:115:31)
- **should timeout health checks**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"degraded"[39m
Received: [31m"unknown"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:131:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processTimers (node:internal/timers:520:9)
- **should create alerts for unhealthy services**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"un[7mhealthy[27m"[39m
Received: [31m"un[7mknown[27m"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:149:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processTimers (node:internal/timers:520:9)
- **should resolve alerts when service recovers**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:174:31)
- **should create degraded alerts before critical alerts**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"alert": ObjectContaining {"serviceName": "test-service", "severity": "medium"}}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:201:24)
- **should evaluate overall system health**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"degradedCount": 1, "healthyCount": 1, "status": "unhealthy", "totalServices": 3, "unhealthyCount": 1}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:243:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processTimers (node:internal/timers:520:9)
- **should return all alerts including resolved ones**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\healthMonitor.test.ts:318:32)
- **should perform periodic health checks**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m{"id": "test-connection"}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\connectionManager.test.ts:157:31)
- **should remove unhealthy connections**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m0[39m
Received: [31m1[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\connectionManager.test.ts:171:39)

## Performance Analysis
- **Average Duration**: 129980.00ms
- **Memory Peak**: 87.48MB

## Recommendations


---
*Generated at 2025-09-26T22:07:56.146Z by EnhancedTestLogger*