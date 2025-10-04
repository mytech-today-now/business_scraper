# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 14
- **Success Rate**: 64.29%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should return pong response with correct structure**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveProperty[2m([22m[32mpath[39m[2m, [22m[32mvalue[39m[2m)[22m

Expected path: [32m"message"[39m
Received path: [31m[][39m

Expected value: [32m"pong"[39m
Received value: [31m{"responseTime": 0, "server": "business-scraper", "status": "ok", "timestamp": "2025-10-04T21:15:10.101Z"}[39m
    at Object.toHaveProperty (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\ping\ping-api.test.ts:32:20)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should include server information**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a number or bigint

Received has value: [31mundefined[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\ping\ping-api.test.ts:68:34)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle malformed requests gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"pong"[39m
Received: [31mundefined[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\ping\ping-api.test.ts:199:28)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should maintain consistent response format**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveProperty[2m([22m[32mpath[39m[2m, [22m[32mvalue[39m[2m)[22m

Expected path: [32m"message"[39m
Received path: [31m[][39m

Expected value: [32m"pong"[39m
Received value: [31m{"responseTime": 0, "server": "business-scraper", "status": "ok", "timestamp": "2025-10-04T21:15:10.217Z"}[39m
    at toHaveProperty (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\ping\ping-api.test.ts:220:22)
    at Array.forEach (<anonymous>)
    at Object.forEach (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\ping\ping-api.test.ts:219:17)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle different client IPs**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"192.168.1.1"[39m
Received: [31mundefined[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\ping\ping-api.test.ts:265:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 11928.00ms
- **Memory Peak**: 95.45MB

## Recommendations


---
*Generated at 2025-10-04T21:15:10.331Z by EnhancedTestLogger*