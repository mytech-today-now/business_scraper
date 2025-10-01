# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 12
- **Success Rate**: 83.33%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should perform periodic health checks**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m{"id": "test-connection"}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\connectionManager.test.ts:157:31)
- **should remove unhealthy connections**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m0[39m
Received: [31m1[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\resilience\connectionManager.test.ts:171:39)

## Performance Analysis
- **Average Duration**: 94464.00ms
- **Memory Peak**: 87.57MB

## Recommendations


---
*Generated at 2025-09-26T22:09:19.188Z by EnhancedTestLogger*