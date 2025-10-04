# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 12
- **Success Rate**: 66.67%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should complete full payment intent creation and confirmation flow**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"user-123"[39m, [32m"test@example.com"[39m, [32m"Test User"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\payment-integration.test.ts:94:64)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should complete full subscription creation flow**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"user-123"[39m, [32m"test@example.com"[39m, [32m"Test User"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\payment-integration.test.ts:200:64)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle subscription cancellation flow**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\payment-integration.test.ts:228:57)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should validate subscription access correctly**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"user-123"[39m, [32m"premium_feature"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\payment-integration.test.ts:252:70)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 93936.00ms
- **Memory Peak**: 95.41MB

## Recommendations


---
*Generated at 2025-10-04T18:16:44.798Z by EnhancedTestLogger*