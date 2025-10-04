# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 37
- **Success Rate**: 94.59%
- **Critical Issues**: 0
- **Quality Gate**: WARNING

## Test Results
### Failed Tests
- **should handle subscription cancellation**: Error: No active subscription to cancel
    at PaymentController.cancelSubscription (Q:\_kyle\temp_documents\GitHub\business_scraper\src\controller\paymentController.ts:173:13)
    at Object.cancelSubscription (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\controller\paymentController.working.test.ts:127:31)
- **should handle errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\controller\paymentController.working.test.ts:241:29)

## Performance Analysis
- **Average Duration**: 16843.00ms
- **Memory Peak**: 103.02MB

## Recommendations


---
*Generated at 2025-10-03T23:30:25.675Z by EnhancedTestLogger*