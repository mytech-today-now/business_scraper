# Comprehensive Test Report

## Executive Summary
- **Overall Status**: PASSED
- **Total Tests**: 20
- **Success Rate**: 95.00%
- **Critical Issues**: 0
- **Quality Gate**: PASSED

## Test Results
### Failed Tests
- **should generate secure MFA secret**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: [32m"Business Scraper App"[39m
Received string:    [31m"otpauth://totp/Business%20Scraper%20App%20(test%40example.com)?secret=HZRECLRUONLWI23ZO5QXIODOO55VAOTLMEYEIYRQKEYT6PRZOR6Q"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\security\authentication-security.test.ts:103:35)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 163800.00ms
- **Memory Peak**: 110.77MB

## Recommendations


---
*Generated at 2025-10-02T10:41:09.506Z by EnhancedTestLogger*