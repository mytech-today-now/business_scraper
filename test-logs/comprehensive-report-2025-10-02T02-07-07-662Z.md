# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 12
- **Success Rate**: 41.67%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should never expose actual session ID in any environment**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoMatch[2m([22m[32mexpected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a string

Received has value: [31mundefined[39m
    at Object.toMatch (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:65:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should not expose session ID in production environment**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"[SESSION_ACTIVE]"[39m
Received: [31mundefined[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:81:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should not expose session ID in development environment**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoMatch[2m([22m[32mexpected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a string

Received has value: [31mundefined[39m
    at Object.toMatch (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:97:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize error responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"Database connection"[39m
Received string:        [31m"[7mDatabase connection[27m failed: [REDACTED]"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:117:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should never expose actual session ID on successful login**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:138:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should not expose sensitive data in failed login responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m401[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:179:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle logout securely**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:234:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 11988.00ms
- **Memory Peak**: 92.98MB

## Recommendations


---
*Generated at 2025-10-02T02:07:07.662Z by EnhancedTestLogger*