# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 8
- **Success Rate**: 12.50%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should never expose password hashes in user list**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:99:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should mask PII data in production**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:131:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize error responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"Database error"[39m
Received string:        [31m"[7mDatabase error[27m: [REDACTED]"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:158:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should remove total_count from individual user objects**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:173:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should never expose password data in user creation response**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m201[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:202:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize user creation error responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"database_url=postgresql://user:pass@localhost"[39m
Received string:        [31m"User creation failed: [7mdatabase_url=postgresql://user:pass@localhost[27m"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:263:30)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle all authentication field variations**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m201[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:322:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 6856.00ms
- **Memory Peak**: 81.35MB

## Recommendations


---
*Generated at 2025-10-02T02:07:20.754Z by EnhancedTestLogger*