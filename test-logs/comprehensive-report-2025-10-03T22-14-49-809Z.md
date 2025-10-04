# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 19
- **Success Rate**: 73.68%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should not expose session IDs in any response**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"authenticated": true, "csrfToken": "csrf-token", "sessionId": "[SESSION_ACTIVE]"}[39m, [32m200[39m, [32mObjectContaining {"context": "Auth Session Check", "sanitizeSession": true}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:246:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should use secure session creation**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"csrfToken": "secure-csrf", "sessionId": "[SESSION_CREATED]", "success": true}[39m, [32m200[39m, [32mObjectContaining {"context": "Auth Login Success", "sanitizeSession": true}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:289:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should set secure cookie attributes**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"sessionId": "[SESSION_CREATED]", "success": true}[39m, [32m200[39m, [32mObjectContaining {"context": "Auth Login Success", "sanitizeSession": true}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:611:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should log all authentication events securely**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:653:36)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize audit logs to prevent log injection**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:686:36)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 21280.00ms
- **Memory Peak**: 92.88MB

## Recommendations


---
*Generated at 2025-10-03T22:14:49.809Z by EnhancedTestLogger*