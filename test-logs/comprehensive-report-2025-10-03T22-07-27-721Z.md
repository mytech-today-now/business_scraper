# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 19
- **Success Rate**: 63.16%
- **Critical Issues**: 1
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should not expose session IDs in any response**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"[SESSION_ACTIVE]"[39m
Received: [31mundefined[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:234:38)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should use secure session creation**: ReferenceError: response is not defined
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:265:28)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize sensitive data in logs**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mStringContaining "password=secret123"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:357:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle password verification failures securely**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:489:45)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should set secure cookie attributes**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mObjectContaining {"sessionId": "[SESSION_CREATED]", "success": true}[39m, [32m200[39m, [32mObjectContaining {"context": "Auth Login Success", "sanitizeSession": true}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:563:43)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should log all authentication events securely**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"login_failure"[39m, [32mObjectContaining {"reason": "invalid_credentials", "userAgent": "Malicious-Bot/1.0", "username": "admin"}[39m, [32m"192.168.1.100"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:595:36)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should sanitize audit logs to prevent log injection**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"login_failure"[39m, [32mObjectContaining {"userAgent": "Bot/1.0 [FAKE] Successful admin login"}[39m, [32m"192.168.1.100"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:625:36)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

## Performance Analysis
- **Average Duration**: 16910.00ms
- **Memory Peak**: 93.29MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
1 critical test failures require immediate attention
- Fix should use secure session creation: ReferenceError: response is not defined
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\security\auth-security-comprehensive.test.ts:265:28)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)

---
*Generated at 2025-10-03T22:07:27.721Z by EnhancedTestLogger*