# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 42
- **Success Rate**: 0.00%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should create new session when no session exists**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoEqual[2m([22m[32mexpected[39m[2m) // deep equality[22m

[32m- Expected  - 2[39m
[31m+ Received  + 1[39m

[2m  Object {[22m
[2m    "authenticated": false,[22m
[32m-   "csrfToken": "csrf-token-123",[39m
[32m-   "sessionId": "session-123",[39m
[31m+   "expiresAt": "2025-10-03T02:49:53.111Z",[39m
[2m  }[22m
    at Object.toEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:118:20)

## Performance Analysis
- **Average Duration**: 21832.00ms
- **Memory Peak**: 92.58MB

## Recommendations


---
*Generated at 2025-10-03T01:49:53.502Z by EnhancedTestLogger*