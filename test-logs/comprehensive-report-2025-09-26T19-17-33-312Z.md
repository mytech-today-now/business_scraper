# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 12
- **Success Rate**: 66.67%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should handle 401 errors gracefully without flashing**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\csrf-token-fix-validation.test.ts:78:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should refresh token when near expiration**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"[7mrefreshed[27m-token"[39m
Received: [31m"[7mexpiring[27m-token"[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\csrf-token-fix-validation.test.ts:172:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should not show 401 errors as user-facing errors**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\csrf-token-fix-validation.test.ts:259:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should show meaningful errors for non-401 failures**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: [32m"Network error"[39m
Received string:    [31m"Cannot read properties of undefined (reading 'ok') (after 4 attempts)"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\csrf-token-fix-validation.test.ts:280:36)

## Performance Analysis
- **Average Duration**: 167148.00ms
- **Memory Peak**: 109.88MB

## Recommendations


---
*Generated at 2025-09-26T19:17:33.312Z by EnhancedTestLogger*