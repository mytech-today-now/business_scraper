# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 229
- **Success Rate**: 64.19%
- **Critical Issues**: 45
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should fetch CSRF token from /api/csrf successfully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:81:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should fallback to /api/auth when /api/csrf fails**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:118:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should retry with exponential backoff on failures**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"retry-success-token"[39m
Received: [31mnull[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:164:40)
- **should handle maximum retry attempts**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: [32m"Failed to fetch CSRF token"[39m
Received string:    [31m"No CSRF token in response (after 4 attempts)"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:188:36)
- **should refresh token manually**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:221:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should validate token expiration**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:254:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should provide proper headers for requests**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:277:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should provide CSRF input for forms**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:307:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should validate form before submission**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:336:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should submit form with CSRF protection**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:369:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle form submission with object data**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:412:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle network errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:439:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle malformed JSON responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:460:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle missing CSRF token in response**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:479:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle server errors with proper status codes**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:498:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should prevent token theft through XSS**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:521:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle concurrent token refresh requests**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:545:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should rate limit token refresh requests**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:576:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle high-frequency token validation**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:609:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle memory efficiently with large tokens**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:644:42)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle multiple hook instances efficiently**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mfalse[39m
Received: [31mtrue[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
    [36m<div />[39m
    [36m<div />[39m
    [36m<div />[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:672:56)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:46:7
    at new Promise (<anonymous>)
    at waitFor (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:36:10)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:164:54
    at Object.asyncWrapper (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\pure.js:88:28)
    at waitForWrapper (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:164:35)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:672:16
    at Array.map (<anonymous>)
    at Object.map (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:671:31)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle extremely long token values**: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:702:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle null and undefined values gracefully**: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:725:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle token expiration edge cases**: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:751:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should handle browser storage limitations**: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:821:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should meet OWASP CSRF protection standards**: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:850:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should implement proper token rotation**: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:893:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should maintain audit trail for security events**: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:927:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- **should allow access with valid session**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject request without authorization header**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject request with invalid token format**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject request with expired session**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle session validation errors**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should validate CSRF token for state-changing requests**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject POST request without CSRF token**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should skip CSRF validation for GET requests**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should allow requests within rate limit**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject requests exceeding rate limit**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should block requests from suspicious sources**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should allow requests from trusted sources**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should refresh session when near expiration**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle session refresh failures**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle malformed JWT tokens**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle concurrent authentication requests**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledTimes[2m([22m[32mexpected[39m[2m)[22m

Expected number of calls: [32m10[39m
Received number of calls: [31m0[39m
    at Object.toHaveBeenCalledTimes (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:623:27)
- **should handle missing IP address**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle network timeouts during session validation**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle memory pressure during authentication**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should validate authorization header format variations**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle special characters in tokens**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle extremely long tokens**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle case-sensitive header validation**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should cache session validation results**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle high-frequency authentication requests**: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should authenticate valid user credentials**: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:253:21)
- **should generate MFA secret successfully**: Error: Failed to generate MFA secret
    at generateMFASecret (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\auth.ts:377:11)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:328:45)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should verify MFA through authentication flow**: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:375:21)
- **should handle authentication without MFA**: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:427:21)
- **should enable MFA for user with valid code**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:442:22)
- **should disable MFA for user**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:450:22)
- **should enforce password security requirements**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"password123"[39m, [32m"weak-hash"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:475:34)
- **should handle GDPR compliance flags**: TypeError: Cannot read properties of null (reading 'complianceFlags')
    at Object.complianceFlags (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:501:21)
- **should update last login timestamp**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mStringContaining "UPDATE users SET last_login = NOW()"[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:529:28)
- **should handle authentication with MFA requirement**: TypeError: Cannot read properties of null (reading 'mfaEnabled')
    at Object.mfaEnabled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:558:21)
- **should handle concurrent authentication requests**: TypeError: Cannot read properties of null (reading 'id')
    at id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:614:23)
    at Array.forEach (<anonymous>)
    at Object.forEach (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:612:15)
- **should allow authenticated requests with valid session**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:135:27)
- **should enforce role-based access control**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m403[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:180:31)
- **should enforce permission-based access control**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalled[2m()[22m

Expected number of calls: >= [32m1[39m
Received number of calls:    [31m0[39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:199:27)
- **should block suspicious activity**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m429[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:213:31)
- **should require JWT when configured**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m401[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:248:31)
- **should enforce strict IP binding when configured**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m401[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:268:31)
- **should handle authentication errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:280:31)
- **optionalAuth should return authenticated context when available**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:358:41)
- **isAuthenticated should return true for valid session**: TypeError: Cannot read properties of undefined (reading 'isValid')
    at isValid (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\auth-middleware.ts:301:38)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:380:37)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **validateAndRefreshSession should refresh near-expiry session**: TypeError: {(intermediate value)(intermediate value)} is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:433:7)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **validateAndRefreshSession should handle renewal failure gracefully**: TypeError: {(intermediate value)(intermediate value)} is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:466:7)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should validate IP address binding**: TypeError: Cannot read properties of null (reading 'ipValidated')
    at Object.ipValidated (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:513:27)
- **should detect and block suspicious activity patterns**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m429[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:549:31)
- **should handle device fingerprint validation**: TypeError: Cannot read properties of null (reading 'deviceValidated')
    at Object.deviceValidated (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:580:27)
- **should handle memory efficiently with large session data**: TypeError: {(intermediate value)(intermediate value)} is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:661:7)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle malformed session cookies**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m401[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:694:31)
- **should handle extremely long session IDs**: TypeError: "x".repeat(...) is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:699:40)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should maintain session security flags for compliance**: TypeError: Cannot read properties of null (reading 'securityFlags')
    at Object.securityFlags (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:825:27)

## Performance Analysis
- **Average Duration**: 317831.00ms
- **Memory Peak**: 144.86MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
45 critical test failures require immediate attention
- Fix should handle extremely long token values: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:702:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- Fix should handle null and undefined values gracefully: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:725:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- Fix should handle token expiration edge cases: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:751:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- Fix should handle browser storage limitations: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:821:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- Fix should meet OWASP CSRF protection standards: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:850:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- Fix should implement proper token rotation: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:893:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- Fix should maintain audit trail for security events: TypeError: Cannot read properties of null (reading 'isLoading')

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at isLoading (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\hooks\useCSRFProtection.comprehensive.test.ts:927:31)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:82:9
- Fix should allow access with valid session: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject request without authorization header: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject request with invalid token format: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject request with expired session: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle session validation errors: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should validate CSRF token for state-changing requests: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject POST request without CSRF token: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should skip CSRF validation for GET requests: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should allow requests within rate limit: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject requests exceeding rate limit: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should block requests from suspicious sources: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should allow requests from trusted sources: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should refresh session when near expiration: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle session refresh failures: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle malformed JWT tokens: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle missing IP address: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle network timeouts during session validation: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle memory pressure during authentication: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should validate authorization header format variations: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle special characters in tokens: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle extremely long tokens: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle case-sensitive header validation: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should cache session validation results: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle high-frequency authentication requests: TypeError: _authratelimiter.authRateLimiter.checkRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\middleware\auth-middleware.comprehensive.test.ts:106:52)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should authenticate valid user credentials: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:253:21)
- Fix should verify MFA through authentication flow: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:375:21)
- Fix should handle authentication without MFA: TypeError: Cannot read properties of null (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:427:21)
- Fix should handle GDPR compliance flags: TypeError: Cannot read properties of null (reading 'complianceFlags')
    at Object.complianceFlags (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:501:21)
- Fix should handle authentication with MFA requirement: TypeError: Cannot read properties of null (reading 'mfaEnabled')
    at Object.mfaEnabled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:558:21)
- Fix should handle concurrent authentication requests: TypeError: Cannot read properties of null (reading 'id')
    at id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:614:23)
    at Array.forEach (<anonymous>)
    at Object.forEach (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth.comprehensive.test.ts:612:15)
- Fix isAuthenticated should return true for valid session: TypeError: Cannot read properties of undefined (reading 'isValid')
    at isValid (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\auth-middleware.ts:301:38)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:380:37)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix validateAndRefreshSession should refresh near-expiry session: TypeError: {(intermediate value)(intermediate value)} is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:433:7)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix validateAndRefreshSession should handle renewal failure gracefully: TypeError: {(intermediate value)(intermediate value)} is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:466:7)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should validate IP address binding: TypeError: Cannot read properties of null (reading 'ipValidated')
    at Object.ipValidated (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:513:27)
- Fix should handle device fingerprint validation: TypeError: Cannot read properties of null (reading 'deviceValidated')
    at Object.deviceValidated (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:580:27)
- Fix should handle memory efficiently with large session data: TypeError: {(intermediate value)(intermediate value)} is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:661:7)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle extremely long session IDs: TypeError: "x".repeat(...) is not a function
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:699:40)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should maintain session security flags for compliance: TypeError: Cannot read properties of null (reading 'securityFlags')
    at Object.securityFlags (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\auth-middleware.comprehensive.test.ts:825:27)

---
*Generated at 2025-10-03T22:37:44.181Z by EnhancedTestLogger*