# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 2671
- **Success Rate**: 0.56%
- **Critical Issues**: 6
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should retry on immediate connection failure**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThanOrEqual[2m([22m[32mexpected[39m[2m)[22m

Expected: >= [32m2[39m
Received:    [31m1[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBeGreaterThanOrEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:160:56)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should fallback to batch search when enabled**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"completed"[39m
Received: [31m"error"[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:182:48)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should handle connection failure after opening**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:208:54)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processTimers (node:internal/timers:520:9)
- **should perform health check before retrying**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"/api/health"[39m, [32mAny<Object>[39m

Number of calls: [31m0[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:228:27)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should fallback when health check fails**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"completed"[39m
Received: [31m"error"[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:251:48)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should open circuit breaker after multiple failures**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThanOrEqual[2m([22m[32mexpected[39m[2m)[22m

Expected: >= [32m5[39m
Received:    [31m0[39m
    at Object.toBeGreaterThanOrEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:281:54)
- **should handle offline scenarios**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: [32m"Network connection lost"[39m
Received string:    [31m"Unable to create streaming connection - pool exhausted"[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:305:38)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should recover from temporary connection issues**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.connection-error.test.ts:356:44)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should start streaming successfully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"streaming"[39m
Received: [31m"completed"[39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div />[39m
  [36m</body>[39m
[36m</html>[39m
    at toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:112:46)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should handle streaming results**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"Test Restaurant"[39m
Received: [31m"Fallback Business"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:142:44)
- **should handle progress updates**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m1[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:167:48)
- **should handle connection errors and retry**: TypeError: Cannot read properties of undefined (reading 'simulateError')
    at simulateError (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:230:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:229:14)
- **should fallback to batch search after max retries**: TypeError: Cannot read properties of undefined (reading 'simulateError')
    at simulateError (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:269:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:268:14)
- **should handle completion message**: TypeError: Cannot read properties of undefined (reading 'simulateMessage')
    at simulateMessage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:299:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:298:14)
- **should clear results**: TypeError: Cannot read properties of undefined (reading 'simulateMessage')
    at simulateMessage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:319:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:318:14)
- **should not add results when paused**: TypeError: Cannot read properties of undefined (reading 'simulateOpen')
    at simulateOpen (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:350:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:349:14)
- **should handle error messages from stream**: TypeError: Cannot read properties of undefined (reading 'simulateMessage')
    at simulateMessage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:381:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:380:14)
- **should handle EventSource connection errors**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoBeNull[2m()[22m

Received: [31mnull[39m
    at Object.toBeNull (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\regression\useSearchStreamingHook.test.ts:179:40)
- **should implement circuit breaker pattern**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: [32m"circuit breaker"[39m
Received string:    [31m"Batch search failed: 500"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\regression\useSearchStreamingHook.test.ts:204:36)
- **should perform health checks before retrying**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"/api/health"[39m, [32mAny<Object>[39m
Received: [31m"/api/search"[39m, [2m{"body": "{\"provider\":\"comprehensive\",\"query\":\"test query\",\"location\":\"12345\",\"maxResults\":1000}", "headers": {"Content-Type": "application/json"}, "method": "POST"}[22m

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\regression\useSearchStreamingHook.test.ts:215:25)
- **should fallback to batch search when streaming fails**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"fallback"[39m
Received: [31m"error"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\regression\useSearchStreamingHook.test.ts:240:46)
- **should handle streaming completion**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32mtrue[39m
Received: [31mfalse[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\regression\useSearchStreamingHook.test.ts:283:42)

## Performance Analysis
- **Average Duration**: 784686.00ms
- **Memory Peak**: 769.05MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
6 critical test failures require immediate attention
- Fix should handle connection errors and retry: TypeError: Cannot read properties of undefined (reading 'simulateError')
    at simulateError (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:230:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:229:14)
- Fix should fallback to batch search after max retries: TypeError: Cannot read properties of undefined (reading 'simulateError')
    at simulateError (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:269:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:268:14)
- Fix should handle completion message: TypeError: Cannot read properties of undefined (reading 'simulateMessage')
    at simulateMessage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:299:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:298:14)
- Fix should clear results: TypeError: Cannot read properties of undefined (reading 'simulateMessage')
    at simulateMessage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:319:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:318:14)
- Fix should not add results when paused: TypeError: Cannot read properties of undefined (reading 'simulateOpen')
    at simulateOpen (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:350:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:349:14)
- Fix should handle error messages from stream: TypeError: Cannot read properties of undefined (reading 'simulateMessage')
    at simulateMessage (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:381:19)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:48:24
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2512:16)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\hooks\__tests__\useSearchStreaming.test.ts:380:14)

---
*Generated at 2025-09-25T23:22:25.507Z by EnhancedTestLogger*