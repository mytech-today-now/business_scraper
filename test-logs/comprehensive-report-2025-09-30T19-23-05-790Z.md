# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 89
- **Success Rate**: 48.31%
- **Critical Issues**: 28
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
- **should execute all retention policies**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:73:20)
- **should log audit event for retention execution**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:82:7)
- **should execute retention policy successfully**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:117:19)
- **should handle different data types**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:136:21)
- **should process audit logs according to policy**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:180:7)
- **should not delete when autoDelete is false**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:213:7)
- **should return all retention jobs**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- **should filter jobs by policy ID**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- **should filter jobs by status**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- **should filter jobs by date range**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- **should sort jobs by scheduled date (newest first)**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- **should return data archives**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:337:7)
- **should filter archives by data type**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:337:7)
- **should filter archives by date range**: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:337:7)
- **should truncate very long strings**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveLength[2m([22m[32mexpected[39m[2m)[22m

Expected length: [32m1015[39m
Received length: [31m1014[39m
Received string: [31m"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...[TRUNCATED]"[39m
    at Object.toHaveLength (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:262:35)
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
- **should record successful authentication**: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:312:35)
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
- **should record failed authentication**: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:331:35)
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
- **should block IP after multiple failed attempts**: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:350:21)
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
- **should generate authentication statistics**: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:366:19)
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
- **should trigger alerts for critical events**: TypeError: crypto.randomUUID is not a function
    at SecurityAlertManager.randomUUID [as createAlert] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:419:18)
    at SecurityAlertManager.createAlert [as processSecurityEvent] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:221:26)
    at Object.processSecurityEvent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:390:35)
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
- **should respect cooldown periods**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeGreaterThan[2m([22m[32mexpected[39m[2m)[22m

Expected: > [32m0[39m
Received:   [31m0[39m
    at Object.toBeGreaterThan (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:416:34)
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
- **should acknowledge alerts**: TypeError: crypto.randomUUID is not a function
    at SecurityAlertManager.randomUUID [as createAlert] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:419:18)
    at SecurityAlertManager.createAlert [as processSecurityEvent] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:221:26)
    at Object.processSecurityEvent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:423:35)
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
- **should resolve alerts**: TypeError: Cannot read properties of undefined (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:447:33)
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
- **should generate alert statistics**: TypeError: crypto.randomUUID is not a function
    at SecurityAlertManager.randomUUID [as createAlert] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:419:18)
    at SecurityAlertManager.createAlert [as processSecurityEvent] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:221:26)
    at Object.processSecurityEvent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:467:20)
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

## Performance Analysis
- **Average Duration**: 148912.00ms
- **Memory Peak**: 116.91MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
28 critical test failures require immediate attention
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
- Fix should execute all retention policies: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:73:20)
- Fix should log audit event for retention execution: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:82:7)
- Fix should execute retention policy successfully: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:117:19)
- Fix should handle different data types: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:136:21)
- Fix should process audit logs according to policy: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:180:7)
- Fix should not delete when autoDelete is false: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:213:7)
- Fix should return all retention jobs: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- Fix should filter jobs by policy ID: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- Fix should filter jobs by status: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- Fix should filter jobs by date range: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- Fix should sort jobs by scheduled date (newest first): TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:279:7)
- Fix should return data archives: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:337:7)
- Fix should filter archives by data type: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:337:7)
- Fix should filter archives by date range: TypeError: Cannot read properties of undefined (reading 'logs')
    at DataRetentionService.logs [as processAuditLogs] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:225:34)
    at DataRetentionService.executeRetentionPolicy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:177:11)
    at DataRetentionService.executeRetentionPolicies (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\dataRetentionService.ts:124:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\compliance\dataRetention.test.ts:337:7)
- Fix should record successful authentication: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:312:35)
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
- Fix should record failed authentication: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:331:35)
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
- Fix should block IP after multiple failed attempts: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:350:21)
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
- Fix should generate authentication statistics: TypeError: crypto.createHash is not a function
    at AuthenticationMonitor.createHash [as generateDeviceFingerprint] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:419:19)
    at AuthenticationMonitor.generateDeviceFingerprint [as recordAuthAttempt] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\authenticationMonitor.ts:123:31)
    at Object.recordAuthAttempt (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:366:19)
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
- Fix should trigger alerts for critical events: TypeError: crypto.randomUUID is not a function
    at SecurityAlertManager.randomUUID [as createAlert] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:419:18)
    at SecurityAlertManager.createAlert [as processSecurityEvent] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:221:26)
    at Object.processSecurityEvent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:390:35)
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
- Fix should acknowledge alerts: TypeError: crypto.randomUUID is not a function
    at SecurityAlertManager.randomUUID [as createAlert] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:419:18)
    at SecurityAlertManager.createAlert [as processSecurityEvent] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:221:26)
    at Object.processSecurityEvent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:423:35)
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
- Fix should resolve alerts: TypeError: Cannot read properties of undefined (reading 'id')
    at Object.id (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:447:33)
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
- Fix should generate alert statistics: TypeError: crypto.randomUUID is not a function
    at SecurityAlertManager.randomUUID [as createAlert] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:419:18)
    at SecurityAlertManager.createAlert [as processSecurityEvent] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\securityAlerts.ts:221:26)
    at Object.processSecurityEvent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\securityMonitoring.test.ts:467:20)
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

---
*Generated at 2025-09-30T19:23:05.790Z by EnhancedTestLogger*