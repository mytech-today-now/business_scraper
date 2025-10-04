# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 6
- **Success Rate**: 66.67%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should create payment intent with proper validation**: PaymentError: Failed to create payment intent
    at StripeService.createPaymentIntent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\model\stripeService.ts:197:13)
    at Object.createPaymentIntent (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\critical\payment-processing.test.ts:45:49)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle payment failures gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mrejects[2m.[22mtoThrow[2m([22m[32mexpected[39m[2m)[22m

Expected substring: [32m"Your card was declined."[39m
Received message:   [31m"Failed to create payment intent"[39m

    [0m [90m 195 |[39m     } [36mcatch[39m (error) {
     [90m 196 |[39m       logger[33m.[39merror([32m'StripeService'[39m[33m,[39m [32m'Failed to create payment intent'[39m[33m,[39m error)
    [31m[1m>[22m[39m[90m 197 |[39m       [36mthrow[39m [36mnew[39m [33mPaymentError[39m(
     [90m     |[39m             [31m[1m^[22m[39m
     [90m 198 |[39m         [32m'Failed to create payment intent'[39m[33m,[39m
     [90m 199 |[39m         [32m'PAYMENT_INTENT_CREATION_FAILED'[39m[33m,[39m
     [90m 200 |[39m         error [36mas[39m [33mStripe[39m[33m.[39m[33mStripeRawError[39m[0m

      [2mat StripeService.createPaymentIntent ([22msrc/model/stripeService.ts[2m:197:13)[22m
      [2mat Object.createPaymentIntent ([22msrc/__tests__/critical/payment-processing.test.ts[2m:73:23)[22m
    at Object.toThrow (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\expect\build\index.js:218:22)
    at Object.toThrow (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\critical\payment-processing.test.ts:74:17)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
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
- **Average Duration**: 4404.00ms
- **Memory Peak**: 86.03MB

## Recommendations


---
*Generated at 2025-10-03T21:33:52.813Z by EnhancedTestLogger*