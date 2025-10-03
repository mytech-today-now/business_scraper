# Comprehensive Test Report

## Executive Summary
- **Overall Status**: WARNING
- **Total Tests**: 20
- **Success Rate**: 0.00%
- **Critical Issues**: 0
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should render desktop navigation when not mobile**: Error: Element type is invalid: expected a string (for built-in components) or a class/function (for composite components) but got: object.

Check the render method of `MobileNavigation`.
    at createFiberFromTypeAndProps (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:28478:17)
    at createFiberFromElement (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:28504:15)
    at createChild (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:13345:28)
    at reconcileChildrenArray (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:13640:25)
    at reconcileChildFibers (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:14057:16)
    at reconcileChildren (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:19186:28)
    at updateHostComponent (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:19953:3)
    at beginWork (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:21657:14)
    at beginWork$1 (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:27465:14)
    at performUnitOfWork (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:26599:12)
    at workLoopSync (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:26505:5)
    at renderRootSync (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:26473:7)
    at recoverFromConcurrentError (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:25889:20)
    at performConcurrentWorkOnRoot (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react-dom\cjs\react-dom.development.js:25789:22)
    at flushActQueue (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2667:24)
    at act (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\react\cjs\react.development.js:2582:11)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\act-compat.js:47:25
    at renderRoot (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\pure.js:180:26)
    at render (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\dist\pure.js:271:10)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\components\MobileNavigation.test.tsx:40:13)
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
- **Average Duration**: 26280.00ms
- **Memory Peak**: 107.38MB

## Recommendations


---
*Generated at 2025-10-02T20:04:04.976Z by EnhancedTestLogger*