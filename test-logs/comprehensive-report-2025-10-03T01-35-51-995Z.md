# Comprehensive Test Report

## Executive Summary
- **Overall Status**: FAILED
- **Total Tests**: 287
- **Success Rate**: 47.39%
- **Critical Issues**: 26
- **Quality Gate**: FAILED

## Test Results
### Failed Tests
- **should allow navigation to configuration tab**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveLength[2m([22m[32mexpected[39m[2m)[22m

Expected length: [32m4[39m
Received length: [31m2[39m
Received array:  [31m[<button class="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch">Configuration</button>, <h2 class="text-2xl font-bold">Configuration</h2>][39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div>[39m
      [36m<div[39m
        [33mclass[39m=[32m"min-h-screen bg-background"[39m
      [36m>[39m
        [36m<header[39m
          [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center justify-between"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
              [36m>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
                [36m>[39m
                  [36m<img[39m
                    [33malt[39m=[32m"Business Scraper Logo"[39m
                    [33mclass[39m=[32m"object-contain"[39m
                    [33mdata-nimg[39m=[32m"1"[39m
                    [33mdecoding[39m=[32m"async"[39m
                    [33mfetchpriority[39m=[32m"high"[39m
                    [33mheight[39m=[32m"32"[39m
                    [33msizes[39m=[32m"32px"[39m
                    [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                    [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                    [33mstyle[39m=[32m"color: transparent;"[39m
                    [33mwidth[39m=[32m"32"[39m
                  [36m/>[39m
                  [36m<h1[39m
                    [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                  [36m>[39m
                    [0mBusiness Scraper[0m
                  [36m</h1>[39m
                [36m</div>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
                [36m>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mConfiguration[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mScraping[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mAI Insights[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
                      [33mwidth[39m=[32m"24"[39m
                    [36m/>[39m
                    [0mBI Dashboard[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
       ...
    at toHaveLength (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:139:54)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should allow editing configuration fields**: Error: Found a label with the text of: /zip code/i, however no form control was found associated to that label. Make sure you're using the "for" attribute or "aria-labelledby" attribute correctly.

Ignored nodes: comments, script, style
[36m<body>[39m
  [36m<div>[39m
    [36m<div[39m
      [33mclass[39m=[32m"min-h-screen bg-background"[39m
    [36m>[39m
      [36m<header[39m
        [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
      [36m>[39m
        [36m<div[39m
          [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"flex items-center justify-between"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
              [36m>[39m
                [36m<img[39m
                  [33malt[39m=[32m"Business Scraper Logo"[39m
                  [33mclass[39m=[32m"object-contain"[39m
                  [33mdata-nimg[39m=[32m"1"[39m
                  [33mdecoding[39m=[32m"async"[39m
                  [33mfetchpriority[39m=[32m"high"[39m
                  [33mheight[39m=[32m"32"[39m
                  [33msizes[39m=[32m"32px"[39m
                  [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                  [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                  [33mstyle[39m=[32m"color: transparent;"[39m
                  [33mwidth[39m=[32m"32"[39m
                [36m/>[39m
                [36m<h1[39m
                  [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                [36m>[39m
                  [0mBusiness Scraper[0m
                [36m</h1>[39m
              [36m</div>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
              [36m>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [0mConfiguration[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [0mScraping[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [0mAI Insights[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [36m<svg[39m
                    [33maria-hidden[39m=[32m"true"[39m
                    [33maria-label[39m=[32m"Default"[39m
                    [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                    [33mdata-testid[39m=[32m"default-icon"[39m
                    [33mfill[39m=[32m"none"[39m
                    [33mheight[39m=[32m"24"[39m
                    [33mrole[39m=[32m"img"[39m
                    [33mstroke[39m=[32m"currentColor"[39m
                    [33mstroke-linecap[39m=[32m"round"[39m
                    [33mstroke-linejoin[39m=[32m"round"[39m
                    [33mstroke-width[39m=[32m"2"[39m
                    [33mviewBox[39m=[32m"0 0 24 24"[39m
                    [33mwidth[39m=[32m"24"[39m
                  [36m/>[39m
                  [0mBI Dashboard[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [36m<svg[39m
                    [33maria-hidden[39m=[32m"true"[39m
                    [33maria-label[39m=[32m"Default"[39m
                    [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                    [33mdata-testid[39m=[32m"default-icon"[39m
                    [33mfill[39m=[32m"none"[39m
                    [33mheight[39m=[32m"24"[39m
                    [33mrole[39m=[32m"img"[39m
                    [33mstroke[39m=[32m"currentColor"[39m
                    [33mstroke-linecap[39m=[32m"round"[39m
                    [33mstroke-linejoin[39m=[32m"round"[39m
                    [33mstroke-width[39m=[32m"2"[39m
                    [33mviewBox[39m=[32m"0 0 24 24"[39m
                    [33mwidth[39m=[32m"24"[39m
                  [36m/>[39m
                  [0mAnalytics[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inl...
    at waitForWrapper (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:163:27)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:153:20)
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
- **should not show scraping lock banner**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveLength[2m([22m[32mexpected[39m[2m)[22m

Expected length: [32m4[39m
Received length: [31m2[39m
Received array:  [31m[<button class="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch">Configuration</button>, <h2 class="text-2xl font-bold">Configuration</h2>][39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div>[39m
      [36m<div[39m
        [33mclass[39m=[32m"min-h-screen bg-background"[39m
      [36m>[39m
        [36m<header[39m
          [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center justify-between"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
              [36m>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
                [36m>[39m
                  [36m<img[39m
                    [33malt[39m=[32m"Business Scraper Logo"[39m
                    [33mclass[39m=[32m"object-contain"[39m
                    [33mdata-nimg[39m=[32m"1"[39m
                    [33mdecoding[39m=[32m"async"[39m
                    [33mfetchpriority[39m=[32m"high"[39m
                    [33mheight[39m=[32m"32"[39m
                    [33msizes[39m=[32m"32px"[39m
                    [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                    [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                    [33mstyle[39m=[32m"color: transparent;"[39m
                    [33mwidth[39m=[32m"32"[39m
                  [36m/>[39m
                  [36m<h1[39m
                    [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                  [36m>[39m
                    [0mBusiness Scraper[0m
                  [36m</h1>[39m
                [36m</div>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
                [36m>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mConfiguration[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mScraping[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mAI Insights[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
                      [33mwidth[39m=[32m"24"[39m
                    [36m/>[39m
                    [0mBI Dashboard[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
       ...
    at toHaveLength (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:165:54)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should disable navigation to configuration tab**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveLength[2m([22m[32mexpected[39m[2m)[22m

Expected length: [32m4[39m
Received length: [31m2[39m
Received array:  [31m[<button class="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed" disabled="" title="Configuration cannot be changed while scraping is active. Please stop scraping first.">Configuration<span class="ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full">🔒</span></button>, <h2 class="text-2xl font-bold">Configuration</h2>][39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div>[39m
      [36m<div[39m
        [33mclass[39m=[32m"min-h-screen bg-background"[39m
      [36m>[39m
        [36m<header[39m
          [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center justify-between"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
              [36m>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
                [36m>[39m
                  [36m<img[39m
                    [33malt[39m=[32m"Business Scraper Logo"[39m
                    [33mclass[39m=[32m"object-contain"[39m
                    [33mdata-nimg[39m=[32m"1"[39m
                    [33mdecoding[39m=[32m"async"[39m
                    [33mfetchpriority[39m=[32m"high"[39m
                    [33mheight[39m=[32m"32"[39m
                    [33msizes[39m=[32m"32px"[39m
                    [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                    [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                    [33mstyle[39m=[32m"color: transparent;"[39m
                    [33mwidth[39m=[32m"32"[39m
                  [36m/>[39m
                  [36m<h1[39m
                    [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                  [36m>[39m
                    [0mBusiness Scraper[0m
                  [36m</h1>[39m
                [36m</div>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
                [36m>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed"[39m
                    [33mdisabled[39m=[32m""[39m
                    [33mtitle[39m=[32m"Configuration cannot be changed while scraping is active. Please stop scraping first."[39m
                  [36m>[39m
                    [0mConfiguration[0m
                    [36m<span[39m
                      [33mclass[39m=[32m"ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full"[39m
                    [36m>[39m
                      [0m🔒[0m
                    [36m</span>[39m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mScraping[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mAI Insights[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
                      [33mwidth[39m=[32m"24"[39m
                    [36m/>[39m
                    [0mBI Dashboard[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39...
    at toHaveLength (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:189:54)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should show tooltip explaining why configuration is locked**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveLength[2m([22m[32mexpected[39m[2m)[22m

Expected length: [32m4[39m
Received length: [31m2[39m
Received array:  [31m[<button class="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed" disabled="" title="Configuration cannot be changed while scraping is active. Please stop scraping first.">Configuration<span class="ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full">🔒</span></button>, <h2 class="text-2xl font-bold">Configuration</h2>][39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div>[39m
      [36m<div[39m
        [33mclass[39m=[32m"min-h-screen bg-background"[39m
      [36m>[39m
        [36m<header[39m
          [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center justify-between"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
              [36m>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
                [36m>[39m
                  [36m<img[39m
                    [33malt[39m=[32m"Business Scraper Logo"[39m
                    [33mclass[39m=[32m"object-contain"[39m
                    [33mdata-nimg[39m=[32m"1"[39m
                    [33mdecoding[39m=[32m"async"[39m
                    [33mfetchpriority[39m=[32m"high"[39m
                    [33mheight[39m=[32m"32"[39m
                    [33msizes[39m=[32m"32px"[39m
                    [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                    [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                    [33mstyle[39m=[32m"color: transparent;"[39m
                    [33mwidth[39m=[32m"32"[39m
                  [36m/>[39m
                  [36m<h1[39m
                    [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                  [36m>[39m
                    [0mBusiness Scraper[0m
                  [36m</h1>[39m
                [36m</div>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
                [36m>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed"[39m
                    [33mdisabled[39m=[32m""[39m
                    [33mtitle[39m=[32m"Configuration cannot be changed while scraping is active. Please stop scraping first."[39m
                  [36m>[39m
                    [0mConfiguration[0m
                    [36m<span[39m
                      [33mclass[39m=[32m"ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full"[39m
                    [36m>[39m
                      [0m🔒[0m
                    [36m</span>[39m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mScraping[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mAI Insights[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
                      [33mwidth[39m=[32m"24"[39m
                    [36m/>[39m
                    [0mBI Dashboard[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39...
    at toHaveLength (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:214:54)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should disable configuration input fields**: Error: Found a label with the text of: /zip code/i, however no form control was found associated to that label. Make sure you're using the "for" attribute or "aria-labelledby" attribute correctly.

Ignored nodes: comments, script, style
[36m<body>[39m
  [36m<div>[39m
    [36m<div[39m
      [33mclass[39m=[32m"min-h-screen bg-background"[39m
    [36m>[39m
      [36m<header[39m
        [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
      [36m>[39m
        [36m<div[39m
          [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"flex items-center justify-between"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
              [36m>[39m
                [36m<img[39m
                  [33malt[39m=[32m"Business Scraper Logo"[39m
                  [33mclass[39m=[32m"object-contain"[39m
                  [33mdata-nimg[39m=[32m"1"[39m
                  [33mdecoding[39m=[32m"async"[39m
                  [33mfetchpriority[39m=[32m"high"[39m
                  [33mheight[39m=[32m"32"[39m
                  [33msizes[39m=[32m"32px"[39m
                  [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                  [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                  [33mstyle[39m=[32m"color: transparent;"[39m
                  [33mwidth[39m=[32m"32"[39m
                [36m/>[39m
                [36m<h1[39m
                  [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                [36m>[39m
                  [0mBusiness Scraper[0m
                [36m</h1>[39m
              [36m</div>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
              [36m>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed"[39m
                  [33mdisabled[39m=[32m""[39m
                  [33mtitle[39m=[32m"Configuration cannot be changed while scraping is active. Please stop scraping first."[39m
                [36m>[39m
                  [0mConfiguration[0m
                  [36m<span[39m
                    [33mclass[39m=[32m"ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full"[39m
                  [36m>[39m
                    [0m🔒[0m
                  [36m</span>[39m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [0mScraping[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [0mAI Insights[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [36m<svg[39m
                    [33maria-hidden[39m=[32m"true"[39m
                    [33maria-label[39m=[32m"Default"[39m
                    [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                    [33mdata-testid[39m=[32m"default-icon"[39m
                    [33mfill[39m=[32m"none"[39m
                    [33mheight[39m=[32m"24"[39m
                    [33mrole[39m=[32m"img"[39m
                    [33mstroke[39m=[32m"currentColor"[39m
                    [33mstroke-linecap[39m=[32m"round"[39m
                    [33mstroke-linejoin[39m=[32m"round"[39m
                    [33mstroke-width[39m=[32m"2"[39m
                    [33mviewBox[39m=[32m"0 0 24 24"[39m
                    [33mwidth[39m=[32m"24"[39m
                  [36m/>[39m
                  [0mBI Dashboard[0m
                [36m</button>[39m
                [36m<button[39m
                  [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                [36m>[39m
                  [36m<svg[39m
                    [33maria-hidden[39m=[32m"true"[39m
                    [33maria-label[39m=[32m"Default"[39m
                    [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                    [33mdata-testid[39m=[32m"default-icon"[39m
                    [33mfill[39m=[32m"none"[39m
                    [33mheight[39m=[32m"24"[39m
                    [33mrole[39m=[32m"img"[39m
                    [33mstroke[39m=[3...
    at waitForWrapper (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:163:27)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:244:20)
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
- **should allow navigation to scraping tab when scraping is active**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveLength[2m([22m[32mexpected[39m[2m)[22m

Expected length: [32m2[39m
Received length: [31m1[39m
Received array:  [31m[<button class="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch">Scraping</button>][39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div>[39m
      [36m<div[39m
        [33mclass[39m=[32m"min-h-screen bg-background"[39m
      [36m>[39m
        [36m<header[39m
          [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center justify-between"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
              [36m>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
                [36m>[39m
                  [36m<img[39m
                    [33malt[39m=[32m"Business Scraper Logo"[39m
                    [33mclass[39m=[32m"object-contain"[39m
                    [33mdata-nimg[39m=[32m"1"[39m
                    [33mdecoding[39m=[32m"async"[39m
                    [33mfetchpriority[39m=[32m"high"[39m
                    [33mheight[39m=[32m"32"[39m
                    [33msizes[39m=[32m"32px"[39m
                    [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                    [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                    [33mstyle[39m=[32m"color: transparent;"[39m
                    [33mwidth[39m=[32m"32"[39m
                  [36m/>[39m
                  [36m<h1[39m
                    [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                  [36m>[39m
                    [0mBusiness Scraper[0m
                  [36m</h1>[39m
                [36m</div>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
                [36m>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed"[39m
                    [33mdisabled[39m=[32m""[39m
                    [33mtitle[39m=[32m"Configuration cannot be changed while scraping is active. Please stop scraping first."[39m
                  [36m>[39m
                    [0mConfiguration[0m
                    [36m<span[39m
                      [33mclass[39m=[32m"ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full"[39m
                    [36m>[39m
                      [0m🔒[0m
                    [36m</span>[39m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mScraping[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mAI Insights[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
                      [33mwidth[39m=[32m"24"[39m
                    [36m/>[39m
                    [0mBI Dashboard[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39...
    at toHaveLength (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:324:33)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should prevent navigation back to configuration during scraping**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveLength[2m([22m[32mexpected[39m[2m)[22m

Expected length: [32m4[39m
Received length: [31m2[39m
Received array:  [31m[<button class="inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed" disabled="" title="Configuration cannot be changed while scraping is active. Please stop scraping first.">Configuration<span class="ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full">🔒</span></button>, <h2 class="text-2xl font-bold">Configuration</h2>][39m

Ignored nodes: comments, script, style
[36m<html>[39m
  [36m<head />[39m
  [36m<body>[39m
    [36m<div>[39m
      [36m<div[39m
        [33mclass[39m=[32m"min-h-screen bg-background"[39m
      [36m>[39m
        [36m<header[39m
          [33mclass[39m=[32m"border-b bg-card sticky top-0 z-40"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"container mx-auto px-4 py-3 md:py-4"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex items-center justify-between"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-center gap-2 md:gap-4"[39m
              [36m>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-2 md:gap-3"[39m
                [36m>[39m
                  [36m<img[39m
                    [33malt[39m=[32m"Business Scraper Logo"[39m
                    [33mclass[39m=[32m"object-contain"[39m
                    [33mdata-nimg[39m=[32m"1"[39m
                    [33mdecoding[39m=[32m"async"[39m
                    [33mfetchpriority[39m=[32m"high"[39m
                    [33mheight[39m=[32m"32"[39m
                    [33msizes[39m=[32m"32px"[39m
                    [33msrc[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=3840&q=90"[39m
                    [33msrcset[39m=[32m"/_next/image?url=%2Ffavicon.ico&w=16&q=90 16w, /_next/image?url=%2Ffavicon.ico&w=32&q=90 32w, /_next/image?url=%2Ffavicon.ico&w=48&q=90 48w, /_next/image?url=%2Ffavicon.ico&w=64&q=90 64w, /_next/image?url=%2Ffavicon.ico&w=96&q=90 96w, /_next/image?url=%2Ffavicon.ico&w=128&q=90 128w, /_next/image?url=%2Ffavicon.ico&w=256&q=90 256w, /_next/image?url=%2Ffavicon.ico&w=384&q=90 384w, /_next/image?url=%2Ffavicon.ico&w=640&q=90 640w, /_next/image?url=%2Ffavicon.ico&w=750&q=90 750w, /_next/image?url=%2Ffavicon.ico&w=828&q=90 828w, /_next/image?url=%2Ffavicon.ico&w=1080&q=90 1080w, /_next/image?url=%2Ffavicon.ico&w=1200&q=90 1200w, /_next/image?url=%2Ffavicon.ico&w=1920&q=90 1920w, /_next/image?url=%2Ffavicon.ico&w=2048&q=90 2048w, /_next/image?url=%2Ffavicon.ico&w=3840&q=90 3840w"[39m
                    [33mstyle[39m=[32m"color: transparent;"[39m
                    [33mwidth[39m=[32m"32"[39m
                  [36m/>[39m
                  [36m<h1[39m
                    [33mclass[39m=[32m"text-lg md:text-2xl font-bold truncate"[39m
                  [36m>[39m
                    [0mBusiness Scraper[0m
                  [36m</h1>[39m
                [36m</div>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"flex items-center gap-1 bg-muted rounded-lg p-1"[39m
                [36m>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-9 rounded-md px-3 min-h-touch opacity-50 cursor-not-allowed"[39m
                    [33mdisabled[39m=[32m""[39m
                    [33mtitle[39m=[32m"Configuration cannot be changed while scraping is active. Please stop scraping first."[39m
                  [36m>[39m
                    [0mConfiguration[0m
                    [36m<span[39m
                      [33mclass[39m=[32m"ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full"[39m
                    [36m>[39m
                      [0m🔒[0m
                    [36m</span>[39m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mScraping[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [0mAI Insights[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39m=[32m"default-icon"[39m
                      [33mfill[39m=[32m"none"[39m
                      [33mheight[39m=[32m"24"[39m
                      [33mrole[39m=[32m"img"[39m
                      [33mstroke[39m=[32m"currentColor"[39m
                      [33mstroke-linecap[39m=[32m"round"[39m
                      [33mstroke-linejoin[39m=[32m"round"[39m
                      [33mstroke-width[39m=[32m"2"[39m
                      [33mviewBox[39m=[32m"0 0 24 24"[39m
                      [33mwidth[39m=[32m"24"[39m
                    [36m/>[39m
                    [0mBI Dashboard[0m
                  [36m</button>[39m
                  [36m<button[39m
                    [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-9 rounded-md px-3 min-h-touch"[39m
                  [36m>[39m
                    [36m<svg[39m
                      [33maria-hidden[39m=[32m"true"[39m
                      [33maria-label[39m=[32m"Default"[39m
                      [33mclass[39m=[32m"lucide lucide-default h-4 w-4 mr-1"[39m
                      [33mdata-testid[39...
    at toHaveLength (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\view\components\App-scraping-lock.test.tsx:349:54)
    at runWithExpensiveErrorDiagnosticsDisabled (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:47:12)
    at checkCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:124:77)
    at checkRealTimersCallback (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:118:16)
    at Timeout.task [as _onTimeout] (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jsdom\lib\jsdom\browser\Window.js:520:19)
    at listOnTimeout (node:internal/timers:588:17)
    at processTimers (node:internal/timers:523:7)
- **should return paginated users list**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:112:33)
- **should handle search and filtering**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m{"isActive": true, "limit": 20, "page": 1, "role": "admin", "search": "test"}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:139:52)
- **should create a new user**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

[32m- Expected[39m
[31m+ Received[39m

  [2m{"email": "newuser@example.com", "firstName": "New", "lastName": "User", "password": "password123", "username": "newuser"}[22m,
[31m+ ""[39m,

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:182:54)
- **should delete multiple users**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:261:33)
- **should authenticate user successfully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:299:33)
- **should reject invalid credentials**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m401[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:329:33)
- **should register new user successfully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m201[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:372:33)
- **should create a new team**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m201[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:413:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should return dashboard metrics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:447:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle database errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"[7mF[27mailed t[7mo retrieve us[27mers"[39m
Received: [31m"[7mQuery structure validation f[27mailed[7m:[27m t[7mext: Text contains potentially dangerous SQL patt[27mer[7mn[27ms"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:463:26)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should handle missing permissions**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m403[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\tests\multi-user\api-endpoints.test.ts:498:31)
    at processTicksAndRejections (node:internal/process/task_queues:105:5)
- **should show real-time validation for Google Search API key**: TestingLibraryElementError: Unable to find a label with the text of: /Google Search.*API Key/i

Ignored nodes: comments, script, style
[36m<body>[39m
  [36m<div>[39m
    [36m<div[39m
      [33mclass[39m=[32m"fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"[39m
    [36m>[39m
      [36m<div[39m
        [33mclass[39m=[32m"bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"[39m
      [36m>[39m
        [36m<div[39m
          [33mclass[39m=[32m"sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"flex items-center space-x-3"[39m
          [36m>[39m
            [36m<svg[39m
              [33maria-hidden[39m=[32m"true"[39m
              [33maria-label[39m=[32m"Default"[39m
              [33mclass[39m=[32m"lucide lucide-default h-6 w-6 text-blue-600"[39m
              [33mdata-testid[39m=[32m"default-icon"[39m
              [33mfill[39m=[32m"none"[39m
              [33mheight[39m=[32m"24"[39m
              [33mrole[39m=[32m"img"[39m
              [33mstroke[39m=[32m"currentColor"[39m
              [33mstroke-linecap[39m=[32m"round"[39m
              [33mstroke-linejoin[39m=[32m"round"[39m
              [33mstroke-width[39m=[32m"2"[39m
              [33mviewBox[39m=[32m"0 0 24 24"[39m
              [33mwidth[39m=[32m"24"[39m
            [36m/>[39m
            [36m<div>[39m
              [36m<h2[39m
                [33mclass[39m=[32m"text-xl font-semibold"[39m
              [36m>[39m
                [0mAPI Configuration[0m
              [36m</h2>[39m
              [36m<p[39m
                [33mclass[39m=[32m"text-sm text-gray-600"[39m
              [36m>[39m
                [0mSecurely configure your search engine API credentials[0m
              [36m</p>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<button[39m
            [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"[39m
          [36m>[39m
            [0m✕[0m
          [36m</button>[39m
        [36m</div>[39m
        [36m<div[39m
          [33mclass[39m=[32m"p-6 space-y-6"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm border-blue-200 bg-blue-50"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 p-6 pt-6"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-start space-x-3"[39m
              [36m>[39m
                [36m<svg[39m
                  [33maria-hidden[39m=[32m"true"[39m
                  [33maria-label[39m=[32m"Default"[39m
                  [33mclass[39m=[32m"lucide lucide-default h-5 w-5 text-blue-600 mt-1"[39m
                  [33mdata-testid[39m=[32m"default-icon"[39m
                  [33mfill[39m=[32m"none"[39m
                  [33mheight[39m=[32m"24"[39m
                  [33mrole[39m=[32m"img"[39m
                  [33mstroke[39m=[32m"currentColor"[39m
                  [33mstroke-linecap[39m=[32m"round"[39m
                  [33mstroke-linejoin[39m=[32m"round"[39m
                  [33mstroke-width[39m=[32m"2"[39m
                  [33mviewBox[39m=[32m"0 0 24 24"[39m
                  [33mwidth[39m=[32m"24"[39m
                [36m/>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"text-sm"[39m
                [36m>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"font-medium text-blue-800 mb-2"[39m
                  [36m>[39m
                    [0mSecure Local Storage[0m
                  [36m</p>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"text-blue-700"[39m
                  [36m>[39m
                    [0mYour API credentials are encrypted using AES-256 encryption and stored locally in your browser. They never leave your device and are not transmitted to our servers.[0m
                  [36m</p>[39m
                [36m</div>[39m
              [36m</div>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex flex-col space-y-1.5 p-6"[39m
            [36m>[39m
              [36m<h3[39m
                [33mclass[39m=[32m"text-2xl font-semibold leading-none tracking-tight flex items-center space-x-2"[39m
              [36m>[39m
                [36m<span>[39m
                  [0mGoogle APIs[0m
                [36m</span>[39m
              [36m</h3>[39m
            [36m</div>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 space-y-6"[39m
            [36m>[39m
              [36m<div>[39m
                [36m<h4[39m
                  [33mclass[39m=[32m"text-sm font-medium text-gray-900 mb-3"[39m
                [36m>[39m
                  [0mGoogle Custom Search API[0m
                [36m</h4>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"grid grid-cols-1 md:grid-cols-2 gap-4"[39m
                [36m>[39m
                  [36m<div[39m
                    [33mclass[39m=[32m"relative"[39m
                  [36m>[39m
                    [36m<div[39m
                      [33mclass[39m=[32m"space-y-2"[39m
                    [36m>[39m
                      [36m<label[39m
                        [33mclass[39m=[32m"text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"[39m
                        [33mfor[39m=[32m":r0:"[39m
                      [36m>[39m
                        [0mAPI Key[0m
                      [36m</label>[39m
                      [36m<div[39m
                        [33mclass[39m=[32m"relative"[39m
                      [36m>[39m
                        [36m<input[39m
                          [33maria-invalid[39m=[32m"false"[39m
                          [33mclass[39m=[32m"flex h-10 w-full rounded-md border bg-background py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 transition-colors duration-200 px-3 pr-3 border-input focus-visible:ring-ring"[39m
                          [33mid[39m=[32m":r0:"[39m
                          [33mplaceholder[39m=[...
    at Object.getElementError (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:37:19)
    at getAllByLabelText (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\queries\label-text.js:111:38)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\query-helpers.js:52:17
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\query-helpers.js:95:19
    at Object.getByLabelText (Q:\_kyle\temp_documents\GitHub\business_scraper\__tests__\components\ApiConfigurationPage.test.tsx:59:32)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should show real-time validation for Google Search Engine ID**: Error: Unable to find an element with the text: /Google Search Engine ID is required/i. This could be because the text is broken up by multiple elements. In this case, you can provide a function for your text matcher to make your matcher more flexible.

Ignored nodes: comments, script, style
[36m<body>[39m
  [36m<div>[39m
    [36m<div[39m
      [33mclass[39m=[32m"fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"[39m
    [36m>[39m
      [36m<div[39m
        [33mclass[39m=[32m"bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"[39m
      [36m>[39m
        [36m<div[39m
          [33mclass[39m=[32m"sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"flex items-center space-x-3"[39m
          [36m>[39m
            [36m<svg[39m
              [33maria-hidden[39m=[32m"true"[39m
              [33maria-label[39m=[32m"Default"[39m
              [33mclass[39m=[32m"lucide lucide-default h-6 w-6 text-blue-600"[39m
              [33mdata-testid[39m=[32m"default-icon"[39m
              [33mfill[39m=[32m"none"[39m
              [33mheight[39m=[32m"24"[39m
              [33mrole[39m=[32m"img"[39m
              [33mstroke[39m=[32m"currentColor"[39m
              [33mstroke-linecap[39m=[32m"round"[39m
              [33mstroke-linejoin[39m=[32m"round"[39m
              [33mstroke-width[39m=[32m"2"[39m
              [33mviewBox[39m=[32m"0 0 24 24"[39m
              [33mwidth[39m=[32m"24"[39m
            [36m/>[39m
            [36m<div>[39m
              [36m<h2[39m
                [33mclass[39m=[32m"text-xl font-semibold"[39m
              [36m>[39m
                [0mAPI Configuration[0m
              [36m</h2>[39m
              [36m<p[39m
                [33mclass[39m=[32m"text-sm text-gray-600"[39m
              [36m>[39m
                [0mSecurely configure your search engine API credentials[0m
              [36m</p>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<button[39m
            [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"[39m
          [36m>[39m
            [0m✕[0m
          [36m</button>[39m
        [36m</div>[39m
        [36m<div[39m
          [33mclass[39m=[32m"p-6 space-y-6"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm border-blue-200 bg-blue-50"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 p-6 pt-6"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-start space-x-3"[39m
              [36m>[39m
                [36m<svg[39m
                  [33maria-hidden[39m=[32m"true"[39m
                  [33maria-label[39m=[32m"Default"[39m
                  [33mclass[39m=[32m"lucide lucide-default h-5 w-5 text-blue-600 mt-1"[39m
                  [33mdata-testid[39m=[32m"default-icon"[39m
                  [33mfill[39m=[32m"none"[39m
                  [33mheight[39m=[32m"24"[39m
                  [33mrole[39m=[32m"img"[39m
                  [33mstroke[39m=[32m"currentColor"[39m
                  [33mstroke-linecap[39m=[32m"round"[39m
                  [33mstroke-linejoin[39m=[32m"round"[39m
                  [33mstroke-width[39m=[32m"2"[39m
                  [33mviewBox[39m=[32m"0 0 24 24"[39m
                  [33mwidth[39m=[32m"24"[39m
                [36m/>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"text-sm"[39m
                [36m>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"font-medium text-blue-800 mb-2"[39m
                  [36m>[39m
                    [0mSecure Local Storage[0m
                  [36m</p>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"text-blue-700"[39m
                  [36m>[39m
                    [0mYour API credentials are encrypted using AES-256 encryption and stored locally in your browser. They never leave your device and are not transmitted to our servers.[0m
                  [36m</p>[39m
                [36m</div>[39m
              [36m</div>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex flex-col space-y-1.5 p-6"[39m
            [36m>[39m
              [36m<h3[39m
                [33mclass[39m=[32m"text-2xl font-semibold leading-none tracking-tight flex items-center space-x-2"[39m
              [36m>[39m
                [36m<span>[39m
                  [0mGoogle APIs[0m
                [36m</span>[39m
              [36m</h3>[39m
            [36m</div>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 space-y-6"[39m
            [36m>[39m
              [36m<div>[39m
                [36m<h4[39m
                  [33mclass[39m=[32m"text-sm font-medium text-gray-900 mb-3"[39m
                [36m>[39m
                  [0mGoogle Custom Search API[0m
                [36m</h4>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"grid grid-cols-1 md:grid-cols-2 gap-4"[39m
                [36m>[39m
                  [36m<div[39m
                    [33mclass[39m=[32m"relative"[39m
                  [36m>[39m
                    [36m<div[39m
                      [33mclass[39m=[32m"space-y-2"[39m
                    [36m>[39m
                      [36m<label[39m
                        [33mclass[39m=[32m"text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"[39m
                        [33mfor[39m=[32m":r7:"[39m
                      [36m>[39m
                        [0mAPI Key[0m
                      [36m</label>[39m
                      [36m<div[39m
                        [33mclass[39m=[32m"relative"[39m
                      [36m>[39m
                        [36m<input[39m
                          [33maria-invalid[39m=[32m"false"[39m
                          [33mclass[39m=[32m"flex h-10 w-full rounded-md border bg-background py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 transition-colors duration-200 px-3 pr-3 border-input focus-visible:ring-ring"[39m
                          [33mid[39m=[32m":r7:"[39m
                          [33mplaceholder[39m=[...
    at waitForWrapper (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\wait-for.js:163:27)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\__tests__\components\ApiConfigurationPage.test.tsx:101:18)
- **should maintain accessibility attributes**: TestingLibraryElementError: Unable to find a label with the text of: /Google Search.*API Key/i

Ignored nodes: comments, script, style
[36m<body>[39m
  [36m<div>[39m
    [36m<div[39m
      [33mclass[39m=[32m"fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"[39m
    [36m>[39m
      [36m<div[39m
        [33mclass[39m=[32m"bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"[39m
      [36m>[39m
        [36m<div[39m
          [33mclass[39m=[32m"sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"flex items-center space-x-3"[39m
          [36m>[39m
            [36m<svg[39m
              [33maria-hidden[39m=[32m"true"[39m
              [33maria-label[39m=[32m"Default"[39m
              [33mclass[39m=[32m"lucide lucide-default h-6 w-6 text-blue-600"[39m
              [33mdata-testid[39m=[32m"default-icon"[39m
              [33mfill[39m=[32m"none"[39m
              [33mheight[39m=[32m"24"[39m
              [33mrole[39m=[32m"img"[39m
              [33mstroke[39m=[32m"currentColor"[39m
              [33mstroke-linecap[39m=[32m"round"[39m
              [33mstroke-linejoin[39m=[32m"round"[39m
              [33mstroke-width[39m=[32m"2"[39m
              [33mviewBox[39m=[32m"0 0 24 24"[39m
              [33mwidth[39m=[32m"24"[39m
            [36m/>[39m
            [36m<div>[39m
              [36m<h2[39m
                [33mclass[39m=[32m"text-xl font-semibold"[39m
              [36m>[39m
                [0mAPI Configuration[0m
              [36m</h2>[39m
              [36m<p[39m
                [33mclass[39m=[32m"text-sm text-gray-600"[39m
              [36m>[39m
                [0mSecurely configure your search engine API credentials[0m
              [36m</p>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<button[39m
            [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"[39m
          [36m>[39m
            [0m✕[0m
          [36m</button>[39m
        [36m</div>[39m
        [36m<div[39m
          [33mclass[39m=[32m"p-6 space-y-6"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm border-blue-200 bg-blue-50"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 p-6 pt-6"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-start space-x-3"[39m
              [36m>[39m
                [36m<svg[39m
                  [33maria-hidden[39m=[32m"true"[39m
                  [33maria-label[39m=[32m"Default"[39m
                  [33mclass[39m=[32m"lucide lucide-default h-5 w-5 text-blue-600 mt-1"[39m
                  [33mdata-testid[39m=[32m"default-icon"[39m
                  [33mfill[39m=[32m"none"[39m
                  [33mheight[39m=[32m"24"[39m
                  [33mrole[39m=[32m"img"[39m
                  [33mstroke[39m=[32m"currentColor"[39m
                  [33mstroke-linecap[39m=[32m"round"[39m
                  [33mstroke-linejoin[39m=[32m"round"[39m
                  [33mstroke-width[39m=[32m"2"[39m
                  [33mviewBox[39m=[32m"0 0 24 24"[39m
                  [33mwidth[39m=[32m"24"[39m
                [36m/>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"text-sm"[39m
                [36m>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"font-medium text-blue-800 mb-2"[39m
                  [36m>[39m
                    [0mSecure Local Storage[0m
                  [36m</p>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"text-blue-700"[39m
                  [36m>[39m
                    [0mYour API credentials are encrypted using AES-256 encryption and stored locally in your browser. They never leave your device and are not transmitted to our servers.[0m
                  [36m</p>[39m
                [36m</div>[39m
              [36m</div>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex flex-col space-y-1.5 p-6"[39m
            [36m>[39m
              [36m<h3[39m
                [33mclass[39m=[32m"text-2xl font-semibold leading-none tracking-tight flex items-center space-x-2"[39m
              [36m>[39m
                [36m<span>[39m
                  [0mGoogle APIs[0m
                [36m</span>[39m
              [36m</h3>[39m
            [36m</div>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 space-y-6"[39m
            [36m>[39m
              [36m<div>[39m
                [36m<h4[39m
                  [33mclass[39m=[32m"text-sm font-medium text-gray-900 mb-3"[39m
                [36m>[39m
                  [0mGoogle Custom Search API[0m
                [36m</h4>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"grid grid-cols-1 md:grid-cols-2 gap-4"[39m
                [36m>[39m
                  [36m<div[39m
                    [33mclass[39m=[32m"relative"[39m
                  [36m>[39m
                    [36m<div[39m
                      [33mclass[39m=[32m"space-y-2"[39m
                    [36m>[39m
                      [36m<label[39m
                        [33mclass[39m=[32m"text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"[39m
                        [33mfor[39m=[32m":re:"[39m
                      [36m>[39m
                        [0mAPI Key[0m
                      [36m</label>[39m
                      [36m<div[39m
                        [33mclass[39m=[32m"relative"[39m
                      [36m>[39m
                        [36m<input[39m
                          [33maria-invalid[39m=[32m"false"[39m
                          [33mclass[39m=[32m"flex h-10 w-full rounded-md border bg-background py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 transition-colors duration-200 px-3 pr-3 border-input focus-visible:ring-ring"[39m
                          [33mid[39m=[32m":re:"[39m
                          [33mplaceholder[39m=[...
    at Object.getElementError (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:37:19)
    at getAllByLabelText (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\queries\label-text.js:111:38)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\query-helpers.js:52:17
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\query-helpers.js:95:19
    at Object.getByLabelText (Q:\_kyle\temp_documents\GitHub\business_scraper\__tests__\components\ApiConfigurationPage.test.tsx:128:32)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should clear validation errors when input changes**: TestingLibraryElementError: Unable to find a label with the text of: /Google Search.*API Key/i

Ignored nodes: comments, script, style
[36m<body>[39m
  [36m<div>[39m
    [36m<div[39m
      [33mclass[39m=[32m"fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"[39m
    [36m>[39m
      [36m<div[39m
        [33mclass[39m=[32m"bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"[39m
      [36m>[39m
        [36m<div[39m
          [33mclass[39m=[32m"sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"flex items-center space-x-3"[39m
          [36m>[39m
            [36m<svg[39m
              [33maria-hidden[39m=[32m"true"[39m
              [33maria-label[39m=[32m"Default"[39m
              [33mclass[39m=[32m"lucide lucide-default h-6 w-6 text-blue-600"[39m
              [33mdata-testid[39m=[32m"default-icon"[39m
              [33mfill[39m=[32m"none"[39m
              [33mheight[39m=[32m"24"[39m
              [33mrole[39m=[32m"img"[39m
              [33mstroke[39m=[32m"currentColor"[39m
              [33mstroke-linecap[39m=[32m"round"[39m
              [33mstroke-linejoin[39m=[32m"round"[39m
              [33mstroke-width[39m=[32m"2"[39m
              [33mviewBox[39m=[32m"0 0 24 24"[39m
              [33mwidth[39m=[32m"24"[39m
            [36m/>[39m
            [36m<div>[39m
              [36m<h2[39m
                [33mclass[39m=[32m"text-xl font-semibold"[39m
              [36m>[39m
                [0mAPI Configuration[0m
              [36m</h2>[39m
              [36m<p[39m
                [33mclass[39m=[32m"text-sm text-gray-600"[39m
              [36m>[39m
                [0mSecurely configure your search engine API credentials[0m
              [36m</p>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<button[39m
            [33mclass[39m=[32m"inline-flex items-center justify-center rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"[39m
          [36m>[39m
            [0m✕[0m
          [36m</button>[39m
        [36m</div>[39m
        [36m<div[39m
          [33mclass[39m=[32m"p-6 space-y-6"[39m
        [36m>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm border-blue-200 bg-blue-50"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 p-6 pt-6"[39m
            [36m>[39m
              [36m<div[39m
                [33mclass[39m=[32m"flex items-start space-x-3"[39m
              [36m>[39m
                [36m<svg[39m
                  [33maria-hidden[39m=[32m"true"[39m
                  [33maria-label[39m=[32m"Default"[39m
                  [33mclass[39m=[32m"lucide lucide-default h-5 w-5 text-blue-600 mt-1"[39m
                  [33mdata-testid[39m=[32m"default-icon"[39m
                  [33mfill[39m=[32m"none"[39m
                  [33mheight[39m=[32m"24"[39m
                  [33mrole[39m=[32m"img"[39m
                  [33mstroke[39m=[32m"currentColor"[39m
                  [33mstroke-linecap[39m=[32m"round"[39m
                  [33mstroke-linejoin[39m=[32m"round"[39m
                  [33mstroke-width[39m=[32m"2"[39m
                  [33mviewBox[39m=[32m"0 0 24 24"[39m
                  [33mwidth[39m=[32m"24"[39m
                [36m/>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"text-sm"[39m
                [36m>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"font-medium text-blue-800 mb-2"[39m
                  [36m>[39m
                    [0mSecure Local Storage[0m
                  [36m</p>[39m
                  [36m<p[39m
                    [33mclass[39m=[32m"text-blue-700"[39m
                  [36m>[39m
                    [0mYour API credentials are encrypted using AES-256 encryption and stored locally in your browser. They never leave your device and are not transmitted to our servers.[0m
                  [36m</p>[39m
                [36m</div>[39m
              [36m</div>[39m
            [36m</div>[39m
          [36m</div>[39m
          [36m<div[39m
            [33mclass[39m=[32m"rounded-lg border bg-card text-card-foreground shadow-sm"[39m
          [36m>[39m
            [36m<div[39m
              [33mclass[39m=[32m"flex flex-col space-y-1.5 p-6"[39m
            [36m>[39m
              [36m<h3[39m
                [33mclass[39m=[32m"text-2xl font-semibold leading-none tracking-tight flex items-center space-x-2"[39m
              [36m>[39m
                [36m<span>[39m
                  [0mGoogle APIs[0m
                [36m</span>[39m
              [36m</h3>[39m
            [36m</div>[39m
            [36m<div[39m
              [33mclass[39m=[32m"p-6 pt-0 space-y-6"[39m
            [36m>[39m
              [36m<div>[39m
                [36m<h4[39m
                  [33mclass[39m=[32m"text-sm font-medium text-gray-900 mb-3"[39m
                [36m>[39m
                  [0mGoogle Custom Search API[0m
                [36m</h4>[39m
                [36m<div[39m
                  [33mclass[39m=[32m"grid grid-cols-1 md:grid-cols-2 gap-4"[39m
                [36m>[39m
                  [36m<div[39m
                    [33mclass[39m=[32m"relative"[39m
                  [36m>[39m
                    [36m<div[39m
                      [33mclass[39m=[32m"space-y-2"[39m
                    [36m>[39m
                      [36m<label[39m
                        [33mclass[39m=[32m"text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"[39m
                        [33mfor[39m=[32m":rl:"[39m
                      [36m>[39m
                        [0mAPI Key[0m
                      [36m</label>[39m
                      [36m<div[39m
                        [33mclass[39m=[32m"relative"[39m
                      [36m>[39m
                        [36m<input[39m
                          [33maria-invalid[39m=[32m"false"[39m
                          [33mclass[39m=[32m"flex h-10 w-full rounded-md border bg-background py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 transition-colors duration-200 px-3 pr-3 border-input focus-visible:ring-ring"[39m
                          [33mid[39m=[32m":rl:"[39m
                          [33mplaceholder[39m=[...
    at Object.getElementError (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\config.js:37:19)
    at getAllByLabelText (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\queries\label-text.js:111:38)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\query-helpers.js:52:17
    at Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\@testing-library\react\node_modules\@testing-library\dom\dist\query-helpers.js:95:19
    at Object.getByLabelText (Q:\_kyle\temp_documents\GitHub\business_scraper\__tests__\components\ApiConfigurationPage.test.tsx:155:32)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:316:40)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:252:3)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should return upload configuration**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeDefined[2m()[22m

Received: [31mundefined[39m
    at toBeDefined (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\setup\testSetup.ts:129:35)
    at Array.forEach (<anonymous>)
    at Object.forEach [as validateEnvironmentIntegrity] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\setup\testSetup.ts:128:21)
    at Object.validateEnvironmentIntegrity (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:81:25)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:254:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should return different configs for different types**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeDefined[2m()[22m

Received: [31mundefined[39m
    at toBeDefined (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\setup\testSetup.ts:129:35)
    at Array.forEach (<anonymous>)
    at Object.forEach [as validateEnvironmentIntegrity] (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\setup\testSetup.ts:128:21)
    at Object.validateEnvironmentIntegrity (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:81:25)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:254:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject non-POST requests**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m405[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:119:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should accept valid file uploads**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:135:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should reject files exceeding size limit**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:156:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should reject executable files**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:173:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should reject empty files**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:190:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle multiple file uploads**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:210:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should enforce file count limits**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:233:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should save files when requested**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:256:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle malicious script content**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:275:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should validate JSON structure for backup files**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:293:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should reject invalid JSON for backup files**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:310:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should validate CSV structure for data import**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:327:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should include security scan details in response**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:344:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle file processing errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:372:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should quarantine malicious files**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:395:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should detect path traversal in filenames**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:412:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle different upload types with appropriate security**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\upload.test.ts:431:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should get job status**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m404[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:175:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should validate business data**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:261:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should validate batch of businesses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:298:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should limit batch validation size**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:323:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should find duplicates**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:357:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should compare two records**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:389:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should get retention policies**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:408:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should export data with enhanced options**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:440:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should get overview statistics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:455:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should get validation statistics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:468:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle invalid stats type**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:479:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle missing request body**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:509:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle database connection errors**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m401[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\api.test.ts:529:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle valid search request**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:52:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle invalid ZIP code format**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: [32m"ZIP code"[39m
Received string:    [31m"Validation failed"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:130:26)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle valid scrape request**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:245:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle cleanup action**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:319:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return configuration**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveProperty[2m([22m[32mpath[39m[2m)[22m

Expected path: [32m"config"[39m
Received path: [31m[][39m

Received value: [31m{"app": {"debug": false, "environment": "test", "name": "Business Scraper App", "version": "6.10.1"}, "cache": {"type": "redis"}, "features": {"enableAuth": true, "enableCaching": true, "enableDebugMode": false, "enableExperimentalFeatures": false, "enableMetrics": true, "enableRateLimiting": true}, "logging": {"format": "json", "level": "info"}, "scraping": {"maxRetries": 3, "maxSearchResults": 50, "timeout": 30000}}[39m
    at Object.toHaveProperty (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:363:20)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return health status**: Error: Configuration error
    at Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:369:15
    at Runtime.requireMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:940:55)
    at Runtime.requireModuleOrMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1046:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\database.ts:4765:28)
    at Runtime._execModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1439:24)
    at Runtime._loadModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1022:12)
    at Runtime.requireModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:882:12)
    at Runtime._generateMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1690:34)
    at Runtime.requireMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:996:39)
    at Runtime.requireModuleOrMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1046:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\health\route.ts:1897:27)
    at Runtime._execModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1439:24)
    at Runtime._loadModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1022:12)
    at Runtime.requireModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:882:12)
    at Runtime.requireModuleOrMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1048:21)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:386:34
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:386:28)
- **should include service health checks**: Error: Configuration error
    at Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:369:15
    at Runtime.requireMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:940:55)
    at Runtime.requireModuleOrMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1046:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\lib\database.ts:4765:28)
    at Runtime._execModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1439:24)
    at Runtime._loadModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1022:12)
    at Runtime.requireModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:882:12)
    at Runtime._generateMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1690:34)
    at Runtime.requireMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:996:39)
    at Runtime.requireModuleOrMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1046:21)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\health\route.ts:1897:27)
    at Runtime._execModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1439:24)
    at Runtime._loadModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1022:12)
    at Runtime.requireModule (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:882:12)
    at Runtime.requireModuleOrMock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runtime\build\index.js:1048:21)
    at Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:386:34
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at Object.<anonymous> (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\comprehensive\apiEndpoints.comprehensive.test.ts:386:28)
- **should create payment intent for authenticated user**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\payment-api.test.ts:219:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should reject unauthenticated requests**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m401[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\payment-api.test.ts:238:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should validate request body**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"[7mV[27malid[7mation failed[27m"[39m
Received: [31m"[7mInv[27malid[7m JSON in request body[27m"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\payment-api.test.ts:257:34)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle Stripe errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\payment-api.test.ts:274:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should retrieve payment intent for authenticated user**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\payment-api.test.ts:328:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should reject unauthorized access to payment intent**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m404[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\tests\integration\payment-api.test.ts:372:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should accept valid query parameters**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:84:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return 429 when rate limited**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m429[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:101:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should proceed when rate limit allows**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:125:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return 503 when health check fails**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m503[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:141:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should proceed when health check passes**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:165:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle health check errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m503[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:178:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should set correct SSE headers**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"text/event-stream"[39m
Received: [31m"application/json"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:199:52)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle streaming service errors**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:217:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should call processStreamingSearch with correct parameters**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"test query"[39m, [32m"test location"[39m, [32mAny<Function>[39m, [32mAny<Function>[39m, [32mAny<Function>[39m, [32mAny<Function>[39m, [32m{"batchSize": 25, "delayBetweenBatches": 200, "enableRealTimeUpdates": true, "maxResults": 500}[39m

Number of calls: [31m0[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:239:61)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle OPTIONS requests**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"GET"[39m
Received: [31m"GET[7m, POST, PUT, DELETE, OPTIONS[27m"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\app\api\stream-search\__tests__\route.test.ts:292:68)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **GET /api/v1/templates should return template list**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:194:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **GET /api/v1/templates with platform filter**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:207:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **GET /api/v1/templates with details**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:218:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **POST /api/v1/exports should create export successfully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:262:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **POST /api/v1/exports should validate required fields**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:287:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **POST /api/v1/exports should validate business data**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:308:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **GET /api/v1/analytics?type=realtime should return real-time metrics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:321:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **GET /api/v1/analytics?type=client should return client analytics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:337:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **GET /api/v1/analytics?type=system should return system analytics**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:351:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **GET /api/v1/analytics with date range should filter data**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:371:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle invalid JSON in request body**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:390:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle missing required parameters**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m403[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:403:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should include rate limit headers**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBeTruthy[2m()[22m

Received: [31mnull[39m
    at Object.toBeTruthy (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\integration\api-endpoints.test.ts:429:61)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should process successful request**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

[32m- Expected[39m
[31m+ Received[39m

  [2m{"_bodyUsed": false, "body": undefined, "cookies": {"delete": [Function mockConstructor], "get": [Function mockConstructor], "getAll": [Function mockConstructor], "has": [Function mockConstructor], "set": [Function mockConstructor]}, "headers": {}, "method": "GET", "nextUrl": "https://example.com/api/v1/test", "url": "https://example.com/api/v1/test", Symbol(internal request): {"cookies": {"_headers": {}, "_parsed": Map {}}, "geo": {}, "ip": undefined, "nextUrl": "https://example.com/api/v1/test", "url": "https://example.com/api/v1/test"}}[22m,
[32m- ObjectContaining {"metadata": ObjectContaining {"ip": "127.0.0.1", "method": "GET", "userAgent": "test-agent"}, "permissions": Any<Array>, "requestId": Any<String>}[39m,
[31m+ {"clientId": "oauth-client", "metadata": {"ip": undefined, "method": "GET", "pathname": "/api/v1/test", "userAgent": "test-agent"}, "permissions": ["read:businesses", "write:businesses", "read:exports", "write:exports"], "rateLimit": {"remaining": 99, "resetTime": 60}, "requestId": "req_1759455339328_f8fzme505", "startTime": 1759455339328, "userId": "oauth-user"}[39m,

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\integrations\api-framework.test.ts:91:27)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should record request metrics**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32mAny<String>[39m, [32mAny<String>[39m, [32m"GET"[39m, [32m200[39m, [32mAny<Number>[39m, [32mAny<Number>[39m, [32mObjectContaining {"ip": "127.0.0.1", "userAgent": "test-agent"}[39m
Received: [2m"oauth-client"[22m, [2m"/api/v1/test"[22m, [2m"GET"[22m, [2m200[22m, [2m1[22m, [2m128[22m, [31m{"ip": undefined, "userAgent": "test-agent"}[39m

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\lib\integrations\api-framework.test.ts:348:47)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should create new session and return CSRF token for unauthenticated users**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoEqual[2m([22m[32mexpected[39m[2m) // deep equality[22m

[32m- Expected  - 2[39m
[31m+ Received  + 0[39m

[2m  Object {[22m
[2m    "authenticated": false,[22m
[32m-   "csrfToken": "csrf-token-123",[39m
[2m    "expiresAt": Any<String>,[22m
[32m-   "sessionId": "new-session-123",[39m
[2m  }[22m
    at Object.toEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-csrf.test.ts:50:20)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return existing session data for authenticated users**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoEqual[2m([22m[32mexpected[39m[2m) // deep equality[22m

[32m- Expected  - 2[39m
[31m+ Received  + 0[39m

[2m  Object {[22m
[2m    "authenticated": true,[22m
[32m-   "csrfToken": "csrf-token-456",[39m
[2m    "expiresAt": Any<String>,[22m
[32m-   "sessionId": "existing-session-456",[39m
[2m  }[22m
    at Object.toEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-csrf.test.ts:89:20)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should create new session when existing session is invalid**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoEqual[2m([22m[32mexpected[39m[2m) // deep equality[22m

[32m- Expected  - 2[39m
[31m+ Received  + 0[39m

[2m  Object {[22m
[2m    "authenticated": false,[22m
[32m-   "csrfToken": "csrf-token-789",[39m
[2m    "expiresAt": Any<String>,[22m
[32m-   "sessionId": "replacement-session-789",[39m
[2m  }[22m
    at Object.toEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-csrf.test.ts:124:20)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle expired sessions by creating new ones**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoEqual[2m([22m[32mexpected[39m[2m) // deep equality[22m

[32m- Expected  - 2[39m
[31m+ Received  + 0[39m

[2m  Object {[22m
[2m    "authenticated": false,[22m
[32m-   "csrfToken": "new-csrf-token",[39m
[2m    "expiresAt": Any<String>,[22m
[32m-   "sessionId": "new-session-after-expiry",[39m
[2m  }[22m
    at Object.toEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-csrf.test.ts:167:20)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"Internal server error"[39m
Received: [31m"Session creation failed"[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-csrf.test.ts:193:26)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should provide valid CSRF tokens that can be used for authentication**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"valid-csrf-token"[39m
Received: [31mundefined[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-csrf.test.ts:218:33)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should set secure session cookies with proper attributes**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: [32m"SameSite=Strict"[39m
Received string:    [31m"session-id=secure-session; Path=/; Expires=Fri, 03 Oct 2025 02:35:39 GMT; Max-Age=3600; HttpOnly; SameSite=strict"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-csrf.test.ts:246:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should never expose password hashes in user list**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:99:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should mask PII data in production**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:131:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should sanitize error responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"Database error"[39m
Received string:        [31m"[7mDatabase error[27m: [REDACTED]"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:158:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should remove total_count from individual user objects**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:173:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should never expose password data in user creation response**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m201[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:202:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should sanitize user creation error responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"database_url=postgresql://user:pass@localhost"[39m
Received string:        [31m"User creation failed: [7mdatabase_url=postgresql://user:pass@localhost[27m"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:263:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle all authentication field variations**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m201[39m
Received: [31m400[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\users-security.test.ts:322:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should never expose actual session ID in any environment**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoMatch[2m([22m[32mexpected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a string

Received has value: [31mundefined[39m
    at Object.toMatch (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:65:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should not expose session ID in production environment**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m"[SESSION_ACTIVE]"[39m
Received: [31mundefined[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:81:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should not expose session ID in development environment**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoMatch[2m([22m[32mexpected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a string

Received has value: [31mundefined[39m
    at Object.toMatch (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:97:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should sanitize error responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mnot[2m.[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected substring: not [32m"Database connection"[39m
Received string:        [31m"[7mDatabase connection[27m failed: [REDACTED]"[39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:117:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should never expose actual session ID on successful login**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m200[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:138:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should not expose sensitive data in failed login responses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m401[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth-security.test.ts:179:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return existing CSRF token for valid session**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"existing-session-id"[39m
Received: [31m"mock-session-id"[39m

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\csrf.test.ts:108:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should create new session when existing session is invalid**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"invalid-session-id"[39m
Received: [31m"mock-session-id"[39m

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\csrf.test.ts:143:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle errors gracefully**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoEqual[2m([22m[32mexpected[39m[2m) // deep equality[22m

[32m- Expected  - 0[39m
[31m+ Received  + 2[39m

[2m  Object {[22m
[2m    "error": "Internal server error",[22m
[31m+   "retryable": false,[39m
[31m+   "type": "server_error",[39m
[2m  }[22m
    at Object.toEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\csrf.test.ts:163:20)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should refresh CSRF token for valid session**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"test-session-id"[39m
Received: [31m"mock-session-id"[39m

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\csrf.test.ts:210:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return 401 for missing session**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoEqual[2m([22m[32mexpected[39m[2m) // deep equality[22m

[32m- Expected  - 1[39m
[31m+ Received  + 1[39m

[2m  Object {[22m
[32m-   "error": "No session found",[39m
[31m+   "error": "Invalid session",[39m
[2m  }[22m
    at Object.toEqual (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\csrf.test.ts:226:20)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should return 401 for invalid session**: Error: [2mexpect([22m[31mjest.fn()[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

Expected: [32m"invalid-session-id"[39m
Received: [31m"mock-session-id"[39m

Number of calls: [31m1[39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\csrf.test.ts:250:30)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should create new session when no session exists**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should return existing valid session**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should create new session when existing session is invalid**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should successfully authenticate with valid credentials**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject invalid credentials**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject missing username or password**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle malformed JSON request**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle account lockout after too many failed attempts**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle invalid input format**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle session creation failure**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should successfully authenticate multi-user login**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject invalid multi-user credentials**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle rate limiting for multi-user login**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should successfully register new user**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject registration with missing fields**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle user creation failure**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should reject invalid action**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should return authenticated status for valid session**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should return unauthenticated status for missing session**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle network errors gracefully**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should sanitize error messages in responses**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle concurrent login attempts**: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle storage errors**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveBeenCalled[2m()[22m

[1mMatcher error[22m: [31mreceived[39m value must be a mock or spy function

Received has type:  function
Received has value: [31m[Function error][39m
    at Object.toHaveBeenCalled (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:243:28)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should successfully save multiple businesses**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a mock or spy function

Received has type:  function
Received has value: [31m[Function info][39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:290:27)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle malformed JSON**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m400[39m
Received: [31m500[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:359:31)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle enhanced filtering with complex criteria**: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle cursor-based pagination with enhanced filtering**: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should validate enhanced filtering parameters**: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle enhanced filtering service errors**: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- **should handle malformed date filters**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoContain[2m([22m[32mexpected[39m[2m) // indexOf[22m

Expected value: [32m500[39m
Received array: [31m[200, 400][39m
    at Object.toContain (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:513:26)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
- **should handle database connection failures**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoHaveBeenCalledWith[2m([22m[32m...expected[39m[2m)[22m

[1mMatcher error[22m: [31mreceived[39m value must be a mock or spy function

Received has type:  function
Received has value: [31m[Function error][39m
    at Object.toHaveBeenCalledWith (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:568:28)
- **should optimize memory usage during filtering**: Error: [2mexpect([22m[31mreceived[39m[2m).[22mtoBe[2m([22m[32mexpected[39m[2m) // Object.is equality[22m

Expected: [32m500[39m
Received: [31m100[39m
    at Object.toBe (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:626:32)

## Performance Analysis
- **Average Duration**: 406228.00ms
- **Memory Peak**: 509.15MB

## Recommendations
### Fix Critical Test Failures (CRITICAL)
26 critical test failures require immediate attention
- Fix should create new session when no session exists: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should return existing valid session: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should create new session when existing session is invalid: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should successfully authenticate with valid credentials: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject invalid credentials: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject missing username or password: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle malformed JSON request: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle account lockout after too many failed attempts: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle invalid input format: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle session creation failure: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should successfully authenticate multi-user login: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject invalid multi-user credentials: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle rate limiting for multi-user login: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should successfully register new user: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject registration with missing fields: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle user creation failure: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should reject invalid action: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should return authenticated status for valid session: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should return unauthenticated status for missing session: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle network errors gracefully: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should sanitize error messages in responses: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle concurrent login attempts: TypeError: _advancedRateLimit.advancedRateLimitService.checkApiRateLimit.mockReturnValue is not a function
    at Object.mockReturnValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\auth\auth-route.comprehensive.test.ts:94:64)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle enhanced filtering with complex criteria: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle cursor-based pagination with enhanced filtering: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should validate enhanced filtering parameters: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)
- Fix should handle enhanced filtering service errors: TypeError: mockFilteringService.filterBusinesses.mockResolvedValue is not a function
    at Object.mockResolvedValue (Q:\_kyle\temp_documents\GitHub\business_scraper\src\__tests__\api\businesses\businesses-route.comprehensive.test.ts:389:61)
    at Promise.then.completed (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\utils.js:231:10)
    at _callCircusHook (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:281:40)
    at runNextTicks (node:internal/process/task_queues:65:5)
    at processImmediate (node:internal/timers:453:9)
    at _runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:246:5)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:126:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at _runTestsForDescribeBlock (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:121:9)
    at run (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\run.js:71:3)
    at runAndTransformResultsToJestFormat (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapterInit.js:122:21)
    at jestAdapter (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-circus\build\legacy-code-todo-rewrite\jestAdapter.js:79:19)
    at runTestInternal (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:367:16)
    at runTest (Q:\_kyle\temp_documents\GitHub\business_scraper\node_modules\jest-runner\build\runTest.js:444:34)

---
*Generated at 2025-10-03T01:35:51.995Z by EnhancedTestLogger*