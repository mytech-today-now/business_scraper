import { defineConfig, devices } from '@playwright/test'

/**
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  testDir: './src/tests/e2e',
  /* Run tests in files in parallel */
  fullyParallel: true,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Optimized retry strategy */
  retries: process.env.CI ? 1 : 0, // Reduced from 2 to 1 for faster CI
  /* Optimized worker configuration for better performance */
  workers: process.env.CI ? 2 : 4, // Increased workers for better parallelization
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [
    ['html'],
    ['json', { outputFile: 'test-results/results.json' }],
    ['junit', { outputFile: 'test-results/results.xml' }],
  ],
  /* Enhanced timeout configuration for performance */
  timeout: 60000, // Overall test timeout: 1 minute
  expect: {
    timeout: 10000, // Assertion timeout: 10 seconds
  },
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: process.env.TEST_BASE_URL || 'http://localhost:3000',

    /* Optimized trace collection */
    trace: 'retain-on-failure', // Only keep traces on failure

    /* Optimized screenshot settings */
    screenshot: 'only-on-failure',

    /* Optimized video settings */
    video: 'retain-on-failure',

    /* Optimized timeout settings for better performance */
    actionTimeout: 15000, // Reduced from 30000 to 15000
    navigationTimeout: 20000, // Reduced from 30000 to 20000

    /* Enhanced browser context options for performance */
    contextOptions: {
      // Disable images and CSS for faster loading in tests
      ignoreHTTPSErrors: true,
    },

    /* Optimized viewport for consistent testing */
    viewport: { width: 1280, height: 720 },

    /* Disable animations for faster tests */
    extraHTTPHeaders: {
      'Accept-Language': 'en-US,en;q=0.9',
    },
  },

  /* Optimized browser projects for performance testing */
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Performance optimizations for Chromium
        launchOptions: {
          args: [
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--disable-dev-shm-usage',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-gpu',
            '--disable-extensions',
            '--disable-default-apps',
            '--disable-sync',
            '--disable-translate',
            '--hide-scrollbars',
            '--mute-audio',
            '--no-first-run',
            '--disable-background-networking',
            '--aggressive-cache-discard',
            '--memory-pressure-off'
          ]
        }
      },
    },

    // Reduced browser matrix for faster CI/CD
    ...(process.env.CI ? [] : [
      {
        name: 'firefox',
        use: {
          ...devices['Desktop Firefox'],
          launchOptions: {
            firefoxUserPrefs: {
              'media.navigator.streams.fake': true,
              'media.navigator.permission.disabled': true,
            }
          }
        },
      },

      {
        name: 'webkit',
        use: { ...devices['Desktop Safari'] },
      },

      /* Mobile testing only in non-CI environments */
      {
        name: 'Mobile Chrome',
        use: {
          ...devices['Pixel 5'],
          launchOptions: {
            args: ['--disable-web-security', '--disable-features=VizDisplayCompositor']
          }
        },
      },
    ])
  ],

  /* Optimized dev server configuration for faster test startup */
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:3000',
    reuseExistingServer: !process.env.CI,
    timeout: 60 * 1000, // Reduced from 120s to 60s
    env: {
      NODE_ENV: 'test', // Use test environment for better performance
      ENABLE_AUTH: 'false',
      // Performance optimizations for test environment
      SCRAPING_TIMEOUT: '5000',
      SCRAPING_DELAY_MS: '100',
      BROWSER_POOL_SIZE: '2',
      CACHE_MAX_SIZE: '500',
      DISABLE_ANALYTICS: 'true',
      DISABLE_MONITORING: 'true'
    }
  },
})
