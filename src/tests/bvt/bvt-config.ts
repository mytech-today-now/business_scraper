/**
 * Build Verification Test (BVT) Configuration
 * Defines the lightweight test suite covering all 12 testing areas
 */

export interface BVTTestCategory {
  name: string
  description: string
  timeout: number
  retries: number
  priority: 'critical' | 'high' | 'medium' | 'low'
  tests: BVTTest[]
}

export interface BVTTest {
  name: string
  description: string
  testFunction: string
  timeout: number
  expectedDuration: number // in milliseconds
  dependencies?: string[]
}

export interface BVTConfig {
  maxExecutionTime: number // 10 minutes = 600000ms
  parallelExecution: boolean
  failFast: boolean
  retryFailedTests: boolean
  reportingLevel: 'minimal' | 'standard' | 'detailed'
  categories: BVTTestCategory[]
}

export const BVT_CONFIG: BVTConfig = {
  maxExecutionTime: 600000, // 10 minutes
  parallelExecution: true,
  failFast: false, // Continue running other tests even if some fail
  retryFailedTests: true,
  reportingLevel: 'standard',
  categories: [
    {
      name: 'functional',
      description: 'Core workflow functionality verification',
      timeout: 60000,
      retries: 2,
      priority: 'critical',
      tests: [
        {
          name: 'api-heartbeat',
          description: 'Verify core API endpoints respond',
          testFunction: 'testApiHeartbeat',
          timeout: 10000,
          expectedDuration: 2000,
        },
        {
          name: 'login-workflow',
          description: 'Verify login functionality works',
          testFunction: 'testLoginWorkflow',
          timeout: 15000,
          expectedDuration: 5000,
        },
        {
          name: 'navigation-basic',
          description: 'Verify basic navigation works',
          testFunction: 'testBasicNavigation',
          timeout: 10000,
          expectedDuration: 3000,
        },
      ],
    },
    {
      name: 'unit',
      description: 'Critical unit test canaries',
      timeout: 30000,
      retries: 1,
      priority: 'critical',
      tests: [
        {
          name: 'core-utilities',
          description: 'Test critical utility functions',
          testFunction: 'testCoreUtilities',
          timeout: 5000,
          expectedDuration: 1000,
        },
        {
          name: 'data-models',
          description: 'Test core data model validation',
          testFunction: 'testDataModels',
          timeout: 5000,
          expectedDuration: 1000,
        },
      ],
    },
    {
      name: 'integration',
      description: 'Key interface validation',
      timeout: 45000,
      retries: 2,
      priority: 'high',
      tests: [
        {
          name: 'database-connection',
          description: 'Verify database connectivity',
          testFunction: 'testDatabaseConnection',
          timeout: 10000,
          expectedDuration: 2000,
        },
        {
          name: 'api-integration',
          description: 'Test API endpoint integration',
          testFunction: 'testApiIntegration',
          timeout: 15000,
          expectedDuration: 3000,
        },
      ],
    },
    {
      name: 'system',
      description: 'System health and availability',
      timeout: 60000,
      retries: 2,
      priority: 'critical',
      tests: [
        {
          name: 'application-startup',
          description: 'Verify application starts correctly',
          testFunction: 'testApplicationStartup',
          timeout: 30000,
          expectedDuration: 5000,
        },
        {
          name: 'service-availability',
          description: 'Check all services are available',
          testFunction: 'testServiceAvailability',
          timeout: 15000,
          expectedDuration: 3000,
        },
        {
          name: 'resource-limits',
          description: 'Verify resource usage within limits',
          testFunction: 'testResourceLimits',
          timeout: 10000,
          expectedDuration: 2000,
        },
      ],
    },
    {
      name: 'regression',
      description: 'Historical bug prevention',
      timeout: 30000,
      retries: 1,
      priority: 'high',
      tests: [
        {
          name: 'critical-bugs',
          description: 'Test for previously fixed critical bugs',
          testFunction: 'testCriticalBugRegression',
          timeout: 15000,
          expectedDuration: 3000,
        },
        {
          name: 'auth-regression',
          description: 'Authentication regression checks',
          testFunction: 'testAuthRegression',
          timeout: 10000,
          expectedDuration: 2000,
        },
      ],
    },
    {
      name: 'smoke',
      description: 'Basic deployment validation',
      timeout: 30000,
      retries: 1,
      priority: 'critical',
      tests: [
        {
          name: 'deployment-health',
          description: 'Basic deployment health check',
          testFunction: 'testDeploymentHealth',
          timeout: 10000,
          expectedDuration: 2000,
        },
        {
          name: 'environment-config',
          description: 'Verify environment configuration',
          testFunction: 'testEnvironmentConfig',
          timeout: 5000,
          expectedDuration: 1000,
        },
      ],
    },
    {
      name: 'sanity',
      description: 'Core feature verification',
      timeout: 45000,
      retries: 2,
      priority: 'high',
      tests: [
        {
          name: 'search-functionality',
          description: 'Basic search functionality works',
          testFunction: 'testSearchFunctionality',
          timeout: 20000,
          expectedDuration: 5000,
        },
        {
          name: 'data-export',
          description: 'Basic data export works',
          testFunction: 'testDataExport',
          timeout: 15000,
          expectedDuration: 3000,
        },
      ],
    },
    {
      name: 'performance',
      description: 'Lightweight performance checks',
      timeout: 60000,
      retries: 2,
      priority: 'medium',
      tests: [
        {
          name: 'response-times',
          description: 'API response times under 500ms',
          testFunction: 'testResponseTimes',
          timeout: 30000,
          expectedDuration: 10000,
        },
        {
          name: 'page-load-times',
          description: 'Page load times under 3 seconds',
          testFunction: 'testPageLoadTimes',
          timeout: 20000,
          expectedDuration: 5000,
        },
      ],
    },
    {
      name: 'security',
      description: 'Security quick scan',
      timeout: 45000,
      retries: 1,
      priority: 'critical',
      tests: [
        {
          name: 'auth-validation',
          description: 'Authentication paths intact',
          testFunction: 'testAuthValidation',
          timeout: 15000,
          expectedDuration: 3000,
        },
        {
          name: 'authorization-check',
          description: 'Authorization controls working',
          testFunction: 'testAuthorizationCheck',
          timeout: 10000,
          expectedDuration: 2000,
        },
        {
          name: 'security-headers',
          description: 'Security headers present',
          testFunction: 'testSecurityHeaders',
          timeout: 5000,
          expectedDuration: 1000,
        },
      ],
    },
    {
      name: 'usability',
      description: 'Basic UI validation',
      timeout: 30000,
      retries: 2,
      priority: 'medium',
      tests: [
        {
          name: 'ui-elements',
          description: 'Essential UI elements visible and clickable',
          testFunction: 'testUIElements',
          timeout: 15000,
          expectedDuration: 3000,
        },
        {
          name: 'form-validation',
          description: 'Basic form validation works',
          testFunction: 'testFormValidation',
          timeout: 10000,
          expectedDuration: 2000,
        },
      ],
    },
    {
      name: 'compatibility',
      description: 'Common environment validation',
      timeout: 45000,
      retries: 1,
      priority: 'medium',
      tests: [
        {
          name: 'browser-compatibility',
          description: 'Works in Chrome (primary browser)',
          testFunction: 'testBrowserCompatibility',
          timeout: 20000,
          expectedDuration: 5000,
        },
        {
          name: 'docker-environment',
          description: 'Works in Docker environment',
          testFunction: 'testDockerEnvironment',
          timeout: 15000,
          expectedDuration: 3000,
        },
      ],
    },
    {
      name: 'acceptance',
      description: 'Deployment readiness confirmation',
      timeout: 30000,
      retries: 1,
      priority: 'critical',
      tests: [
        {
          name: 'version-metadata',
          description: 'Version and build metadata correct',
          testFunction: 'testVersionMetadata',
          timeout: 5000,
          expectedDuration: 1000,
        },
        {
          name: 'deployment-readiness',
          description: 'All deployment readiness signals present',
          testFunction: 'testDeploymentReadiness',
          timeout: 10000,
          expectedDuration: 2000,
        },
      ],
    },
  ],
}

// Calculate total expected duration
export const getTotalExpectedDuration = (): number => {
  return BVT_CONFIG.categories.reduce((total, category) => {
    return total + category.tests.reduce((catTotal, test) => {
      return catTotal + test.expectedDuration
    }, 0)
  }, 0)
}

// Get tests by priority
export const getTestsByPriority = (priority: 'critical' | 'high' | 'medium' | 'low'): BVTTest[] => {
  return BVT_CONFIG.categories
    .filter(category => category.priority === priority)
    .flatMap(category => category.tests)
}

// Validate configuration
export const validateBVTConfig = (): { valid: boolean; errors: string[] } => {
  const errors: string[] = []
  const totalExpected = getTotalExpectedDuration()
  
  if (totalExpected > BVT_CONFIG.maxExecutionTime) {
    errors.push(`Total expected duration (${totalExpected}ms) exceeds max execution time (${BVT_CONFIG.maxExecutionTime}ms)`)
  }
  
  // Validate all 12 categories are present
  const requiredCategories = [
    'functional', 'unit', 'integration', 'system', 'regression', 
    'smoke', 'sanity', 'performance', 'security', 'usability', 
    'compatibility', 'acceptance'
  ]
  
  const presentCategories = BVT_CONFIG.categories.map(cat => cat.name)
  const missingCategories = requiredCategories.filter(cat => !presentCategories.includes(cat))
  
  if (missingCategories.length > 0) {
    errors.push(`Missing required categories: ${missingCategories.join(', ')}`)
  }
  
  return {
    valid: errors.length === 0,
    errors
  }
}
