/**
 * Test Fixtures and Safe Test Data
 * Centralized location for test data to avoid hardcoded values in test files
 */

// Safe test business data
export const mockBusinessData = [
  {
    id: 'test-business-1',
    businessName: 'Test Technology Corp',
    email: ['contact@testtech.example', 'info@testtech.example'],
    phone: '+1-555-0123',
    websiteUrl: 'https://testtech.example',
    address: {
      street: '123 Innovation Drive',
      city: 'Tech City',
      state: 'TC',
      zipCode: '12345',
    },
    industry: 'Technology',
    contactPerson: 'John Developer',
    coordinates: {
      lat: 40.7128,
      lng: -74.006,
    },
    scrapedAt: new Date('2024-01-01T12:00:00Z'),
  },
  {
    id: 'test-business-2',
    businessName: 'Sample Retail Store',
    email: ['sales@sampleretail.example'],
    phone: '+1-555-0456',
    websiteUrl: 'https://sampleretail.example',
    address: {
      street: '456 Commerce Street',
      city: 'Retail Town',
      state: 'RT',
      zipCode: '67890',
    },
    industry: 'Retail',
    contactPerson: 'Jane Manager',
    coordinates: {
      lat: 34.0522,
      lng: -118.2437,
    },
    scrapedAt: new Date('2024-01-02T12:00:00Z'),
  },
]

// Safe test configuration data
export const mockConfigData = {
  app: {
    name: 'Test Application',
    version: '1.0.0',
    environment: 'test',
    debug: false,
    port: 3000,
  },
  database: {
    host: 'localhost',
    port: 5432,
    name: 'test_database',
    user: 'test_user',
    password: 'safe_test_password',
    poolMin: 2,
    poolMax: 10,
    idleTimeout: 30000,
    connectionTimeout: 5000,
    ssl: false,
  },
  security: {
    enableAuth: false,
    sessionTimeout: 3600000,
    maxLoginAttempts: 5,
    lockoutDuration: 900000,
    rateLimitWindow: 60000,
    rateLimitMax: 100,
    scrapingRateLimit: 10,
    adminUsername: 'test_admin',
    adminPassword: 'test_password_123',
  },
  scraping: {
    timeout: 30000,
    maxRetries: 3,
    delayMs: 1000,
    searchEngineTimeout: 10000,
    maxSearchResults: 50,
  },
  apiKeys: {
    googleMaps: undefined,
    openCage: undefined,
    bingSearch: undefined,
    yandexSearch: undefined,
  },
  cache: {
    type: 'memory' as const,
    memory: {
      maxSize: 1000,
      ttl: 3600000,
    },
  },
  logging: {
    level: 'info' as const,
    format: 'text' as const,
    enableConsole: true,
    enableFile: false,
    filePath: './logs/test.log',
    maxFileSize: 10485760,
    maxFiles: 5,
  },
  features: {
    enableAuth: false,
    enableCaching: true,
    enableRateLimiting: true,
    enableMetrics: false,
    enableDebugMode: false,
    enableExperimentalFeatures: false,
  },
}

// Safe test API credentials
export const mockApiCredentials = {
  googleSearchApiKey: 'test-api-key-12345',
  googleSearchEngineId: 'test-engine-id-67890',
  domainBlacklist: ['example-spam.test', 'unwanted-site.test', 'blocked-domain.test'],
}

// Encoded malicious patterns for security testing (base64 encoded to avoid direct exposure)
export const encodedSecurityPatterns = {
  // Base64 encoded: <script>alert("XSS")</script>
  xssPattern: 'PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',

  // Base64 encoded: SELECT * FROM users WHERE id = 1 OR 1=1
  sqlInjectionPattern: 'U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDEgT1IgMT0x',

  // Base64 encoded: ../../../etc/passwd
  pathTraversalPattern: 'Li4vLi4vLi4vZXRjL3Bhc3N3ZA==',

  // Base64 encoded: EXEC xp_cmdshell('dir')
  commandInjectionPattern: 'RVhFQyB4cF9jbWRzaGVsbCgnZGlyJyk=',
}

// Helper function to decode security patterns for testing
export function decodeSecurityPattern(encodedPattern: string): string {
  return Buffer.from(encodedPattern, 'base64').toString('utf-8')
}

// Safe file content for testing
export const testFileContents = {
  plainText: 'This is safe test content for file operations.',
  csvData:
    'name,category,email\nTest Business,Technology,test@example.com\nSample Store,Retail,sample@example.com',
  jsonData: '{"businesses": [{"name": "Test Corp", "industry": "Tech"}]}',
  htmlContent:
    '<html><head><title>Safe Test Page</title></head><body><h1>Test Content</h1></body></html>',
}

// Test file metadata
export const testFileMetadata = {
  textFile: {
    name: 'test-document.txt',
    type: 'text/plain',
    size: testFileContents.plainText.length,
  },
  csvFile: {
    name: 'test-data.csv',
    type: 'text/csv',
    size: testFileContents.csvData.length,
  },
  jsonFile: {
    name: 'test-backup.json',
    type: 'application/json',
    size: testFileContents.jsonData.length,
  },
  htmlFile: {
    name: 'test-page.html',
    type: 'text/html',
    size: testFileContents.htmlContent.length,
  },
}

// Test directory structure (virtual paths for mocking)
export const testPaths = {
  tempDir: '/tmp/test-files',
  uploadsDir: '/tmp/test-uploads',
  quarantineDir: '/tmp/test-quarantine',
  logsDir: '/tmp/test-logs',
  backupDir: '/tmp/test-backup',
}
