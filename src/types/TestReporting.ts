/**
 * Enhanced Test Reporting Types
 * Professional-grade test reporting with comprehensive metadata and GitHub integration
 */

export interface TestExecutionContext {
  environment: string
  nodeVersion: string
  platform: string
  timestamp: string
  duration: number
  workingDirectory: string
  configuration: Record<string, any>
  dependencies: Record<string, string>
}

export interface TestMetadata {
  testId: string
  testName: string
  testDescription: string
  filePath: string
  relativePath: string
  suite: string
  category: TestCategory
  tags: string[]
  priority: TestPriority
  author?: string
  lastModified?: string
}

export interface TestPerformanceMetrics {
  startTime: number
  endTime: number
  duration: number
  memoryUsage: {
    heapUsed: number
    heapTotal: number
    external: number
    rss: number
  }
  cpuUsage?: {
    user: number
    system: number
  }
  resourceUsage?: {
    fileHandles: number
    networkConnections: number
  }
}

export interface TestResult {
  metadata: TestMetadata
  status: TestStatus
  performance: TestPerformanceMetrics
  error?: TestError
  assertions?: TestAssertion[]
  coverage?: TestCoverage
  retryCount: number
  flakiness?: TestFlakiness
  githubIssue?: GitHubIssueReference
}

export interface TestError {
  message: string
  stack?: string
  type: ErrorType
  severity: ErrorSeverity
  category: ErrorCategory
  reproductionSteps?: string[]
  expectedBehavior?: string
  actualBehavior?: string
  debugInfo?: Record<string, any>
}

export interface TestAssertion {
  description: string
  expected: any
  actual: any
  passed: boolean
  operator: string
  location?: {
    file: string
    line: number
    column: number
  }
}

export interface TestCoverage {
  lines: {
    total: number
    covered: number
    percentage: number
  }
  functions: {
    total: number
    covered: number
    percentage: number
  }
  branches: {
    total: number
    covered: number
    percentage: number
  }
  statements: {
    total: number
    covered: number
    percentage: number
  }
  files: string[]
}

export interface TestFlakiness {
  isFlaky: boolean
  flakinessScore: number // 0-1, where 1 is most flaky
  historicalFailureRate: number
  consecutiveFailures: number
  lastStableRun?: string
}

export interface GitHubIssueReference {
  issueNumber?: number
  issueUrl?: string
  status: 'open' | 'closed' | 'pending'
  createdAt?: string
  assignees?: string[]
  labels?: string[]
  resolution?: string
}

export interface TestSuiteResult {
  metadata: {
    suiteName: string
    suiteDescription: string
    filePath: string
    totalTests: number
    executionContext: TestExecutionContext
  }
  summary: {
    passed: number
    failed: number
    skipped: number
    pending: number
    successRate: number
    duration: number
    criticalFailures: number
    highPriorityFailures: number
  }
  tests: TestResult[]
  coverage: TestCoverage
  performance: {
    averageDuration: number
    slowestTest: TestResult
    fastestTest: TestResult
    memoryPeak: number
    totalMemoryUsage: number
  }
  trends?: TestTrends
  recommendations: TestRecommendation[]
}

export interface TestTrends {
  historicalSuccessRate: number[]
  performanceTrend: 'improving' | 'degrading' | 'stable'
  flakinessScore: number
  regressionDetected: boolean
  qualityGate: 'passed' | 'failed' | 'warning'
}

export interface TestRecommendation {
  type: 'performance' | 'reliability' | 'coverage' | 'maintenance'
  priority: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  actionItems: string[]
  estimatedEffort?: string
  relatedTests?: string[]
}

export interface ComprehensiveTestReport {
  metadata: {
    reportId: string
    generatedAt: string
    version: string
    reportType: 'comprehensive' | 'summary' | 'executive'
    generator: string
  }
  executiveSummary: {
    overallStatus: 'passed' | 'failed' | 'warning'
    totalSuites: number
    totalTests: number
    successRate: number
    criticalIssues: number
    keyMetrics: Record<string, number>
    qualityGate: 'passed' | 'failed' | 'warning'
  }
  testInventory: {
    suites: TestSuiteResult[]
    categories: Record<TestCategory, number>
    priorities: Record<TestPriority, number>
    environments: string[]
  }
  detailedResults: {
    failures: TestResult[]
    criticalFailures: TestResult[]
    flakyTests: TestResult[]
    slowTests: TestResult[]
    coverageGaps: string[]
  }
  issueTracking: {
    openIssues: GitHubIssueReference[]
    resolvedIssues: GitHubIssueReference[]
    newIssuesCreated: GitHubIssueReference[]
    escalatedIssues: GitHubIssueReference[]
  }
  performanceAnalysis: {
    executionMetrics: TestPerformanceMetrics
    resourceUsage: Record<string, number>
    bottlenecks: string[]
    optimizationOpportunities: string[]
  }
  recommendations: {
    immediate: TestRecommendation[]
    shortTerm: TestRecommendation[]
    longTerm: TestRecommendation[]
  }
  historicalContext: {
    previousReports: string[]
    trendAnalysis: TestTrends
    regressionAnalysis: {
      detected: boolean
      affectedTests: string[]
      rootCause?: string
    }
    improvementTracking: {
      resolvedIssues: number
      performanceGains: number
      coverageIncrease: number
    }
  }
}

// Enums
export enum TestStatus {
  PASSED = 'passed',
  FAILED = 'failed',
  SKIPPED = 'skipped',
  PENDING = 'pending',
  TIMEOUT = 'timeout',
  ERROR = 'error'
}

export enum TestCategory {
  UNIT = 'unit',
  INTEGRATION = 'integration',
  E2E = 'e2e',
  SYSTEM = 'system',
  REGRESSION = 'regression',
  ACCEPTANCE = 'acceptance',
  PERFORMANCE = 'performance',
  LOAD = 'load',
  SECURITY = 'security',
  COMPATIBILITY = 'compatibility',
  ACCESSIBILITY = 'accessibility',
  EXPLORATORY = 'exploratory'
}

export enum TestPriority {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low'
}

export enum ErrorType {
  ASSERTION = 'assertion',
  TIMEOUT = 'timeout',
  SYNTAX = 'syntax',
  ASYNC = 'async',
  DEPENDENCY = 'dependency',
  MOCK = 'mock',
  NETWORK = 'network',
  DATABASE = 'database',
  PERMISSION = 'permission',
  CONFIGURATION = 'configuration',
  UNKNOWN = 'unknown'
}

export enum ErrorSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low'
}

export enum ErrorCategory {
  FUNCTIONAL = 'functional',
  PERFORMANCE = 'performance',
  SECURITY = 'security',
  USABILITY = 'usability',
  COMPATIBILITY = 'compatibility',
  RELIABILITY = 'reliability',
  MAINTAINABILITY = 'maintainability'
}
