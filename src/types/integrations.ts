/**
 * Integration System Type Definitions
 * Types for OAuth 2.0, webhooks, API framework, and scheduling
 */

/**
 * OAuth 2.0 Configuration
 */
export interface OAuth2Config {
  clientId: string
  clientSecret: string
  authorizationUrl: string
  tokenUrl: string
  redirectUri: string
  scopes: string[]
  responseType: 'code' | 'token'
  grantType: 'authorization_code' | 'client_credentials' | 'refresh_token'
  pkce?: boolean
  state?: string
}

/**
 * OAuth 2.0 Token
 */
export interface OAuth2Token {
  accessToken: string
  refreshToken?: string
  tokenType: 'Bearer' | 'Basic'
  expiresIn: number
  expiresAt: number
  scope: string[]
  issuedAt: number
}

/**
 * OAuth 2.0 Client
 */
export interface OAuth2Client {
  id: string
  name: string
  description: string
  config: OAuth2Config
  tokens: OAuth2Token[]
  status: 'active' | 'inactive' | 'revoked'
  createdAt: string
  updatedAt: string
  lastUsed?: string
  usageCount: number
}

/**
 * API Key Configuration
 */
export interface ApiKeyConfig {
  id: string
  name: string
  description: string
  key: string
  secret?: string
  permissions: ApiPermission[]
  rateLimit: {
    requestsPerMinute: number
    requestsPerHour: number
    requestsPerDay: number
  }
  ipWhitelist?: string[]
  expiresAt?: string
  status: 'active' | 'inactive' | 'revoked'
  createdAt: string
  lastUsed?: string
  usageCount: number
}

/**
 * API Permissions
 */
export type ApiPermission =
  | 'read:businesses'
  | 'write:businesses'
  | 'read:exports'
  | 'write:exports'
  | 'read:templates'
  | 'write:templates'
  | 'read:analytics'
  | 'admin:all'

/**
 * Webhook Configuration
 */
export interface WebhookConfig {
  id: string
  name: string
  description: string
  url: string
  events: WebhookEvent[]
  headers?: Record<string, string>
  secret?: string
  retryPolicy: {
    maxRetries: number
    retryDelay: number
    backoffMultiplier: number
    maxDelay: number
  }
  timeout: number
  status: 'active' | 'inactive' | 'failed'
  createdAt: string
  updatedAt: string
  lastTriggered?: string
  successCount: number
  failureCount: number
}

/**
 * Webhook Events
 */
export type WebhookEvent =
  | 'export.completed'
  | 'export.failed'
  | 'data.scraped'
  | 'data.validated'
  | 'template.created'
  | 'template.updated'
  | 'user.authenticated'
  | 'system.error'

/**
 * Webhook Payload
 */
export interface WebhookPayload {
  id: string
  event: WebhookEvent
  timestamp: string
  data: any
  metadata: {
    source: string
    version: string
    requestId: string
  }
}

/**
 * Webhook Delivery Result
 */
export interface WebhookDeliveryResult {
  id: string
  webhookId: string
  event: WebhookEvent
  url: string
  status: 'success' | 'failed' | 'pending' | 'retrying'
  httpStatus?: number
  responseTime: number
  attempts: number
  lastAttempt: string
  nextRetry?: string
  error?: string
  response?: string
}

/**
 * Export Schedule Configuration
 */
export interface ExportScheduleConfig {
  id: string
  name: string
  description: string
  templateId: string
  schedule: {
    type: 'cron' | 'interval'
    expression: string // Cron expression or interval (e.g., '0 9 * * 1' or '1h')
    timezone: string
  }
  filters?: {
    industries?: string[]
    locations?: string[]
    dateRange?: {
      start: string
      end: string
    }
    customFilters?: Record<string, any>
  }
  delivery: {
    method: 'webhook' | 'email' | 'ftp' | 'api'
    destination: string
    format: 'csv' | 'json' | 'xlsx'
    compression?: 'gzip' | 'zip'
  }
  status: 'active' | 'inactive' | 'paused'
  createdAt: string
  updatedAt: string
  lastRun?: string
  nextRun?: string
  runCount: number
  successCount: number
  failureCount: number
}

/**
 * Scheduled Export Result
 */
export interface ScheduledExportResult {
  id: string
  scheduleId: string
  templateId: string
  status: 'success' | 'failed' | 'running' | 'cancelled'
  startTime: string
  endTime?: string
  duration?: number
  recordsProcessed: number
  recordsExported: number
  errors: string[]
  deliveryStatus: 'pending' | 'delivered' | 'failed'
  deliveryDetails?: {
    method: string
    destination: string
    deliveredAt?: string
    error?: string
  }
}

/**
 * API Usage Analytics
 */
export interface ApiUsageAnalytics {
  clientId: string
  period: {
    start: string
    end: string
  }
  metrics: {
    totalRequests: number
    successfulRequests: number
    failedRequests: number
    averageResponseTime: number
    dataTransferred: number
    rateLimitHits: number
  }
  endpoints: Array<{
    path: string
    method: string
    requests: number
    averageResponseTime: number
    errorRate: number
  }>
  errors: Array<{
    timestamp: string
    endpoint: string
    error: string
    count: number
  }>
}

/**
 * Integration Health Status
 */
export interface IntegrationHealthStatus {
  service: string
  status: 'healthy' | 'degraded' | 'unhealthy'
  lastCheck: string
  responseTime: number
  uptime: number
  errors: Array<{
    timestamp: string
    error: string
    severity: 'low' | 'medium' | 'high' | 'critical'
  }>
  metrics: Record<string, number>
}

/**
 * API Framework Configuration
 */
export interface ApiFrameworkConfig {
  version: string
  baseUrl: string
  authentication: {
    methods: ('oauth2' | 'api_key' | 'session')[]
    defaultMethod: 'oauth2' | 'api_key' | 'session'
  }
  rateLimit: {
    global: {
      requestsPerMinute: number
      requestsPerHour: number
    }
    perClient: {
      requestsPerMinute: number
      requestsPerHour: number
    }
  }
  cors: {
    enabled: boolean
    origins: string[]
    methods: string[]
    headers: string[]
  }
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error'
    includeRequestBody: boolean
    includeResponseBody: boolean
    sensitiveFields: string[]
  }
  monitoring: {
    enabled: boolean
    metricsEndpoint: string
    healthEndpoint: string
  }
}

/**
 * API Request Context
 */
export interface ApiRequestContext {
  requestId: string
  clientId?: string
  userId?: string
  permissions: ApiPermission[]
  rateLimit: {
    remaining: number
    resetTime: number
  }
  startTime: number
  metadata: Record<string, any>
}

/**
 * API Response Format
 */
export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  error?: {
    code: string
    message: string
    details?: any
  }
  metadata: {
    requestId: string
    timestamp: string
    version: string
    rateLimit?: {
      remaining: number
      resetTime: number
    }
  }
  pagination?: {
    page: number
    limit: number
    total: number
    hasNext: boolean
    hasPrev: boolean
  }
}

/**
 * Integration Service Interface
 */
export interface IntegrationService {
  // OAuth 2.0 Management
  createOAuth2Client(
    config: Omit<
      OAuth2Client,
      'id' | 'tokens' | 'status' | 'createdAt' | 'updatedAt' | 'usageCount'
    >
  ): Promise<OAuth2Client>
  getOAuth2Client(id: string): Promise<OAuth2Client | null>
  refreshToken(clientId: string): Promise<OAuth2Token>
  revokeToken(clientId: string): Promise<void>

  // API Key Management
  createApiKey(
    config: Omit<ApiKeyConfig, 'id' | 'key' | 'status' | 'createdAt' | 'usageCount'>
  ): Promise<ApiKeyConfig>
  getApiKey(id: string): Promise<ApiKeyConfig | null>
  revokeApiKey(id: string): Promise<void>

  // Webhook Management
  createWebhook(
    config: Omit<
      WebhookConfig,
      'id' | 'status' | 'createdAt' | 'updatedAt' | 'successCount' | 'failureCount'
    >
  ): Promise<WebhookConfig>
  updateWebhook(id: string, config: Partial<WebhookConfig>): Promise<WebhookConfig>
  deleteWebhook(id: string): Promise<void>
  triggerWebhook(id: string, event: WebhookEvent, data: any): Promise<WebhookDeliveryResult>

  // Schedule Management
  createSchedule(
    config: Omit<
      ExportScheduleConfig,
      'id' | 'status' | 'createdAt' | 'updatedAt' | 'runCount' | 'successCount' | 'failureCount'
    >
  ): Promise<ExportScheduleConfig>
  updateSchedule(id: string, config: Partial<ExportScheduleConfig>): Promise<ExportScheduleConfig>
  deleteSchedule(id: string): Promise<void>

  // Analytics
  getUsageAnalytics(
    clientId: string,
    period: { start: string; end: string }
  ): Promise<ApiUsageAnalytics>
  getHealthStatus(): Promise<IntegrationHealthStatus[]>
}
