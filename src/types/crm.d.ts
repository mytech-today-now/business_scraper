/**
 * CRM Integration Type Definitions
 * Comprehensive types for enterprise CRM integrations
 */

import { BusinessRecord } from './business'

// Base CRM Integration Types
export interface CRMProvider {
  id: string
  name: string
  type: 'salesforce' | 'hubspot' | 'pipedrive' | 'custom'
  version: string
  isActive: boolean
  configuration: CRMConfiguration
  capabilities: CRMCapabilities
}

export interface CRMConfiguration {
  apiEndpoint: string
  authentication: CRMAuthentication
  syncSettings: SyncSettings
  fieldMappings: FieldMapping[]
  webhookUrl?: string
  rateLimits: RateLimitConfig
}

export interface CRMAuthentication {
  type: 'oauth2' | 'api_key' | 'basic' | 'custom'
  credentials: Record<string, string>
  tokenExpiry?: Date
  refreshToken?: string
  scopes?: string[]
}

export interface CRMCapabilities {
  bidirectionalSync: boolean
  realTimeUpdates: boolean
  bulkOperations: boolean
  customFields: boolean
  webhookSupport: boolean
  deduplication: boolean
  validation: boolean
}

export interface SyncSettings {
  direction: 'push' | 'pull' | 'bidirectional'
  frequency: 'realtime' | 'hourly' | 'daily' | 'weekly' | 'manual'
  batchSize: number
  conflictResolution: 'source_wins' | 'target_wins' | 'merge' | 'manual'
  enableDeduplication: boolean
  enableValidation: boolean
}

export interface FieldMapping {
  sourceField: string
  targetField: string
  transformation?: string
  required: boolean
  dataType: 'string' | 'number' | 'boolean' | 'date' | 'array' | 'object'
}

export interface RateLimitConfig {
  requestsPerMinute: number
  requestsPerHour: number
  requestsPerDay: number
  burstLimit: number
}

// Salesforce Specific Types
export interface SalesforceConfiguration extends CRMConfiguration {
  instanceUrl: string
  apiVersion: string
  managedPackageNamespace?: string
  customObjects: SalesforceCustomObject[]
  triggers: SalesforceTrigger[]
  lwcComponents: SalesforceLWC[]
}

export interface SalesforceCustomObject {
  apiName: string
  label: string
  fields: SalesforceField[]
  triggers: string[]
}

export interface SalesforceField {
  apiName: string
  label: string
  type: string
  required: boolean
  unique: boolean
}

export interface SalesforceTrigger {
  name: string
  objectName: string
  events: (
    | 'before_insert'
    | 'after_insert'
    | 'before_update'
    | 'after_update'
    | 'before_delete'
    | 'after_delete'
  )[]
  isActive: boolean
}

export interface SalesforceLWC {
  name: string
  description: string
  targets: string[]
  isExposed: boolean
}

// HubSpot Specific Types
export interface HubSpotConfiguration extends CRMConfiguration {
  portalId: string
  appId: string
  marketplaceListingId?: string
  pipelines: HubSpotPipeline[]
  properties: HubSpotProperty[]
  workflows: HubSpotWorkflow[]
}

export interface HubSpotPipeline {
  id: string
  label: string
  stages: HubSpotStage[]
  objectType: 'contacts' | 'companies' | 'deals' | 'tickets'
}

export interface HubSpotStage {
  id: string
  label: string
  probability: number
  closedWon: boolean
}

export interface HubSpotProperty {
  name: string
  label: string
  type: string
  fieldType: string
  groupName: string
  options?: HubSpotPropertyOption[]
}

export interface HubSpotPropertyOption {
  label: string
  value: string
  displayOrder: number
}

export interface HubSpotWorkflow {
  id: string
  name: string
  type: string
  enabled: boolean
  triggers: HubSpotTrigger[]
  actions: HubSpotAction[]
}

export interface HubSpotTrigger {
  type: string
  filterFamily: string
  filters: HubSpotFilter[]
}

export interface HubSpotFilter {
  property: string
  operator: string
  value: string
}

export interface HubSpotAction {
  type: string
  settings: Record<string, any>
}

// Pipedrive Specific Types
export interface PipedriveConfiguration extends CRMConfiguration {
  companyDomain: string
  pipelines: PipedrivePipeline[]
  customFields: PipedriveCustomField[]
  activities: PipedriveActivity[]
}

export interface PipedrivePipeline {
  id: number
  name: string
  stages: PipedriveStage[]
  dealProbability: boolean
}

export interface PipedriveStage {
  id: number
  name: string
  pipelineId: number
  rottenFlag: boolean
  rottenDays: number
}

export interface PipedriveCustomField {
  id: number
  key: string
  name: string
  fieldType: string
  options?: PipedriveFieldOption[]
}

export interface PipedriveFieldOption {
  id: number
  label: string
}

export interface PipedriveActivity {
  id: number
  subject: string
  type: string
  dueDate?: Date
  duration?: string
}

// CRM Sync Data Types
export interface CRMSyncRecord {
  id: string
  crmProviderId: string
  sourceRecordId: string
  targetRecordId?: string
  businessRecord: BusinessRecord
  syncStatus: 'pending' | 'syncing' | 'synced' | 'failed' | 'conflict'
  syncDirection: 'push' | 'pull'
  lastSyncAt?: Date
  nextSyncAt?: Date
  syncAttempts: number
  errors: CRMSyncError[]
  metadata: Record<string, any>
}

export interface CRMSyncError {
  timestamp: Date
  errorCode: string
  errorMessage: string
  errorDetails?: Record<string, any>
  isRetryable: boolean
}

export interface CRMSyncBatch {
  id: string
  crmProviderId: string
  records: CRMSyncRecord[]
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'partial'
  startedAt?: Date
  completedAt?: Date
  totalRecords: number
  successfulRecords: number
  failedRecords: number
  errors: CRMSyncError[]
}

// CRM Analytics and Reporting
export interface CRMSyncMetrics {
  crmProviderId: string
  timeRange: {
    start: Date
    end: Date
  }
  totalSyncs: number
  successfulSyncs: number
  failedSyncs: number
  averageSyncTime: number
  dataQualityScore: number
  deduplicationRate: number
  validationErrors: number
}

export interface CRMDataQuality {
  recordId: string
  qualityScore: number
  issues: CRMDataQualityIssue[]
  suggestions: CRMDataQualitySuggestion[]
}

export interface CRMDataQualityIssue {
  field: string
  issueType: 'missing' | 'invalid' | 'duplicate' | 'outdated' | 'inconsistent'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
}

export interface CRMDataQualitySuggestion {
  field: string
  suggestedValue: string
  confidence: number
  reason: string
}

// Webhook and Real-time Update Types
export interface CRMWebhookEvent {
  id: string
  crmProviderId: string
  eventType: string
  objectType: string
  objectId: string
  timestamp: Date
  data: Record<string, any>
  signature?: string
}

export interface CRMWebhookSubscription {
  id: string
  crmProviderId: string
  eventTypes: string[]
  callbackUrl: string
  isActive: boolean
  secret: string
  createdAt: Date
  lastTriggeredAt?: Date
}

// Custom CRM Adapter Types
export interface CustomCRMAdapter {
  id: string
  name: string
  description: string
  apiType: 'rest' | 'graphql' | 'soap' | 'custom'
  endpoints: CRMEndpoint[]
  authentication: CRMAuthentication
  dataMapping: CustomDataMapping
  validation: CustomValidation
}

export interface CRMEndpoint {
  name: string
  url: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  headers: Record<string, string>
  queryParams?: Record<string, string>
  bodyTemplate?: string
  responseMapping: ResponseMapping
}

export interface ResponseMapping {
  dataPath: string
  fields: FieldMapping[]
  pagination?: PaginationMapping
}

export interface PaginationMapping {
  nextPagePath?: string
  totalCountPath?: string
  pageSize: number
}

export interface CustomDataMapping {
  businessToTarget: FieldMapping[]
  targetToBusiness: FieldMapping[]
  transformations: DataTransformation[]
}

export interface DataTransformation {
  name: string
  type: 'format' | 'calculate' | 'lookup' | 'conditional'
  sourceFields: string[]
  targetField: string
  logic: string
}

export interface CustomValidation {
  rules: ValidationRule[]
  requiredFields: string[]
  uniqueFields: string[]
}

export interface ValidationRule {
  field: string
  type: 'regex' | 'range' | 'enum' | 'custom'
  value: string | number | string[]
  errorMessage: string
}
