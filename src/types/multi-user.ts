/**
 * Multi-User Collaboration Type Definitions
 * Comprehensive TypeScript interfaces for users, roles, teams, workspaces, and collaboration features
 */

// Base types for common fields
export interface BaseEntity {
  id: string
  createdAt: Date
  updatedAt: Date
}

export interface TimestampedEntity extends BaseEntity {
  createdAt: Date
  updatedAt: Date
}

// Permission system types
export type Permission = 
  // System permissions
  | 'system.manage'
  | 'system.view'
  // User management
  | 'users.manage'
  | 'users.invite'
  | 'users.view'
  | 'users.edit'
  | 'users.delete'
  // Team management
  | 'teams.manage'
  | 'teams.create'
  | 'teams.edit'
  | 'teams.delete'
  | 'teams.view'
  | 'teams.invite'
  // Workspace management
  | 'workspaces.manage'
  | 'workspaces.create'
  | 'workspaces.edit'
  | 'workspaces.delete'
  | 'workspaces.view'
  | 'workspaces.invite'
  // Campaign management
  | 'campaigns.manage'
  | 'campaigns.create'
  | 'campaigns.edit'
  | 'campaigns.delete'
  | 'campaigns.view'
  | 'campaigns.run'
  // Data management
  | 'data.manage'
  | 'data.view'
  | 'data.edit'
  | 'data.delete'
  | 'data.validate'
  | 'data.enrich'
  | 'data.export'
  // Scraping operations
  | 'scraping.run'
  | 'scraping.view'
  | 'scraping.manage'
  // Analytics and reporting
  | 'analytics.view'
  | 'analytics.manage'
  | 'reports.create'
  | 'reports.view'
  | 'reports.export'
  // Audit and compliance
  | 'audit.view'
  | 'audit.manage'

export type RoleName = 'admin' | 'manager' | 'analyst' | 'contributor' | 'viewer'

export type TeamRole = 'owner' | 'admin' | 'member' | 'viewer'

export type WorkspaceRole = 'admin' | 'manager' | 'analyst' | 'contributor' | 'viewer'

// User-related types
export interface User extends TimestampedEntity {
  username: string
  email: string
  firstName: string
  lastName: string
  avatarUrl?: string
  isActive: boolean
  isVerified: boolean
  lastLoginAt?: Date
  passwordChangedAt: Date
  
  // Profile information
  jobTitle?: string
  department?: string
  phone?: string
  timezone: string
  language: string
  preferences: UserPreferences
  
  // Security settings
  twoFactorEnabled: boolean
  twoFactorSecret?: string
  failedLoginAttempts: number
  lockedUntil?: Date
}

export interface UserPreferences {
  theme?: 'light' | 'dark' | 'auto'
  notifications?: NotificationPreferences
  dashboard?: DashboardPreferences
  scraping?: ScrapingPreferences
  [key: string]: any
}

export interface NotificationPreferences {
  email: boolean
  browser: boolean
  scrapingComplete: boolean
  teamInvites: boolean
  dataValidation: boolean
  systemAlerts: boolean
}

export interface DashboardPreferences {
  defaultView: 'campaigns' | 'analytics' | 'team'
  chartsVisible: boolean
  refreshInterval: number
  compactMode: boolean
}

export interface ScrapingPreferences {
  defaultSearchRadius: number
  defaultSearchDepth: number
  defaultPagesPerSite: number
  autoValidation: boolean
}

export interface UserProfile {
  id: string
  username: string
  email: string
  firstName: string
  lastName: string
  fullName: string
  avatarUrl?: string
  jobTitle?: string
  department?: string
  isActive: boolean
  lastLoginAt?: Date
  roles: UserRole[]
  teams: TeamMembership[]
  workspaces: WorkspaceMembership[]
}

// Role and permission types
export interface Role extends TimestampedEntity {
  name: RoleName
  displayName: string
  description?: string
  isSystemRole: boolean
  permissions: Permission[]
}

export interface UserRole extends BaseEntity {
  userId: string
  roleId: string
  role: Role
  assignedBy?: string
  assignedAt: Date
  expiresAt?: Date
  isActive: boolean
}

// Team-related types
export interface Team extends TimestampedEntity {
  name: string
  description?: string
  ownerId: string
  owner: User
  isActive: boolean
  settings: TeamSettings
  memberCount?: number
  workspaceCount?: number
}

export interface TeamSettings {
  allowMemberInvites: boolean
  requireApprovalForJoining: boolean
  defaultWorkspaceRole: WorkspaceRole
  [key: string]: any
}

export interface TeamMembership extends BaseEntity {
  teamId: string
  team: Team
  userId: string
  user: User
  role: TeamRole
  joinedAt: Date
  invitedBy?: string
  isActive: boolean
}

// Workspace-related types
export interface Workspace extends TimestampedEntity {
  name: string
  description?: string
  teamId: string
  team: Team
  ownerId: string
  owner: User
  isActive: boolean
  settings: WorkspaceSettings
  
  // Workspace configuration
  defaultSearchRadius: number
  defaultSearchDepth: number
  defaultPagesPerSite: number
  
  // Computed fields
  memberCount?: number
  campaignCount?: number
  businessCount?: number
}

export interface WorkspaceSettings {
  isPublic: boolean
  allowGuestAccess: boolean
  requireApprovalForJoining: boolean
  defaultCampaignSettings: CampaignDefaults
  collaborationSettings: CollaborationSettings
  [key: string]: any
}

export interface CampaignDefaults {
  searchRadius: number
  searchDepth: number
  pagesPerSite: number
  autoValidation: boolean
  sharingEnabled: boolean
}

export interface CollaborationSettings {
  realTimeEditing: boolean
  lockTimeout: number // in minutes
  conflictResolution: 'manual' | 'auto' | 'latest-wins'
  notifyOnChanges: boolean
}

export interface WorkspaceMembership extends BaseEntity {
  workspaceId: string
  workspace: Workspace
  userId: string
  user: User
  role: WorkspaceRole
  permissions: Permission[]
  joinedAt: Date
  invitedBy?: string
  isActive: boolean
}

// Audit and activity tracking types
export type AuditAction = 
  | 'user.login'
  | 'user.logout'
  | 'user.created'
  | 'user.updated'
  | 'user.deleted'
  | 'team.created'
  | 'team.updated'
  | 'team.deleted'
  | 'team.member.added'
  | 'team.member.removed'
  | 'workspace.created'
  | 'workspace.updated'
  | 'workspace.deleted'
  | 'workspace.member.added'
  | 'workspace.member.removed'
  | 'campaign.created'
  | 'campaign.updated'
  | 'campaign.deleted'
  | 'campaign.started'
  | 'campaign.completed'
  | 'scraping.started'
  | 'scraping.completed'
  | 'scraping.failed'
  | 'data.validated'
  | 'data.enriched'
  | 'data.exported'
  | 'role.assigned'
  | 'role.revoked'
  | 'permission.granted'
  | 'permission.revoked'

export type AuditSeverity = 'debug' | 'info' | 'warn' | 'error' | 'critical'

export interface AuditLog extends BaseEntity {
  userId?: string
  user?: User
  action: AuditAction
  resourceType: string
  resourceId?: string
  workspaceId?: string
  workspace?: Workspace
  teamId?: string
  team?: Team
  details: Record<string, any>
  ipAddress?: string
  userAgent?: string
  timestamp: Date
  sessionId?: string
  correlationId?: string
  severity: AuditSeverity
}

// Session management types
export interface UserSession extends BaseEntity {
  userId: string
  user: User
  sessionToken: string
  csrfToken: string
  ipAddress?: string
  userAgent?: string
  isActive: boolean
  expiresAt: Date
  lastAccessedAt: Date
  deviceInfo: DeviceInfo
  locationInfo: LocationInfo
}

export interface DeviceInfo {
  type: 'desktop' | 'mobile' | 'tablet' | 'unknown'
  os?: string
  browser?: string
  version?: string
}

export interface LocationInfo {
  country?: string
  region?: string
  city?: string
  timezone?: string
}

// Collaboration and conflict resolution types
export type LockType = 'edit' | 'view' | 'delete'

export interface CollaborationLock extends BaseEntity {
  resourceType: string
  resourceId: string
  userId: string
  user: User
  workspaceId?: string
  workspace?: Workspace
  lockType: LockType
  acquiredAt: Date
  expiresAt: Date
  isActive: boolean
  details: Record<string, any>
}

// Analytics and reporting types
export interface UserActivitySummary {
  id: string
  username: string
  firstName: string
  lastName: string
  lastLoginAt?: Date
  campaignsCreated: number
  businessesValidated: number
  scrapingSessionsRun: number
  totalActions: number
  avgValidationScore?: number
}

export interface TeamPerformance {
  id: string
  name: string
  memberCount: number
  workspaceCount: number
  totalCampaigns: number
  totalBusinesses: number
  avgConfidenceScore?: number
  completedCampaigns: number
}

export interface WorkspaceAnalytics {
  id: string
  name: string
  teamName: string
  memberCount: number
  campaignCount: number
  businessCount: number
  sessionCount: number
  avgConfidenceScore?: number
  validatedBusinesses: number
  completedCampaigns: number
  lastScrapingActivity?: Date
}

export interface ActiveCollaboration {
  resourceType: string
  resourceId: string
  username: string
  firstName: string
  lastName: string
  workspaceName?: string
  lockType: LockType
  acquiredAt: Date
  expiresAt: Date
  minutesRemaining: number
}

// API request/response types for multi-user operations
export interface CreateUserRequest {
  username: string
  email: string
  password: string
  firstName: string
  lastName: string
  jobTitle?: string
  department?: string
  phone?: string
  timezone?: string
  language?: string
}

export interface UpdateUserRequest {
  firstName?: string
  lastName?: string
  jobTitle?: string
  department?: string
  phone?: string
  timezone?: string
  language?: string
  preferences?: Partial<UserPreferences>
}

export interface CreateTeamRequest {
  name: string
  description?: string
  settings?: Partial<TeamSettings>
}

export interface UpdateTeamRequest {
  name?: string
  description?: string
  settings?: Partial<TeamSettings>
}

export interface CreateWorkspaceRequest {
  name: string
  description?: string
  teamId: string
  settings?: Partial<WorkspaceSettings>
  defaultSearchRadius?: number
  defaultSearchDepth?: number
  defaultPagesPerSite?: number
}

export interface UpdateWorkspaceRequest {
  name?: string
  description?: string
  settings?: Partial<WorkspaceSettings>
  defaultSearchRadius?: number
  defaultSearchDepth?: number
  defaultPagesPerSite?: number
}

export interface InviteUserRequest {
  email: string
  role: WorkspaceRole | TeamRole
  workspaceId?: string
  teamId?: string
  message?: string
}

export interface AssignRoleRequest {
  userId: string
  roleId: string
  expiresAt?: Date
}

export interface GrantPermissionRequest {
  userId: string
  workspaceId: string
  permissions: Permission[]
}

// Real-time collaboration types
export interface CollaborationEvent {
  type: 'user_joined' | 'user_left' | 'resource_locked' | 'resource_unlocked' | 'data_updated'
  userId: string
  username: string
  workspaceId: string
  resourceType?: string
  resourceId?: string
  timestamp: Date
  data?: Record<string, any>
}

export interface RealtimeUpdate {
  id: string
  type: 'campaign' | 'business' | 'session' | 'user' | 'workspace'
  action: 'created' | 'updated' | 'deleted'
  resourceId: string
  userId: string
  workspaceId: string
  data: Record<string, any>
  timestamp: Date
}

// ROI and analytics types
export interface ROIMetrics {
  workspaceId: string
  period: 'day' | 'week' | 'month' | 'quarter' | 'year'
  startDate: Date
  endDate: Date

  // Input metrics
  totalCampaigns: number
  totalScrapingSessions: number
  totalTimeSpent: number // in hours
  totalCosts: number // estimated costs

  // Output metrics
  totalBusinessesFound: number
  validatedBusinesses: number
  highQualityLeads: number // confidence > 0.8
  contactsEnriched: number

  // Quality metrics
  avgConfidenceScore: number
  dataAccuracyRate: number
  duplicateRate: number

  // Conversion metrics (if available)
  leadsContacted?: number
  responseRate?: number
  conversionRate?: number

  // ROI calculations
  costPerLead: number
  costPerValidatedLead: number
  estimatedValue: number
  roi: number // return on investment percentage
}

export interface PerformanceMetrics {
  workspaceId: string
  period: 'hour' | 'day' | 'week' | 'month'
  timestamp: Date

  // Scraping performance
  avgScrapingTime: number // in seconds
  requestThroughput: number // requests per minute
  errorRate: number // percentage
  successRate: number // percentage

  // System performance
  avgResponseTime: number // in milliseconds
  memoryUsage: number // in MB
  cpuUsage: number // percentage

  // User activity
  activeUsers: number
  concurrentSessions: number
  totalActions: number
}

export interface DataQualityMetrics {
  workspaceId: string
  campaignId?: string
  period: 'day' | 'week' | 'month'

  // Data quality indicators
  totalRecords: number
  validRecords: number
  invalidRecords: number
  duplicateRecords: number
  incompleteRecords: number

  // Confidence score distribution
  highConfidence: number // > 0.8
  mediumConfidence: number // 0.5 - 0.8
  lowConfidence: number // < 0.5

  // Enrichment metrics
  enrichmentRate: number // percentage of records enriched
  enrichmentAccuracy: number // accuracy of enriched data

  // Validation metrics
  validationRate: number // percentage of records validated
  validationAccuracy: number // accuracy of validation
  avgValidationTime: number // in seconds
}

// Extended business record for multi-user context
export interface MultiUserBusinessRecord {
  id: string
  campaignId: string
  workspaceId: string
  name: string
  email: string[]
  phone?: string
  website?: string
  address: Record<string, any>
  confidenceScore: number
  scrapedAt: Date

  // Multi-user fields
  createdBy: string
  updatedBy?: string
  validationStatus: 'pending' | 'validated' | 'rejected' | 'needs_review'
  validatedBy?: string
  validatedAt?: Date

  // Additional business data
  contactPerson?: string
  coordinates?: { lat: number; lng: number }
  industry?: string
  businessDescription?: string
  socialMedia?: Record<string, string>
  businessHours?: Record<string, any>
  employeeCount?: number
  annualRevenue?: number
  foundedYear?: number

  // Metadata
  createdAt: Date
  updatedAt: Date
}

// Extended campaign for multi-user context
export interface MultiUserCampaign {
  id: string
  workspaceId: string
  name: string
  industry: string
  location: string
  status: 'draft' | 'active' | 'paused' | 'completed' | 'cancelled'
  createdAt: Date
  updatedAt: Date
  parameters: Record<string, any>

  // Multi-user fields
  createdBy: string
  updatedBy?: string
  isShared: boolean
  sharingPermissions: Record<string, any>

  // Additional campaign metadata
  description?: string
  searchRadius: number
  searchDepth: number
  pagesPerSite: number
  zipCode?: string

  // Computed fields
  businessCount?: number
  sessionCount?: number
  lastActivity?: Date
}

// Utility types for API responses
export interface PaginatedResponse<T> {
  data: T[]
  pagination: {
    page: number
    limit: number
    total: number
    totalPages: number
    hasNext: boolean
    hasPrev: boolean
  }
}

export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  error?: string
  message?: string
  timestamp: Date
}

export interface MultiUserApiError {
  code: string
  message: string
  details?: Record<string, any>
  timestamp: Date
  requestId?: string
}

// WebSocket message types for real-time collaboration
export interface WebSocketMessage {
  type: 'collaboration_event' | 'realtime_update' | 'notification' | 'heartbeat'
  payload: CollaborationEvent | RealtimeUpdate | NotificationMessage | HeartbeatMessage
  timestamp: Date
  userId?: string
  workspaceId?: string
}

export interface NotificationMessage {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  message: string
  userId: string
  workspaceId?: string
  actionUrl?: string
  expiresAt?: Date
}

export interface HeartbeatMessage {
  userId: string
  workspaceId: string
  timestamp: Date
}
