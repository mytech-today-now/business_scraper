/**
 * Multi-User Components Export Index
 * Centralized exports for all multi-user collaboration components
 */

export { UserManagement } from './UserManagement'
export { TeamWorkspace } from './TeamWorkspace'
export { CollaborationPanel } from './CollaborationPanel'
export { AnalyticsDashboard } from './AnalyticsDashboard'

// Re-export types for convenience
export type {
  User,
  Role,
  Team,
  Workspace,
  CreateUserRequest,
  UpdateUserRequest,
  CreateTeamRequest,
  CreateWorkspaceRequest,
  CollaborationEvent,
  RealtimeUpdate,
  NotificationMessage,
  DashboardMetrics,
  PerformanceMetrics,
  DataQualityMetrics,
  UserActivitySummary,
  TeamPerformance,
  WorkspaceAnalytics
} from '@/types/multi-user'
