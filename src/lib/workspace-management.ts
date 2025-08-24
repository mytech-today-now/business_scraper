/**
 * Workspace Management Service
 * Handles team workspaces, shared projects, and collaborative features
 */

import { 
  Workspace, 
  Team,
  WorkspaceMembership,
  CreateWorkspaceRequest,
  UpdateWorkspaceRequest,
  CreateTeamRequest,
  UpdateTeamRequest,
  WorkspaceRole,
  TeamRole,
  Permission
} from '@/types/multi-user'
import { database } from './postgresql-database'
import { logger } from '@/utils/logger'
import { generateId } from './security'
import { RBACService } from './rbac'

export class WorkspaceManagementService {
  /**
   * Create a new team
   */
  static async createTeam(
    teamData: CreateTeamRequest,
    ownerId: string
  ): Promise<Team> {
    try {
      const teamId = generateId()
      const now = new Date()

      // Insert team
      await database.query(`
        INSERT INTO teams (id, name, description, owner_id, settings, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        teamId,
        teamData.name,
        teamData.description || null,
        ownerId,
        JSON.stringify(teamData.settings || {
          allowMemberInvites: false,
          requireApprovalForJoining: true,
          defaultWorkspaceRole: 'contributor'
        }),
        now,
        now
      ])

      // Add owner as team member
      await database.query(`
        INSERT INTO team_members (team_id, user_id, role, invited_by, joined_at)
        VALUES ($1, $2, $3, $4, $5)
      `, [teamId, ownerId, 'owner', ownerId, now])

      // Get created team with owner info
      const team = await this.getTeamById(teamId)
      
      if (!team) {
        throw new Error('Failed to retrieve created team')
      }

      logger.info('Workspace Management', 'Team created successfully', {
        teamId,
        name: teamData.name,
        ownerId
      })

      return team
    } catch (error) {
      logger.error('Workspace Management', 'Error creating team', error)
      throw error
    }
  }

  /**
   * Create a new workspace
   */
  static async createWorkspace(
    workspaceData: CreateWorkspaceRequest,
    ownerId: string
  ): Promise<Workspace> {
    try {
      const workspaceId = generateId()
      const now = new Date()

      // Verify team exists and user has permission
      const team = await this.getTeamById(workspaceData.teamId)
      if (!team) {
        throw new Error('Team not found')
      }

      // Check if user can create workspaces in this team
      const teamMembership = await this.getTeamMembership(workspaceData.teamId, ownerId)
      if (!teamMembership || !['owner', 'admin'].includes(teamMembership.role)) {
        throw new Error('Insufficient permissions to create workspace in this team')
      }

      // Insert workspace
      await database.query(`
        INSERT INTO workspaces (
          id, name, description, team_id, owner_id, settings,
          default_search_radius, default_search_depth, default_pages_per_site,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      `, [
        workspaceId,
        workspaceData.name,
        workspaceData.description || null,
        workspaceData.teamId,
        ownerId,
        JSON.stringify(workspaceData.settings || {
          isPublic: false,
          allowGuestAccess: false,
          requireApprovalForJoining: true,
          defaultCampaignSettings: {
            searchRadius: workspaceData.defaultSearchRadius || 25,
            searchDepth: workspaceData.defaultSearchDepth || 3,
            pagesPerSite: workspaceData.defaultPagesPerSite || 5,
            autoValidation: false,
            sharingEnabled: true
          },
          collaborationSettings: {
            realTimeEditing: true,
            lockTimeout: 30,
            conflictResolution: 'manual',
            notifyOnChanges: true
          }
        }),
        workspaceData.defaultSearchRadius || 25,
        workspaceData.defaultSearchDepth || 3,
        workspaceData.defaultPagesPerSite || 5,
        now,
        now
      ])

      // Add owner as workspace member with admin role
      await database.query(`
        INSERT INTO workspace_members (workspace_id, user_id, role, permissions, invited_by, joined_at)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [
        workspaceId,
        ownerId,
        'admin',
        JSON.stringify(RBACService.getWorkspaceRolePermissions('admin')),
        ownerId,
        now
      ])

      // Get created workspace with full details
      const workspace = await this.getWorkspaceById(workspaceId)
      
      if (!workspace) {
        throw new Error('Failed to retrieve created workspace')
      }

      logger.info('Workspace Management', 'Workspace created successfully', {
        workspaceId,
        name: workspaceData.name,
        teamId: workspaceData.teamId,
        ownerId
      })

      return workspace
    } catch (error) {
      logger.error('Workspace Management', 'Error creating workspace', error)
      throw error
    }
  }

  /**
   * Get team by ID with full details
   */
  static async getTeamById(teamId: string): Promise<Team | null> {
    try {
      const result = await database.query(`
        SELECT 
          t.*,
          u.username as owner_username,
          u.first_name as owner_first_name,
          u.last_name as owner_last_name,
          COUNT(DISTINCT tm.user_id) as member_count,
          COUNT(DISTINCT w.id) as workspace_count
        FROM teams t
        JOIN users u ON t.owner_id = u.id
        LEFT JOIN team_members tm ON t.id = tm.team_id AND tm.is_active = true
        LEFT JOIN workspaces w ON t.id = w.team_id AND w.is_active = true
        WHERE t.id = $1 AND t.is_active = true
        GROUP BY t.id, u.username, u.first_name, u.last_name
      `, [teamId])

      if (!result.rows[0]) {
        return null
      }

      const row = result.rows[0]
      
      return {
        id: row.id,
        name: row.name,
        description: row.description,
        ownerId: row.owner_id,
        owner: {
          id: row.owner_id,
          username: row.owner_username,
          firstName: row.owner_first_name,
          lastName: row.owner_last_name
        } as any, // Simplified owner object
        isActive: row.is_active,
        settings: row.settings,
        memberCount: parseInt(row.member_count),
        workspaceCount: parseInt(row.workspace_count),
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }
    } catch (error) {
      logger.error('Workspace Management', 'Error fetching team by ID', error)
      throw error
    }
  }

  /**
   * Get workspace by ID with full details
   */
  static async getWorkspaceById(workspaceId: string): Promise<Workspace | null> {
    try {
      const result = await database.query(`
        SELECT 
          w.*,
          t.name as team_name,
          u.username as owner_username,
          u.first_name as owner_first_name,
          u.last_name as owner_last_name,
          COUNT(DISTINCT wm.user_id) as member_count,
          COUNT(DISTINCT c.id) as campaign_count,
          COUNT(DISTINCT b.id) as business_count
        FROM workspaces w
        JOIN teams t ON w.team_id = t.id
        JOIN users u ON w.owner_id = u.id
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id AND wm.is_active = true
        LEFT JOIN campaigns c ON w.id = c.workspace_id
        LEFT JOIN businesses b ON c.id = b.campaign_id
        WHERE w.id = $1 AND w.is_active = true
        GROUP BY w.id, t.name, u.username, u.first_name, u.last_name
      `, [workspaceId])

      if (!result.rows[0]) {
        return null
      }

      const row = result.rows[0]
      
      return {
        id: row.id,
        name: row.name,
        description: row.description,
        teamId: row.team_id,
        team: {
          id: row.team_id,
          name: row.team_name
        } as any, // Simplified team object
        ownerId: row.owner_id,
        owner: {
          id: row.owner_id,
          username: row.owner_username,
          firstName: row.owner_first_name,
          lastName: row.owner_last_name
        } as any, // Simplified owner object
        isActive: row.is_active,
        settings: row.settings,
        defaultSearchRadius: row.default_search_radius,
        defaultSearchDepth: row.default_search_depth,
        defaultPagesPerSite: row.default_pages_per_site,
        memberCount: parseInt(row.member_count),
        campaignCount: parseInt(row.campaign_count),
        businessCount: parseInt(row.business_count),
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }
    } catch (error) {
      logger.error('Workspace Management', 'Error fetching workspace by ID', error)
      throw error
    }
  }

  /**
   * Add user to team
   */
  static async addTeamMember(
    teamId: string,
    userId: string,
    role: TeamRole,
    invitedBy: string
  ): Promise<void> {
    try {
      // Check if user is already a member
      const existingMembership = await this.getTeamMembership(teamId, userId)
      if (existingMembership) {
        throw new Error('User is already a team member')
      }

      // Insert team membership
      await database.query(`
        INSERT INTO team_members (team_id, user_id, role, invited_by, joined_at)
        VALUES ($1, $2, $3, $4, $5)
      `, [teamId, userId, role, invitedBy, new Date()])

      logger.info('Workspace Management', 'Team member added successfully', {
        teamId,
        userId,
        role,
        invitedBy
      })
    } catch (error) {
      logger.error('Workspace Management', 'Error adding team member', error)
      throw error
    }
  }

  /**
   * Add user to workspace
   */
  static async addWorkspaceMember(
    workspaceId: string,
    userId: string,
    role: WorkspaceRole,
    permissions: Permission[],
    invitedBy: string
  ): Promise<void> {
    try {
      // Check if user is already a member
      const existingMembership = await this.getWorkspaceMembership(workspaceId, userId)
      if (existingMembership) {
        throw new Error('User is already a workspace member')
      }

      // Get default permissions for role if not provided
      const effectivePermissions = permissions.length > 0 
        ? permissions 
        : RBACService.getWorkspaceRolePermissions(role)

      // Insert workspace membership
      await database.query(`
        INSERT INTO workspace_members (workspace_id, user_id, role, permissions, invited_by, joined_at)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [
        workspaceId,
        userId,
        role,
        JSON.stringify(effectivePermissions),
        invitedBy,
        new Date()
      ])

      logger.info('Workspace Management', 'Workspace member added successfully', {
        workspaceId,
        userId,
        role,
        permissions: effectivePermissions,
        invitedBy
      })
    } catch (error) {
      logger.error('Workspace Management', 'Error adding workspace member', error)
      throw error
    }
  }

  /**
   * Get team membership for a user
   */
  static async getTeamMembership(teamId: string, userId: string): Promise<TeamMembership | null> {
    try {
      const result = await database.query(`
        SELECT tm.*, t.name as team_name, u.username, u.first_name, u.last_name
        FROM team_members tm
        JOIN teams t ON tm.team_id = t.id
        JOIN users u ON tm.user_id = u.id
        WHERE tm.team_id = $1 AND tm.user_id = $2 AND tm.is_active = true
      `, [teamId, userId])

      if (!result.rows[0]) {
        return null
      }

      const row = result.rows[0]
      
      return {
        id: row.id,
        teamId: row.team_id,
        team: {
          id: row.team_id,
          name: row.team_name
        } as any,
        userId: row.user_id,
        user: {
          id: row.user_id,
          username: row.username,
          firstName: row.first_name,
          lastName: row.last_name
        } as any,
        role: row.role,
        joinedAt: row.joined_at,
        isActive: row.is_active,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }
    } catch (error) {
      logger.error('Workspace Management', 'Error fetching team membership', error)
      throw error
    }
  }

  /**
   * Get workspace membership for a user
   */
  static async getWorkspaceMembership(workspaceId: string, userId: string): Promise<WorkspaceMembership | null> {
    try {
      const result = await database.query(`
        SELECT wm.*, w.name as workspace_name, u.username, u.first_name, u.last_name
        FROM workspace_members wm
        JOIN workspaces w ON wm.workspace_id = w.id
        JOIN users u ON wm.user_id = u.id
        WHERE wm.workspace_id = $1 AND wm.user_id = $2 AND wm.is_active = true
      `, [workspaceId, userId])

      if (!result.rows[0]) {
        return null
      }

      const row = result.rows[0]
      
      return {
        id: row.id,
        workspaceId: row.workspace_id,
        workspace: {
          id: row.workspace_id,
          name: row.workspace_name
        } as any,
        userId: row.user_id,
        user: {
          id: row.user_id,
          username: row.username,
          firstName: row.first_name,
          lastName: row.last_name
        } as any,
        role: row.role,
        permissions: row.permissions,
        joinedAt: row.joined_at,
        isActive: row.is_active,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }
    } catch (error) {
      logger.error('Workspace Management', 'Error fetching workspace membership', error)
      throw error
    }
  }

  /**
   * List user's teams
   */
  static async getUserTeams(userId: string): Promise<Team[]> {
    try {
      const result = await database.query(`
        SELECT 
          t.*,
          tm.role as user_role,
          tm.joined_at as user_joined_at,
          u.username as owner_username,
          COUNT(DISTINCT tm2.user_id) as member_count,
          COUNT(DISTINCT w.id) as workspace_count
        FROM teams t
        JOIN team_members tm ON t.id = tm.team_id
        JOIN users u ON t.owner_id = u.id
        LEFT JOIN team_members tm2 ON t.id = tm2.team_id AND tm2.is_active = true
        LEFT JOIN workspaces w ON t.id = w.team_id AND w.is_active = true
        WHERE tm.user_id = $1 AND tm.is_active = true AND t.is_active = true
        GROUP BY t.id, tm.role, tm.joined_at, u.username
        ORDER BY tm.joined_at DESC
      `, [userId])

      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        description: row.description,
        ownerId: row.owner_id,
        owner: {
          id: row.owner_id,
          username: row.owner_username
        } as any,
        isActive: row.is_active,
        settings: row.settings,
        memberCount: parseInt(row.member_count),
        workspaceCount: parseInt(row.workspace_count),
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }))
    } catch (error) {
      logger.error('Workspace Management', 'Error fetching user teams', error)
      throw error
    }
  }

  /**
   * List user's workspaces
   */
  static async getUserWorkspaces(userId: string): Promise<Workspace[]> {
    try {
      const result = await database.query(`
        SELECT 
          w.*,
          wm.role as user_role,
          wm.permissions as user_permissions,
          wm.joined_at as user_joined_at,
          t.name as team_name,
          u.username as owner_username,
          COUNT(DISTINCT wm2.user_id) as member_count,
          COUNT(DISTINCT c.id) as campaign_count
        FROM workspaces w
        JOIN workspace_members wm ON w.id = wm.workspace_id
        JOIN teams t ON w.team_id = t.id
        JOIN users u ON w.owner_id = u.id
        LEFT JOIN workspace_members wm2 ON w.id = wm2.workspace_id AND wm2.is_active = true
        LEFT JOIN campaigns c ON w.id = c.workspace_id
        WHERE wm.user_id = $1 AND wm.is_active = true AND w.is_active = true
        GROUP BY w.id, wm.role, wm.permissions, wm.joined_at, t.name, u.username
        ORDER BY wm.joined_at DESC
      `, [userId])

      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        description: row.description,
        teamId: row.team_id,
        team: {
          id: row.team_id,
          name: row.team_name
        } as any,
        ownerId: row.owner_id,
        owner: {
          id: row.owner_id,
          username: row.owner_username
        } as any,
        isActive: row.is_active,
        settings: row.settings,
        defaultSearchRadius: row.default_search_radius,
        defaultSearchDepth: row.default_search_depth,
        defaultPagesPerSite: row.default_pages_per_site,
        memberCount: parseInt(row.member_count),
        campaignCount: parseInt(row.campaign_count),
        createdAt: row.created_at,
        updatedAt: row.updated_at
      }))
    } catch (error) {
      logger.error('Workspace Management', 'Error fetching user workspaces', error)
      throw error
    }
  }
}
