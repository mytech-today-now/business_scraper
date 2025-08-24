/**
 * Role-Based Access Control (RBAC) System
 * Provides comprehensive permission checking and role management
 */

import { 
  Permission, 
  RoleName, 
  User, 
  Role, 
  UserRole, 
  WorkspaceRole, 
  TeamRole,
  WorkspaceMembership,
  TeamMembership 
} from '@/types/multi-user'
import { logger } from '@/utils/logger'

// Permission hierarchy and relationships
const PERMISSION_HIERARCHY: Record<Permission, Permission[]> = {
  // System permissions
  'system.manage': ['system.view', 'users.manage', 'teams.manage', 'workspaces.manage'],
  'system.view': [],
  
  // User management permissions
  'users.manage': ['users.view', 'users.edit', 'users.delete', 'users.invite'],
  'users.invite': ['users.view'],
  'users.view': [],
  'users.edit': ['users.view'],
  'users.delete': ['users.view'],
  
  // Team management permissions
  'teams.manage': ['teams.create', 'teams.edit', 'teams.delete', 'teams.view', 'teams.invite'],
  'teams.create': ['teams.view'],
  'teams.edit': ['teams.view'],
  'teams.delete': ['teams.view'],
  'teams.view': [],
  'teams.invite': ['teams.view'],
  
  // Workspace management permissions
  'workspaces.manage': ['workspaces.create', 'workspaces.edit', 'workspaces.delete', 'workspaces.view', 'workspaces.invite'],
  'workspaces.create': ['workspaces.view'],
  'workspaces.edit': ['workspaces.view'],
  'workspaces.delete': ['workspaces.view'],
  'workspaces.view': [],
  'workspaces.invite': ['workspaces.view'],
  
  // Campaign management permissions
  'campaigns.manage': ['campaigns.create', 'campaigns.edit', 'campaigns.delete', 'campaigns.view', 'campaigns.run'],
  'campaigns.create': ['campaigns.view'],
  'campaigns.edit': ['campaigns.view'],
  'campaigns.delete': ['campaigns.view'],
  'campaigns.view': [],
  'campaigns.run': ['campaigns.view'],
  
  // Data management permissions
  'data.manage': ['data.view', 'data.edit', 'data.delete', 'data.validate', 'data.enrich', 'data.export'],
  'data.view': [],
  'data.edit': ['data.view'],
  'data.delete': ['data.view'],
  'data.validate': ['data.view'],
  'data.enrich': ['data.view'],
  'data.export': ['data.view'],
  
  // Scraping permissions
  'scraping.manage': ['scraping.run', 'scraping.view'],
  'scraping.run': ['scraping.view'],
  'scraping.view': [],
  
  // Analytics permissions
  'analytics.manage': ['analytics.view', 'reports.create', 'reports.view', 'reports.export'],
  'analytics.view': [],
  'reports.create': ['reports.view'],
  'reports.view': [],
  'reports.export': ['reports.view'],
  
  // Audit permissions
  'audit.manage': ['audit.view'],
  'audit.view': []
}

// Default role permissions
const DEFAULT_ROLE_PERMISSIONS: Record<RoleName, Permission[]> = {
  admin: [
    'system.manage',
    'users.manage',
    'teams.manage',
    'workspaces.manage',
    'campaigns.manage',
    'data.manage',
    'scraping.manage',
    'analytics.manage',
    'audit.manage'
  ],
  manager: [
    'teams.manage',
    'workspaces.manage',
    'campaigns.manage',
    'data.manage',
    'analytics.view',
    'users.invite',
    'scraping.run'
  ],
  analyst: [
    'campaigns.view',
    'data.view',
    'analytics.view',
    'reports.create',
    'data.export',
    'scraping.view'
  ],
  contributor: [
    'campaigns.create',
    'campaigns.edit',
    'data.validate',
    'data.enrich',
    'scraping.run',
    'campaigns.view',
    'data.view'
  ],
  viewer: [
    'campaigns.view',
    'data.view',
    'reports.view'
  ]
}

/**
 * RBAC Service for managing roles and permissions
 */
export class RBACService {
  /**
   * Check if a user has a specific permission
   */
  static hasPermission(
    user: User,
    permission: Permission,
    context?: {
      workspaceId?: string
      teamId?: string
      resourceId?: string
    }
  ): boolean {
    try {
      // Get all user permissions from roles and workspace memberships
      const userPermissions = this.getUserPermissions(user, context)
      
      // Check direct permission
      if (userPermissions.includes(permission)) {
        return true
      }
      
      // Check inherited permissions through hierarchy
      return this.hasInheritedPermission(userPermissions, permission)
    } catch (error) {
      logger.error('RBAC', 'Error checking permission', { 
        userId: user.id, 
        permission, 
        context,
        error 
      })
      return false
    }
  }

  /**
   * Check if a user has any of the specified permissions
   */
  static hasAnyPermission(
    user: User,
    permissions: Permission[],
    context?: {
      workspaceId?: string
      teamId?: string
      resourceId?: string
    }
  ): boolean {
    return permissions.some(permission => 
      this.hasPermission(user, permission, context)
    )
  }

  /**
   * Check if a user has all of the specified permissions
   */
  static hasAllPermissions(
    user: User,
    permissions: Permission[],
    context?: {
      workspaceId?: string
      teamId?: string
      resourceId?: string
    }
  ): boolean {
    return permissions.every(permission => 
      this.hasPermission(user, permission, context)
    )
  }

  /**
   * Get all permissions for a user
   */
  static getUserPermissions(
    user: User,
    context?: {
      workspaceId?: string
      teamId?: string
    }
  ): Permission[] {
    const permissions = new Set<Permission>()

    // Add permissions from user roles
    if (user.roles) {
      user.roles.forEach(userRole => {
        if (userRole.isActive && (!userRole.expiresAt || userRole.expiresAt > new Date())) {
          userRole.role.permissions.forEach(permission => {
            permissions.add(permission)
          })
        }
      })
    }

    // Add permissions from workspace memberships
    if (user.workspaces && context?.workspaceId) {
      const workspaceMembership = user.workspaces.find(
        ws => ws.workspaceId === context.workspaceId && ws.isActive
      )
      if (workspaceMembership) {
        workspaceMembership.permissions.forEach(permission => {
          permissions.add(permission)
        })
        
        // Add role-based permissions for workspace
        const rolePermissions = this.getWorkspaceRolePermissions(workspaceMembership.role)
        rolePermissions.forEach(permission => {
          permissions.add(permission)
        })
      }
    }

    // Add permissions from team memberships
    if (user.teams && context?.teamId) {
      const teamMembership = user.teams.find(
        team => team.teamId === context.teamId && team.isActive
      )
      if (teamMembership) {
        const rolePermissions = this.getTeamRolePermissions(teamMembership.role)
        rolePermissions.forEach(permission => {
          permissions.add(permission)
        })
      }
    }

    return Array.from(permissions)
  }

  /**
   * Check if user has inherited permission through hierarchy
   */
  private static hasInheritedPermission(
    userPermissions: Permission[],
    targetPermission: Permission
  ): boolean {
    // Check if any user permission grants the target permission
    return userPermissions.some(userPermission => {
      const inheritedPermissions = PERMISSION_HIERARCHY[userPermission] || []
      return inheritedPermissions.includes(targetPermission)
    })
  }

  /**
   * Get permissions for a workspace role
   */
  static getWorkspaceRolePermissions(role: WorkspaceRole): Permission[] {
    switch (role) {
      case 'admin':
        return [
          'workspaces.manage',
          'campaigns.manage',
          'data.manage',
          'scraping.manage',
          'analytics.view',
          'users.invite'
        ]
      case 'manager':
        return [
          'campaigns.manage',
          'data.manage',
          'scraping.run',
          'analytics.view',
          'workspaces.view'
        ]
      case 'analyst':
        return [
          'campaigns.view',
          'data.view',
          'analytics.view',
          'reports.create',
          'data.export'
        ]
      case 'contributor':
        return [
          'campaigns.create',
          'campaigns.edit',
          'data.validate',
          'data.enrich',
          'scraping.run'
        ]
      case 'viewer':
        return [
          'campaigns.view',
          'data.view',
          'reports.view'
        ]
      default:
        return []
    }
  }

  /**
   * Get permissions for a team role
   */
  static getTeamRolePermissions(role: TeamRole): Permission[] {
    switch (role) {
      case 'owner':
        return [
          'teams.manage',
          'workspaces.manage',
          'users.invite'
        ]
      case 'admin':
        return [
          'teams.edit',
          'workspaces.create',
          'users.invite'
        ]
      case 'member':
        return [
          'teams.view',
          'workspaces.view'
        ]
      case 'viewer':
        return [
          'teams.view'
        ]
      default:
        return []
    }
  }

  /**
   * Validate if a role assignment is valid
   */
  static validateRoleAssignment(
    assignerUser: User,
    targetUserId: string,
    role: RoleName,
    context?: {
      workspaceId?: string
      teamId?: string
    }
  ): { valid: boolean; reason?: string } {
    // System admins can assign any role
    if (this.hasPermission(assignerUser, 'system.manage')) {
      return { valid: true }
    }

    // Check if user has permission to manage users
    if (!this.hasPermission(assignerUser, 'users.manage', context)) {
      return { 
        valid: false, 
        reason: 'Insufficient permissions to assign roles' 
      }
    }

    // Prevent non-admins from assigning admin roles
    if (role === 'admin' && !this.hasPermission(assignerUser, 'system.manage')) {
      return { 
        valid: false, 
        reason: 'Only system administrators can assign admin roles' 
      }
    }

    return { valid: true }
  }

  /**
   * Get effective permissions for a role
   */
  static getEffectivePermissions(role: RoleName): Permission[] {
    const directPermissions = DEFAULT_ROLE_PERMISSIONS[role] || []
    const effectivePermissions = new Set<Permission>(directPermissions)

    // Add inherited permissions
    directPermissions.forEach(permission => {
      const inherited = PERMISSION_HIERARCHY[permission] || []
      inherited.forEach(inheritedPermission => {
        effectivePermissions.add(inheritedPermission)
      })
    })

    return Array.from(effectivePermissions)
  }

  /**
   * Check if a user can access a specific resource
   */
  static canAccessResource(
    user: User,
    resourceType: string,
    resourceId: string,
    action: 'view' | 'edit' | 'delete' | 'manage',
    context?: {
      workspaceId?: string
      teamId?: string
    }
  ): boolean {
    // Map actions to permissions
    const permissionMap: Record<string, Record<string, Permission>> = {
      campaign: {
        view: 'campaigns.view',
        edit: 'campaigns.edit',
        delete: 'campaigns.delete',
        manage: 'campaigns.manage'
      },
      business: {
        view: 'data.view',
        edit: 'data.edit',
        delete: 'data.delete',
        manage: 'data.manage'
      },
      workspace: {
        view: 'workspaces.view',
        edit: 'workspaces.edit',
        delete: 'workspaces.delete',
        manage: 'workspaces.manage'
      },
      team: {
        view: 'teams.view',
        edit: 'teams.edit',
        delete: 'teams.delete',
        manage: 'teams.manage'
      }
    }

    const permission = permissionMap[resourceType]?.[action]
    if (!permission) {
      logger.warn('RBAC', 'Unknown resource type or action', { 
        resourceType, 
        action 
      })
      return false
    }

    return this.hasPermission(user, permission, { 
      ...context, 
      resourceId 
    })
  }
}
