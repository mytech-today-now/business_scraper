/**
 * Enhanced Role-Based Access Control (RBAC) Implementation
 * Implements comprehensive RBAC with permissions, roles, and access control enforcement
 */

import { NextRequest } from 'next/server'
import { logger } from '@/utils/logger'
import { auditService } from '@/model/auditService'

// Define comprehensive permissions for the business scraper application
export enum Permission {
  // Data permissions
  READ_BUSINESSES = 'read:businesses',
  WRITE_BUSINESSES = 'write:businesses',
  DELETE_BUSINESSES = 'delete:businesses',
  EXPORT_BUSINESSES = 'export:businesses',
  IMPORT_BUSINESSES = 'import:businesses',
  
  // Scraping permissions
  START_SCRAPING = 'scraping:start',
  STOP_SCRAPING = 'scraping:stop',
  CONFIGURE_SCRAPING = 'scraping:configure',
  VIEW_SCRAPING_LOGS = 'scraping:logs',
  MANAGE_SCRAPING_ENGINES = 'scraping:engines',
  
  // Search permissions
  SEARCH_BUSINESSES = 'search:businesses',
  ADVANCED_SEARCH = 'search:advanced',
  SAVE_SEARCHES = 'search:save',
  
  // Analytics permissions
  VIEW_ANALYTICS = 'analytics:view',
  EXPORT_ANALYTICS = 'analytics:export',
  CONFIGURE_ANALYTICS = 'analytics:configure',
  
  // Integration permissions
  MANAGE_INTEGRATIONS = 'integrations:manage',
  VIEW_INTEGRATIONS = 'integrations:view',
  CONFIGURE_CRM = 'integrations:crm',
  CONFIGURE_WEBHOOKS = 'integrations:webhooks',
  
  // Admin permissions
  MANAGE_USERS = 'admin:users',
  MANAGE_SYSTEM = 'admin:system',
  VIEW_AUDIT_LOGS = 'admin:audit',
  MANAGE_SECURITY = 'admin:security',
  CONFIGURE_SETTINGS = 'admin:settings',
  MANAGE_BACKUPS = 'admin:backups',
  
  // API permissions
  API_ACCESS = 'api:access',
  API_ADMIN = 'api:admin',
  API_RATE_LIMIT_OVERRIDE = 'api:rate_limit_override',
  
  // Compliance permissions
  VIEW_COMPLIANCE = 'compliance:view',
  MANAGE_COMPLIANCE = 'compliance:manage',
  EXPORT_COMPLIANCE_REPORTS = 'compliance:export',
  
  // Monitoring permissions
  VIEW_MONITORING = 'monitoring:view',
  CONFIGURE_MONITORING = 'monitoring:configure',
  MANAGE_ALERTS = 'monitoring:alerts'
}

// Define roles with hierarchical structure
export enum Role {
  SUPER_ADMIN = 'super_admin',
  ADMIN = 'admin',
  OPERATOR = 'operator',
  ANALYST = 'analyst',
  VIEWER = 'viewer',
  COMPLIANCE_OFFICER = 'compliance_officer',
  API_USER = 'api_user',
  GUEST = 'guest'
}

// Role hierarchy (higher roles inherit permissions from lower roles)
export const roleHierarchy: Record<Role, Role[]> = {
  [Role.SUPER_ADMIN]: [Role.ADMIN, Role.OPERATOR, Role.ANALYST, Role.VIEWER, Role.COMPLIANCE_OFFICER, Role.API_USER],
  [Role.ADMIN]: [Role.OPERATOR, Role.ANALYST, Role.VIEWER, Role.API_USER],
  [Role.OPERATOR]: [Role.ANALYST, Role.VIEWER],
  [Role.ANALYST]: [Role.VIEWER],
  [Role.VIEWER]: [],
  [Role.COMPLIANCE_OFFICER]: [Role.VIEWER],
  [Role.API_USER]: [],
  [Role.GUEST]: []
}

// Define permissions for each role
export const rolePermissions: Record<Role, Permission[]> = {
  [Role.SUPER_ADMIN]: Object.values(Permission), // All permissions
  
  [Role.ADMIN]: [
    // Data permissions
    Permission.READ_BUSINESSES,
    Permission.WRITE_BUSINESSES,
    Permission.DELETE_BUSINESSES,
    Permission.EXPORT_BUSINESSES,
    Permission.IMPORT_BUSINESSES,
    
    // Scraping permissions
    Permission.START_SCRAPING,
    Permission.STOP_SCRAPING,
    Permission.CONFIGURE_SCRAPING,
    Permission.VIEW_SCRAPING_LOGS,
    Permission.MANAGE_SCRAPING_ENGINES,
    
    // Search permissions
    Permission.SEARCH_BUSINESSES,
    Permission.ADVANCED_SEARCH,
    Permission.SAVE_SEARCHES,
    
    // Analytics permissions
    Permission.VIEW_ANALYTICS,
    Permission.EXPORT_ANALYTICS,
    Permission.CONFIGURE_ANALYTICS,
    
    // Integration permissions
    Permission.MANAGE_INTEGRATIONS,
    Permission.VIEW_INTEGRATIONS,
    Permission.CONFIGURE_CRM,
    Permission.CONFIGURE_WEBHOOKS,
    
    // Admin permissions (limited)
    Permission.MANAGE_USERS,
    Permission.VIEW_AUDIT_LOGS,
    Permission.CONFIGURE_SETTINGS,
    
    // API permissions
    Permission.API_ACCESS,
    
    // Monitoring permissions
    Permission.VIEW_MONITORING,
    Permission.CONFIGURE_MONITORING,
    Permission.MANAGE_ALERTS
  ],
  
  [Role.OPERATOR]: [
    // Data permissions
    Permission.READ_BUSINESSES,
    Permission.WRITE_BUSINESSES,
    Permission.EXPORT_BUSINESSES,
    Permission.IMPORT_BUSINESSES,
    
    // Scraping permissions
    Permission.START_SCRAPING,
    Permission.STOP_SCRAPING,
    Permission.CONFIGURE_SCRAPING,
    Permission.VIEW_SCRAPING_LOGS,
    
    // Search permissions
    Permission.SEARCH_BUSINESSES,
    Permission.ADVANCED_SEARCH,
    Permission.SAVE_SEARCHES,
    
    // Analytics permissions
    Permission.VIEW_ANALYTICS,
    Permission.EXPORT_ANALYTICS,
    
    // Integration permissions
    Permission.VIEW_INTEGRATIONS,
    Permission.CONFIGURE_CRM,
    
    // API permissions
    Permission.API_ACCESS,
    
    // Monitoring permissions
    Permission.VIEW_MONITORING
  ],
  
  [Role.ANALYST]: [
    // Data permissions
    Permission.READ_BUSINESSES,
    Permission.EXPORT_BUSINESSES,
    
    // Search permissions
    Permission.SEARCH_BUSINESSES,
    Permission.ADVANCED_SEARCH,
    Permission.SAVE_SEARCHES,
    
    // Analytics permissions
    Permission.VIEW_ANALYTICS,
    Permission.EXPORT_ANALYTICS,
    Permission.CONFIGURE_ANALYTICS,
    
    // Integration permissions
    Permission.VIEW_INTEGRATIONS,
    
    // Monitoring permissions
    Permission.VIEW_MONITORING
  ],
  
  [Role.VIEWER]: [
    // Data permissions
    Permission.READ_BUSINESSES,
    Permission.EXPORT_BUSINESSES,
    
    // Search permissions
    Permission.SEARCH_BUSINESSES,
    
    // Analytics permissions
    Permission.VIEW_ANALYTICS,
    
    // Integration permissions
    Permission.VIEW_INTEGRATIONS
  ],
  
  [Role.COMPLIANCE_OFFICER]: [
    // Data permissions
    Permission.READ_BUSINESSES,
    Permission.EXPORT_BUSINESSES,
    
    // Search permissions
    Permission.SEARCH_BUSINESSES,
    
    // Compliance permissions
    Permission.VIEW_COMPLIANCE,
    Permission.MANAGE_COMPLIANCE,
    Permission.EXPORT_COMPLIANCE_REPORTS,
    
    // Admin permissions (audit only)
    Permission.VIEW_AUDIT_LOGS,
    
    // Monitoring permissions
    Permission.VIEW_MONITORING
  ],
  
  [Role.API_USER]: [
    // Data permissions
    Permission.READ_BUSINESSES,
    Permission.WRITE_BUSINESSES,
    Permission.EXPORT_BUSINESSES,
    
    // Search permissions
    Permission.SEARCH_BUSINESSES,
    Permission.ADVANCED_SEARCH,
    
    // API permissions
    Permission.API_ACCESS
  ],
  
  [Role.GUEST]: [
    // Very limited permissions
    Permission.READ_BUSINESSES,
    Permission.SEARCH_BUSINESSES
  ]
}

// Resource-based permissions for fine-grained access control
export interface ResourcePermission {
  resource: string
  action: string
  conditions?: Record<string, any>
}

export interface UserContext {
  userId: string
  roles: Role[]
  permissions: Permission[]
  resourcePermissions: ResourcePermission[]
  sessionId?: string
  ipAddress?: string
  metadata?: Record<string, any>
}

export interface AccessControlResult {
  allowed: boolean
  reason?: string
  requiredPermissions?: Permission[]
  missingPermissions?: Permission[]
}

export class EnhancedRBACService {
  private static instance: EnhancedRBACService

  static getInstance(): EnhancedRBACService {
    if (!EnhancedRBACService.instance) {
      EnhancedRBACService.instance = new EnhancedRBACService()
    }
    return EnhancedRBACService.instance
  }

  /**
   * Check if user has specific permission
   */
  hasPermission(userContext: UserContext, requiredPermission: Permission): boolean {
    // Check direct permissions
    if (userContext.permissions.includes(requiredPermission)) {
      return true
    }

    // Check role-based permissions with hierarchy
    for (const role of userContext.roles) {
      if (this.roleHasPermission(role, requiredPermission)) {
        return true
      }
    }

    return false
  }

  /**
   * Check if user has any of the required permissions
   */
  hasAnyPermission(userContext: UserContext, requiredPermissions: Permission[]): boolean {
    return requiredPermissions.some(permission => this.hasPermission(userContext, permission))
  }

  /**
   * Check if user has all required permissions
   */
  hasAllPermissions(userContext: UserContext, requiredPermissions: Permission[]): boolean {
    return requiredPermissions.every(permission => this.hasPermission(userContext, permission))
  }

  /**
   * Check access control for a specific action
   */
  async checkAccess(
    userContext: UserContext,
    requiredPermissions: Permission[],
    resource?: string,
    action?: string
  ): Promise<AccessControlResult> {
    try {
      // Check if user has required permissions
      const missingPermissions = requiredPermissions.filter(
        permission => !this.hasPermission(userContext, permission)
      )

      if (missingPermissions.length > 0) {
        // Log access denied
        await auditService.logSecurityEvent('access_denied', {
          userId: userContext.userId,
          requiredPermissions,
          missingPermissions,
          resource,
          action,
          roles: userContext.roles,
          sessionId: userContext.sessionId,
          ipAddress: userContext.ipAddress,
          timestamp: new Date()
        })

        return {
          allowed: false,
          reason: 'Insufficient permissions',
          requiredPermissions,
          missingPermissions
        }
      }

      // Check resource-specific permissions if applicable
      if (resource && action) {
        const hasResourceAccess = this.checkResourcePermission(userContext, resource, action)
        if (!hasResourceAccess) {
          await auditService.logSecurityEvent('resource_access_denied', {
            userId: userContext.userId,
            resource,
            action,
            roles: userContext.roles,
            sessionId: userContext.sessionId,
            timestamp: new Date()
          })

          return {
            allowed: false,
            reason: 'Resource access denied'
          }
        }
      }

      // Log successful access
      await auditService.logSecurityEvent('access_granted', {
        userId: userContext.userId,
        permissions: requiredPermissions,
        resource,
        action,
        roles: userContext.roles,
        sessionId: userContext.sessionId,
        timestamp: new Date()
      })

      return { allowed: true }
    } catch (error) {
      logger.error('RBAC', 'Access control check failed', error)
      return {
        allowed: false,
        reason: 'Access control error'
      }
    }
  }

  /**
   * Get all permissions for user (including inherited)
   */
  getUserPermissions(userContext: UserContext): Permission[] {
    const permissions = new Set<Permission>(userContext.permissions)

    // Add role-based permissions with hierarchy
    for (const role of userContext.roles) {
      const rolePerms = this.getRolePermissions(role)
      rolePerms.forEach(perm => permissions.add(perm))
    }

    return Array.from(permissions)
  }

  /**
   * Check if role has permission (including hierarchy)
   */
  private roleHasPermission(role: Role, permission: Permission): boolean {
    // Check direct role permissions
    const directPermissions = rolePermissions[role] || []
    if (directPermissions.includes(permission)) {
      return true
    }

    // Check inherited permissions from role hierarchy
    const inheritedRoles = roleHierarchy[role] || []
    for (const inheritedRole of inheritedRoles) {
      const inheritedPermissions = rolePermissions[inheritedRole] || []
      if (inheritedPermissions.includes(permission)) {
        return true
      }
    }

    return false
  }

  /**
   * Get all permissions for a role (including inherited)
   */
  private getRolePermissions(role: Role): Permission[] {
    const permissions = new Set<Permission>()

    // Add direct permissions
    const directPermissions = rolePermissions[role] || []
    directPermissions.forEach(perm => permissions.add(perm))

    // Add inherited permissions
    const inheritedRoles = roleHierarchy[role] || []
    for (const inheritedRole of inheritedRoles) {
      const inheritedPermissions = rolePermissions[inheritedRole] || []
      inheritedPermissions.forEach(perm => permissions.add(perm))
    }

    return Array.from(permissions)
  }

  /**
   * Check resource-specific permissions
   */
  private checkResourcePermission(userContext: UserContext, resource: string, action: string): boolean {
    return userContext.resourcePermissions.some(
      rp => rp.resource === resource && rp.action === action
    )
  }

  /**
   * Create user context from session and user data
   */
  createUserContext(
    userId: string,
    roles: Role[],
    sessionId?: string,
    ipAddress?: string,
    additionalPermissions: Permission[] = [],
    resourcePermissions: ResourcePermission[] = []
  ): UserContext {
    return {
      userId,
      roles,
      permissions: additionalPermissions,
      resourcePermissions,
      sessionId,
      ipAddress,
      metadata: {
        createdAt: new Date(),
        lastUpdated: new Date()
      }
    }
  }

  /**
   * Validate role assignment
   */
  validateRoleAssignment(roles: Role[]): { valid: boolean; errors: string[] } {
    const errors: string[] = []

    // Check for valid roles
    for (const role of roles) {
      if (!Object.values(Role).includes(role)) {
        errors.push(`Invalid role: ${role}`)
      }
    }

    // Check for conflicting roles (business logic)
    if (roles.includes(Role.GUEST) && roles.length > 1) {
      errors.push('Guest role cannot be combined with other roles')
    }

    return {
      valid: errors.length === 0,
      errors
    }
  }
}

// Export singleton instance
export const enhancedRBAC = EnhancedRBACService.getInstance()

// Utility functions for common permission checks
export function hasPermission(userContext: UserContext, permission: Permission): boolean {
  return enhancedRBAC.hasPermission(userContext, permission)
}

export function hasAnyPermission(userContext: UserContext, permissions: Permission[]): boolean {
  return enhancedRBAC.hasAnyPermission(userContext, permissions)
}

export function hasAllPermissions(userContext: UserContext, permissions: Permission[]): boolean {
  return enhancedRBAC.hasAllPermissions(userContext, permissions)
}

export async function checkAccess(
  userContext: UserContext,
  requiredPermissions: Permission[],
  resource?: string,
  action?: string
): Promise<AccessControlResult> {
  return enhancedRBAC.checkAccess(userContext, requiredPermissions, resource, action)
}
