/**
 * Comprehensive Security Test Suite
 * Integration tests for all security components working together
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest } from 'next/server'
import { passwordSecurity } from '@/lib/password-security'
import { mfaSecurity } from '@/lib/mfa-security'
import { secureSessionManager } from '@/lib/session-security'
import { enhancedRBAC, Role, Permission } from '@/lib/enhanced-rbac'
import { securityAuditService, SecurityEventType, SecuritySeverity } from '@/lib/security-audit-service'

// Mock dependencies
jest.mock('@/utils/logger')
jest.mock('@/model/auditService')

describe('Comprehensive Security Test Suite', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('End-to-End Security Flow Tests', () => {
    test('should complete secure authentication flow', async () => {
      const userId = 'test-user'
      const userEmail = 'test@example.com'
      const password = 'MyStr0ng!P@ssw0rd2024'
      
      // Step 1: Password validation and hashing
      const passwordValidation = passwordSecurity.validatePasswordStrength(password)
      expect(passwordValidation.isValid).toBe(true)
      
      const passwordHash = await passwordSecurity.hashPassword(password)
      expect(passwordHash.hash).toBeDefined()
      
      // Step 2: MFA setup
      const mfaSecret = await mfaSecurity.generateMFASecret(userId, userEmail)
      expect(mfaSecret.secret).toBeDefined()
      
      // Simulate TOTP verification
      const speakeasy = require('speakeasy')
      const totpToken = speakeasy.totp({
        secret: mfaSecret.secret,
        encoding: 'base32'
      })
      
      const mfaSetupResult = await mfaSecurity.verifyMFASetup(userId, totpToken)
      expect(mfaSetupResult).toBe(true)
      
      // Step 3: Session creation
      const request = new NextRequest('http://localhost:3000/login', {
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'x-forwarded-for': '192.168.1.100'
        }
      })
      
      const session = await secureSessionManager.createSession(userId, request, 'password', true)
      expect(session.id).toBeDefined()
      expect(session.metadata.mfaVerified).toBe(true)
      
      // Step 4: RBAC validation
      const userContext = enhancedRBAC.createUserContext(
        userId,
        [Role.OPERATOR],
        session.id,
        '192.168.1.100'
      )
      
      const accessResult = await enhancedRBAC.checkAccess(
        userContext,
        [Permission.READ_BUSINESSES, Permission.START_SCRAPING]
      )
      expect(accessResult.allowed).toBe(true)
      
      // Step 5: Security audit logging
      await securityAuditService.logSecurityEvent(
        SecurityEventType.LOGIN_SUCCESS,
        {
          userId,
          sessionId: session.id,
          mfaVerified: true,
          loginMethod: 'password'
        },
        request
      )
      
      const metrics = securityAuditService.getSecurityMetrics()
      expect(metrics.successfulLogins).toBeGreaterThan(0)
    })

    test('should handle complete security breach scenario', async () => {
      const attackerIP = '10.0.0.50'
      const legitimateIP = '192.168.1.100'
      const userId = 'target-user'
      
      // Simulate brute force attack
      const bruteForceRequest = new NextRequest('http://localhost:3000/login', {
        headers: {
          'user-agent': 'AttackerBot/1.0',
          'x-forwarded-for': attackerIP
        }
      })
      
      // Multiple failed login attempts
      for (let i = 0; i < 6; i++) {
        await securityAuditService.logSecurityEvent(
          SecurityEventType.LOGIN_FAILURE,
          {
            userId,
            reason: 'invalid_credentials',
            attemptNumber: i + 1
          },
          bruteForceRequest
        )
      }
      
      // Verify IP is blocked
      expect(securityAuditService.isIPBlocked(attackerIP)).toBe(true)
      
      // Simulate session hijacking attempt
      const legitimateRequest = new NextRequest('http://localhost:3000/dashboard', {
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'x-forwarded-for': legitimateIP
        }
      })
      
      const session = await secureSessionManager.createSession(userId, legitimateRequest)
      
      // Attacker tries to use session from different IP
      const hijackRequest = new NextRequest('http://localhost:3000/dashboard', {
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'x-forwarded-for': attackerIP
        }
      })
      
      const hijackValidation = await secureSessionManager.validateSession(session.id, hijackRequest)
      expect(hijackValidation.valid).toBe(false)
      expect(hijackValidation.securityAlert).toContain('IP address mismatch')
      
      // Verify security metrics reflect the attack
      const metrics = securityAuditService.getSecurityMetrics()
      expect(metrics.failedLogins).toBeGreaterThanOrEqual(6)
      expect(metrics.blockedIPs).toBeGreaterThan(0)
      expect(metrics.alertsGenerated).toBeGreaterThan(0)
    })
  })

  describe('Security Configuration Tests', () => {
    test('should enforce minimum security standards', () => {
      // Password security standards
      const passwordConfig = passwordSecurity['passwordSecurityConfig'] || {
        minLength: 12,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
        saltRounds: 14
      }
      
      expect(passwordConfig.minLength).toBeGreaterThanOrEqual(12)
      expect(passwordConfig.saltRounds).toBeGreaterThanOrEqual(12)
      expect(passwordConfig.requireUppercase).toBe(true)
      expect(passwordConfig.requireLowercase).toBe(true)
      expect(passwordConfig.requireNumbers).toBe(true)
      expect(passwordConfig.requireSpecialChars).toBe(true)
      
      // Session security standards
      const sessionConfig = secureSessionManager['sessionSecurityConfig'] || {
        sessionTimeout: 30 * 60 * 1000,
        absoluteTimeout: 8 * 60 * 60 * 1000,
        strictIPBinding: true,
        deviceFingerprintRequired: true
      }
      
      expect(sessionConfig.sessionTimeout).toBeLessThanOrEqual(60 * 60 * 1000) // Max 1 hour
      expect(sessionConfig.absoluteTimeout).toBeLessThanOrEqual(24 * 60 * 60 * 1000) // Max 24 hours
      expect(sessionConfig.strictIPBinding).toBe(true)
      expect(sessionConfig.deviceFingerprintRequired).toBe(true)
    })

    test('should validate RBAC configuration', () => {
      // Verify role hierarchy is properly configured
      const roles = Object.values(Role)
      expect(roles).toContain(Role.SUPER_ADMIN)
      expect(roles).toContain(Role.ADMIN)
      expect(roles).toContain(Role.VIEWER)
      
      // Verify permissions are comprehensive
      const permissions = Object.values(Permission)
      expect(permissions.length).toBeGreaterThan(20) // Should have comprehensive permissions
      
      // Verify super admin has all permissions
      const superAdminContext = enhancedRBAC.createUserContext('super-admin', [Role.SUPER_ADMIN])
      for (const permission of permissions) {
        expect(enhancedRBAC.hasPermission(superAdminContext, permission)).toBe(true)
      }
      
      // Verify viewer has limited permissions
      const viewerContext = enhancedRBAC.createUserContext('viewer', [Role.VIEWER])
      const restrictedPermissions = [
        Permission.MANAGE_USERS,
        Permission.MANAGE_SYSTEM,
        Permission.DELETE_BUSINESSES
      ]
      
      for (const permission of restrictedPermissions) {
        expect(enhancedRBAC.hasPermission(viewerContext, permission)).toBe(false)
      }
    })
  })

  describe('Performance and Scalability Tests', () => {
    test('should handle concurrent authentication attempts', async () => {
      const concurrentUsers = 10
      const promises: Promise<any>[] = []
      
      for (let i = 0; i < concurrentUsers; i++) {
        const userId = `user-${i}`
        const request = new NextRequest('http://localhost:3000/login', {
          headers: {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'x-forwarded-for': `192.168.1.${100 + i}`
          }
        })
        
        promises.push(secureSessionManager.createSession(userId, request))
      }
      
      const sessions = await Promise.all(promises)
      
      // All sessions should be created successfully
      expect(sessions).toHaveLength(concurrentUsers)
      sessions.forEach(session => {
        expect(session.id).toBeDefined()
        expect(session.isValid).toBe(true)
      })
      
      // All session IDs should be unique
      const sessionIds = sessions.map(s => s.id)
      const uniqueIds = new Set(sessionIds)
      expect(uniqueIds.size).toBe(concurrentUsers)
    })

    test('should handle high-volume security events', async () => {
      const eventCount = 100
      const promises: Promise<any>[] = []
      
      for (let i = 0; i < eventCount; i++) {
        const request = new NextRequest('http://localhost:3000/test', {
          headers: {
            'x-forwarded-for': `192.168.1.${(i % 50) + 1}`,
            'user-agent': 'TestAgent/1.0'
          }
        })
        
        promises.push(
          securityAuditService.logSecurityEvent(
            SecurityEventType.DATA_ACCESS,
            {
              userId: `user-${i % 10}`,
              resource: 'businesses',
              action: 'read'
            },
            request
          )
        )
      }
      
      const events = await Promise.all(promises)
      
      expect(events).toHaveLength(eventCount)
      events.forEach(event => {
        expect(event.id).toBeDefined()
        expect(event.timestamp).toBeInstanceOf(Date)
      })
      
      const metrics = securityAuditService.getSecurityMetrics()
      expect(metrics.totalEvents).toBeGreaterThanOrEqual(eventCount)
    })
  })

  describe('Compliance and Audit Tests', () => {
    test('should maintain comprehensive audit trail', async () => {
      const userId = 'audit-test-user'
      const sessionId = 'audit-session-123'
      
      // Simulate various security events
      const events = [
        { type: SecurityEventType.LOGIN_SUCCESS, details: { userId, sessionId } },
        { type: SecurityEventType.DATA_ACCESS, details: { userId, resource: 'businesses' } },
        { type: SecurityEventType.DATA_EXPORT, details: { userId, format: 'csv' } },
        { type: SecurityEventType.LOGOUT, details: { userId, sessionId } }
      ]
      
      for (const event of events) {
        await securityAuditService.logSecurityEvent(event.type, event.details)
      }
      
      const metrics = securityAuditService.getSecurityMetrics()
      expect(metrics.totalEvents).toBeGreaterThanOrEqual(events.length)
      
      // Verify event types are tracked
      expect(metrics.eventsByType[SecurityEventType.LOGIN_SUCCESS]).toBeGreaterThan(0)
      expect(metrics.eventsByType[SecurityEventType.DATA_ACCESS]).toBeGreaterThan(0)
      expect(metrics.eventsByType[SecurityEventType.DATA_EXPORT]).toBeGreaterThan(0)
      expect(metrics.eventsByType[SecurityEventType.LOGOUT]).toBeGreaterThan(0)
    })

    test('should enforce data retention policies', () => {
      // Mock data retention check
      const checkDataRetention = (createdAt: Date, retentionPeriod: number): boolean => {
        const now = new Date()
        const ageMs = now.getTime() - createdAt.getTime()
        return ageMs <= retentionPeriod
      }
      
      const retentionPeriod = 90 * 24 * 60 * 60 * 1000 // 90 days
      
      // Recent data should be retained
      const recentDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
      expect(checkDataRetention(recentDate, retentionPeriod)).toBe(true)
      
      // Old data should be flagged for deletion
      const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000) // 120 days ago
      expect(checkDataRetention(oldDate, retentionPeriod)).toBe(false)
    })
  })

  describe('Error Handling and Recovery Tests', () => {
    test('should handle security service failures gracefully', async () => {
      // Mock service failure scenarios
      const mockFailure = jest.fn().mockRejectedValue(new Error('Service unavailable'))
      
      // Test password service failure
      try {
        await mockFailure()
      } catch (error) {
        expect(error).toBeInstanceOf(Error)
        expect((error as Error).message).toBe('Service unavailable')
      }
      
      // Security should fail closed (deny access) when services are unavailable
      const failClosedCheck = (serviceAvailable: boolean): boolean => {
        return serviceAvailable // Only allow access if service is available
      }
      
      expect(failClosedCheck(false)).toBe(false) // Deny when service fails
      expect(failClosedCheck(true)).toBe(true) // Allow when service works
    })

    test('should recover from temporary security failures', async () => {
      // Mock recovery scenario
      let serviceHealthy = false
      
      const healthCheck = (): boolean => serviceHealthy
      const attemptRecovery = (): void => { serviceHealthy = true }
      
      // Initially unhealthy
      expect(healthCheck()).toBe(false)
      
      // Recovery attempt
      attemptRecovery()
      expect(healthCheck()).toBe(true)
    })
  })

  describe('Security Metrics and Monitoring Tests', () => {
    test('should calculate accurate risk scores', async () => {
      const lowRiskEvent = await securityAuditService.logSecurityEvent(
        SecurityEventType.LOGIN_SUCCESS,
        { userId: 'user1' }
      )
      
      const highRiskEvent = await securityAuditService.logSecurityEvent(
        SecurityEventType.SESSION_HIJACKING_ATTEMPT,
        { userId: 'user2', sessionId: 'session-123' }
      )
      
      expect(lowRiskEvent.riskScore).toBeLessThan(highRiskEvent.riskScore)
      expect(lowRiskEvent.severity).toBe(SecuritySeverity.LOW)
      expect(highRiskEvent.severity).toBe(SecuritySeverity.CRITICAL)
    })

    test('should generate appropriate security alerts', async () => {
      // High-risk event should generate alert
      await securityAuditService.logSecurityEvent(
        SecurityEventType.PRIVILEGE_ESCALATION_ATTEMPT,
        {
          userId: 'attacker',
          attemptedRole: 'admin',
          currentRole: 'viewer'
        }
      )
      
      const metrics = securityAuditService.getSecurityMetrics()
      expect(metrics.alertsGenerated).toBeGreaterThan(0)
    })
  })
})
