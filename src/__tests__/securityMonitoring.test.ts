/**
 * Security Monitoring & Logging Tests
 * Business Scraper Application - Security Event Tracking Tests
 */

import {
  SecurityLogger,
  SecurityEventType,
  SecuritySeverity,
  sanitizeLogData,
  validateLogData,
} from '@/lib/securityLogger'
import { AuthenticationMonitor } from '@/lib/authenticationMonitor'
import { SecurityAlertManager } from '@/lib/securityAlerts'

// Mock dependencies
jest.mock('@/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

describe('Security Logger', () => {
  let securityLogger: SecurityLogger

  beforeEach(() => {
    securityLogger = new SecurityLogger()
  })

  describe('Security Event Logging', () => {
    it('should log security events with all required fields', () => {
      const event = securityLogger.logSecurityEvent(
        SecurityEventType.LOGIN_FAILURE,
        SecuritySeverity.MEDIUM,
        'authentication',
        { username: 'testuser', reason: 'invalid_password' }
      )

      expect(event.id).toBeDefined()
      expect(event.timestamp).toBeInstanceOf(Date)
      expect(event.type).toBe(SecurityEventType.LOGIN_FAILURE)
      expect(event.severity).toBe(SecuritySeverity.MEDIUM)
      expect(event.source).toBe('authentication')
      expect(event.details.username).toBe('testuser')
      expect(event.riskScore).toBeGreaterThan(0)
    })

    it('should calculate appropriate risk scores', () => {
      const lowRiskEvent = securityLogger.logSecurityEvent(
        SecurityEventType.LOGIN_SUCCESS,
        SecuritySeverity.LOW,
        'authentication'
      )

      const highRiskEvent = securityLogger.logSecurityEvent(
        SecurityEventType.SQL_INJECTION_ATTEMPT,
        SecuritySeverity.CRITICAL,
        'input_validation'
      )

      expect(lowRiskEvent.riskScore).toBeLessThan(highRiskEvent.riskScore)
      expect(highRiskEvent.riskScore).toBeGreaterThanOrEqual(7)
    })

    it('should track suspicious IPs', () => {
      securityLogger.logSecurityEvent(
        SecurityEventType.BRUTE_FORCE_ATTEMPT,
        SecuritySeverity.CRITICAL,
        'authentication',
        { ip: '192.168.1.100' }
      )

      expect(securityLogger.isSuspiciousIP('192.168.1.100')).toBe(true)
      expect(securityLogger.isSuspiciousIP('192.168.1.101')).toBe(false)
    })

    it('should track blocked IPs', () => {
      securityLogger.logSecurityEvent(
        SecurityEventType.LOGIN_BLOCKED,
        SecuritySeverity.HIGH,
        'authentication',
        { ip: '192.168.1.200' },
        undefined,
        true // blocked
      )

      expect(securityLogger.isBlockedIP('192.168.1.200')).toBe(true)
      expect(securityLogger.isBlockedIP('192.168.1.201')).toBe(false)
    })
  })

  describe('Authentication Event Logging', () => {
    it('should log successful authentication', () => {
      const mockRequest = {
        nextUrl: { pathname: '/login' },
        method: 'POST',
        headers: new Map([['user-agent', 'test-browser']]),
        cookies: new Map(),
      } as any

      const event = securityLogger.logAuthEvent(SecurityEventType.LOGIN_SUCCESS, mockRequest, {
        username: 'testuser',
      })

      expect(event.type).toBe(SecurityEventType.LOGIN_SUCCESS)
      expect(event.severity).toBe(SecuritySeverity.LOW)
      expect(event.details.username).toBe('testuser')
    })

    it('should log failed authentication with escalating severity', () => {
      const mockRequest = {
        nextUrl: { pathname: '/login' },
        method: 'POST',
        headers: new Map([['user-agent', 'test-browser']]),
        cookies: new Map(),
      } as any

      const event = securityLogger.logFailedAuth(mockRequest, 'testuser', 'invalid_password')

      expect(event.type).toBe(SecurityEventType.LOGIN_FAILURE)
      expect(event.details.username).toBe('testuser')
      expect(event.details.reason).toBe('invalid_password')
    })
  })

  describe('Security Metrics', () => {
    it('should generate comprehensive security metrics', () => {
      // Generate some test events
      securityLogger.logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, SecuritySeverity.LOW, 'auth')
      securityLogger.logSecurityEvent(
        SecurityEventType.LOGIN_FAILURE,
        SecuritySeverity.MEDIUM,
        'auth'
      )
      securityLogger.logSecurityEvent(
        SecurityEventType.SQL_INJECTION_ATTEMPT,
        SecuritySeverity.HIGH,
        'input'
      )

      const metrics = securityLogger.getSecurityMetrics(24)

      expect(metrics.totalEvents).toBe(3)
      expect(metrics.eventsByType[SecurityEventType.LOGIN_SUCCESS]).toBe(1)
      expect(metrics.eventsByType[SecurityEventType.LOGIN_FAILURE]).toBe(1)
      expect(metrics.eventsByType[SecurityEventType.SQL_INJECTION_ATTEMPT]).toBe(1)
      expect(metrics.eventsBySeverity[SecuritySeverity.LOW]).toBe(1)
      expect(metrics.eventsBySeverity[SecuritySeverity.MEDIUM]).toBe(1)
      expect(metrics.eventsBySeverity[SecuritySeverity.HIGH]).toBe(1)
    })

    it('should calculate average risk score correctly', () => {
      securityLogger.logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, SecuritySeverity.LOW, 'auth') // ~1
      securityLogger.logSecurityEvent(
        SecurityEventType.SQL_INJECTION_ATTEMPT,
        SecuritySeverity.CRITICAL,
        'input'
      ) // ~20

      const metrics = securityLogger.getSecurityMetrics(24)
      expect(metrics.averageRiskScore).toBeGreaterThan(5)
      expect(metrics.averageRiskScore).toBeLessThan(15)
    })
  })

  describe('Data Export', () => {
    it('should export events as JSON', () => {
      securityLogger.logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, SecuritySeverity.LOW, 'auth')

      const exported = securityLogger.exportEvents(24)
      const data = JSON.parse(exported)

      expect(data.exportTimestamp).toBeDefined()
      expect(data.timeWindow).toBe('24 hours')
      expect(data.eventCount).toBe(1)
      expect(data.events).toHaveLength(1)
      expect(data.events[0].type).toBe(SecurityEventType.LOGIN_SUCCESS)
    })
  })
})

describe('Log Data Sanitization', () => {
  describe('sanitizeLogData', () => {
    it('should redact sensitive field names', () => {
      const data = {
        username: 'testuser',
        password: 'secret123',
        email: 'test@example.com',
        apiKey: 'abc123',
        normalField: 'normal_value',
      }

      const sanitized = sanitizeLogData(data)

      expect(sanitized.username).toBe('testuser')
      expect(sanitized.password).toBe('[REDACTED]')
      expect(sanitized.email).toBe('[REDACTED]')
      expect(sanitized.apiKey).toBe('[REDACTED]')
      expect(sanitized.normalField).toBe('normal_value')
    })

    it('should sanitize nested objects', () => {
      const data = {
        user: {
          name: 'testuser',
          password: 'secret123',
          profile: {
            email: 'test@example.com',
            phone: '555-1234',
          },
        },
      }

      const sanitized = sanitizeLogData(data)

      expect(sanitized.user.name).toBe('testuser')
      expect(sanitized.user.password).toBe('[REDACTED]')
      expect(sanitized.user.profile.email).toBe('[REDACTED]')
      expect(sanitized.user.profile.phone).toBe('[REDACTED]')
    })

    it('should sanitize arrays', () => {
      const data = {
        users: [
          { name: 'user1', password: 'secret1' },
          { name: 'user2', token: 'token123' },
        ],
      }

      const sanitized = sanitizeLogData(data)

      expect(sanitized.users[0].name).toBe('user1')
      expect(sanitized.users[0].password).toBe('[REDACTED]')
      expect(sanitized.users[1].name).toBe('user2')
      expect(sanitized.users[1].token).toBe('[REDACTED]')
    })

    it('should mask sensitive patterns in strings', () => {
      const data = {
        message: 'User test@example.com called 555-123-4567 with card 4111-1111-1111-1111',
      }

      const sanitized = sanitizeLogData(data)

      expect(sanitized.message).toContain('[EMAIL_REDACTED]')
      expect(sanitized.message).toContain('[PHONE_REDACTED]')
      expect(sanitized.message).toContain('[CARD_REDACTED]')
      expect(sanitized.message).not.toContain('test@example.com')
      expect(sanitized.message).not.toContain('555-123-4567')
      expect(sanitized.message).not.toContain('4111-1111-1111-1111')
    })

    it('should truncate very long strings', () => {
      const longString = 'a'.repeat(1500)
      const data = { longField: longString }

      const sanitized = sanitizeLogData(data)

      expect(sanitized.longField).toHaveLength(1014) // 1000 + '...[TRUNCATED]' (14 chars)
      expect(sanitized.longField).toMatch(/\[TRUNCATED\]$/)
    })
  })

  describe('validateLogData', () => {
    it('should detect sensitive data in logs', () => {
      const data = {
        username: 'testuser',
        password: 'secret123',
        message: 'Login attempt for test@example.com',
      }

      const validation = validateLogData(data)

      expect(validation.isValid).toBe(false)
      expect(validation.issues).toContain('Potential password field detected in log data')
      expect(validation.issues).toContain('Email address detected in log data')
      expect(validation.sanitizedData.password).toBe('[REDACTED]')
    })

    it('should pass validation for clean data', () => {
      const data = {
        username: 'testuser',
        action: 'login',
        timestamp: new Date().toISOString(),
      }

      const validation = validateLogData(data)

      expect(validation.isValid).toBe(true)
      expect(validation.issues).toHaveLength(0)
    })
  })
})

describe('Authentication Monitor', () => {
  let authMonitor: AuthenticationMonitor

  beforeEach(() => {
    authMonitor = new AuthenticationMonitor()
  })

  describe('Authentication Attempt Recording', () => {
    it('should record successful authentication', () => {
      const mockRequest = {
        headers: new Map([['user-agent', 'test-browser']]),
        nextUrl: { pathname: '/login' },
        cookies: {
          get: (name: string) => name === 'session-id' ? { value: 'session123' } : undefined
        }
      } as any

      const attempt = authMonitor.recordAuthAttempt(
        mockRequest,
        'testuser',
        true,
        undefined,
        'session123'
      )

      expect(attempt.success).toBe(true)
      expect(attempt.username).toBe('testuser')
      expect(attempt.sessionId).toBe('session123')
    })

    it('should record failed authentication', () => {
      const mockRequest = {
        headers: new Map([['user-agent', 'test-browser']]),
        nextUrl: { pathname: '/login' },
        cookies: {
          get: (name: string) => name === 'session-id' ? { value: 'session123' } : undefined
        }
      } as any

      const attempt = authMonitor.recordAuthAttempt(
        mockRequest,
        'testuser',
        false,
        'invalid_password'
      )

      expect(attempt.success).toBe(false)
      expect(attempt.failureReason).toBe('invalid_password')
    })

    it('should block IP after multiple failed attempts', () => {
      const testIP = '192.168.1.100'
      const mockRequest = {
        headers: new Map([
          ['user-agent', 'test-browser'],
          ['x-forwarded-for', testIP]
        ]),
        nextUrl: { pathname: '/login' },
        cookies: {
          get: (name: string) => name === 'session-id' ? { value: 'session123' } : undefined
        }
      } as any

      // Simulate multiple failed attempts
      for (let i = 0; i < 6; i++) {
        authMonitor.recordAuthAttempt(mockRequest, `user${i}`, false, 'invalid_password')
      }

      // Check authentication statistics to verify pattern tracking
      const stats = authMonitor.getAuthStats()
      expect(stats.failedLogins).toBeGreaterThanOrEqual(6)

      // Get the actual IP that was tracked (since getClientIP might return different value)
      const patterns = (authMonitor as any).patterns
      const allPatterns = Array.from(patterns.keys())
      expect(patterns.size).toBeGreaterThan(0)

      // IP should be blocked after 5 failed attempts
      const actualIP = allPatterns[0]
      expect(authMonitor.isIPBlocked(actualIP)).toBe(true)
    })
  })

  describe('Authentication Statistics', () => {
    it('should generate authentication statistics', () => {
      const mockRequest = {
        headers: new Map([['user-agent', 'test-browser']]),
        nextUrl: { pathname: '/login' },
        cookies: {
          get: (name: string) => name === 'session-id' ? { value: 'session123' } : undefined
        }
      } as any

      // Record some attempts
      authMonitor.recordAuthAttempt(mockRequest, 'user1', true)
      authMonitor.recordAuthAttempt(mockRequest, 'user2', false, 'invalid_password')
      authMonitor.recordAuthAttempt(mockRequest, 'user3', false, 'account_locked')

      const stats = authMonitor.getAuthStats(24)

      expect(stats.totalAttempts).toBe(3)
      expect(stats.successfulLogins).toBe(1)
      expect(stats.failedLogins).toBe(2)
      expect(stats.topFailureReasons).toHaveLength(2)
      expect(stats.topFailureReasons[0].reason).toBe('invalid_password')
    })
  })
})

describe('Security Alert Manager', () => {
  let alertManager: SecurityAlertManager

  beforeEach(() => {
    alertManager = new SecurityAlertManager()
  })

  describe('Alert Processing', () => {
    it('should trigger alerts for critical events', () => {
      const alerts = alertManager.processSecurityEvent(
        SecurityEventType.SQL_INJECTION_ATTEMPT,
        SecuritySeverity.CRITICAL,
        { ip: '192.168.1.100', message: 'SQL injection detected' }
      )

      expect(alerts.length).toBeGreaterThan(0)
      expect(alerts[0].severity).toBe(SecuritySeverity.CRITICAL)
      expect(alerts[0].title).toContain('SQL_INJECTION_ATTEMPT')
    })

    it('should respect cooldown periods', () => {
      // First alert should trigger
      const firstAlerts = alertManager.processSecurityEvent(
        SecurityEventType.LOGIN_FAILURE,
        SecuritySeverity.HIGH,
        { ip: '192.168.1.100' }
      )

      // Second alert immediately after should be blocked by cooldown
      const secondAlerts = alertManager.processSecurityEvent(
        SecurityEventType.LOGIN_FAILURE,
        SecuritySeverity.HIGH,
        { ip: '192.168.1.100' }
      )

      expect(firstAlerts.length).toBeGreaterThan(0)
      expect(secondAlerts.length).toBe(0)
    })
  })

  describe('Alert Management', () => {
    it('should acknowledge alerts', () => {
      const alerts = alertManager.processSecurityEvent(
        SecurityEventType.BRUTE_FORCE_ATTEMPT,
        SecuritySeverity.HIGH,
        { ip: '192.168.1.100' }
      )

      const alertId = alerts[0].id
      const result = alertManager.acknowledgeAlert(alertId, 'admin')

      expect(result).toBe(true)

      const recentAlerts = alertManager.getRecentAlerts(10)
      const acknowledgedAlert = recentAlerts.find(a => a.id === alertId)
      expect(acknowledgedAlert?.acknowledged).toBe(true)
      expect(acknowledgedAlert?.acknowledgedBy).toBe('admin')
    })

    it('should resolve alerts', () => {
      const alerts = alertManager.processSecurityEvent(
        SecurityEventType.UNAUTHORIZED_ACCESS,
        SecuritySeverity.MEDIUM,
        { ip: '192.168.1.100' }
      )

      const alertId = alerts[0].id
      const result = alertManager.resolveAlert(alertId, 'admin')

      expect(result).toBe(true)

      const recentAlerts = alertManager.getRecentAlerts(10)
      const resolvedAlert = recentAlerts.find(a => a.id === alertId)
      expect(resolvedAlert?.resolved).toBe(true)
      expect(resolvedAlert?.resolvedBy).toBe('admin')
    })
  })

  describe('Alert Statistics', () => {
    it('should generate alert statistics', () => {
      // Generate some test alerts
      alertManager.processSecurityEvent(
        SecurityEventType.LOGIN_FAILURE,
        SecuritySeverity.MEDIUM,
        {}
      )
      alertManager.processSecurityEvent(
        SecurityEventType.SQL_INJECTION_ATTEMPT,
        SecuritySeverity.CRITICAL,
        {}
      )

      const stats = alertManager.getAlertStats(24)

      expect(stats.totalAlerts).toBeGreaterThanOrEqual(2)
      expect(stats.alertsBySeverity[SecuritySeverity.MEDIUM]).toBeGreaterThanOrEqual(1)
      expect(stats.alertsBySeverity[SecuritySeverity.CRITICAL]).toBeGreaterThanOrEqual(1)
    })
  })
})
