/**
 * Security Alert System
 * Business Scraper Application - Real-time Security Monitoring & Alerting
 */

import { logger } from '@/utils/logger'
import { SecurityEventType, SecuritySeverity } from './securityLogger'

/**
 * Alert channel types
 */
export enum AlertChannel {
  EMAIL = 'EMAIL',
  WEBHOOK = 'WEBHOOK',
  LOG = 'LOG',
  CONSOLE = 'CONSOLE',
  DATABASE = 'DATABASE'
}

/**
 * Alert configuration
 */
export interface AlertRule {
  id: string
  name: string
  description: string
  enabled: boolean
  eventTypes: SecurityEventType[]
  severity: SecuritySeverity[]
  conditions: AlertCondition[]
  channels: AlertChannel[]
  cooldown: number // minutes
  maxAlertsPerHour: number
}

/**
 * Alert condition
 */
export interface AlertCondition {
  type: 'count' | 'rate' | 'pattern' | 'threshold'
  field?: string
  operator: 'gt' | 'gte' | 'lt' | 'lte' | 'eq' | 'contains' | 'matches'
  value: number | string
  timeWindow?: number // minutes
}

/**
 * Alert instance
 */
export interface SecurityAlert {
  id: string
  ruleId: string
  ruleName: string
  timestamp: Date
  severity: SecuritySeverity
  title: string
  description: string
  details: Record<string, any>
  acknowledged: boolean
  acknowledgedBy?: string
  acknowledgedAt?: Date
  resolved: boolean
  resolvedBy?: string
  resolvedAt?: Date
}

/**
 * Alert notification
 */
export interface AlertNotification {
  id: string
  alertId: string
  channel: AlertChannel
  status: 'pending' | 'sent' | 'failed'
  sentAt?: Date
  error?: string
  retryCount: number
}

/**
 * Security Alert Manager
 */
export class SecurityAlertManager {
  private rules: Map<string, AlertRule> = new Map()
  private alerts: SecurityAlert[] = []
  private notifications: AlertNotification[] = []
  private lastAlertTime = new Map<string, Date>()
  private alertCounts = new Map<string, number>()
  private maxAlerts = 5000
  private maxNotifications = 10000

  constructor() {
    this.initializeDefaultRules()
  }

  /**
   * Initialize default alert rules
   */
  private initializeDefaultRules(): void {
    const defaultRules: AlertRule[] = [
      {
        id: 'critical-events',
        name: 'Critical Security Events',
        description: 'Alert on any critical security event',
        enabled: true,
        eventTypes: Object.values(SecurityEventType),
        severity: [SecuritySeverity.CRITICAL],
        conditions: [],
        channels: [AlertChannel.LOG, AlertChannel.CONSOLE],
        cooldown: 5,
        maxAlertsPerHour: 20
      },
      {
        id: 'failed-login-burst',
        name: 'Failed Login Burst',
        description: 'Multiple failed login attempts in short time',
        enabled: true,
        eventTypes: [SecurityEventType.LOGIN_FAILURE],
        severity: [SecuritySeverity.MEDIUM, SecuritySeverity.HIGH, SecuritySeverity.CRITICAL],
        conditions: [
          {
            type: 'count',
            operator: 'gte',
            value: 10,
            timeWindow: 5
          }
        ],
        channels: [AlertChannel.LOG, AlertChannel.CONSOLE],
        cooldown: 15,
        maxAlertsPerHour: 4
      },
      {
        id: 'sql-injection-attempt',
        name: 'SQL Injection Attempt',
        description: 'Potential SQL injection attack detected',
        enabled: true,
        eventTypes: [SecurityEventType.SQL_INJECTION_ATTEMPT],
        severity: [SecuritySeverity.HIGH, SecuritySeverity.CRITICAL],
        conditions: [],
        channels: [AlertChannel.LOG, AlertChannel.CONSOLE],
        cooldown: 10,
        maxAlertsPerHour: 6
      },
      {
        id: 'brute-force-attack',
        name: 'Brute Force Attack',
        description: 'Brute force attack pattern detected',
        enabled: true,
        eventTypes: [SecurityEventType.BRUTE_FORCE_ATTEMPT],
        severity: [SecuritySeverity.HIGH, SecuritySeverity.CRITICAL],
        conditions: [],
        channels: [AlertChannel.LOG, AlertChannel.CONSOLE],
        cooldown: 30,
        maxAlertsPerHour: 2
      },
      {
        id: 'unauthorized-data-access',
        name: 'Unauthorized Data Access',
        description: 'Attempt to access data without authorization',
        enabled: true,
        eventTypes: [SecurityEventType.UNAUTHORIZED_DATA_ACCESS],
        severity: [SecuritySeverity.MEDIUM, SecuritySeverity.HIGH, SecuritySeverity.CRITICAL],
        conditions: [],
        channels: [AlertChannel.LOG, AlertChannel.CONSOLE],
        cooldown: 10,
        maxAlertsPerHour: 10
      },
      {
        id: 'high-risk-activity',
        name: 'High Risk Activity',
        description: 'High volume of high-risk security events',
        enabled: true,
        eventTypes: Object.values(SecurityEventType),
        severity: [SecuritySeverity.HIGH, SecuritySeverity.CRITICAL],
        conditions: [
          {
            type: 'count',
            operator: 'gte',
            value: 20,
            timeWindow: 60
          }
        ],
        channels: [AlertChannel.LOG, AlertChannel.CONSOLE],
        cooldown: 60,
        maxAlertsPerHour: 1
      }
    ]

    defaultRules.forEach(rule => this.rules.set(rule.id, rule))
  }

  /**
   * Process security event and check for alerts
   */
  processSecurityEvent(
    eventType: SecurityEventType,
    severity: SecuritySeverity,
    details: Record<string, any>
  ): SecurityAlert[] {
    const triggeredAlerts: SecurityAlert[] = []

    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue

      // Check if event matches rule criteria
      if (!this.eventMatchesRule(eventType, severity, details, rule)) {
        continue
      }

      // Check cooldown
      if (this.isInCooldown(rule.id)) {
        continue
      }

      // Check rate limiting
      if (this.exceedsRateLimit(rule.id)) {
        continue
      }

      // Create alert
      const alert = this.createAlert(rule, eventType, severity, details)
      triggeredAlerts.push(alert)

      // Send notifications
      this.sendNotifications(alert, rule.channels)

      // Update tracking
      this.updateAlertTracking(rule.id)
    }

    return triggeredAlerts
  }

  /**
   * Check if event matches alert rule
   */
  private eventMatchesRule(
    eventType: SecurityEventType,
    severity: SecuritySeverity,
    details: Record<string, any>,
    rule: AlertRule
  ): boolean {
    // Check event type
    if (!rule.eventTypes.includes(eventType)) {
      return false
    }

    // Check severity
    if (!rule.severity.includes(severity)) {
      return false
    }

    // Check conditions
    for (const condition of rule.conditions) {
      if (!this.evaluateCondition(condition, eventType, severity, details)) {
        return false
      }
    }

    return true
  }

  /**
   * Evaluate alert condition
   */
  private evaluateCondition(
    condition: AlertCondition,
    eventType: SecurityEventType,
    severity: SecuritySeverity,
    details: Record<string, any>
  ): boolean {
    switch (condition.type) {
      case 'count':
        return this.evaluateCountCondition(condition, eventType)
      case 'rate':
        return this.evaluateRateCondition(condition, eventType)
      case 'threshold':
        return this.evaluateThresholdCondition(condition, details)
      case 'pattern':
        return this.evaluatePatternCondition(condition, details)
      default:
        return false
    }
  }

  /**
   * Evaluate count-based condition
   */
  private evaluateCountCondition(condition: AlertCondition, eventType: SecurityEventType): boolean {
    const timeWindow = condition.timeWindow || 60 // Default 1 hour
    const cutoff = new Date(Date.now() - timeWindow * 60 * 1000)
    
    // This would typically query the security events from the logger
    // For now, we'll use a simplified approach
    const recentEventCount = this.getRecentEventCount(eventType, cutoff)
    
    return this.compareValues(recentEventCount, condition.operator, condition.value as number)
  }

  /**
   * Evaluate rate-based condition
   */
  private evaluateRateCondition(condition: AlertCondition, eventType: SecurityEventType): boolean {
    const timeWindow = condition.timeWindow || 60
    const cutoff = new Date(Date.now() - timeWindow * 60 * 1000)
    
    const eventCount = this.getRecentEventCount(eventType, cutoff)
    const rate = eventCount / timeWindow // events per minute
    
    return this.compareValues(rate, condition.operator, condition.value as number)
  }

  /**
   * Evaluate threshold-based condition
   */
  private evaluateThresholdCondition(condition: AlertCondition, details: Record<string, any>): boolean {
    if (!condition.field) return false
    
    const value = details[condition.field]
    if (value === undefined) return false
    
    return this.compareValues(value, condition.operator, condition.value)
  }

  /**
   * Evaluate pattern-based condition
   */
  private evaluatePatternCondition(condition: AlertCondition, details: Record<string, any>): boolean {
    if (!condition.field) return false
    
    const value = details[condition.field]
    if (typeof value !== 'string') return false
    
    switch (condition.operator) {
      case 'contains':
        return value.includes(condition.value as string)
      case 'matches':
        const regex = new RegExp(condition.value as string)
        return regex.test(value)
      default:
        return false
    }
  }

  /**
   * Compare values based on operator
   */
  private compareValues(actual: any, operator: string, expected: any): boolean {
    switch (operator) {
      case 'gt': return actual > expected
      case 'gte': return actual >= expected
      case 'lt': return actual < expected
      case 'lte': return actual <= expected
      case 'eq': return actual === expected
      default: return false
    }
  }

  /**
   * Get recent event count (simplified implementation)
   */
  private getRecentEventCount(eventType: SecurityEventType, cutoff: Date): number {
    // This would typically query the security logger
    // For now, return a placeholder value
    return 0
  }

  /**
   * Check if rule is in cooldown period
   */
  private isInCooldown(ruleId: string): boolean {
    const lastAlert = this.lastAlertTime.get(ruleId)
    if (!lastAlert) return false

    const rule = this.rules.get(ruleId)
    if (!rule) return false

    const cooldownEnd = new Date(lastAlert.getTime() + rule.cooldown * 60 * 1000)
    return new Date() < cooldownEnd
  }

  /**
   * Check if rule exceeds rate limit
   */
  private exceedsRateLimit(ruleId: string): boolean {
    const rule = this.rules.get(ruleId)
    if (!rule) return false

    const hourAgo = new Date(Date.now() - 60 * 60 * 1000)
    const recentAlerts = this.alerts.filter(alert => 
      alert.ruleId === ruleId && alert.timestamp >= hourAgo
    )

    return recentAlerts.length >= rule.maxAlertsPerHour
  }

  /**
   * Create security alert
   */
  private createAlert(
    rule: AlertRule,
    eventType: SecurityEventType,
    severity: SecuritySeverity,
    details: Record<string, any>
  ): SecurityAlert {
    const alert: SecurityAlert = {
      id: crypto.randomUUID(),
      ruleId: rule.id,
      ruleName: rule.name,
      timestamp: new Date(),
      severity,
      title: `${rule.name}: ${eventType}`,
      description: this.generateAlertDescription(rule, eventType, details),
      details,
      acknowledged: false,
      resolved: false
    }

    this.alerts.push(alert)
    if (this.alerts.length > this.maxAlerts) {
      this.alerts = this.alerts.slice(-this.maxAlerts)
    }

    logger.warn('SecurityAlert', `Security alert triggered: ${alert.title}`, {
      alertId: alert.id,
      ruleId: rule.id,
      severity,
      eventType
    })

    return alert
  }

  /**
   * Generate alert description
   */
  private generateAlertDescription(
    rule: AlertRule,
    eventType: SecurityEventType,
    details: Record<string, any>
  ): string {
    let description = rule.description

    if (details.ip) {
      description += ` from IP ${details.ip}`
    }

    if (details.username) {
      description += ` for user ${details.username}`
    }

    if (details.endpoint) {
      description += ` on endpoint ${details.endpoint}`
    }

    if (details.message) {
      description += `. ${details.message}`
    }

    return description
  }

  /**
   * Send notifications for alert
   */
  private sendNotifications(alert: SecurityAlert, channels: AlertChannel[]): void {
    for (const channel of channels) {
      const notification: AlertNotification = {
        id: crypto.randomUUID(),
        alertId: alert.id,
        channel,
        status: 'pending',
        retryCount: 0
      }

      this.notifications.push(notification)
      if (this.notifications.length > this.maxNotifications) {
        this.notifications = this.notifications.slice(-this.maxNotifications)
      }

      // Send notification
      this.sendNotification(notification, alert)
    }
  }

  /**
   * Send individual notification
   */
  private async sendNotification(notification: AlertNotification, alert: SecurityAlert): Promise<void> {
    try {
      switch (notification.channel) {
        case AlertChannel.LOG:
          this.sendLogNotification(alert)
          break
        case AlertChannel.CONSOLE:
          this.sendConsoleNotification(alert)
          break
        case AlertChannel.EMAIL:
          await this.sendEmailNotification(alert)
          break
        case AlertChannel.WEBHOOK:
          await this.sendWebhookNotification(alert)
          break
        case AlertChannel.DATABASE:
          await this.sendDatabaseNotification(alert)
          break
      }

      notification.status = 'sent'
      notification.sentAt = new Date()
    } catch (error) {
      notification.status = 'failed'
      notification.error = error instanceof Error ? error.message : 'Unknown error'
      notification.retryCount++

      logger.error('SecurityAlert', `Failed to send notification`, {
        notificationId: notification.id,
        channel: notification.channel,
        error: notification.error
      })
    }
  }

  /**
   * Send log notification
   */
  private sendLogNotification(alert: SecurityAlert): void {
    const logLevel = alert.severity === SecuritySeverity.CRITICAL ? 'error' : 'warn'
    logger[logLevel]('SecurityAlert', alert.title, {
      alertId: alert.id,
      severity: alert.severity,
      description: alert.description,
      details: alert.details
    })
  }

  /**
   * Send console notification
   */
  private sendConsoleNotification(alert: SecurityAlert): void {
    const timestamp = alert.timestamp.toISOString()
    const severityIcon = alert.severity === SecuritySeverity.CRITICAL ? '🚨' : '⚠️'
    
    console.warn(`${severityIcon} [${timestamp}] SECURITY ALERT: ${alert.title}`)
    console.warn(`   Description: ${alert.description}`)
    console.warn(`   Severity: ${alert.severity}`)
    console.warn(`   Alert ID: ${alert.id}`)
  }

  /**
   * Send email notification (placeholder)
   */
  private async sendEmailNotification(alert: SecurityAlert): Promise<void> {
    // Placeholder for email notification
    // In production, integrate with email service (SendGrid, SES, etc.)
    logger.info('SecurityAlert', `Email notification would be sent for alert: ${alert.id}`)
  }

  /**
   * Send webhook notification (placeholder)
   */
  private async sendWebhookNotification(alert: SecurityAlert): Promise<void> {
    // Placeholder for webhook notification
    // In production, send HTTP POST to configured webhook URL
    logger.info('SecurityAlert', `Webhook notification would be sent for alert: ${alert.id}`)
  }

  /**
   * Send database notification (placeholder)
   */
  private async sendDatabaseNotification(alert: SecurityAlert): Promise<void> {
    // Placeholder for database notification
    // In production, insert alert into database table
    logger.info('SecurityAlert', `Database notification would be sent for alert: ${alert.id}`)
  }

  /**
   * Update alert tracking
   */
  private updateAlertTracking(ruleId: string): void {
    this.lastAlertTime.set(ruleId, new Date())
    
    const currentCount = this.alertCounts.get(ruleId) || 0
    this.alertCounts.set(ruleId, currentCount + 1)
  }

  /**
   * Get recent alerts
   */
  getRecentAlerts(limit: number = 100): SecurityAlert[] {
    return [...this.alerts].reverse().slice(0, limit)
  }

  /**
   * Get alert statistics
   */
  getAlertStats(timeWindow: number = 24): {
    totalAlerts: number
    alertsBySeverity: Record<SecuritySeverity, number>
    alertsByRule: Array<{ ruleId: string; ruleName: string; count: number }>
    acknowledgedAlerts: number
    resolvedAlerts: number
  } {
    const cutoff = new Date(Date.now() - timeWindow * 60 * 60 * 1000)
    const recentAlerts = this.alerts.filter(alert => alert.timestamp >= cutoff)

    const alertsBySeverity = recentAlerts.reduce((acc, alert) => {
      acc[alert.severity] = (acc[alert.severity] || 0) + 1
      return acc
    }, {} as Record<SecuritySeverity, number>)

    const alertsByRule = Object.entries(
      recentAlerts.reduce((acc, alert) => {
        acc[alert.ruleId] = (acc[alert.ruleId] || 0) + 1
        return acc
      }, {} as Record<string, number>)
    ).map(([ruleId, count]) => ({
      ruleId,
      ruleName: this.rules.get(ruleId)?.name || 'Unknown',
      count
    }))

    return {
      totalAlerts: recentAlerts.length,
      alertsBySeverity,
      alertsByRule,
      acknowledgedAlerts: recentAlerts.filter(alert => alert.acknowledged).length,
      resolvedAlerts: recentAlerts.filter(alert => alert.resolved).length
    }
  }

  /**
   * Acknowledge alert
   */
  acknowledgeAlert(alertId: string, acknowledgedBy: string): boolean {
    const alert = this.alerts.find(a => a.id === alertId)
    if (!alert) return false

    alert.acknowledged = true
    alert.acknowledgedBy = acknowledgedBy
    alert.acknowledgedAt = new Date()

    logger.info('SecurityAlert', `Alert acknowledged`, {
      alertId,
      acknowledgedBy,
      acknowledgedAt: alert.acknowledgedAt
    })

    return true
  }

  /**
   * Resolve alert
   */
  resolveAlert(alertId: string, resolvedBy: string): boolean {
    const alert = this.alerts.find(a => a.id === alertId)
    if (!alert) return false

    alert.resolved = true
    alert.resolvedBy = resolvedBy
    alert.resolvedAt = new Date()

    logger.info('SecurityAlert', `Alert resolved`, {
      alertId,
      resolvedBy,
      resolvedAt: alert.resolvedAt
    })

    return true
  }

  /**
   * Add custom alert rule
   */
  addAlertRule(rule: AlertRule): void {
    this.rules.set(rule.id, rule)
    logger.info('SecurityAlert', `Alert rule added: ${rule.name}`, { ruleId: rule.id })
  }

  /**
   * Update alert rule
   */
  updateAlertRule(ruleId: string, updates: Partial<AlertRule>): boolean {
    const rule = this.rules.get(ruleId)
    if (!rule) return false

    Object.assign(rule, updates)
    logger.info('SecurityAlert', `Alert rule updated: ${rule.name}`, { ruleId })
    return true
  }

  /**
   * Delete alert rule
   */
  deleteAlertRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId)
    if (!rule) return false

    this.rules.delete(ruleId)
    logger.info('SecurityAlert', `Alert rule deleted: ${rule.name}`, { ruleId })
    return true
  }

  /**
   * Get all alert rules
   */
  getAlertRules(): AlertRule[] {
    return Array.from(this.rules.values())
  }
}

// Export singleton instance
export const securityAlertManager = new SecurityAlertManager()
