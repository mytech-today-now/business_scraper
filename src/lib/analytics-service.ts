/**
 * Analytics Service
 * Provides real-time analytics, performance metrics, and business intelligence
 */

import { 
  PerformanceMetrics, 
  DataQualityMetrics, 
  UserActivitySummary,
  TeamPerformance,
  WorkspaceAnalytics
} from '@/types/multi-user'
import { database } from './postgresql-database'
import { logger } from '@/utils/logger'

export interface AnalyticsFilters {
  workspaceId?: string
  teamId?: string
  userId?: string
  startDate?: Date
  endDate?: Date
  period?: 'hour' | 'day' | 'week' | 'month'
}

export interface DashboardMetrics {
  overview: {
    totalUsers: number
    activeUsers: number
    totalTeams: number
    totalWorkspaces: number
    totalCampaigns: number
    totalBusinesses: number
    totalSessions: number
  }
  performance: PerformanceMetrics
  dataQuality: DataQualityMetrics
  userActivity: UserActivitySummary[]
  teamPerformance: TeamPerformance[]
  workspaceAnalytics: WorkspaceAnalytics[]
  trends: {
    userGrowth: Array<{ date: string; count: number }>
    campaignActivity: Array<{ date: string; count: number }>
    dataQualityTrend: Array<{ date: string; score: number }>
  }
}

export class AnalyticsService {
  /**
   * Get comprehensive dashboard metrics
   */
  static async getDashboardMetrics(filters: AnalyticsFilters): Promise<DashboardMetrics> {
    try {
      const [
        overview,
        performance,
        dataQuality,
        userActivity,
        teamPerformance,
        workspaceAnalytics,
        trends
      ] = await Promise.all([
        this.getOverviewMetrics(filters),
        this.getPerformanceMetrics(filters),
        this.getDataQualityMetrics(filters),
        this.getUserActivitySummary(filters),
        this.getTeamPerformance(filters),
        this.getWorkspaceAnalytics(filters),
        this.getTrendMetrics(filters)
      ])

      return {
        overview,
        performance,
        dataQuality,
        userActivity,
        teamPerformance,
        workspaceAnalytics,
        trends
      }
    } catch (error) {
      logger.error('Analytics Service', 'Error getting dashboard metrics', error)
      throw error
    }
  }

  /**
   * Get overview metrics
   */
  static async getOverviewMetrics(filters: AnalyticsFilters): Promise<DashboardMetrics['overview']> {
    try {
      const conditions = this.buildWhereConditions(filters)
      const { whereClause, values } = conditions

      // Get basic counts
      const overviewQuery = `
        SELECT 
          (SELECT COUNT(*) FROM users WHERE is_active = true) as total_users,
          (SELECT COUNT(*) FROM users WHERE is_active = true AND last_login_at > CURRENT_DATE - INTERVAL '30 days') as active_users,
          (SELECT COUNT(*) FROM teams WHERE is_active = true) as total_teams,
          (SELECT COUNT(*) FROM workspaces WHERE is_active = true) as total_workspaces,
          (SELECT COUNT(*) FROM campaigns) as total_campaigns,
          (SELECT COUNT(*) FROM businesses) as total_businesses,
          (SELECT COUNT(*) FROM scraping_sessions) as total_sessions
      `

      const result = await database.query(overviewQuery)
      const row = result.rows[0]

      return {
        totalUsers: parseInt(row.total_users),
        activeUsers: parseInt(row.active_users),
        totalTeams: parseInt(row.total_teams),
        totalWorkspaces: parseInt(row.total_workspaces),
        totalCampaigns: parseInt(row.total_campaigns),
        totalBusinesses: parseInt(row.total_businesses),
        totalSessions: parseInt(row.total_sessions)
      }
    } catch (error) {
      logger.error('Analytics Service', 'Error getting overview metrics', error)
      throw error
    }
  }

  /**
   * Get performance metrics
   */
  static async getPerformanceMetrics(filters: AnalyticsFilters): Promise<PerformanceMetrics> {
    try {
      const conditions = this.buildWhereConditions(filters, 'ss')
      const { whereClause, values } = conditions

      const performanceQuery = `
        SELECT 
          AVG(EXTRACT(EPOCH FROM (ss.completed_at - ss.started_at))) as avg_scraping_time,
          AVG(ss.successful_scrapes::float / NULLIF(ss.total_urls, 0) * 100) as success_rate,
          AVG(ss.failed_scrapes::float / NULLIF(ss.total_urls, 0) * 100) as error_rate,
          COUNT(DISTINCT ss.id) as total_sessions,
          SUM(ss.successful_scrapes) as total_successful,
          SUM(ss.failed_scrapes) as total_failed
        FROM scraping_sessions ss
        ${whereClause}
        AND ss.completed_at IS NOT NULL
      `

      const result = await database.query(performanceQuery, values)
      const row = result.rows[0]

      // Calculate additional metrics
      const totalRequests = (parseInt(row.total_successful) || 0) + (parseInt(row.total_failed) || 0)
      const requestThroughput = totalRequests > 0 ? totalRequests / Math.max(1, parseInt(row.total_sessions)) : 0

      return {
        workspaceId: filters.workspaceId || '',
        period: filters.period || 'day',
        timestamp: new Date(),
        avgScrapingTime: parseFloat(row.avg_scraping_time) || 0,
        requestThroughput,
        errorRate: parseFloat(row.error_rate) || 0,
        successRate: parseFloat(row.success_rate) || 0,
        avgResponseTime: 0, // Would need to be tracked separately
        memoryUsage: 0, // Would need to be tracked separately
        cpuUsage: 0, // Would need to be tracked separately
        activeUsers: 0, // Would need to be calculated separately
        concurrentSessions: 0, // Would need to be tracked separately
        totalActions: parseInt(row.total_sessions) || 0
      }
    } catch (error) {
      logger.error('Analytics Service', 'Error getting performance metrics', error)
      throw error
    }
  }

  /**
   * Get data quality metrics
   */
  static async getDataQualityMetrics(filters: AnalyticsFilters): Promise<DataQualityMetrics> {
    try {
      const conditions = this.buildWhereConditions(filters, 'b')
      const { whereClause, values } = conditions

      const qualityQuery = `
        SELECT 
          COUNT(*) as total_records,
          COUNT(CASE WHEN b.validation_status = 'validated' THEN 1 END) as valid_records,
          COUNT(CASE WHEN b.validation_status = 'rejected' THEN 1 END) as invalid_records,
          COUNT(CASE WHEN b.confidence_score > 0.8 THEN 1 END) as high_confidence,
          COUNT(CASE WHEN b.confidence_score BETWEEN 0.5 AND 0.8 THEN 1 END) as medium_confidence,
          COUNT(CASE WHEN b.confidence_score < 0.5 THEN 1 END) as low_confidence,
          AVG(b.confidence_score) as avg_confidence,
          COUNT(CASE WHEN array_length(b.email, 1) > 0 THEN 1 END) as enriched_records
        FROM businesses b
        LEFT JOIN campaigns c ON b.campaign_id = c.id
        ${whereClause}
      `

      const result = await database.query(qualityQuery, values)
      const row = result.rows[0]

      const totalRecords = parseInt(row.total_records) || 0
      const validRecords = parseInt(row.valid_records) || 0
      const enrichedRecords = parseInt(row.enriched_records) || 0

      return {
        workspaceId: filters.workspaceId || '',
        campaignId: undefined,
        period: filters.period || 'day',
        totalRecords,
        validRecords,
        invalidRecords: parseInt(row.invalid_records) || 0,
        duplicateRecords: 0, // Would need separate duplicate detection query
        incompleteRecords: totalRecords - validRecords,
        highConfidence: parseInt(row.high_confidence) || 0,
        mediumConfidence: parseInt(row.medium_confidence) || 0,
        lowConfidence: parseInt(row.low_confidence) || 0,
        enrichmentRate: totalRecords > 0 ? (enrichedRecords / totalRecords) * 100 : 0,
        enrichmentAccuracy: 0, // Would need to be tracked separately
        validationRate: totalRecords > 0 ? (validRecords / totalRecords) * 100 : 0,
        validationAccuracy: 0, // Would need to be tracked separately
        avgValidationTime: 0 // Would need to be tracked separately
      }
    } catch (error) {
      logger.error('Analytics Service', 'Error getting data quality metrics', error)
      throw error
    }
  }

  /**
   * Get user activity summary
   */
  static async getUserActivitySummary(filters: AnalyticsFilters): Promise<UserActivitySummary[]> {
    try {
      const conditions = this.buildWhereConditions(filters, 'u')
      const { whereClause, values } = conditions

      const activityQuery = `
        SELECT 
          u.id,
          u.username,
          u.first_name,
          u.last_name,
          u.last_login_at,
          COUNT(DISTINCT c.id) as campaigns_created,
          COUNT(DISTINCT b.id) FILTER (WHERE b.validated_by = u.id) as businesses_validated,
          COUNT(DISTINCT ss.id) FILTER (WHERE ss.created_by = u.id) as scraping_sessions_run,
          COUNT(DISTINCT al.id) as total_actions,
          AVG(b.confidence_score) FILTER (WHERE b.validated_by = u.id) as avg_validation_score
        FROM users u
        LEFT JOIN campaigns c ON u.id = c.created_by
        LEFT JOIN businesses b ON u.id = b.validated_by
        LEFT JOIN scraping_sessions ss ON u.id = ss.created_by
        LEFT JOIN audit_logs al ON u.id = al.user_id
        ${whereClause}
        AND u.is_active = true
        GROUP BY u.id, u.username, u.first_name, u.last_name, u.last_login_at
        ORDER BY total_actions DESC
        LIMIT 20
      `

      const result = await database.query(activityQuery, values)

      return result.rows.map(row => ({
        id: row.id,
        username: row.username,
        firstName: row.first_name,
        lastName: row.last_name,
        lastLoginAt: row.last_login_at,
        campaignsCreated: parseInt(row.campaigns_created) || 0,
        businessesValidated: parseInt(row.businesses_validated) || 0,
        scrapingSessionsRun: parseInt(row.scraping_sessions_run) || 0,
        totalActions: parseInt(row.total_actions) || 0,
        avgValidationScore: parseFloat(row.avg_validation_score) || undefined
      }))
    } catch (error) {
      logger.error('Analytics Service', 'Error getting user activity summary', error)
      throw error
    }
  }

  /**
   * Get team performance metrics
   */
  static async getTeamPerformance(filters: AnalyticsFilters): Promise<TeamPerformance[]> {
    try {
      const conditions = this.buildWhereConditions(filters, 't')
      const { whereClause, values } = conditions

      const teamQuery = `
        SELECT 
          t.id,
          t.name,
          COUNT(DISTINCT tm.user_id) FILTER (WHERE tm.is_active = true) as member_count,
          COUNT(DISTINCT w.id) FILTER (WHERE w.is_active = true) as workspace_count,
          COUNT(DISTINCT c.id) as total_campaigns,
          COUNT(DISTINCT b.id) as total_businesses,
          AVG(b.confidence_score) as avg_confidence_score,
          COUNT(CASE WHEN c.status = 'completed' THEN 1 END) as completed_campaigns
        FROM teams t
        LEFT JOIN team_members tm ON t.id = tm.team_id
        LEFT JOIN workspaces w ON t.id = w.team_id
        LEFT JOIN campaigns c ON w.id = c.workspace_id
        LEFT JOIN businesses b ON c.id = b.campaign_id
        ${whereClause}
        AND t.is_active = true
        GROUP BY t.id, t.name
        ORDER BY total_campaigns DESC
        LIMIT 20
      `

      const result = await database.query(teamQuery, values)

      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        memberCount: parseInt(row.member_count) || 0,
        workspaceCount: parseInt(row.workspace_count) || 0,
        totalCampaigns: parseInt(row.total_campaigns) || 0,
        totalBusinesses: parseInt(row.total_businesses) || 0,
        avgConfidenceScore: parseFloat(row.avg_confidence_score) || undefined,
        completedCampaigns: parseInt(row.completed_campaigns) || 0
      }))
    } catch (error) {
      logger.error('Analytics Service', 'Error getting team performance', error)
      throw error
    }
  }

  /**
   * Get workspace analytics
   */
  static async getWorkspaceAnalytics(filters: AnalyticsFilters): Promise<WorkspaceAnalytics[]> {
    try {
      const conditions = this.buildWhereConditions(filters, 'w')
      const { whereClause, values } = conditions

      const workspaceQuery = `
        SELECT 
          w.id,
          w.name,
          t.name as team_name,
          COUNT(DISTINCT wm.user_id) FILTER (WHERE wm.is_active = true) as member_count,
          COUNT(DISTINCT c.id) as campaign_count,
          COUNT(DISTINCT b.id) as business_count,
          COUNT(DISTINCT ss.id) as session_count,
          AVG(b.confidence_score) as avg_confidence_score,
          COUNT(CASE WHEN b.validation_status = 'validated' THEN 1 END) as validated_businesses,
          COUNT(CASE WHEN c.status = 'completed' THEN 1 END) as completed_campaigns,
          MAX(ss.completed_at) as last_scraping_activity
        FROM workspaces w
        JOIN teams t ON w.team_id = t.id
        LEFT JOIN workspace_members wm ON w.id = wm.workspace_id
        LEFT JOIN campaigns c ON w.id = c.workspace_id
        LEFT JOIN businesses b ON c.id = b.campaign_id
        LEFT JOIN scraping_sessions ss ON w.id = ss.workspace_id
        ${whereClause}
        AND w.is_active = true
        GROUP BY w.id, w.name, t.name
        ORDER BY campaign_count DESC
        LIMIT 20
      `

      const result = await database.query(workspaceQuery, values)

      return result.rows.map(row => ({
        id: row.id,
        name: row.name,
        teamName: row.team_name,
        memberCount: parseInt(row.member_count) || 0,
        campaignCount: parseInt(row.campaign_count) || 0,
        businessCount: parseInt(row.business_count) || 0,
        sessionCount: parseInt(row.session_count) || 0,
        avgConfidenceScore: parseFloat(row.avg_confidence_score) || undefined,
        validatedBusinesses: parseInt(row.validated_businesses) || 0,
        completedCampaigns: parseInt(row.completed_campaigns) || 0,
        lastScrapingActivity: row.last_scraping_activity
      }))
    } catch (error) {
      logger.error('Analytics Service', 'Error getting workspace analytics', error)
      throw error
    }
  }

  /**
   * Get trend metrics
   */
  static async getTrendMetrics(filters: AnalyticsFilters): Promise<DashboardMetrics['trends']> {
    try {
      const dateRange = this.getDateRange(filters)
      
      // User growth trend
      const userGrowthQuery = `
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as count
        FROM users
        WHERE created_at >= $1 AND created_at <= $2
        GROUP BY DATE(created_at)
        ORDER BY date
      `
      const userGrowthResult = await database.query(userGrowthQuery, [dateRange.start, dateRange.end])

      // Campaign activity trend
      const campaignActivityQuery = `
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as count
        FROM campaigns
        WHERE created_at >= $1 AND created_at <= $2
        GROUP BY DATE(created_at)
        ORDER BY date
      `
      const campaignActivityResult = await database.query(campaignActivityQuery, [dateRange.start, dateRange.end])

      // Data quality trend
      const dataQualityQuery = `
        SELECT 
          DATE(scraped_at) as date,
          AVG(confidence_score) as score
        FROM businesses
        WHERE scraped_at >= $1 AND scraped_at <= $2
        GROUP BY DATE(scraped_at)
        ORDER BY date
      `
      const dataQualityResult = await database.query(dataQualityQuery, [dateRange.start, dateRange.end])

      return {
        userGrowth: userGrowthResult.rows.map(row => ({
          date: row.date,
          count: parseInt(row.count)
        })),
        campaignActivity: campaignActivityResult.rows.map(row => ({
          date: row.date,
          count: parseInt(row.count)
        })),
        dataQualityTrend: dataQualityResult.rows.map(row => ({
          date: row.date,
          score: parseFloat(row.score)
        }))
      }
    } catch (error) {
      logger.error('Analytics Service', 'Error getting trend metrics', error)
      throw error
    }
  }

  /**
   * Build WHERE conditions for queries
   */
  private static buildWhereConditions(filters: AnalyticsFilters, tableAlias?: string): {
    whereClause: string
    values: any[]
  } {
    const conditions: string[] = ['1=1']
    const values: any[] = []
    let paramIndex = 1

    const prefix = tableAlias ? `${tableAlias}.` : ''

    if (filters.workspaceId) {
      conditions.push(`${prefix}workspace_id = $${paramIndex++}`)
      values.push(filters.workspaceId)
    }

    if (filters.teamId) {
      conditions.push(`${prefix}team_id = $${paramIndex++}`)
      values.push(filters.teamId)
    }

    if (filters.userId) {
      conditions.push(`${prefix}user_id = $${paramIndex++}`)
      values.push(filters.userId)
    }

    if (filters.startDate) {
      conditions.push(`${prefix}created_at >= $${paramIndex++}`)
      values.push(filters.startDate)
    }

    if (filters.endDate) {
      conditions.push(`${prefix}created_at <= $${paramIndex++}`)
      values.push(filters.endDate)
    }

    return {
      whereClause: conditions.length > 1 ? `WHERE ${conditions.join(' AND ')}` : '',
      values
    }
  }

  /**
   * Get date range for trends
   */
  private static getDateRange(filters: AnalyticsFilters): { start: Date; end: Date } {
    const end = filters.endDate || new Date()
    let start = filters.startDate

    if (!start) {
      // Default to appropriate range based on period
      const daysBack = filters.period === 'hour' ? 1 :
                      filters.period === 'day' ? 30 :
                      filters.period === 'week' ? 90 :
                      365 // month or default

      start = new Date(end.getTime() - daysBack * 24 * 60 * 60 * 1000)
    }

    return { start, end }
  }

  /**
   * Get real-time metrics (for WebSocket updates)
   */
  static async getRealtimeMetrics(workspaceId?: string): Promise<{
    activeUsers: number
    activeSessions: number
    recentActivity: Array<{ action: string; timestamp: Date; user: string }>
  }> {
    try {
      // Get active users (logged in within last hour)
      const activeUsersQuery = `
        SELECT COUNT(DISTINCT user_id) as count
        FROM user_sessions
        WHERE is_active = true 
        AND last_accessed_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'
        ${workspaceId ? 'AND workspace_id = $1' : ''}
      `
      const activeUsersResult = await database.query(
        activeUsersQuery, 
        workspaceId ? [workspaceId] : []
      )

      // Get active scraping sessions
      const activeSessionsQuery = `
        SELECT COUNT(*) as count
        FROM scraping_sessions
        WHERE status = 'running'
        ${workspaceId ? 'AND workspace_id = $1' : ''}
      `
      const activeSessionsResult = await database.query(
        activeSessionsQuery,
        workspaceId ? [workspaceId] : []
      )

      // Get recent activity
      const recentActivityQuery = `
        SELECT 
          al.action,
          al.timestamp,
          u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ${workspaceId ? 'WHERE al.workspace_id = $1' : 'WHERE 1=1'}
        ORDER BY al.timestamp DESC
        LIMIT 10
      `
      const recentActivityResult = await database.query(
        recentActivityQuery,
        workspaceId ? [workspaceId] : []
      )

      return {
        activeUsers: parseInt(activeUsersResult.rows[0].count) || 0,
        activeSessions: parseInt(activeSessionsResult.rows[0].count) || 0,
        recentActivity: recentActivityResult.rows.map(row => ({
          action: row.action,
          timestamp: row.timestamp,
          user: row.username || 'Unknown'
        }))
      }
    } catch (error) {
      logger.error('Analytics Service', 'Error getting realtime metrics', error)
      throw error
    }
  }
}
