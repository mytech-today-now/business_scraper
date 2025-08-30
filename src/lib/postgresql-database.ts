/**
 * PostgreSQL database implementation
 * Server-side database operations using pg library
 */

import crypto from 'crypto'
import { Pool, PoolClient } from 'pg'
import { DatabaseInterface, DatabaseConfig } from './database'
import { logger } from '@/utils/logger'
import { SecureDatabase } from './secureDatabase'
import { metrics } from '@/lib/metrics'
import { withDatabasePerformanceTracking } from '@/middleware/performanceMiddleware'

export class PostgreSQLDatabase implements DatabaseInterface {
  private secureDb: SecureDatabase

  constructor(config: DatabaseConfig) {
    // Create secure database connection with hardened configuration
    this.secureDb = new SecureDatabase({
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.username,
      password: config.password,
      ssl: config.ssl,
      min: config.poolMin || 2,
      max: config.poolMax || 10,
      idleTimeoutMillis: config.idleTimeout || 30000,
      connectionTimeoutMillis: config.connectionTimeout || 5000,
    })

    this.connected = true
    logger.info('PostgreSQL', 'Secure database connection initialized')
  }

  private async query(text: string, params?: any[]): Promise<any> {
    // Use performance tracking wrapper for monitoring service integration
    return withDatabasePerformanceTracking(
      `postgresql_${this.extractOperationType(text).toLowerCase()}_${this.extractTableName(text)}`,
      async () => {
        const startTime = Date.now()
        const operation = this.extractOperationType(text)
        const table = this.extractTableName(text)

        try {
          // Initialize metrics
          await metrics.initialize()

          // Use secure database wrapper with SQL injection protection
          const result = await this.secureDb.query(text, params, {
            validateQuery: true,
            logQuery: process.env.NODE_ENV === 'development',
          })

          const duration = (Date.now() - startTime) / 1000

          // Record successful query metrics (existing Prometheus metrics)
          metrics.dbQueryDuration.observe({ operation, table, status: 'success' }, duration)
          metrics.dbQueryTotal.inc({ operation, table, status: 'success' })

          return result
        } catch (error) {
          const duration = (Date.now() - startTime) / 1000

          // Record error metrics
          metrics.dbQueryDuration.observe({ operation, table, status: 'error' }, duration)
          metrics.dbQueryTotal.inc({ operation, table, status: 'error' })
          metrics.dbQueryErrors.inc({
            operation,
            table,
            error_type: error instanceof Error ? error.name : 'unknown',
          })

          throw error
        }
      }
    )
  }

  private extractOperationType(query: string): string {
    const normalizedQuery = query.trim().toUpperCase()
    if (normalizedQuery.startsWith('SELECT')) return 'SELECT'
    if (normalizedQuery.startsWith('INSERT')) return 'INSERT'
    if (normalizedQuery.startsWith('UPDATE')) return 'UPDATE'
    if (normalizedQuery.startsWith('DELETE')) return 'DELETE'
    if (normalizedQuery.startsWith('CREATE')) return 'CREATE'
    if (normalizedQuery.startsWith('DROP')) return 'DROP'
    if (normalizedQuery.startsWith('ALTER')) return 'ALTER'
    return 'OTHER'
  }

  private extractTableName(query: string): string {
    const normalizedQuery = query.trim().toUpperCase()

    // Extract table name from different query types
    let match = normalizedQuery.match(/FROM\s+(\w+)/i)
    if (match) return match[1].toLowerCase()

    match = normalizedQuery.match(/INTO\s+(\w+)/i)
    if (match) return match[1].toLowerCase()

    match = normalizedQuery.match(/UPDATE\s+(\w+)/i)
    if (match) return match[1].toLowerCase()

    match = normalizedQuery.match(/TABLE\s+(\w+)/i)
    if (match) return match[1].toLowerCase()

    return 'unknown'
  }

  // Campaign operations
  async createCampaign(campaign: any): Promise<string> {
    const id = campaign.id || crypto.randomUUID()

    const query = `
      INSERT INTO campaigns (
        id, name, industry, location, status, description,
        search_radius, search_depth, pages_per_site, zip_code, parameters
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id
    `

    const values = [
      id,
      campaign.name,
      campaign.industry,
      campaign.location,
      campaign.status || 'draft',
      campaign.description,
      campaign.searchRadius || 25,
      campaign.searchDepth || 3,
      campaign.pagesPerSite || 5,
      campaign.zipCode,
      JSON.stringify(campaign.parameters || {}),
    ]

    try {
      const result = await this.query(query, values)
      logger.info('PostgreSQL', `Created campaign: ${campaign.name}`)
      return result.rows[0].id
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to create campaign', error)
      throw error
    }
  }

  async getCampaign(id: string): Promise<any | null> {
    const query = 'SELECT * FROM campaigns WHERE id = $1'

    try {
      const result = await this.query(query, [id])
      if (result.rows.length === 0) {
        return null
      }

      const row = result.rows[0]
      return {
        id: row.id,
        name: row.name,
        industry: row.industry,
        location: row.location,
        status: row.status,
        description: row.description,
        searchRadius: row.search_radius,
        searchDepth: row.search_depth,
        pagesPerSite: row.pages_per_site,
        zipCode: row.zip_code,
        parameters: row.parameters,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get campaign', error)
      return null
    }
  }

  async updateCampaign(id: string, updates: any): Promise<void> {
    const setClause = []
    const values = []
    let paramIndex = 1

    // Build dynamic SET clause
    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined) {
        const dbKey =
          key === 'searchRadius'
            ? 'search_radius'
            : key === 'searchDepth'
              ? 'search_depth'
              : key === 'pagesPerSite'
                ? 'pages_per_site'
                : key === 'zipCode'
                  ? 'zip_code'
                  : key

        setClause.push(`${dbKey} = $${paramIndex}`)
        values.push(key === 'parameters' ? JSON.stringify(value) : value)
        paramIndex++
      }
    }

    if (setClause.length === 0) {
      return // Nothing to update
    }

    setClause.push(`updated_at = CURRENT_TIMESTAMP`)
    values.push(id)

    const query = `UPDATE campaigns SET ${setClause.join(', ')} WHERE id = $${paramIndex}`

    try {
      await this.query(query, values)
      logger.info('PostgreSQL', `Updated campaign: ${id}`)
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to update campaign', error)
      throw error
    }
  }

  async deleteCampaign(id: string): Promise<void> {
    const query = 'DELETE FROM campaigns WHERE id = $1'

    try {
      await this.query(query, [id])
      logger.info('PostgreSQL', `Deleted campaign: ${id}`)
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to delete campaign', error)
      throw error
    }
  }

  async listCampaigns(filters?: any): Promise<any[]> {
    let query = 'SELECT * FROM campaigns'
    const values = []
    const conditions = []

    if (filters) {
      if (filters.status) {
        conditions.push(`status = $${conditions.length + 1}`)
        values.push(filters.status)
      }
      if (filters.industry) {
        conditions.push(`industry = $${conditions.length + 1}`)
        values.push(filters.industry)
      }
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`
    }

    query += ' ORDER BY created_at DESC'

    try {
      const result = await this.query(query, values)
      return result.rows.map((row: any) => ({
        id: row.id,
        name: row.name,
        industry: row.industry,
        location: row.location,
        status: row.status,
        description: row.description,
        searchRadius: row.search_radius,
        searchDepth: row.search_depth,
        pagesPerSite: row.pages_per_site,
        zipCode: row.zip_code,
        parameters: row.parameters,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }))
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to list campaigns', error)
      return []
    }
  }

  // Business operations
  async createBusiness(business: any): Promise<string> {
    const id = business.id || crypto.randomUUID()

    const query = `
      INSERT INTO businesses (
        id, campaign_id, name, email, phone, website, address,
        confidence_score, contact_person, coordinates, industry,
        business_description, social_media, business_hours,
        employee_count, annual_revenue, founded_year
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
      RETURNING id
    `

    const values = [
      id,
      business.campaignId,
      business.name,
      business.email || [],
      business.phone,
      business.website,
      JSON.stringify(business.address || {}),
      business.confidenceScore || 0.0,
      business.contactPerson,
      business.coordinates ? JSON.stringify(business.coordinates) : null,
      business.industry,
      business.businessDescription,
      business.socialMedia ? JSON.stringify(business.socialMedia) : null,
      business.businessHours ? JSON.stringify(business.businessHours) : null,
      business.employeeCount,
      business.annualRevenue,
      business.foundedYear,
    ]

    try {
      const result = await this.query(query, values)
      logger.info('PostgreSQL', `Created business: ${business.name}`)
      return result.rows[0].id
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to create business', error)
      throw error
    }
  }

  async getBusiness(id: string): Promise<any | null> {
    const query = 'SELECT * FROM businesses WHERE id = $1'

    try {
      const result = await this.query(query, [id])
      if (result.rows.length === 0) {
        return null
      }

      const row = result.rows[0]
      return {
        id: row.id,
        campaignId: row.campaign_id,
        name: row.name,
        email: row.email,
        phone: row.phone,
        website: row.website,
        address: row.address,
        confidenceScore: row.confidence_score,
        contactPerson: row.contact_person,
        coordinates: row.coordinates,
        industry: row.industry,
        businessDescription: row.business_description,
        socialMedia: row.social_media,
        businessHours: row.business_hours,
        employeeCount: row.employee_count,
        annualRevenue: row.annual_revenue,
        foundedYear: row.founded_year,
        scrapedAt: row.scraped_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get business', error)
      return null
    }
  }

  async updateBusiness(id: string, updates: any): Promise<void> {
    const setClause = []
    const values = []
    let paramIndex = 1

    // Build dynamic SET clause
    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined) {
        const dbKey =
          key === 'campaignId'
            ? 'campaign_id'
            : key === 'confidenceScore'
              ? 'confidence_score'
              : key === 'contactPerson'
                ? 'contact_person'
                : key === 'businessDescription'
                  ? 'business_description'
                  : key === 'socialMedia'
                    ? 'social_media'
                    : key === 'businessHours'
                      ? 'business_hours'
                      : key === 'employeeCount'
                        ? 'employee_count'
                        : key === 'annualRevenue'
                          ? 'annual_revenue'
                          : key === 'foundedYear'
                            ? 'founded_year'
                            : key

        setClause.push(`${dbKey} = $${paramIndex}`)

        if (['address', 'coordinates', 'socialMedia', 'businessHours'].includes(key)) {
          values.push(JSON.stringify(value))
        } else {
          values.push(value)
        }
        paramIndex++
      }
    }

    if (setClause.length === 0) {
      return // Nothing to update
    }

    setClause.push(`updated_at = CURRENT_TIMESTAMP`)
    values.push(id)

    const query = `UPDATE businesses SET ${setClause.join(', ')} WHERE id = $${paramIndex}`

    try {
      await this.query(query, values)
      logger.info('PostgreSQL', `Updated business: ${id}`)
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to update business', error)
      throw error
    }
  }

  async deleteBusiness(id: string): Promise<void> {
    const query = 'DELETE FROM businesses WHERE id = $1'

    try {
      await this.query(query, [id])
      logger.info('PostgreSQL', `Deleted business: ${id}`)
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to delete business', error)
      throw error
    }
  }

  async listBusinesses(campaignId?: string, filters?: any): Promise<any[]> {
    let query = 'SELECT * FROM businesses'
    const values = []
    const conditions = []

    if (campaignId) {
      conditions.push(`campaign_id = $${conditions.length + 1}`)
      values.push(campaignId)
    }

    if (filters) {
      if (filters.industry) {
        conditions.push(`industry = $${conditions.length + 1}`)
        values.push(filters.industry)
      }
      if (filters.minConfidenceScore) {
        conditions.push(`confidence_score >= $${conditions.length + 1}`)
        values.push(filters.minConfidenceScore)
      }
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`
    }

    query += ' ORDER BY scraped_at DESC'

    try {
      const result = await this.query(query, values)
      return result.rows.map((row: any) => ({
        id: row.id,
        campaignId: row.campaign_id,
        name: row.name,
        email: row.email,
        phone: row.phone,
        website: row.website,
        address: row.address,
        confidenceScore: row.confidence_score,
        contactPerson: row.contact_person,
        coordinates: row.coordinates,
        industry: row.industry,
        businessDescription: row.business_description,
        socialMedia: row.social_media,
        businessHours: row.business_hours,
        employeeCount: row.employee_count,
        annualRevenue: row.annual_revenue,
        foundedYear: row.founded_year,
        scrapedAt: row.scraped_at,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }))
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to list businesses', error)
      return []
    }
  }

  // Scraping session operations
  async createSession(session: any): Promise<string> {
    const id = session.id || crypto.randomUUID()

    const query = `
      INSERT INTO scraping_sessions (
        id, campaign_id, status, total_urls, successful_scrapes, failed_scrapes,
        errors, session_config, user_agent, timeout_ms, max_retries, delay_ms,
        current_url, progress_percentage
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
      RETURNING id
    `

    const values = [
      id,
      session.campaignId,
      session.status || 'pending',
      session.totalUrls || 0,
      session.successfulScrapes || 0,
      session.failedScrapes || 0,
      JSON.stringify(session.errors || []),
      JSON.stringify(session.sessionConfig || {}),
      session.userAgent,
      session.timeoutMs || 30000,
      session.maxRetries || 3,
      session.delayMs || 1000,
      session.currentUrl,
      session.progressPercentage || 0.0,
    ]

    try {
      const result = await this.query(query, values)
      logger.info('PostgreSQL', `Created scraping session: ${id}`)
      return result.rows[0].id
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to create session', error)
      throw error
    }
  }

  async getSession(id: string): Promise<any | null> {
    const query = 'SELECT * FROM scraping_sessions WHERE id = $1'

    try {
      const result = await this.query(query, [id])
      if (result.rows.length === 0) {
        return null
      }

      const row = result.rows[0]
      return {
        id: row.id,
        campaignId: row.campaign_id,
        status: row.status,
        startedAt: row.started_at,
        completedAt: row.completed_at,
        totalUrls: row.total_urls,
        successfulScrapes: row.successful_scrapes,
        failedScrapes: row.failed_scrapes,
        errors: row.errors,
        sessionConfig: row.session_config,
        userAgent: row.user_agent,
        timeoutMs: row.timeout_ms,
        maxRetries: row.max_retries,
        delayMs: row.delay_ms,
        currentUrl: row.current_url,
        progressPercentage: row.progress_percentage,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get session', error)
      return null
    }
  }

  async updateSession(id: string, updates: any): Promise<void> {
    const setClause = []
    const values = []
    let paramIndex = 1

    // Build dynamic SET clause
    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined) {
        const dbKey =
          key === 'campaignId'
            ? 'campaign_id'
            : key === 'startedAt'
              ? 'started_at'
              : key === 'completedAt'
                ? 'completed_at'
                : key === 'totalUrls'
                  ? 'total_urls'
                  : key === 'successfulScrapes'
                    ? 'successful_scrapes'
                    : key === 'failedScrapes'
                      ? 'failed_scrapes'
                      : key === 'sessionConfig'
                        ? 'session_config'
                        : key === 'userAgent'
                          ? 'user_agent'
                          : key === 'timeoutMs'
                            ? 'timeout_ms'
                            : key === 'maxRetries'
                              ? 'max_retries'
                              : key === 'delayMs'
                                ? 'delay_ms'
                                : key === 'currentUrl'
                                  ? 'current_url'
                                  : key === 'progressPercentage'
                                    ? 'progress_percentage'
                                    : key

        setClause.push(`${dbKey} = $${paramIndex}`)

        if (['errors', 'sessionConfig'].includes(key)) {
          values.push(JSON.stringify(value))
        } else {
          values.push(value)
        }
        paramIndex++
      }
    }

    if (setClause.length === 0) {
      return // Nothing to update
    }

    setClause.push(`updated_at = CURRENT_TIMESTAMP`)
    values.push(id)

    const query = `UPDATE scraping_sessions SET ${setClause.join(', ')} WHERE id = $${paramIndex}`

    try {
      await this.query(query, values)
      logger.info('PostgreSQL', `Updated session: ${id}`)
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to update session', error)
      throw error
    }
  }

  async deleteSession(id: string): Promise<void> {
    const query = 'DELETE FROM scraping_sessions WHERE id = $1'

    try {
      await this.query(query, [id])
      logger.info('PostgreSQL', `Deleted session: ${id}`)
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to delete session', error)
      throw error
    }
  }

  async listSessions(campaignId?: string, filters?: any): Promise<any[]> {
    let query = 'SELECT * FROM scraping_sessions'
    const values = []
    const conditions = []

    if (campaignId) {
      conditions.push(`campaign_id = $${conditions.length + 1}`)
      values.push(campaignId)
    }

    if (filters) {
      if (filters.status) {
        conditions.push(`status = $${conditions.length + 1}`)
        values.push(filters.status)
      }
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`
    }

    query += ' ORDER BY started_at DESC'

    try {
      const result = await this.query(query, values)
      return result.rows.map((row: any) => ({
        id: row.id,
        campaignId: row.campaign_id,
        status: row.status,
        startedAt: row.started_at,
        completedAt: row.completed_at,
        totalUrls: row.total_urls,
        successfulScrapes: row.successful_scrapes,
        failedScrapes: row.failed_scrapes,
        errors: row.errors,
        sessionConfig: row.session_config,
        userAgent: row.user_agent,
        timeoutMs: row.timeout_ms,
        maxRetries: row.max_retries,
        delayMs: row.delay_ms,
        currentUrl: row.current_url,
        progressPercentage: row.progress_percentage,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }))
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to list sessions', error)
      return []
    }
  }

  // Settings operations
  async getSetting(key: string): Promise<any | null> {
    const query = 'SELECT * FROM app_settings WHERE key = $1'

    try {
      const result = await this.query(query, [key])
      if (result.rows.length === 0) {
        return null
      }

      const row = result.rows[0]
      let value = row.value

      // Parse value based on type
      switch (row.value_type) {
        case 'number':
          value = parseFloat(value)
          break
        case 'boolean':
          value = value === 'true'
          break
        case 'json':
          try {
            value = JSON.parse(value)
          } catch {
            // Keep as string if parsing fails
          }
          break
        default:
          // Keep as string
          break
      }

      return {
        key: row.key,
        value,
        type: row.value_type,
        description: row.description,
        category: row.category,
        isSensitive: row.is_sensitive,
        updatedAt: row.updated_at,
      }
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get setting', error)
      return null
    }
  }

  async setSetting(key: string, value: any, type?: string): Promise<void> {
    const valueType = type || typeof value
    const stringValue = valueType === 'json' ? JSON.stringify(value) : String(value)

    const query = `
      INSERT INTO app_settings (key, value, value_type)
      VALUES ($1, $2, $3)
      ON CONFLICT (key)
      DO UPDATE SET value = EXCLUDED.value, value_type = EXCLUDED.value_type, updated_at = CURRENT_TIMESTAMP
    `

    try {
      await this.query(query, [key, stringValue, valueType])
      logger.info('PostgreSQL', `Set setting: ${key}`)
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to set setting', error)
      throw error
    }
  }

  async getSettings(category?: string): Promise<any[]> {
    let query = 'SELECT * FROM app_settings'
    const values = []

    if (category) {
      query += ' WHERE category = $1'
      values.push(category)
    }

    query += ' ORDER BY category, key'

    try {
      const result = await this.query(query, values)
      return result.rows.map((row: any) => {
        let value = row.value

        // Parse value based on type
        switch (row.value_type) {
          case 'number':
            value = parseFloat(value)
            break
          case 'boolean':
            value = value === 'true'
            break
          case 'json':
            try {
              value = JSON.parse(value)
            } catch {
              // Keep as string if parsing fails
            }
            break
          default:
            // Keep as string
            break
        }

        return {
          key: row.key,
          value,
          type: row.value_type,
          description: row.description,
          category: row.category,
          isSensitive: row.is_sensitive,
          updatedAt: row.updated_at,
        }
      })
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get settings', error)
      return []
    }
  }

  // Utility operations
  async getStats(): Promise<any> {
    const queries = [
      'SELECT COUNT(*) as campaigns FROM campaigns',
      'SELECT COUNT(*) as businesses FROM businesses',
      'SELECT COUNT(*) as sessions FROM scraping_sessions',
      'SELECT COUNT(*) as settings FROM app_settings',
    ]

    try {
      const results = await Promise.all(queries.map(q => this.query(q)))

      return {
        campaigns: parseInt(results[0].rows[0].campaigns),
        businesses: parseInt(results[1].rows[0].businesses),
        sessions: parseInt(results[2].rows[0].sessions),
        settings: parseInt(results[3].rows[0].settings),
      }
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get stats', error)
      return { campaigns: 0, businesses: 0, sessions: 0, settings: 0 }
    }
  }

  // Public query method for direct SQL execution
  async executeQuery(text: string, params?: any[]): Promise<any> {
    return this.query(text, params)
  }

  // AI Analytics operations
  async saveAIAnalytics(analytics: any): Promise<string> {
    const id = analytics.id || crypto.randomUUID()

    const query = `
      INSERT INTO ai_analytics (
        id, campaign_id, analysis_type, data, insights, confidence_score,
        processing_time_ms, model_version, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
      RETURNING id
    `

    const values = [
      id,
      analytics.campaignId,
      analytics.analysisType,
      JSON.stringify(analytics.data || {}),
      JSON.stringify(analytics.insights || {}),
      analytics.confidenceScore || 0.0,
      analytics.processingTimeMs || 0,
      analytics.modelVersion || 'v1.0',
    ]

    try {
      const result = await this.query(query, values)
      logger.info('PostgreSQL', `Saved AI analytics: ${analytics.analysisType}`)
      return result.rows[0].id
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to save AI analytics', error)
      throw error
    }
  }

  async getAIAnalytics(id: string): Promise<any | null> {
    const query = 'SELECT * FROM ai_analytics WHERE id = $1'

    try {
      const result = await this.query(query, [id])
      if (result.rows.length === 0) {
        return null
      }

      const row = result.rows[0]
      return {
        id: row.id,
        campaignId: row.campaign_id,
        analysisType: row.analysis_type,
        data: row.data,
        insights: row.insights,
        confidenceScore: row.confidence_score,
        processingTimeMs: row.processing_time_ms,
        modelVersion: row.model_version,
        createdAt: row.created_at,
      }
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get AI analytics', error)
      return null
    }
  }

  async getAllAIAnalytics(campaignId?: string): Promise<any[]> {
    let query = 'SELECT * FROM ai_analytics'
    const values = []

    if (campaignId) {
      query += ' WHERE campaign_id = $1'
      values.push(campaignId)
    }

    query += ' ORDER BY created_at DESC'

    try {
      const result = await this.query(query, values)
      return result.rows.map((row: any) => ({
        id: row.id,
        campaignId: row.campaign_id,
        analysisType: row.analysis_type,
        data: row.data,
        insights: row.insights,
        confidenceScore: row.confidence_score,
        processingTimeMs: row.processing_time_ms,
        modelVersion: row.model_version,
        createdAt: row.created_at,
      }))
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get all AI analytics', error)
      return []
    }
  }

  // AI Insights operations
  async saveAIInsights(insights: any): Promise<string> {
    const id = insights.id || crypto.randomUUID()

    const query = `
      INSERT INTO ai_insights (
        id, title, summary, recommendations, data_sources, confidence_level,
        impact_score, category, tags, expires_at, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
      RETURNING id
    `

    const values = [
      id,
      insights.title,
      insights.summary,
      JSON.stringify(insights.recommendations || []),
      JSON.stringify(insights.dataSources || []),
      insights.confidenceLevel || 'medium',
      insights.impactScore || 0.0,
      insights.category || 'general',
      JSON.stringify(insights.tags || []),
      insights.expiresAt,
    ]

    try {
      const result = await this.query(query, values)
      logger.info('PostgreSQL', `Saved AI insights: ${insights.title}`)
      return result.rows[0].id
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to save AI insights', error)
      throw error
    }
  }

  async getLatestAIInsights(limit: number = 10): Promise<any[]> {
    const query = `
      SELECT * FROM ai_insights
      WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP
      ORDER BY created_at DESC
      LIMIT $1
    `

    try {
      const result = await this.query(query, [limit])
      return result.rows.map((row: any) => ({
        id: row.id,
        title: row.title,
        summary: row.summary,
        recommendations: row.recommendations,
        dataSources: row.data_sources,
        confidenceLevel: row.confidence_level,
        impactScore: row.impact_score,
        category: row.category,
        tags: row.tags,
        expiresAt: row.expires_at,
        createdAt: row.created_at,
      }))
    } catch (error) {
      logger.error('PostgreSQL', 'Failed to get latest AI insights', error)
      return []
    }
  }

  async close(): Promise<void> {
    await this.secureDb.close()
    this.connected = false
    logger.info('PostgreSQL', 'Database connection closed')
  }
}

// Create and export database instance
const databaseConfig: DatabaseConfig = {
  type: 'postgresql',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'business_scraper',
  username: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  ssl: process.env.DB_SSL === 'true',
  poolMin: parseInt(process.env.DB_POOL_MIN || '2'),
  poolMax: parseInt(process.env.DB_POOL_MAX || '10'),
  idleTimeout: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '30000'),
  connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '5000'),
}

export const database = new PostgreSQLDatabase(databaseConfig)
