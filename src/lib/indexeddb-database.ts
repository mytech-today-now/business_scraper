/**
 * IndexedDB database implementation
 * Provides compatibility with the existing storage system
 */

import crypto from 'crypto'
import { DatabaseInterface } from './database'
import { storage } from '@/model/storage'
import { BusinessRecord, ScrapingConfig } from '@/types/business'
import { logger } from '@/utils/logger'

/**
 * Interface for application settings
 */
interface AppSetting {
  id: string
  key: string
  value: unknown
  type: string
  updatedAt: Date
}

/**
 * Interface for setting with category
 */
interface CategorizedSetting {
  key: string
  value: unknown
  type: string
  category: string
  updatedAt: Date
}

export class IndexedDBDatabase implements DatabaseInterface {
  private initialized = false

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await storage.initialize()
      this.initialized = true
    }
  }

  // Campaign operations
  async createCampaign(campaign: any): Promise<string> {
    await this.ensureInitialized()
    
    const campaignData = {
      id: campaign.id || crypto.randomUUID(),
      name: campaign.name,
      industry: campaign.industry,
      location: campaign.location,
      status: campaign.status || 'draft',
      createdAt: new Date(),
      updatedAt: new Date(),
      parameters: campaign.parameters || {},
      description: campaign.description,
      searchRadius: campaign.searchRadius || 25,
      searchDepth: campaign.searchDepth || 3,
      pagesPerSite: campaign.pagesPerSite || 5,
      zipCode: campaign.zipCode,
    }

    // Store as a config for now (adapting to existing structure)
    const config: ScrapingConfig & { id: string } = {
      id: campaignData.id,
      industries: [campaignData.industry],
      zipCode: campaignData.zipCode || '',
      searchRadius: campaignData.searchRadius,
      searchDepth: campaignData.searchDepth,
      pagesPerSite: campaignData.pagesPerSite,
    }

    await storage.saveConfig(config)
    
    // Also save campaign metadata in a session-like structure
    await storage.saveSession({
      id: `campaign_${campaignData.id}`,
      name: campaignData.name,
      businesses: [],
      createdAt: campaignData.createdAt,
      updatedAt: campaignData.updatedAt,
    })

    logger.info('IndexedDB', `Created campaign: ${campaignData.name}`)
    return campaignData.id
  }

  async getCampaign(id: string): Promise<any | null> {
    await this.ensureInitialized()

    try {
      const config = await storage.getConfig(id)
      const sessions = await storage.getAllSessions()
      const session = sessions.find(s => s.id === `campaign_${id}`)

      if (!config || !session) {
        return null
      }

      return {
        id,
        name: session.name,
        industry: config.industries[0] || '',
        location: '', // Not stored in current structure
        status: 'active', // Default status
        createdAt: session.createdAt,
        updatedAt: session.updatedAt,
        parameters: {},
        searchRadius: config.searchRadius,
        searchDepth: config.searchDepth,
        pagesPerSite: config.pagesPerSite,
        zipCode: config.zipCode,
      }
    } catch (error) {
      logger.error('IndexedDB', 'Failed to get campaign', error)
      return null
    }
  }

  async updateCampaign(id: string, updates: any): Promise<void> {
    await this.ensureInitialized()
    
    const existing = await this.getCampaign(id)
    if (!existing) {
      throw new Error(`Campaign ${id} not found`)
    }

    // Update config
    const config: ScrapingConfig & { id: string } = {
      id,
      industries: updates.industry ? [updates.industry] : existing.industries,
      zipCode: updates.zipCode || existing.zipCode,
      searchRadius: updates.searchRadius || existing.searchRadius,
      searchDepth: updates.searchDepth || existing.searchDepth,
      pagesPerSite: updates.pagesPerSite || existing.pagesPerSite,
    }

    await storage.saveConfig(config)

    // Update session
    await storage.saveSession({
      id: `campaign_${id}`,
      name: updates.name || existing.name,
      businesses: existing.businesses || [],
      createdAt: existing.createdAt,
      updatedAt: new Date(),
    })

    logger.info('IndexedDB', `Updated campaign: ${id}`)
  }

  async deleteCampaign(id: string): Promise<void> {
    await this.ensureInitialized()
    
    // Delete associated businesses
    const businesses = await this.listBusinesses(id)
    for (const business of businesses) {
      await storage.deleteBusiness(business.id)
    }

    // Delete config and session
    await storage.deleteConfig(id)
    await storage.deleteSession(`campaign_${id}`)

    logger.info('IndexedDB', `Deleted campaign: ${id}`)
  }

  async listCampaigns(_filters?: any): Promise<any[]> {
    await this.ensureInitialized()
    
    try {
      const configs = await storage.getAllConfigs()
      const campaigns = []

      const sessions = await storage.getAllSessions()

      for (const config of configs) {
        const session = sessions.find(s => s.id === `campaign_${config.id}`)
        if (session) {
          campaigns.push({
            id: config.id,
            name: session.name,
            industry: config.industries[0] || '',
            location: '',
            status: 'active',
            createdAt: session.createdAt,
            updatedAt: session.updatedAt,
            searchRadius: config.searchRadius,
            searchDepth: config.searchDepth,
            pagesPerSite: config.pagesPerSite,
            zipCode: config.zipCode,
          })
        }
      }

      return campaigns
    } catch (error) {
      logger.error('IndexedDB', 'Failed to list campaigns', error)
      return []
    }
  }

  // Business operations
  async createBusiness(business: any): Promise<string> {
    await this.ensureInitialized()
    
    const businessRecord: BusinessRecord = {
      id: business.id || crypto.randomUUID(),
      businessName: business.name,
      email: Array.isArray(business.email) ? business.email : [business.email].filter(Boolean),
      phone: business.phone,
      websiteUrl: business.website || '',
      address: business.address || {},
      contactPerson: business.contactPerson,
      coordinates: business.coordinates,
      industry: business.industry || '',
      scrapedAt: business.scrapedAt || new Date(),
    }

    await storage.saveBusiness(businessRecord)
    logger.info('IndexedDB', `Created business: ${businessRecord.businessName}`)
    return businessRecord.id
  }

  async getBusiness(id: string): Promise<any | null> {
    await this.ensureInitialized()
    return await storage.getBusiness(id)
  }

  async updateBusiness(id: string, updates: any): Promise<void> {
    await this.ensureInitialized()
    
    const existing = await storage.getBusiness(id)
    if (!existing) {
      throw new Error(`Business ${id} not found`)
    }

    const updated: BusinessRecord = {
      ...existing,
      ...updates,
      id, // Ensure ID doesn't change
    }

    await storage.saveBusiness(updated)
    logger.info('IndexedDB', `Updated business: ${id}`)
  }

  async deleteBusiness(id: string): Promise<void> {
    await this.ensureInitialized()
    await storage.deleteBusiness(id)
    logger.info('IndexedDB', `Deleted business: ${id}`)
  }

  async listBusinesses(_campaignId?: string, _filters?: any): Promise<any[]> {
    await this.ensureInitialized()
    
    const businesses = await storage.getAllBusinesses()
    
    // Apply filters if provided
    let filtered = businesses
    
    if (filters?.industry) {
      filtered = filtered.filter(b => b.industry === filters.industry)
    }
    
    if (filters?.minConfidenceScore) {
      // IndexedDB doesn't have confidence score, so we'll skip this filter
    }

    return filtered
  }

  // Scraping session operations (using existing session structure)
  async createSession(session: any): Promise<string> {
    await this.ensureInitialized()
    
    const sessionData = {
      id: session.id || crypto.randomUUID(),
      name: session.name || 'Scraping Session',
      businesses: session.businesses || [],
      createdAt: session.createdAt || new Date(),
      updatedAt: new Date(),
    }

    await storage.saveSession(sessionData)
    logger.info('IndexedDB', `Created session: ${sessionData.name}`)
    return sessionData.id
  }

  async getSession(id: string): Promise<any | null> {
    await this.ensureInitialized()
    const sessions = await storage.getAllSessions()
    return sessions.find(s => s.id === id) || null
  }

  async updateSession(id: string, updates: any): Promise<void> {
    await this.ensureInitialized()

    const sessions = await storage.getAllSessions()
    const existing = sessions.find(s => s.id === id)
    if (!existing) {
      throw new Error(`Session ${id} not found`)
    }

    const updated = {
      ...existing,
      ...updates,
      id, // Ensure ID doesn't change
      updatedAt: new Date(),
    }

    await storage.saveSession(updated)
    logger.info('IndexedDB', `Updated session: ${id}`)
  }

  async deleteSession(id: string): Promise<void> {
    await this.ensureInitialized()
    await storage.deleteSession(id)
    logger.info('IndexedDB', `Deleted session: ${id}`)
  }

  async listSessions(_campaignId?: string, _filters?: any): Promise<any[]> {
    await this.ensureInitialized()
    
    const sessions = await storage.getAllSessions()
    
    // Filter out campaign sessions if needed
    const filtered = sessions.filter(s => !s.id.startsWith('campaign_'))
    
    if (campaignId) {
      // For now, return all sessions since we don't have campaign association
      // In a real implementation, you'd filter by campaign_id
    }

    return filtered
  }

  // Settings operations (using app_settings equivalent)
  async getSetting(key: string): Promise<any | null> {
    await this.ensureInitialized()
    
    // For IndexedDB, we'll store settings as special configs
    try {
      const config = await storage.getConfig(`setting_${key}`)
      return config ? config : null
    } catch (error) {
      logger.error('IndexedDB', `Failed to get setting: ${key}`, error)
      return null
    }
  }

  async setSetting(key: string, value: unknown, type?: string): Promise<void> {
    await this.ensureInitialized()

    const setting: AppSetting = {
      id: `setting_${key}`,
      key,
      value,
      type: type || 'string',
      updatedAt: new Date(),
    }

    // Note: This is a workaround since storage.saveConfig expects ScrapingConfig
    // but we're storing application settings. In a real implementation,
    // we would have a separate settings storage method.
    await storage.saveConfig(setting as unknown as ScrapingConfig & { id: string })
    logger.info('IndexedDB', `Set setting: ${key}`)
  }

  async getSettings(category?: string): Promise<CategorizedSetting[]> {
    await this.ensureInitialized()

    try {
      const configs = await storage.getAllConfigs()
      const settings = configs
        .filter(c => c.id.startsWith('setting_'))
        .map(c => {
          const settingData = c as unknown as AppSetting
          return {
            key: c.id.replace('setting_', ''),
            value: settingData.value,
            type: settingData.type || 'string',
            category: category || 'general',
            updatedAt: settingData.updatedAt || new Date(),
          }
        })

      return settings
    } catch (error) {
      logger.error('IndexedDB', 'Failed to get settings', error)
      return []
    }
  }

  // Utility operations
  async getStats(): Promise<any> {
    await this.ensureInitialized()
    return await storage.getStats()
  }

  async close(): Promise<void> {
    await storage.close()
    this.initialized = false
    logger.info('IndexedDB', 'Database connection closed')
  }
}
