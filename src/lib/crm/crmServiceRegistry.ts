/**
 * CRM Service Registry and Factory
 * Central registry for managing CRM service instances and configurations
 */

import { CRMProvider } from '@/types/crm'
import { BaseCRMService } from './baseCRMService'
import { SalesforceService } from './salesforceService'
import { HubSpotService } from './hubspotService'
import { PipedriveService } from './pipedriveService'
import { CustomCRMService } from './customCRMService'
import { logger } from '@/utils/logger'
import { database } from '@/lib/database'

export class CRMServiceRegistry {
  private static instance: CRMServiceRegistry
  private services: Map<string, BaseCRMService> = new Map()
  private providers: Map<string, CRMProvider> = new Map()

  private constructor() {}

  static getInstance(): CRMServiceRegistry {
    if (!CRMServiceRegistry.instance) {
      CRMServiceRegistry.instance = new CRMServiceRegistry()
    }
    return CRMServiceRegistry.instance
  }

  /**
   * Initialize the registry with providers from database
   */
  async initialize(): Promise<void> {
    try {
      logger.info('CRMRegistry', 'Initializing CRM service registry')
      
      // Load providers from database
      const providers = await this.loadProvidersFromDatabase()
      
      for (const provider of providers) {
        await this.registerProvider(provider)
      }
      
      logger.info('CRMRegistry', `Initialized ${providers.length} CRM providers`)
    } catch (error) {
      logger.error('CRMRegistry', 'Failed to initialize CRM registry', error)
      throw error
    }
  }

  /**
   * Register a CRM provider and create its service instance
   */
  async registerProvider(provider: CRMProvider): Promise<void> {
    try {
      logger.info('CRMRegistry', `Registering CRM provider: ${provider.name}`, {
        providerId: provider.id,
        type: provider.type
      })

      // Store provider configuration
      this.providers.set(provider.id, provider)

      // Create service instance based on provider type
      const service = this.createServiceInstance(provider)
      
      if (service) {
        // Initialize the service
        await service.initialize()
        
        // Store service instance
        this.services.set(provider.id, service)
        
        logger.info('CRMRegistry', `Successfully registered CRM provider: ${provider.name}`)
      } else {
        logger.warn('CRMRegistry', `Unsupported CRM provider type: ${provider.type}`)
      }
    } catch (error) {
      logger.error('CRMRegistry', `Failed to register CRM provider: ${provider.name}`, error)
      throw error
    }
  }

  /**
   * Unregister a CRM provider
   */
  async unregisterProvider(providerId: string): Promise<void> {
    try {
      const provider = this.providers.get(providerId)
      if (!provider) {
        throw new Error(`Provider not found: ${providerId}`)
      }

      logger.info('CRMRegistry', `Unregistering CRM provider: ${provider.name}`)

      // Remove service instance
      this.services.delete(providerId)
      
      // Remove provider configuration
      this.providers.delete(providerId)
      
      // Remove from database
      await this.removeProviderFromDatabase(providerId)
      
      logger.info('CRMRegistry', `Successfully unregistered CRM provider: ${provider.name}`)
    } catch (error) {
      logger.error('CRMRegistry', `Failed to unregister CRM provider: ${providerId}`, error)
      throw error
    }
  }

  /**
   * Get a CRM service instance by provider ID
   */
  getService(providerId: string): BaseCRMService | undefined {
    return this.services.get(providerId)
  }

  /**
   * Get all registered CRM services
   */
  getAllServices(): BaseCRMService[] {
    return Array.from(this.services.values())
  }

  /**
   * Get all active CRM services
   */
  getActiveServices(): BaseCRMService[] {
    return Array.from(this.services.values()).filter(service => 
      service.getProvider().isActive
    )
  }

  /**
   * Get CRM services by type
   */
  getServicesByType(type: string): BaseCRMService[] {
    return Array.from(this.services.values()).filter(service => 
      service.getProvider().type === type
    )
  }

  /**
   * Get a CRM provider configuration
   */
  getProvider(providerId: string): CRMProvider | undefined {
    return this.providers.get(providerId)
  }

  /**
   * Get all registered providers
   */
  getAllProviders(): CRMProvider[] {
    return Array.from(this.providers.values())
  }

  /**
   * Update a provider configuration
   */
  async updateProvider(providerId: string, updates: Partial<CRMProvider>): Promise<void> {
    try {
      const provider = this.providers.get(providerId)
      if (!provider) {
        throw new Error(`Provider not found: ${providerId}`)
      }

      // Update provider configuration
      const updatedProvider = { ...provider, ...updates }
      this.providers.set(providerId, updatedProvider)

      // Update in database
      await this.saveProviderToDatabase(updatedProvider)

      // Recreate service instance if configuration changed
      if (updates.configuration || updates.isActive !== undefined) {
        await this.recreateServiceInstance(providerId)
      }

      logger.info('CRMRegistry', `Updated CRM provider: ${provider.name}`)
    } catch (error) {
      logger.error('CRMRegistry', `Failed to update CRM provider: ${providerId}`, error)
      throw error
    }
  }

  /**
   * Test connection for a specific provider
   */
  async testConnection(providerId: string): Promise<boolean> {
    try {
      const service = this.services.get(providerId)
      if (!service) {
        throw new Error(`Service not found: ${providerId}`)
      }

      return await service.validateConnection()
    } catch (error) {
      logger.error('CRMRegistry', `Connection test failed for provider: ${providerId}`, error)
      return false
    }
  }

  /**
   * Test connections for all active providers
   */
  async testAllConnections(): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {}
    
    for (const [providerId, service] of this.services) {
      if (service.getProvider().isActive) {
        try {
          results[providerId] = await service.validateConnection()
        } catch (error) {
          results[providerId] = false
        }
      }
    }
    
    return results
  }

  /**
   * Create a service instance based on provider type
   */
  private createServiceInstance(provider: CRMProvider): BaseCRMService | null {
    switch (provider.type) {
      case 'salesforce':
        return new SalesforceService(provider)
      case 'hubspot':
        return new HubSpotService(provider)
      case 'pipedrive':
        return new PipedriveService(provider)
      case 'custom':
        return new CustomCRMService(provider)
      default:
        logger.warn('CRMRegistry', `Unsupported CRM provider type: ${provider.type}`)
        return null
    }
  }

  /**
   * Recreate a service instance
   */
  private async recreateServiceInstance(providerId: string): Promise<void> {
    const provider = this.providers.get(providerId)
    if (!provider) {
      throw new Error(`Provider not found: ${providerId}`)
    }

    // Remove existing service
    this.services.delete(providerId)

    // Create new service instance
    if (provider.isActive) {
      const service = this.createServiceInstance(provider)
      if (service) {
        await service.initialize()
        this.services.set(providerId, service)
      }
    }
  }

  /**
   * Load providers from database
   */
  private async loadProvidersFromDatabase(): Promise<CRMProvider[]> {
    try {
      // This would typically load from a database table
      // For now, return empty array - will be implemented with database schema
      return []
    } catch (error) {
      logger.error('CRMRegistry', 'Failed to load providers from database', error)
      return []
    }
  }

  /**
   * Save provider to database
   */
  private async saveProviderToDatabase(provider: CRMProvider): Promise<void> {
    try {
      // This would typically save to a database table
      // Implementation will be added with database schema
      logger.debug('CRMRegistry', `Saving provider to database: ${provider.id}`)
    } catch (error) {
      logger.error('CRMRegistry', 'Failed to save provider to database', error)
      throw error
    }
  }

  /**
   * Remove provider from database
   */
  private async removeProviderFromDatabase(providerId: string): Promise<void> {
    try {
      // This would typically remove from a database table
      // Implementation will be added with database schema
      logger.debug('CRMRegistry', `Removing provider from database: ${providerId}`)
    } catch (error) {
      logger.error('CRMRegistry', 'Failed to remove provider from database', error)
      throw error
    }
  }

  /**
   * Get registry statistics
   */
  getStatistics(): {
    totalProviders: number
    activeProviders: number
    providersByType: Record<string, number>
    servicesReady: number
  } {
    const providers = Array.from(this.providers.values())
    const activeProviders = providers.filter(p => p.isActive)
    
    const providersByType: Record<string, number> = {}
    for (const provider of providers) {
      providersByType[provider.type] = (providersByType[provider.type] || 0) + 1
    }

    return {
      totalProviders: providers.length,
      activeProviders: activeProviders.length,
      providersByType,
      servicesReady: this.services.size
    }
  }
}

// Export singleton instance
export const crmServiceRegistry = CRMServiceRegistry.getInstance()
