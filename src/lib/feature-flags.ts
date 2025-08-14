/**
 * Feature flag system for enabling/disabling features based on environment and configuration
 */

import { getConfig, getFeatureFlags } from './config'
import { logger } from '@/utils/logger'

// Feature flag definitions
export interface FeatureFlag {
  key: string
  name: string
  description: string
  defaultValue: boolean
  environments?: ('development' | 'production' | 'test')[]
  dependencies?: string[]
  deprecated?: boolean
  deprecationMessage?: string
}

// Available feature flags
export const FEATURE_FLAGS: Record<string, FeatureFlag> = {
  AUTH: {
    key: 'AUTH',
    name: 'Authentication',
    description: 'Enable user authentication and session management',
    defaultValue: false,
    environments: ['development', 'production', 'test']
  },
  
  CACHING: {
    key: 'CACHING',
    name: 'Caching',
    description: 'Enable caching for improved performance',
    defaultValue: true,
    environments: ['development', 'production', 'test']
  },
  
  RATE_LIMITING: {
    key: 'RATE_LIMITING',
    name: 'Rate Limiting',
    description: 'Enable rate limiting for API endpoints',
    defaultValue: true,
    environments: ['production', 'test']
  },
  
  METRICS: {
    key: 'METRICS',
    name: 'Metrics Collection',
    description: 'Enable metrics collection and monitoring',
    defaultValue: false,
    environments: ['production']
  },
  
  DEBUG_MODE: {
    key: 'DEBUG_MODE',
    name: 'Debug Mode',
    description: 'Enable debug logging and development tools',
    defaultValue: false,
    environments: ['development', 'test']
  },
  
  EXPERIMENTAL_FEATURES: {
    key: 'EXPERIMENTAL_FEATURES',
    name: 'Experimental Features',
    description: 'Enable experimental and beta features',
    defaultValue: false,
    environments: ['development']
  },
  
  ADVANCED_SCRAPING: {
    key: 'ADVANCED_SCRAPING',
    name: 'Advanced Scraping',
    description: 'Enable advanced scraping features like JavaScript rendering',
    defaultValue: false,
    environments: ['development', 'production', 'test']
  },
  
  BULK_OPERATIONS: {
    key: 'BULK_OPERATIONS',
    name: 'Bulk Operations',
    description: 'Enable bulk import/export operations',
    defaultValue: true,
    environments: ['development', 'production', 'test']
  },
  
  API_INTEGRATIONS: {
    key: 'API_INTEGRATIONS',
    name: 'API Integrations',
    description: 'Enable third-party API integrations (Google Maps, etc.)',
    defaultValue: true,
    environments: ['development', 'production', 'test']
  },
  
  REAL_TIME_UPDATES: {
    key: 'REAL_TIME_UPDATES',
    name: 'Real-time Updates',
    description: 'Enable real-time updates via WebSocket',
    defaultValue: false,
    environments: ['development', 'production', 'test'],
    dependencies: ['CACHING']
  },
  
  ENHANCED_VALIDATION: {
    key: 'ENHANCED_VALIDATION',
    name: 'Enhanced Validation',
    description: 'Enable enhanced input validation and sanitization',
    defaultValue: true,
    environments: ['development', 'production', 'test']
  },
  
  PERFORMANCE_MONITORING: {
    key: 'PERFORMANCE_MONITORING',
    name: 'Performance Monitoring',
    description: 'Enable performance monitoring and profiling',
    defaultValue: false,
    environments: ['production'],
    dependencies: ['METRICS']
  },
  
  BACKUP_AUTOMATION: {
    key: 'BACKUP_AUTOMATION',
    name: 'Backup Automation',
    description: 'Enable automated backup and restore functionality',
    defaultValue: false,
    environments: ['production']
  },
  
  MULTI_LANGUAGE: {
    key: 'MULTI_LANGUAGE',
    name: 'Multi-language Support',
    description: 'Enable internationalization and localization',
    defaultValue: false,
    environments: ['development', 'production', 'test'],
    deprecated: false
  },
  
  LEGACY_SUPPORT: {
    key: 'LEGACY_SUPPORT',
    name: 'Legacy Browser Support',
    description: 'Enable support for older browsers',
    defaultValue: false,
    environments: ['production'],
    deprecated: true,
    deprecationMessage: 'Legacy browser support will be removed in v2.0.0'
  }
}

// Feature flag evaluation context
interface FeatureContext {
  environment: 'development' | 'production' | 'test' | string
  userId?: string
  userAgent?: string
  ipAddress?: string
  timestamp: Date
}

/**
 * Feature flag manager
 */
class FeatureFlagManager {
  private cache = new Map<string, boolean>()
  private cacheExpiry = new Map<string, number>()
  private readonly cacheTtl = 5 * 60 * 1000 // 5 minutes

  /**
   * Check if a feature is enabled
   */
  isEnabled(flagKey: string, context?: Partial<FeatureContext>): boolean {
    try {
      // Check cache first
      const cached = this.getCachedValue(flagKey)
      if (cached !== null) {
        return cached
      }

      // Evaluate feature flag
      const result = this.evaluateFlag(flagKey, context)
      
      // Cache the result
      this.setCachedValue(flagKey, result)
      
      return result
    } catch (error) {
      logger.error('FeatureFlags', `Error evaluating feature flag ${flagKey}`, error)
      
      // Return default value on error
      const flag = Object.prototype.hasOwnProperty.call(FEATURE_FLAGS, flagKey)
        ? FEATURE_FLAGS[flagKey as keyof typeof FEATURE_FLAGS]
        : null
      return flag ? flag.defaultValue : false
    }
  }

  /**
   * Evaluate a feature flag
   */
  private evaluateFlag(flagKey: string, context?: Partial<FeatureContext>): boolean {
    const flag = Object.prototype.hasOwnProperty.call(FEATURE_FLAGS, flagKey)
      ? FEATURE_FLAGS[flagKey as keyof typeof FEATURE_FLAGS]
      : null
    
    if (!flag) {
      logger.warn('FeatureFlags', `Unknown feature flag: ${flagKey}`)
      return false
    }

    // Check if feature is deprecated
    if (flag.deprecated) {
      logger.warn('FeatureFlags', `Feature flag ${flagKey} is deprecated: ${flag.deprecationMessage || 'No message provided'}`)
    }

    const config = getConfig()
    const featureFlags = getFeatureFlags()
    const currentEnv = config.app.environment
    
    // Build evaluation context
    const evalContext: FeatureContext = {
      environment: currentEnv,
      timestamp: new Date(),
      ...context
    }

    // Check environment restrictions
    if (flag.environments && !flag.environments.includes(evalContext.environment as 'development' | 'production' | 'test')) {
      logger.debug('FeatureFlags', `Feature ${flagKey} not available in ${evalContext.environment} environment`)
      return false
    }

    // Check dependencies
    if (flag.dependencies) {
      for (const dependency of flag.dependencies) {
        if (!this.isEnabled(dependency, context)) {
          logger.debug('FeatureFlags', `Feature ${flagKey} disabled due to missing dependency: ${dependency}`)
          return false
        }
      }
    }

    // Get value from configuration
    let enabled = flag.defaultValue

    // Override with configuration values
    switch (flagKey) {
      case 'AUTH':
        enabled = featureFlags.enableAuth
        break
      case 'CACHING':
        enabled = featureFlags.enableCaching
        break
      case 'RATE_LIMITING':
        enabled = featureFlags.enableRateLimiting
        break
      case 'METRICS':
        enabled = featureFlags.enableMetrics
        break
      case 'DEBUG_MODE':
        enabled = featureFlags.enableDebugMode
        break
      case 'EXPERIMENTAL_FEATURES':
        enabled = featureFlags.enableExperimentalFeatures
        break
      default:
        // For other flags, check environment variables
        const envVar = `FEATURE_${flagKey}`
        const envValue = Object.prototype.hasOwnProperty.call(process.env, envVar)
          ? (process.env as Record<string, string | undefined>)[envVar]
          : undefined
        if (envValue !== undefined) {
          enabled = ['true', '1', 'yes', 'on'].includes(envValue.toLowerCase())
        }
        break
    }

    logger.debug('FeatureFlags', `Feature ${flagKey} evaluated to ${enabled}`, {
      flag: flag.name,
      environment: evalContext.environment,
      dependencies: flag.dependencies,
      defaultValue: flag.defaultValue
    })

    return enabled
  }

  /**
   * Get cached value
   */
  private getCachedValue(flagKey: string): boolean | null {
    const expiry = this.cacheExpiry.get(flagKey)
    if (expiry && Date.now() > expiry) {
      this.cache.delete(flagKey)
      this.cacheExpiry.delete(flagKey)
      return null
    }
    
    return this.cache.get(flagKey) ?? null
  }

  /**
   * Set cached value
   */
  private setCachedValue(flagKey: string, value: boolean): void {
    this.cache.set(flagKey, value)
    this.cacheExpiry.set(flagKey, Date.now() + this.cacheTtl)
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    this.cache.clear()
    this.cacheExpiry.clear()
    logger.info('FeatureFlags', 'Feature flag cache cleared')
  }

  /**
   * Get all feature flags with their current status
   */
  getAllFlags(context?: Partial<FeatureContext>): Record<string, { enabled: boolean; flag: FeatureFlag }> {
    const result: Record<string, { enabled: boolean; flag: FeatureFlag }> = {}
    
    for (const [key, flag] of Object.entries(FEATURE_FLAGS)) {
      if (typeof key === 'string' && key.length > 0) {
        Object.defineProperty(result, key, {
          value: {
            enabled: this.isEnabled(key, context),
            flag
          },
          writable: true,
          enumerable: true,
          configurable: true
        })
      }
    }
    
    return result
  }

  /**
   * Get feature flags for a specific environment
   */
  getFlagsForEnvironment(environment: string): Record<string, boolean> {
    const context: FeatureContext = {
      environment,
      timestamp: new Date()
    }
    
    const result: Record<string, boolean> = {}
    
    for (const key of Object.keys(FEATURE_FLAGS)) {
      if (typeof key === 'string' && key.length > 0) {
        Object.defineProperty(result, key, {
          value: this.isEnabled(key, context),
          writable: true,
          enumerable: true,
          configurable: true
        })
      }
    }
    
    return result
  }

  /**
   * Validate feature flag dependencies
   */
  validateDependencies(): { isValid: boolean; errors: string[] } {
    const errors: string[] = []
    
    for (const [key, flag] of Object.entries(FEATURE_FLAGS)) {
      if (flag.dependencies) {
        for (const dependency of flag.dependencies) {
          if (typeof dependency === 'string' && dependency.length > 0) {
            if (!Object.prototype.hasOwnProperty.call(FEATURE_FLAGS, dependency)) {
              errors.push(`Feature ${key} depends on unknown feature: ${dependency}`)
            }
          } else {
            errors.push(`Feature ${key} has invalid dependency: ${dependency}`)
          }
        }
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    }
  }
}

// Global feature flag manager instance
const featureFlagManager = new FeatureFlagManager()

/**
 * Check if a feature is enabled
 */
export function isFeatureEnabled(flagKey: string, context?: Partial<FeatureContext>): boolean {
  return featureFlagManager.isEnabled(flagKey, context)
}

/**
 * Get all feature flags
 */
export function getAllFeatureFlags(context?: Partial<FeatureContext>): Record<string, { enabled: boolean; flag: FeatureFlag }> {
  return featureFlagManager.getAllFlags(context)
}

/**
 * Clear feature flag cache
 */
export function clearFeatureFlagCache(): void {
  featureFlagManager.clearCache()
}

/**
 * Validate feature flag dependencies
 */
export function validateFeatureFlagDependencies(): { isValid: boolean; errors: string[] } {
  return featureFlagManager.validateDependencies()
}

/**
 * Get feature flags for environment
 */
export function getFeatureFlagsForEnvironment(environment: string): Record<string, boolean> {
  return featureFlagManager.getFlagsForEnvironment(environment)
}

// Convenience functions for common feature checks
export const Features = {
  isAuthEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('AUTH', context),
  isCachingEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('CACHING', context),
  isRateLimitingEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('RATE_LIMITING', context),
  isMetricsEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('METRICS', context),
  isDebugModeEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('DEBUG_MODE', context),
  areExperimentalFeaturesEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('EXPERIMENTAL_FEATURES', context),
  isAdvancedScrapingEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('ADVANCED_SCRAPING', context),
  areBulkOperationsEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('BULK_OPERATIONS', context),
  areApiIntegrationsEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('API_INTEGRATIONS', context),
  areRealTimeUpdatesEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('REAL_TIME_UPDATES', context),
  isEnhancedValidationEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('ENHANCED_VALIDATION', context),
  isPerformanceMonitoringEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('PERFORMANCE_MONITORING', context),
  isBackupAutomationEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('BACKUP_AUTOMATION', context),
  isMultiLanguageEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('MULTI_LANGUAGE', context),
  isLegacySupportEnabled: (context?: Partial<FeatureContext>) => isFeatureEnabled('LEGACY_SUPPORT', context)
}

// Export the manager for advanced usage
export { featureFlagManager }
