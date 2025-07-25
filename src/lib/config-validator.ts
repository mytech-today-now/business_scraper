/**
 * Configuration validation and health checking utilities
 */

import { AppConfig, getConfig } from './config'
import { logger } from '@/utils/logger'

export interface ValidationResult {
  isValid: boolean
  errors: string[]
  warnings: string[]
  recommendations: string[]
}

export interface ConfigHealthCheck {
  status: 'healthy' | 'warning' | 'error'
  checks: {
    [key: string]: {
      status: 'pass' | 'warn' | 'fail'
      message: string
      details?: any
    }
  }
  summary: {
    total: number
    passed: number
    warnings: number
    failed: number
  }
}

/**
 * Validate the complete application configuration
 */
export function validateConfiguration(): ValidationResult {
  const result: ValidationResult = {
    isValid: true,
    errors: [],
    warnings: [],
    recommendations: []
  }

  try {
    const config = getConfig()
    
    // Validate application configuration
    validateAppConfig(config, result)
    
    // Validate database configuration
    validateDatabaseConfig(config, result)
    
    // Validate security configuration
    validateSecurityConfig(config, result)
    
    // Validate scraping configuration
    validateScrapingConfig(config, result)
    
    // Validate API keys configuration
    validateApiKeysConfig(config, result)
    
    // Validate cache configuration
    validateCacheConfig(config, result)
    
    // Validate logging configuration
    validateLoggingConfig(config, result)
    
    // Validate feature flags
    validateFeatureFlags(config, result)
    
    // Set overall validity
    result.isValid = result.errors.length === 0
    
  } catch (error) {
    result.isValid = false
    result.errors.push(`Configuration loading failed: ${error instanceof Error ? error.message : String(error)}`)
  }

  return result
}

/**
 * Validate application configuration
 */
function validateAppConfig(config: AppConfig, result: ValidationResult): void {
  const { app } = config

  if (!app.name || app.name.trim().length === 0) {
    result.errors.push('Application name cannot be empty')
  }

  if (!app.version || !/^\d+\.\d+\.\d+/.test(app.version)) {
    result.warnings.push('Application version should follow semantic versioning (x.y.z)')
  }

  if (app.environment === 'production' && app.debug) {
    result.warnings.push('Debug mode is enabled in production environment')
  }

  if (app.port < 1024 && process.platform !== 'win32') {
    result.warnings.push('Port numbers below 1024 may require elevated privileges on Unix systems')
  }
}

/**
 * Validate database configuration
 */
function validateDatabaseConfig(config: AppConfig, result: ValidationResult): void {
  const { database } = config

  if (database.url) {
    try {
      const url = new URL(database.url)
      if (!['postgres:', 'postgresql:'].includes(url.protocol)) {
        result.warnings.push('Database URL protocol should be postgresql:// for PostgreSQL')
      }
    } catch {
      result.errors.push('Database URL is not a valid URL')
    }
  }

  if (database.poolMin > database.poolMax) {
    result.errors.push('Database pool minimum size cannot be greater than maximum size')
  }

  if (database.poolMax > 50) {
    result.warnings.push('Database pool maximum size is very high, consider reducing for better resource management')
  }

  if (database.connectionTimeout < 5000) {
    result.warnings.push('Database connection timeout is very low, may cause connection issues')
  }

  if (config.app.environment === 'production' && !database.ssl) {
    result.warnings.push('SSL is not enabled for database connection in production')
  }
}

/**
 * Validate security configuration
 */
function validateSecurityConfig(config: AppConfig, result: ValidationResult): void {
  const { security } = config

  if (security.enableAuth) {
    if (!security.adminPassword && (!security.adminPasswordHash || !security.adminPasswordSalt)) {
      result.errors.push('Authentication is enabled but no password is configured')
    }

    if (security.adminPassword && config.app.environment === 'production') {
      result.warnings.push('Plain text password is used in production, consider using hashed password')
    }

    if (security.sessionTimeout < 300000) { // 5 minutes
      result.warnings.push('Session timeout is very short, may cause frequent re-authentication')
    }

    if (security.maxLoginAttempts > 10) {
      result.warnings.push('Maximum login attempts is high, consider reducing for better security')
    }

    if (security.lockoutDuration < 300000) { // 5 minutes
      result.warnings.push('Account lockout duration is short, may not deter brute force attacks effectively')
    }
  }

  if (security.rateLimitMax > 1000) {
    result.warnings.push('Rate limit is very high, may not effectively prevent abuse')
  }

  if (security.scrapingRateLimit > 100) {
    result.warnings.push('Scraping rate limit is high, may cause issues with target websites')
  }
}

/**
 * Validate scraping configuration
 */
function validateScrapingConfig(config: AppConfig, result: ValidationResult): void {
  const { scraping } = config

  if (scraping.timeout < 5000) {
    result.warnings.push('Scraping timeout is very low, may cause premature timeouts')
  }

  if (scraping.timeout > 120000) { // 2 minutes
    result.warnings.push('Scraping timeout is very high, may cause long waits for failed requests')
  }

  if (scraping.maxRetries > 5) {
    result.warnings.push('Maximum retries is high, may cause excessive delays')
  }

  if (scraping.delayMs < 500) {
    result.warnings.push('Scraping delay is very low, may cause rate limiting by target websites')
  }

  if (scraping.maxSearchResults > 200) {
    result.warnings.push('Maximum search results is high, may cause performance issues')
  }
}

/**
 * Validate API keys configuration
 */
function validateApiKeysConfig(config: AppConfig, result: ValidationResult): void {
  const { apiKeys } = config

  const hasAnyApiKey = Object.values(apiKeys).some(key => key && key.length > 0)
  
  if (!hasAnyApiKey) {
    result.recommendations.push('No API keys configured, some features may have limited functionality')
  }

  // Check for placeholder values
  Object.entries(apiKeys).forEach(([service, key]) => {
    if (key && (key.includes('your_') || key.includes('_here') || key === 'test_key')) {
      result.warnings.push(`${service} API key appears to be a placeholder value`)
    }
  })
}

/**
 * Validate cache configuration
 */
function validateCacheConfig(config: AppConfig, result: ValidationResult): void {
  const { cache } = config

  if (cache.type === 'redis') {
    if (!cache.redis) {
      result.errors.push('Redis cache is enabled but Redis configuration is missing')
    } else {
      if (!cache.redis.host) {
        result.errors.push('Redis host is required when using Redis cache')
      }
      
      if (cache.redis.port < 1 || cache.redis.port > 65535) {
        result.errors.push('Redis port must be a valid port number')
      }
    }
  }

  if (cache.memory.maxSize < 100) {
    result.warnings.push('Memory cache size is very small, may cause frequent cache evictions')
  }

  if (cache.memory.ttl < 60000) { // 1 minute
    result.warnings.push('Cache TTL is very short, may reduce cache effectiveness')
  }
}

/**
 * Validate logging configuration
 */
function validateLoggingConfig(config: AppConfig, result: ValidationResult): void {
  const { logging } = config

  if (!logging.enableConsole && !logging.enableFile) {
    result.warnings.push('Both console and file logging are disabled, no logs will be output')
  }

  if (logging.enableFile && !logging.filePath) {
    result.errors.push('File logging is enabled but no file path is specified')
  }

  if (logging.maxFileSize < 1024 * 1024) { // 1MB
    result.warnings.push('Log file size limit is very small, may cause frequent log rotation')
  }

  if (logging.maxFiles < 2) {
    result.warnings.push('Maximum log files is very low, may cause log loss')
  }

  if (config.app.environment === 'production' && logging.level === 'debug') {
    result.warnings.push('Debug logging is enabled in production, may impact performance')
  }
}

/**
 * Validate feature flags
 */
function validateFeatureFlags(config: AppConfig, result: ValidationResult): void {
  const { features } = config

  if (config.app.environment === 'production' && features.enableExperimentalFeatures) {
    result.warnings.push('Experimental features are enabled in production')
  }

  if (!features.enableRateLimiting && config.app.environment === 'production') {
    result.warnings.push('Rate limiting is disabled in production, may allow abuse')
  }

  if (features.enableMetrics && config.app.environment === 'development') {
    result.recommendations.push('Metrics collection is enabled in development, consider disabling for better performance')
  }
}

/**
 * Perform comprehensive configuration health check
 */
export async function performConfigHealthCheck(): Promise<ConfigHealthCheck> {
  const checks: ConfigHealthCheck['checks'] = {}
  let passed = 0
  let warnings = 0
  let failed = 0

  // Configuration validation check
  try {
    const validation = validateConfiguration()
    if (validation.isValid) {
      checks.configValidation = {
        status: validation.warnings.length > 0 ? 'warn' : 'pass',
        message: validation.warnings.length > 0 
          ? `Configuration valid with ${validation.warnings.length} warnings`
          : 'Configuration is valid',
        details: { warnings: validation.warnings, recommendations: validation.recommendations }
      }
      if (validation.warnings.length > 0) warnings++; else passed++
    } else {
      checks.configValidation = {
        status: 'fail',
        message: `Configuration validation failed with ${validation.errors.length} errors`,
        details: { errors: validation.errors, warnings: validation.warnings }
      }
      failed++
    }
  } catch (error) {
    checks.configValidation = {
      status: 'fail',
      message: 'Configuration validation threw an error',
      details: { error: error instanceof Error ? error.message : String(error) }
    }
    failed++
  }

  // Environment variables check
  try {
    const config = getConfig()
    const requiredEnvVars = ['NODE_ENV']
    const missingVars = requiredEnvVars.filter(varName => !process.env[varName])
    
    if (missingVars.length === 0) {
      checks.environmentVariables = {
        status: 'pass',
        message: 'All required environment variables are present'
      }
      passed++
    } else {
      checks.environmentVariables = {
        status: 'fail',
        message: `Missing required environment variables: ${missingVars.join(', ')}`,
        details: { missing: missingVars }
      }
      failed++
    }
  } catch (error) {
    checks.environmentVariables = {
      status: 'fail',
      message: 'Failed to check environment variables',
      details: { error: error instanceof Error ? error.message : String(error) }
    }
    failed++
  }

  // Security configuration check
  try {
    const config = getConfig()
    if (config.security.enableAuth) {
      const hasValidAuth = config.security.adminPassword || 
                          (config.security.adminPasswordHash && config.security.adminPasswordSalt)
      
      if (hasValidAuth) {
        checks.securityConfig = {
          status: 'pass',
          message: 'Security configuration is valid'
        }
        passed++
      } else {
        checks.securityConfig = {
          status: 'fail',
          message: 'Authentication is enabled but no valid credentials are configured'
        }
        failed++
      }
    } else {
      checks.securityConfig = {
        status: 'warn',
        message: 'Authentication is disabled'
      }
      warnings++
    }
  } catch (error) {
    checks.securityConfig = {
      status: 'fail',
      message: 'Failed to check security configuration',
      details: { error: error instanceof Error ? error.message : String(error) }
    }
    failed++
  }

  // Feature flags consistency check
  try {
    const config = getConfig()
    const inconsistencies: string[] = []
    
    if (config.features.enableAuth !== config.security.enableAuth) {
      inconsistencies.push('Auth feature flag does not match security configuration')
    }
    
    if (inconsistencies.length === 0) {
      checks.featureConsistency = {
        status: 'pass',
        message: 'Feature flags are consistent with configuration'
      }
      passed++
    } else {
      checks.featureConsistency = {
        status: 'warn',
        message: 'Feature flag inconsistencies detected',
        details: { inconsistencies }
      }
      warnings++
    }
  } catch (error) {
    checks.featureConsistency = {
      status: 'fail',
      message: 'Failed to check feature flag consistency',
      details: { error: error instanceof Error ? error.message : String(error) }
    }
    failed++
  }

  const total = passed + warnings + failed
  const status = failed > 0 ? 'error' : warnings > 0 ? 'warning' : 'healthy'

  return {
    status,
    checks,
    summary: {
      total,
      passed,
      warnings,
      failed
    }
  }
}

/**
 * Generate configuration report
 */
export function generateConfigReport(): string {
  const validation = validateConfiguration()
  const config = getConfig()
  
  let report = '# Configuration Report\n\n'
  
  report += `**Environment:** ${config.app.environment}\n`
  report += `**Application:** ${config.app.name} v${config.app.version}\n`
  report += `**Debug Mode:** ${config.app.debug ? 'Enabled' : 'Disabled'}\n\n`
  
  report += '## Validation Results\n\n'
  report += `**Status:** ${validation.isValid ? '✅ Valid' : '❌ Invalid'}\n`
  report += `**Errors:** ${validation.errors.length}\n`
  report += `**Warnings:** ${validation.warnings.length}\n`
  report += `**Recommendations:** ${validation.recommendations.length}\n\n`
  
  if (validation.errors.length > 0) {
    report += '### Errors\n\n'
    validation.errors.forEach(error => {
      report += `- ❌ ${error}\n`
    })
    report += '\n'
  }
  
  if (validation.warnings.length > 0) {
    report += '### Warnings\n\n'
    validation.warnings.forEach(warning => {
      report += `- ⚠️ ${warning}\n`
    })
    report += '\n'
  }
  
  if (validation.recommendations.length > 0) {
    report += '### Recommendations\n\n'
    validation.recommendations.forEach(rec => {
      report += `- 💡 ${rec}\n`
    })
    report += '\n'
  }
  
  report += '## Feature Status\n\n'
  report += `- **Authentication:** ${config.features.enableAuth ? 'Enabled' : 'Disabled'}\n`
  report += `- **Caching:** ${config.features.enableCaching ? 'Enabled' : 'Disabled'}\n`
  report += `- **Rate Limiting:** ${config.features.enableRateLimiting ? 'Enabled' : 'Disabled'}\n`
  report += `- **Metrics:** ${config.features.enableMetrics ? 'Enabled' : 'Disabled'}\n`
  report += `- **Experimental Features:** ${config.features.enableExperimentalFeatures ? 'Enabled' : 'Disabled'}\n`
  
  return report
}
