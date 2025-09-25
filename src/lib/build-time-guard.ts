/**
 * Build-time Database Connection Guard
 * 
 * This utility provides functions to detect build-time environment and prevent
 * database connections during the Next.js build process to avoid ECONNREFUSED errors.
 * 
 * The build process should not require an active database connection, but runtime
 * functionality should work normally.
 */

import { logger } from '../utils/logger'

/**
 * Detects if the current execution is happening during the build process
 */
export function isBuildTime(): boolean {
  // Check for Next.js build environment indicators
  const isNextBuild = process.env.NEXT_PHASE === 'phase-production-build' ||
                      process.env.NEXT_PHASE === 'phase-development-build'
  
  // Check for explicit build flag
  const isBuildFlag = process.env.IS_BUILD_TIME === 'true'
  
  // Check for CI/CD build environment
  const isCIBuild = process.env.CI === 'true' && 
                    (process.env.GITHUB_ACTIONS === 'true' || 
                     process.env.VERCEL === '1' ||
                     process.env.NETLIFY === 'true')
  
  // Check if we're in a build command context
  const isBuildCommand = process.argv.some(arg => 
    arg.includes('next build') || 
    arg.includes('npm run build') || 
    arg.includes('yarn build')
  )
  
  // Check for webpack compilation context
  const isWebpackBuild = typeof process.env.WEBPACK_BUILD !== 'undefined'
  
  const buildTime = isNextBuild || isBuildFlag || isCIBuild || isBuildCommand || isWebpackBuild
  
  if (buildTime) {
    logger.debug('BuildTimeGuard', 'Build-time environment detected', {
      isNextBuild,
      isBuildFlag,
      isCIBuild,
      isBuildCommand,
      isWebpackBuild,
      nodeEnv: process.env.NODE_ENV,
      nextPhase: process.env.NEXT_PHASE
    })
  }
  
  return buildTime
}

/**
 * Detects if database connections should be allowed
 */
export function isDatabaseConnectionAllowed(): boolean {
  // Never allow database connections during build time
  if (isBuildTime()) {
    return false
  }
  
  // Check for explicit database disable flag
  if (process.env.DISABLE_DATABASE === 'true') {
    return false
  }
  
  // Allow database connections in runtime environments
  return true
}

/**
 * Guards database operations to prevent execution during build time
 */
export function guardDatabaseOperation<T>(
  operation: () => Promise<T>,
  fallbackValue: T,
  operationName: string = 'database operation'
): Promise<T> {
  if (!isDatabaseConnectionAllowed()) {
    logger.debug('BuildTimeGuard', `Skipping ${operationName} during build time`, {
      isBuildTime: isBuildTime(),
      operationName
    })
    return Promise.resolve(fallbackValue)
  }
  
  return operation()
}

/**
 * Guards synchronous database operations
 */
export function guardDatabaseOperationSync<T>(
  operation: () => T,
  fallbackValue: T,
  operationName: string = 'database operation'
): T {
  if (!isDatabaseConnectionAllowed()) {
    logger.debug('BuildTimeGuard', `Skipping ${operationName} during build time`, {
      isBuildTime: isBuildTime(),
      operationName
    })
    return fallbackValue
  }
  
  return operation()
}

/**
 * Creates a database connection with build-time protection
 */
export async function createProtectedDatabaseConnection<T>(
  connectionFactory: () => Promise<T>,
  connectionName: string = 'database connection'
): Promise<T | null> {
  if (!isDatabaseConnectionAllowed()) {
    logger.info('BuildTimeGuard', `Skipping ${connectionName} creation during build time`, {
      isBuildTime: isBuildTime(),
      connectionName
    })
    return null
  }
  
  try {
    const connection = await connectionFactory()
    logger.debug('BuildTimeGuard', `${connectionName} created successfully`, {
      connectionName
    })
    return connection
  } catch (error) {
    logger.error('BuildTimeGuard', `Failed to create ${connectionName}`, {
      error: error instanceof Error ? error.message : 'Unknown error',
      connectionName
    })
    throw error
  }
}

/**
 * Wraps a class method to skip execution during build time
 */
export function buildTimeSkip<T extends any[], R>(
  target: any,
  propertyKey: string,
  descriptor: TypedPropertyDescriptor<(...args: T) => Promise<R>>
) {
  const originalMethod = descriptor.value!
  
  descriptor.value = async function (...args: T): Promise<R> {
    if (!isDatabaseConnectionAllowed()) {
      logger.debug('BuildTimeGuard', `Skipping method ${propertyKey} during build time`, {
        className: target.constructor.name,
        methodName: propertyKey,
        isBuildTime: isBuildTime()
      })
      return undefined as any
    }
    
    return originalMethod.apply(this, args)
  }
  
  return descriptor
}

/**
 * Environment configuration for build-time behavior
 */
export interface BuildTimeConfig {
  allowDatabaseConnections: boolean
  skipRetentionPolicies: boolean
  skipBackgroundJobs: boolean
  skipDataMigrations: boolean
  logLevel: 'debug' | 'info' | 'warn' | 'error'
}

/**
 * Gets build-time configuration
 */
export function getBuildTimeConfig(): BuildTimeConfig {
  const isBuild = isBuildTime()
  
  return {
    allowDatabaseConnections: !isBuild && process.env.DISABLE_DATABASE !== 'true',
    skipRetentionPolicies: isBuild || process.env.SKIP_RETENTION_POLICIES === 'true',
    skipBackgroundJobs: isBuild || process.env.SKIP_BACKGROUND_JOBS === 'true',
    skipDataMigrations: isBuild || process.env.SKIP_DATA_MIGRATIONS === 'true',
    logLevel: (process.env.BUILD_LOG_LEVEL as any) || (isBuild ? 'warn' : 'info')
  }
}

/**
 * Logs build-time environment information
 */
export function logBuildTimeEnvironment(): void {
  const config = getBuildTimeConfig()
  
  logger.info('BuildTimeGuard', 'Build-time environment configuration', {
    isBuildTime: isBuildTime(),
    isDatabaseConnectionAllowed: isDatabaseConnectionAllowed(),
    config,
    environment: {
      NODE_ENV: process.env.NODE_ENV,
      NEXT_PHASE: process.env.NEXT_PHASE,
      CI: process.env.CI,
      IS_BUILD_TIME: process.env.IS_BUILD_TIME,
      DISABLE_DATABASE: process.env.DISABLE_DATABASE
    }
  })
}
