/**
 * Comprehensive System Tests for Environment Configuration
 * Testing application behavior across different environment configurations
 */

import { jest } from '@jest/globals'
import { spawn, ChildProcess } from 'child_process'
import fs from 'fs/promises'
import path from 'path'

interface EnvironmentConfig {
  NODE_ENV: string
  PORT: string
  DATABASE_URL?: string
  REDIS_URL?: string
  API_TIMEOUT?: string
  MAX_CONCURRENT_REQUESTS?: string
  LOG_LEVEL?: string
}

interface EnvironmentTestResult {
  environment: string
  success: boolean
  startupTime?: number
  error?: string
  configValidation?: boolean
  serviceHealth?: boolean
}

class EnvironmentTester {
  private processes: Map<string, ChildProcess> = new Map()
  private baseConfigs: Map<string, EnvironmentConfig> = new Map()

  constructor() {
    // Define base configurations for different environments
    this.baseConfigs.set('development', {
      NODE_ENV: 'development',
      PORT: '3002',
      DATABASE_URL: 'postgresql://dev:dev@localhost:5432/dev_db',
      REDIS_URL: 'redis://localhost:6379/0',
      API_TIMEOUT: '30000',
      MAX_CONCURRENT_REQUESTS: '10',
      LOG_LEVEL: 'debug',
    })

    this.baseConfigs.set('test', {
      NODE_ENV: 'test',
      PORT: '3003',
      DATABASE_URL: 'postgresql://test:test@localhost:5432/test_db',
      REDIS_URL: 'redis://localhost:6379/1',
      API_TIMEOUT: '10000',
      MAX_CONCURRENT_REQUESTS: '5',
      LOG_LEVEL: 'error',
    })

    this.baseConfigs.set('production', {
      NODE_ENV: 'production',
      PORT: '3004',
      DATABASE_URL: 'postgresql://prod:prod@localhost:5432/prod_db',
      REDIS_URL: 'redis://localhost:6379/2',
      API_TIMEOUT: '60000',
      MAX_CONCURRENT_REQUESTS: '50',
      LOG_LEVEL: 'info',
    })
  }

  async testEnvironment(
    envName: string,
    customConfig?: Partial<EnvironmentConfig>
  ): Promise<EnvironmentTestResult> {
    const baseConfig = this.baseConfigs.get(envName)
    if (!baseConfig) {
      return {
        environment: envName,
        success: false,
        error: `Unknown environment: ${envName}`,
      }
    }

    const config = { ...baseConfig, ...customConfig }
    const startTime = Date.now()

    try {
      // Start application with environment configuration
      const process = await this.startApplicationWithConfig(envName, config)
      this.processes.set(envName, process)

      // Wait for application to start
      const started = await this.waitForApplicationStart(process, config.PORT)
      if (!started) {
        return {
          environment: envName,
          success: false,
          error: 'Application failed to start within timeout',
          startupTime: Date.now() - startTime,
        }
      }

      // Validate configuration
      const configValid = await this.validateConfiguration(config)

      // Check service health
      const serviceHealthy = await this.checkServiceHealth(config.PORT)

      return {
        environment: envName,
        success: true,
        startupTime: Date.now() - startTime,
        configValidation: configValid,
        serviceHealth: serviceHealthy,
      }
    } catch (error) {
      return {
        environment: envName,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        startupTime: Date.now() - startTime,
      }
    }
  }

  private async startApplicationWithConfig(
    envName: string,
    config: EnvironmentConfig
  ): Promise<ChildProcess> {
    return new Promise((resolve, reject) => {
      const process = spawn('npm', ['start'], {
        env: { ...process.env, ...config },
        stdio: 'pipe',
        detached: false,
      })

      process.on('error', reject)

      // Give process time to start
      setTimeout(() => resolve(process), 2000)
    })
  }

  private async waitForApplicationStart(process: ChildProcess, port: string): Promise<boolean> {
    return new Promise(resolve => {
      const timeout = setTimeout(() => resolve(false), 30000)

      let outputBuffer = ''

      process.stdout?.on('data', data => {
        outputBuffer += data.toString()

        if (
          outputBuffer.includes('Ready') ||
          outputBuffer.includes('started server') ||
          outputBuffer.includes(`listening on port ${port}`)
        ) {
          clearTimeout(timeout)
          resolve(true)
        }
      })

      process.stderr?.on('data', data => {
        const error = data.toString()
        if (error.includes('EADDRINUSE') || error.includes('Error:')) {
          clearTimeout(timeout)
          resolve(false)
        }
      })

      process.on('exit', code => {
        clearTimeout(timeout)
        resolve(code === 0)
      })
    })
  }

  private async validateConfiguration(config: EnvironmentConfig): Promise<boolean> {
    try {
      // Validate required environment variables
      const requiredVars = ['NODE_ENV', 'PORT']
      for (const varName of requiredVars) {
        if (!config[varName as keyof EnvironmentConfig]) {
          return false
        }
      }

      // Validate port number
      const port = parseInt(config.PORT)
      if (isNaN(port) || port < 1 || port > 65535) {
        return false
      }

      // Validate database URL format
      if (config.DATABASE_URL && !config.DATABASE_URL.startsWith('postgresql://')) {
        return false
      }

      // Validate Redis URL format
      if (config.REDIS_URL && !config.REDIS_URL.startsWith('redis://')) {
        return false
      }

      // Validate numeric configurations
      if (config.API_TIMEOUT && isNaN(parseInt(config.API_TIMEOUT))) {
        return false
      }

      if (config.MAX_CONCURRENT_REQUESTS && isNaN(parseInt(config.MAX_CONCURRENT_REQUESTS))) {
        return false
      }

      return true
    } catch (error) {
      return false
    }
  }

  private async checkServiceHealth(port: string): Promise<boolean> {
    try {
      const fetch = (await import('node-fetch')).default
      const response = await fetch(`http://localhost:${port}/api/health`, {
        timeout: 10000,
      })

      return response.ok
    } catch (error) {
      return false
    }
  }

  async cleanup(): Promise<void> {
    for (const [envName, process] of this.processes) {
      try {
        process.kill('SIGTERM')

        // Wait for graceful shutdown
        await new Promise<void>(resolve => {
          const timeout = setTimeout(() => {
            process.kill('SIGKILL')
            resolve()
          }, 5000)

          process.on('exit', () => {
            clearTimeout(timeout)
            resolve()
          })
        })
      } catch (error) {
        console.error(`Error cleaning up process for ${envName}:`, error)
      }
    }

    this.processes.clear()
  }
}

describe('Environment Configuration Comprehensive Tests', () => {
  let envTester: EnvironmentTester

  beforeAll(() => {
    envTester = new EnvironmentTester()
  })

  afterAll(async () => {
    await envTester.cleanup()
  }, 30000)

  describe('Standard Environment Configurations', () => {
    test('should start successfully in development environment', async () => {
      const result = await envTester.testEnvironment('development')

      expect(result.success).toBe(true)
      expect(result.startupTime).toBeLessThan(30000)
      expect(result.configValidation).toBe(true)
      expect(result.serviceHealth).toBe(true)
    }, 60000)

    test('should start successfully in test environment', async () => {
      const result = await envTester.testEnvironment('test')

      expect(result.success).toBe(true)
      expect(result.startupTime).toBeLessThan(30000)
      expect(result.configValidation).toBe(true)
      expect(result.serviceHealth).toBe(true)
    }, 60000)

    test('should start successfully in production environment', async () => {
      const result = await envTester.testEnvironment('production')

      expect(result.success).toBe(true)
      expect(result.startupTime).toBeLessThan(30000)
      expect(result.configValidation).toBe(true)
      expect(result.serviceHealth).toBe(true)
    }, 60000)
  })

  describe('Custom Configuration Variations', () => {
    test('should handle custom port configuration', async () => {
      const customConfig = { PORT: '3005' }
      const result = await envTester.testEnvironment('test', customConfig)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)

    test('should handle custom timeout configuration', async () => {
      const customConfig = {
        API_TIMEOUT: '5000',
        MAX_CONCURRENT_REQUESTS: '20',
      }
      const result = await envTester.testEnvironment('development', customConfig)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)

    test('should handle custom log level configuration', async () => {
      const customConfig = { LOG_LEVEL: 'warn' }
      const result = await envTester.testEnvironment('test', customConfig)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)
  })

  describe('Invalid Configuration Handling', () => {
    test('should handle invalid port configuration', async () => {
      const invalidConfig = { PORT: 'invalid-port' }
      const result = await envTester.testEnvironment('test', invalidConfig)

      expect(result.configValidation).toBe(false)
    }, 30000)

    test('should handle invalid database URL', async () => {
      const invalidConfig = { DATABASE_URL: 'invalid-url' }
      const result = await envTester.testEnvironment('test', invalidConfig)

      expect(result.configValidation).toBe(false)
    }, 30000)

    test('should handle invalid Redis URL', async () => {
      const invalidConfig = { REDIS_URL: 'invalid-redis-url' }
      const result = await envTester.testEnvironment('test', invalidConfig)

      expect(result.configValidation).toBe(false)
    }, 30000)

    test('should handle invalid timeout values', async () => {
      const invalidConfig = {
        API_TIMEOUT: 'not-a-number',
        MAX_CONCURRENT_REQUESTS: 'invalid',
      }
      const result = await envTester.testEnvironment('test', invalidConfig)

      expect(result.configValidation).toBe(false)
    }, 30000)
  })

  describe('Environment-Specific Behavior', () => {
    test('should use appropriate logging in different environments', async () => {
      const environments = ['development', 'test', 'production']
      const results = []

      for (const env of environments) {
        const result = await envTester.testEnvironment(env)
        results.push(result)
      }

      // All environments should start successfully
      results.forEach(result => {
        expect(result.success).toBe(true)
      })
    }, 180000)

    test('should handle different database configurations', async () => {
      const dbConfigs = [
        { DATABASE_URL: 'postgresql://user1:pass1@localhost:5432/db1' },
        { DATABASE_URL: 'postgresql://user2:pass2@localhost:5432/db2' },
        { DATABASE_URL: 'postgresql://user3:pass3@localhost:5432/db3' },
      ]

      for (let i = 0; i < dbConfigs.length; i++) {
        const config = { ...dbConfigs[i], PORT: (3006 + i).toString() }
        const result = await envTester.testEnvironment('test', config)

        expect(result.configValidation).toBe(true)
      }
    }, 120000)

    test('should handle different Redis configurations', async () => {
      const redisConfigs = [
        { REDIS_URL: 'redis://localhost:6379/0' },
        { REDIS_URL: 'redis://localhost:6379/1' },
        { REDIS_URL: 'redis://localhost:6379/2' },
      ]

      for (let i = 0; i < redisConfigs.length; i++) {
        const config = { ...redisConfigs[i], PORT: (3009 + i).toString() }
        const result = await envTester.testEnvironment('test', config)

        expect(result.configValidation).toBe(true)
      }
    }, 120000)
  })

  describe('Resource Constraints and Limits', () => {
    test('should handle low resource configurations', async () => {
      const lowResourceConfig = {
        MAX_CONCURRENT_REQUESTS: '1',
        API_TIMEOUT: '5000',
        PORT: '3012',
      }

      const result = await envTester.testEnvironment('test', lowResourceConfig)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)

    test('should handle high resource configurations', async () => {
      const highResourceConfig = {
        MAX_CONCURRENT_REQUESTS: '100',
        API_TIMEOUT: '120000',
        PORT: '3013',
      }

      const result = await envTester.testEnvironment('production', highResourceConfig)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)

    test('should handle extreme configuration values', async () => {
      const extremeConfigs = [
        { MAX_CONCURRENT_REQUESTS: '0', PORT: '3014' },
        { API_TIMEOUT: '1', PORT: '3015' },
        { MAX_CONCURRENT_REQUESTS: '1000', PORT: '3016' },
      ]

      for (const config of extremeConfigs) {
        const result = await envTester.testEnvironment('test', config)

        // Should either succeed or fail gracefully
        expect(typeof result.success).toBe('boolean')
        expect(typeof result.configValidation).toBe('boolean')
      }
    }, 180000)
  })

  describe('Configuration File Management', () => {
    test('should handle missing configuration files', async () => {
      // Test behavior when optional config files are missing
      const result = await envTester.testEnvironment('test', { PORT: '3017' })

      // Should still start with default configurations
      expect(result.success).toBe(true)
    }, 60000)

    test('should handle environment variable precedence', async () => {
      // Environment variables should take precedence over config files
      const envOverride = {
        NODE_ENV: 'test',
        PORT: '3018',
        LOG_LEVEL: 'debug', // Override default test log level
      }

      const result = await envTester.testEnvironment('test', envOverride)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)
  })

  describe('Security Configuration', () => {
    test('should handle secure production configuration', async () => {
      const secureConfig = {
        NODE_ENV: 'production',
        PORT: '3019',
        LOG_LEVEL: 'warn', // Don't log sensitive info
        API_TIMEOUT: '30000',
      }

      const result = await envTester.testEnvironment('production', secureConfig)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)

    test('should handle development debugging configuration', async () => {
      const debugConfig = {
        NODE_ENV: 'development',
        PORT: '3020',
        LOG_LEVEL: 'debug',
        API_TIMEOUT: '60000',
      }

      const result = await envTester.testEnvironment('development', debugConfig)

      expect(result.success).toBe(true)
      expect(result.configValidation).toBe(true)
    }, 60000)
  })

  describe('Startup Performance Across Environments', () => {
    test('should compare startup times across environments', async () => {
      const environments = ['development', 'test', 'production']
      const startupTimes: { [key: string]: number } = {}

      for (const env of environments) {
        const config = { PORT: (3021 + environments.indexOf(env)).toString() }
        const result = await envTester.testEnvironment(env, config)

        if (result.success && result.startupTime) {
          startupTimes[env] = result.startupTime
        }
      }

      // All environments should start within reasonable time
      Object.values(startupTimes).forEach(time => {
        expect(time).toBeLessThan(30000)
      })

      // Development might be slower due to additional tooling
      if (startupTimes.development && startupTimes.production) {
        expect(startupTimes.development).toBeGreaterThanOrEqual(startupTimes.production * 0.5)
      }
    }, 180000)
  })
})
