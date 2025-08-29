/**
 * Comprehensive Unit Tests for Logger Service
 * Tests all logging functionality and configurations
 */

import { Logger, LogLevel, createLogger, updateLoggerConfig } from '@/utils/logger'
import { jest } from '@jest/globals'

// Mock fs for file operations
jest.mock('fs', () => ({
  createWriteStream: jest.fn(),
  existsSync: jest.fn(() => true),
  mkdirSync: jest.fn(),
  statSync: jest.fn(() => ({ size: 1000 })),
  readdirSync: jest.fn(() => []),
  unlinkSync: jest.fn(),
}))

describe('Logger Service', () => {
  let logger: Logger
  let consoleSpy: jest.SpyInstance

  beforeEach(() => {
    logger = new Logger({
      level: LogLevel.DEBUG,
      enableConsole: true,
      enableStorage: true,
      enableFile: false,
      maxStoredLogs: 100,
    })

    // Spy on console methods
    consoleSpy = jest.spyOn(console, 'log').mockImplementation()
    jest.spyOn(console, 'error').mockImplementation()
    jest.spyOn(console, 'warn').mockImplementation()
    jest.spyOn(console, 'info').mockImplementation()
  })

  afterEach(() => {
    jest.clearAllMocks()
    consoleSpy.mockRestore()
  })

  describe('Basic Logging', () => {
    it('should log messages at different levels', () => {
      logger.debug('Debug message')
      logger.info('Info message')
      logger.warn('Warning message')
      logger.error('Error message')

      expect(consoleSpy).toHaveBeenCalledTimes(4)
    })

    it('should respect log level filtering', () => {
      const warnLogger = new Logger({ level: LogLevel.WARN, enableConsole: true })
      const warnConsoleSpy = jest.spyOn(console, 'log').mockImplementation()

      warnLogger.debug('Debug message') // Should not log
      warnLogger.info('Info message') // Should not log
      warnLogger.warn('Warning message') // Should log
      warnLogger.error('Error message') // Should log

      expect(warnConsoleSpy).toHaveBeenCalledTimes(2)
      warnConsoleSpy.mockRestore()
    })

    it('should handle different data types', () => {
      const testData = {
        string: 'test',
        number: 42,
        boolean: true,
        object: { nested: 'value' },
        array: [1, 2, 3],
        null: null,
        undefined: undefined,
      }

      expect(() => {
        logger.info('String:', testData.string)
        logger.info('Number:', testData.number)
        logger.info('Boolean:', testData.boolean)
        logger.info('Object:', testData.object)
        logger.info('Array:', testData.array)
        logger.info('Null:', testData.null)
        logger.info('Undefined:', testData.undefined)
      }).not.toThrow()
    })
  })

  describe('Structured Logging', () => {
    it('should log with metadata', () => {
      const metadata = {
        userId: '123',
        action: 'login',
        timestamp: new Date().toISOString(),
      }

      logger.info('User logged in', metadata)
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('User logged in'))
    })

    it('should handle error objects', () => {
      const error = new Error('Test error')
      error.stack = 'Error stack trace'

      logger.error('An error occurred', { error })
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Test error'))
    })

    it('should support custom formatting', () => {
      const jsonLogger = new Logger({
        format: 'json',
        enableConsole: true,
      })
      const jsonConsoleSpy = jest.spyOn(console, 'log').mockImplementation()

      jsonLogger.info('JSON message', { key: 'value' })

      const logCall = jsonConsoleSpy.mock.calls[0][0]
      expect(() => JSON.parse(logCall)).not.toThrow()

      jsonConsoleSpy.mockRestore()
    })
  })

  describe('Log Storage', () => {
    it('should store logs in memory', () => {
      logger.info('Stored message 1')
      logger.warn('Stored message 2')
      logger.error('Stored message 3')

      const logs = logger.getLogs()
      expect(logs).toHaveLength(3)
      expect(logs[0].message).toBe('Stored message 1')
      expect(logs[1].level).toBe(LogLevel.WARN)
      expect(logs[2].level).toBe(LogLevel.ERROR)
    })

    it('should respect max stored logs limit', () => {
      const limitedLogger = new Logger({
        enableStorage: true,
        maxStoredLogs: 3,
      })

      for (let i = 1; i <= 5; i++) {
        limitedLogger.info(`Message ${i}`)
      }

      const logs = limitedLogger.getLogs()
      expect(logs).toHaveLength(3)
      expect(logs[0].message).toBe('Message 3') // Oldest logs removed
      expect(logs[2].message).toBe('Message 5')
    })

    it('should filter logs by level', () => {
      logger.debug('Debug message')
      logger.info('Info message')
      logger.warn('Warning message')
      logger.error('Error message')

      const errorLogs = logger.getLogs(LogLevel.ERROR)
      expect(errorLogs).toHaveLength(1)
      expect(errorLogs[0].level).toBe(LogLevel.ERROR)

      const warnAndAbove = logger.getLogs(LogLevel.WARN)
      expect(warnAndAbove).toHaveLength(2)
    })

    it('should clear logs', () => {
      logger.info('Message 1')
      logger.info('Message 2')

      expect(logger.getLogs()).toHaveLength(2)

      logger.clearLogs()
      expect(logger.getLogs()).toHaveLength(0)
    })
  })

  describe('Scoped Logging', () => {
    it('should create scoped loggers', () => {
      const scopedLogger = logger.createScope('TestComponent')
      scopedLogger.info('Scoped message')

      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('TestComponent'))
    })

    it('should maintain scope hierarchy', () => {
      const parentScope = logger.createScope('Parent')
      const childScope = parentScope.createScope('Child')

      childScope.info('Nested message')

      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Parent.Child'))
    })
  })

  describe('Performance Logging', () => {
    it('should measure operation performance', async () => {
      const operation = async () => {
        await new Promise(resolve => setTimeout(resolve, 10))
        return 'result'
      }

      const result = await logger.time('test-operation', operation)

      expect(result).toBe('result')
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('test-operation'))
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('ms'))
    })

    it('should handle synchronous operations', () => {
      const syncOperation = () => {
        let sum = 0
        for (let i = 0; i < 1000; i++) {
          sum += i
        }
        return sum
      }

      const result = logger.timeSync('sync-operation', syncOperation)

      expect(result).toBe(499500) // Sum of 0 to 999
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('sync-operation'))
    })
  })

  describe('Configuration Management', () => {
    it('should update configuration', () => {
      logger.updateConfig({
        level: LogLevel.ERROR,
        enableConsole: false,
      })

      logger.info('This should not log')
      logger.error('This should not log to console')

      expect(consoleSpy).not.toHaveBeenCalled()
    })

    it('should load configuration from environment', () => {
      process.env.LOG_LEVEL = 'warn'
      process.env.LOG_FORMAT = 'json'
      process.env.LOG_ENABLE_CONSOLE = 'false'

      logger.loadConfigFromEnvironment()

      // Verify config was loaded (indirectly through behavior)
      logger.info('Info message') // Should not log due to level
      logger.warn('Warning message') // Should log but not to console

      expect(consoleSpy).not.toHaveBeenCalled()

      // Cleanup
      delete process.env.LOG_LEVEL
      delete process.env.LOG_FORMAT
      delete process.env.LOG_ENABLE_CONSOLE
    })
  })

  describe('Error Handling', () => {
    it('should handle logging errors gracefully', () => {
      // Mock console.log to throw an error
      consoleSpy.mockImplementation(() => {
        throw new Error('Console error')
      })

      expect(() => {
        logger.info('This should not crash')
      }).not.toThrow()
    })

    it('should handle circular references in objects', () => {
      const circularObj: any = { name: 'test' }
      circularObj.self = circularObj

      expect(() => {
        logger.info('Circular object:', circularObj)
      }).not.toThrow()
    })

    it('should handle very large objects', () => {
      const largeObj = {
        data: 'x'.repeat(10000),
        nested: {
          moreData: 'y'.repeat(5000),
        },
      }

      expect(() => {
        logger.info('Large object:', largeObj)
      }).not.toThrow()
    })
  })

  describe('Utility Functions', () => {
    it('should create logger with createLogger function', () => {
      const componentLogger = createLogger('MyComponent')
      componentLogger.info('Component message')

      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('MyComponent'))
    })

    it('should update global config with updateLoggerConfig', () => {
      updateLoggerConfig({
        level: LogLevel.ERROR,
        enableConsole: false,
      })

      const newLogger = createLogger('TestComponent')
      newLogger.info('This should not log')

      expect(consoleSpy).not.toHaveBeenCalled()
    })
  })

  describe('Memory Management', () => {
    it('should not leak memory with many log entries', () => {
      const memoryLogger = new Logger({
        enableStorage: true,
        maxStoredLogs: 1000,
      })

      // Generate many log entries
      for (let i = 0; i < 2000; i++) {
        memoryLogger.info(`Message ${i}`)
      }

      const logs = memoryLogger.getLogs()
      expect(logs.length).toBeLessThanOrEqual(1000)
    })

    it('should handle rapid logging without performance degradation', () => {
      const start = performance.now()

      for (let i = 0; i < 1000; i++) {
        logger.info(`Rapid message ${i}`)
      }

      const end = performance.now()
      const duration = end - start

      // Should complete 1000 log operations in reasonable time
      expect(duration).toBeLessThan(1000) // 1 second
    })
  })

  describe('Integration Tests', () => {
    it('should work with different log levels and formats together', () => {
      const complexLogger = new Logger({
        level: LogLevel.INFO,
        format: 'json',
        enableConsole: true,
        enableStorage: true,
        maxStoredLogs: 50,
      })

      const complexConsoleSpy = jest.spyOn(console, 'log').mockImplementation()

      complexLogger.debug('Debug - should not appear')
      complexLogger.info('Info message', { data: 'test' })
      complexLogger.warn('Warning message')
      complexLogger.error('Error message', { error: new Error('Test') })

      expect(complexConsoleSpy).toHaveBeenCalledTimes(3) // debug filtered out
      expect(complexLogger.getLogs()).toHaveLength(3)

      complexConsoleSpy.mockRestore()
    })
  })
})
