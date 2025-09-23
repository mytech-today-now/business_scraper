'use strict'

// Edge runtime compatible imports
import { getLoggingConfig } from '@/lib/config'

// Check if we're in Edge runtime
const isEdgeRuntime = typeof EdgeRuntime !== 'undefined' ||
  (typeof process !== 'undefined' && process.env.NEXT_RUNTIME === 'edge')

// Conditionally import Node.js modules only in Node.js runtime
let fs: any, path: any, os: any
if (!isEdgeRuntime) {
  try {
    fs = require('fs')
    path = require('path')
    os = require('os')
  } catch (error) {
    // Fallback for Edge runtime
    console.warn('Node.js modules not available in Edge runtime, file logging disabled')
  }
}

/**
 * Log levels enum
 */
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

/**
 * Log entry interface
 */
export interface LogEntry {
  timestamp: Date
  level: LogLevel
  component: string
  message: string
  data?: unknown
  error?: Error
  pid?: number
  hostname?: string
  requestId?: string
}

/**
 * Enhanced logger configuration interface
 */
export interface LoggerConfig {
  level: LogLevel
  format: 'json' | 'text'
  enableConsole: boolean
  enableStorage: boolean
  enableFile: boolean
  filePath?: string
  maxStoredLogs: number
  maxFileSize: number
  maxFiles: number
  formatTimestamp: (date: Date) => string
}

/**
 * Default logger configuration
 */
const DEFAULT_CONFIG: LoggerConfig = {
  level: LogLevel.INFO,
  format: 'text',
  enableConsole: true,
  enableStorage: true,
  enableFile: false,
  maxStoredLogs: 1000,
  maxFileSize: 10 * 1024 * 1024, // 10MB
  maxFiles: 5,
  formatTimestamp: (date: Date) => {
    return date.toLocaleTimeString('en-US', {
      hour12: true,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  },
}

/**
 * Enhanced logger class for structured logging
 * Provides console, in-memory storage, and file logging capabilities
 */
export class Logger {
  private config: LoggerConfig
  private logs: LogEntry[] = []
  private logId = 0
  private fileWriteStream: fs.WriteStream | null = null
  private currentFileSize = 0
  private fileRotationInProgress = false
  private recentLogHashes: Set<string> = new Set()
  private readonly deduplicationWindow = 5000 // 5 seconds

  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }

    // Initialize file logging if enabled
    if (this.config.enableFile && this.config.filePath) {
      this.initializeFileLogging()
    }
  }

  /**
   * Initialize file logging
   */
  private initializeFileLogging(): void {
    if (!this.config.filePath) return

    // Skip file logging in Edge runtime
    if (isEdgeRuntime || !fs || !path) {
      console.warn('Logger: File logging not available in Edge runtime')
      this.config.enableFile = false
      return
    }

    try {
      // Ensure log directory exists
      const logDir = path.dirname(this.config.filePath)
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true })
      }

      // Check current file size
      if (fs.existsSync(this.config.filePath)) {
        const stats = fs.statSync(this.config.filePath)
        this.currentFileSize = stats.size
      }

      // Create write stream
      this.fileWriteStream = fs.createWriteStream(this.config.filePath, { flags: 'a' })

      this.fileWriteStream.on('error', error => {
        console.error('Logger: File write error:', error)
        this.config.enableFile = false
        this.fileWriteStream = null
      })
    } catch (error) {
      console.error('Logger: Failed to initialize file logging:', error)
      this.config.enableFile = false
    }
  }

  /**
   * Log a debug message
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   */
  debug(component: string, message: string, data?: unknown): void {
    this.log(LogLevel.DEBUG, component, message, data)
  }

  /**
   * Log an info message
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   */
  info(component: string, message: string, data?: unknown): void {
    this.log(LogLevel.INFO, component, message, data)
  }

  /**
   * Log a warning message
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   */
  warn(component: string, message: string, data?: unknown): void {
    this.log(LogLevel.WARN, component, message, data)
  }

  /**
   * Log an error message
   * @param component - Component name
   * @param message - Log message
   * @param error - Error object or additional data
   */
  error(component: string, message: string, error?: Error | unknown): void {
    const isError = error instanceof Error
    this.log(
      LogLevel.ERROR,
      component,
      message,
      isError ? undefined : error,
      isError ? error : undefined
    )
  }

  /**
   * Core logging method
   * @param level - Log level
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   * @param error - Error object
   */
  private log(
    level: LogLevel,
    component: string,
    message: string,
    data?: unknown,
    error?: Error
  ): void {
    // Check if log level meets threshold
    if (level < this.config.level) {
      return
    }

    // Create log hash for deduplication
    const logHash = this.createLogHash(level, component, message, data)

    // Check for duplicate logs within the deduplication window
    if (this.recentLogHashes.has(logHash)) {
      return // Skip duplicate log
    }

    // Add to recent logs and clean up old hashes
    this.recentLogHashes.add(logHash)
    setTimeout(() => {
      this.recentLogHashes.delete(logHash)
    }, this.deduplicationWindow)

    const logEntry: LogEntry = {
      timestamp: new Date(),
      level,
      component,
      message,
      data,
      error,
      pid: typeof process !== 'undefined' ? process.pid : undefined,
      hostname: isEdgeRuntime ? 'edge-runtime' :
                typeof window === 'undefined' && os ? os.hostname() : 'browser',
    }

    // Console logging
    if (this.config.enableConsole) {
      this.logToConsole(logEntry)
    }

    // Storage logging
    if (this.config.enableStorage) {
      this.logToStorage(logEntry)
    }

    // File logging
    if (this.config.enableFile && this.fileWriteStream) {
      this.logToFile(logEntry)
    }
  }

  /**
   * Log to console with appropriate formatting
   * @param entry - Log entry
   */
  private logToConsole(entry: LogEntry): void {
    if (this.config.format === 'json') {
      this.logToConsoleJson(entry)
    } else {
      this.logToConsoleText(entry)
    }
  }

  /**
   * Log to console in text format
   * @param entry - Log entry
   */
  private logToConsoleText(entry: LogEntry): void {
    const timestamp = this.config.formatTimestamp(entry.timestamp)
    const levelName = LogLevel[entry.level]
    const prefix = `${timestamp} [${levelName}] [${timestamp}] <${entry.component}> ${levelName}:`

    // Strip ANSI color codes from message
    const cleanMessage = this.stripAnsiCodes(entry.message)

    const args: unknown[] = [prefix, cleanMessage]

    if (entry.data !== undefined) {
      // Clean data if it's a string
      const cleanData = typeof entry.data === 'string' ? this.stripAnsiCodes(entry.data) : entry.data
      args.push(cleanData)
    }

    if (entry.error) {
      args.push(entry.error)
    }

    switch (entry.level) {
      case LogLevel.DEBUG:
        console.debug(...args)
        break
      case LogLevel.INFO:
        console.info(...args)
        break
      case LogLevel.WARN:
        console.warn(...args)
        break
      case LogLevel.ERROR:
        console.error(...args)
        break
    }
  }

  /**
   * Log to console in JSON format
   * @param entry - Log entry
   */
  private logToConsoleJson(entry: LogEntry): void {
    const jsonEntry = {
      timestamp: entry.timestamp.toISOString(),
      level: LogLevel[entry.level],
      component: entry.component,
      message: entry.message,
      ...(entry.data && { data: entry.data }),
      ...(entry.error && {
        error: {
          message: entry.error.message,
          stack: entry.error.stack,
          name: entry.error.name,
        },
      }),
      ...(entry.pid && { pid: entry.pid }),
      ...(entry.hostname && { hostname: entry.hostname }),
      ...(entry.requestId && { requestId: entry.requestId }),
    }

    const jsonString = JSON.stringify(jsonEntry)

    switch (entry.level) {
      case LogLevel.DEBUG:
        console.debug(jsonString)
        break
      case LogLevel.INFO:
        console.info(jsonString)
        break
      case LogLevel.WARN:
        console.warn(jsonString)
        break
      case LogLevel.ERROR:
        console.error(jsonString)
        break
    }
  }

  /**
   * Store log entry in memory
   * @param entry - Log entry
   */
  private logToStorage(entry: LogEntry): void {
    this.logs.push(entry)

    // Maintain maximum log count
    if (this.logs.length > this.config.maxStoredLogs) {
      this.logs = this.logs.slice(-this.config.maxStoredLogs)
    }
  }

  /**
   * Log to file
   * @param entry - Log entry
   */
  private logToFile(entry: LogEntry): void {
    if (!this.fileWriteStream || this.fileRotationInProgress) {
      return
    }

    try {
      let logLine: string

      if (this.config.format === 'json') {
        const jsonEntry = {
          timestamp: entry.timestamp.toISOString(),
          level: LogLevel[entry.level],
          component: entry.component,
          message: entry.message,
          ...(entry.data && { data: entry.data }),
          ...(entry.error && {
            error: {
              message: entry.error.message,
              stack: entry.error.stack,
              name: entry.error.name,
            },
          }),
          ...(entry.pid && { pid: entry.pid }),
          ...(entry.hostname && { hostname: entry.hostname }),
          ...(entry.requestId && { requestId: entry.requestId }),
        }
        logLine = JSON.stringify(jsonEntry) + '\n'
      } else {
        const timestamp = entry.timestamp.toISOString()
        const levelName = LogLevel[entry.level]
        logLine = `[${timestamp}] <${entry.component}> ${levelName}: ${entry.message}`

        if (entry.data) {
          logLine += ` | Data: ${JSON.stringify(entry.data)}`
        }

        if (entry.error) {
          logLine += ` | Error: ${entry.error.message}`
          if (entry.error.stack) {
            logLine += `\nStack: ${entry.error.stack}`
          }
        }

        logLine += '\n'
      }

      // Write to file
      this.fileWriteStream.write(logLine)
      this.currentFileSize += Buffer.byteLength(logLine, 'utf8')

      // Check if file rotation is needed
      if (this.currentFileSize >= this.config.maxFileSize) {
        this.rotateLogFile()
      }
    } catch (error) {
      console.error('Logger: Failed to write to log file:', error)
    }
  }

  /**
   * Rotate log file when it gets too large
   */
  private async rotateLogFile(): Promise<void> {
    if (this.fileRotationInProgress || !this.config.filePath || isEdgeRuntime || !fs) {
      return
    }

    this.fileRotationInProgress = true

    try {
      // Close current stream
      if (this.fileWriteStream) {
        this.fileWriteStream.end()
        this.fileWriteStream = null
      }

      // Rotate existing files
      for (let i = this.config.maxFiles - 1; i > 0; i--) {
        const oldFile = `${this.config.filePath}.${i}`
        const newFile = `${this.config.filePath}.${i + 1}`

        if (fs.existsSync(oldFile)) {
          if (i === this.config.maxFiles - 1) {
            // Delete the oldest file
            fs.unlinkSync(oldFile)
          } else {
            fs.renameSync(oldFile, newFile)
          }
        }
      }

      // Move current file to .1
      if (fs.existsSync(this.config.filePath)) {
        fs.renameSync(this.config.filePath, `${this.config.filePath}.1`)
      }

      // Create new file stream
      this.currentFileSize = 0
      this.fileWriteStream = fs.createWriteStream(this.config.filePath, { flags: 'a' })

      this.fileWriteStream.on('error', error => {
        console.error('Logger: File write error after rotation:', error)
        this.config.enableFile = false
        this.fileWriteStream = null
      })
    } catch (error) {
      console.error('Logger: Failed to rotate log file:', error)
    } finally {
      this.fileRotationInProgress = false
    }
  }

  /**
   * Get all stored logs
   * @param level - Optional level filter
   * @param component - Optional component filter
   * @returns Array of log entries
   */
  getLogs(level?: LogLevel, component?: string): LogEntry[] {
    let filteredLogs = this.logs

    if (level !== undefined) {
      filteredLogs = filteredLogs.filter(log => log.level >= level)
    }

    if (component) {
      filteredLogs = filteredLogs.filter(log =>
        log.component.toLowerCase().includes(component.toLowerCase())
      )
    }

    return filteredLogs.slice() // Return copy
  }

  /**
   * Get recent logs
   * @param count - Number of recent logs to return
   * @returns Array of recent log entries
   */
  getRecentLogs(count: number = 50): LogEntry[] {
    return this.logs.slice(-count)
  }

  /**
   * Clear all stored logs
   */
  clearLogs(): void {
    this.logs = []
    this.info('Logger', 'Logs cleared')
  }

  /**
   * Export logs as formatted string
   * @param level - Optional level filter
   * @param component - Optional component filter
   * @returns Formatted log string
   */
  exportLogs(level?: LogLevel, component?: string): string {
    const logs = this.getLogs(level, component)

    return logs
      .map(entry => {
        const timestamp = this.config.formatTimestamp(entry.timestamp)
        const levelName = LogLevel[entry.level]
        let line = `[${timestamp}] <${entry.component}> ${levelName}: ${entry.message}`

        if (entry.data) {
          line += ` | Data: ${JSON.stringify(entry.data)}`
        }

        if (entry.error) {
          line += ` | Error: ${entry.error.message}`
          if (entry.error.stack) {
            line += `\nStack: ${entry.error.stack}`
          }
        }

        return line
      })
      .join('\n')
  }

  /**
   * Get logging statistics
   * @returns Logging statistics
   */
  getStats(): {
    totalLogs: number
    logsByLevel: Record<string, number>
    logsByComponent: Record<string, number>
    oldestLog?: Date
    newestLog?: Date
  } {
    const logsByLevel: Record<string, number> = {}
    const logsByComponent: Record<string, number> = {}

    for (const log of this.logs) {
      const levelName = LogLevel[log.level]
      logsByLevel[levelName] = (logsByLevel[levelName] || 0) + 1
      logsByComponent[log.component] = (logsByComponent[log.component] || 0) + 1
    }

    return {
      totalLogs: this.logs.length,
      logsByLevel,
      logsByComponent,
      oldestLog: this.logs[0]?.timestamp,
      newestLog: this.logs[this.logs.length - 1]?.timestamp,
    }
  }

  /**
   * Update logger configuration
   * @param config - Partial configuration to update
   */
  updateConfig(config: Partial<LoggerConfig>): void {
    this.config = { ...this.config, ...config }
    this.info('Logger', 'Configuration updated', config)
  }

  /**
   * Create a scoped logger for a specific component
   * @param component - Component name
   * @returns Scoped logger functions
   */
  createScope(component: string): {
    debug: (message: string, data?: unknown) => void
    info: (message: string, data?: unknown) => void
    warn: (message: string, data?: unknown) => void
    error: (message: string, error?: Error | unknown) => void
  } {
    return {
      debug: (message: string, data?: unknown) => this.debug(component, message, data),
      info: (message: string, data?: unknown) => this.info(component, message, data),
      warn: (message: string, data?: unknown) => this.warn(component, message, data),
      error: (message: string, error?: Error | unknown) => this.error(component, message, error),
    }
  }

  /**
   * Close the logger and clean up resources
   */
  async close(): Promise<void> {
    if (this.fileWriteStream) {
      return new Promise(resolve => {
        this.fileWriteStream!.end(() => {
          this.fileWriteStream = null
          resolve()
        })
      })
    }
  }

  /**
   * Load configuration from environment or config system
   */
  loadConfigFromEnvironment(): void {
    try {
      // Try to load from config system
      const loggingConfig = getLoggingConfig()

      this.updateConfig({
        level: this.mapStringToLogLevel(loggingConfig.level),
        format: loggingConfig.format,
        enableConsole: loggingConfig.enableConsole,
        enableFile: loggingConfig.enableFile,
        filePath: loggingConfig.filePath,
        maxFileSize: loggingConfig.maxFileSize,
        maxFiles: loggingConfig.maxFiles,
      })

      // Initialize file logging if it wasn't already initialized
      if (loggingConfig.enableFile && loggingConfig.filePath && !this.fileWriteStream) {
        this.initializeFileLogging()
      }
    } catch (error) {
      // Fallback to environment variables
      const envLogLevel = process.env.LOG_LEVEL?.toLowerCase()
      if (envLogLevel) {
        this.config.level = this.mapStringToLogLevel(envLogLevel)
      }

      const envLogFormat = process.env.LOG_FORMAT?.toLowerCase()
      if (envLogFormat === 'json' || envLogFormat === 'text') {
        this.config.format = envLogFormat
      }

      this.config.enableConsole = process.env.LOG_ENABLE_CONSOLE !== 'false'
      this.config.enableFile = process.env.LOG_ENABLE_FILE === 'true'

      if (this.config.enableFile) {
        this.config.filePath = process.env.LOG_FILE_PATH || './logs/app.log'
        this.initializeFileLogging()
      }
    }
  }

  /**
   * Map string log level to LogLevel enum
   */
  private mapStringToLogLevel(level: string): LogLevel {
    switch (level.toLowerCase()) {
      case 'debug':
        return LogLevel.DEBUG
      case 'info':
        return LogLevel.INFO
      case 'warn':
        return LogLevel.WARN
      case 'error':
        return LogLevel.ERROR
      default:
        return LogLevel.INFO
    }
  }

  /**
   * Create a hash for log deduplication
   */
  private createLogHash(level: LogLevel, component: string, message: string, data?: unknown): string {
    const dataString = data ? JSON.stringify(data) : ''
    return `${level}:${component}:${message}:${dataString}`
  }

  /**
   * Strip ANSI color codes from strings
   */
  private stripAnsiCodes(text: string): string {
    // Remove ANSI escape sequences
    return text.replace(/\x1b\[[0-9;]*m/g, '').replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '')
  }
}

/**
 * Default logger instance with enhanced configuration
 */
export const logger = new Logger({
  level: process.env.NODE_ENV === 'development' ? LogLevel.DEBUG : LogLevel.INFO,
})

// Load configuration when the module is imported
if (typeof window === 'undefined') {
  // Only load config on server side to avoid issues with client-side rendering
  try {
    logger.loadConfigFromEnvironment()
  } catch (error) {
    // Ignore errors during initial load, config might not be available yet
  }
}

/**
 * Create a scoped logger for a component
 * @param component - Component name
 * @returns Scoped logger
 */
export function createLogger(component: string) {
  return logger.createScope(component)
}

/**
 * Update logger configuration
 * @param config - Partial configuration to update
 */
export function updateLoggerConfig(config: Partial<LoggerConfig>): void {
  logger.updateConfig(config)
}

/**
 * Close the default logger
 */
export async function closeLogger(): Promise<void> {
  await logger.close()
}
