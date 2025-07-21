'use strict'

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
  data?: any
  error?: Error
}

/**
 * Logger configuration interface
 */
export interface LoggerConfig {
  level: LogLevel
  enableConsole: boolean
  enableStorage: boolean
  maxStoredLogs: number
  formatTimestamp: (date: Date) => string
}

/**
 * Default logger configuration
 */
const DEFAULT_CONFIG: LoggerConfig = {
  level: LogLevel.INFO,
  enableConsole: true,
  enableStorage: true,
  maxStoredLogs: 1000,
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
 * Logger class for structured logging
 * Provides console and in-memory storage capabilities
 */
export class Logger {
  private config: LoggerConfig
  private logs: LogEntry[] = []
  private logId = 0

  constructor(config: Partial<LoggerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Log a debug message
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   */
  debug(component: string, message: string, data?: any): void {
    this.log(LogLevel.DEBUG, component, message, data)
  }

  /**
   * Log an info message
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   */
  info(component: string, message: string, data?: any): void {
    this.log(LogLevel.INFO, component, message, data)
  }

  /**
   * Log a warning message
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   */
  warn(component: string, message: string, data?: any): void {
    this.log(LogLevel.WARN, component, message, data)
  }

  /**
   * Log an error message
   * @param component - Component name
   * @param message - Log message
   * @param error - Error object or additional data
   */
  error(component: string, message: string, error?: Error | any): void {
    const isError = error instanceof Error
    this.log(LogLevel.ERROR, component, message, isError ? undefined : error, isError ? error : undefined)
  }

  /**
   * Core logging method
   * @param level - Log level
   * @param component - Component name
   * @param message - Log message
   * @param data - Additional data
   * @param error - Error object
   */
  private log(level: LogLevel, component: string, message: string, data?: any, error?: Error): void {
    // Check if log level meets threshold
    if (level < this.config.level) {
      return
    }

    const logEntry: LogEntry = {
      timestamp: new Date(),
      level,
      component,
      message,
      data,
      error,
    }

    // Console logging
    if (this.config.enableConsole) {
      this.logToConsole(logEntry)
    }

    // Storage logging
    if (this.config.enableStorage) {
      this.logToStorage(logEntry)
    }
  }

  /**
   * Log to console with appropriate formatting
   * @param entry - Log entry
   */
  private logToConsole(entry: LogEntry): void {
    const timestamp = this.config.formatTimestamp(entry.timestamp)
    const levelName = LogLevel[entry.level]
    const prefix = `[${timestamp}] <${entry.component}> ${levelName}:`
    
    const args: any[] = [prefix, entry.message]
    
    if (entry.data !== undefined) {
      args.push(entry.data)
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
  createScope(component: string) {
    return {
      debug: (message: string, data?: any) => this.debug(component, message, data),
      info: (message: string, data?: any) => this.info(component, message, data),
      warn: (message: string, data?: any) => this.warn(component, message, data),
      error: (message: string, error?: Error | any) => this.error(component, message, error),
    }
  }
}

/**
 * Default logger instance
 */
export const logger = new Logger({
  level: process.env.NODE_ENV === 'development' ? LogLevel.DEBUG : LogLevel.INFO,
})
