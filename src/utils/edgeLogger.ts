'use strict'

/**
 * Edge Runtime Compatible Logger
 * Simplified logger for use in Next.js middleware and Edge runtime
 */

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  FATAL = 4,
}

export interface EdgeLogEntry {
  timestamp: Date
  level: LogLevel
  component: string
  message: string
  data?: any
  error?: Error | string
}

export interface EdgeLoggingConfig {
  level: LogLevel
  enableConsole: boolean
  component: string
}

/**
 * Edge-compatible logger class
 * Only supports console logging in Edge runtime
 */
export class EdgeLogger {
  private config: EdgeLoggingConfig
  private logs: EdgeLogEntry[] = []
  private maxLogs = 1000

  constructor(config: Partial<EdgeLoggingConfig> = {}) {
    this.config = {
      level: LogLevel.INFO,
      enableConsole: true,
      component: 'EdgeLogger',
      ...config,
    }
  }

  /**
   * Log a message at the specified level
   */
  private log(
    level: LogLevel,
    component: string,
    message: string,
    data?: any,
    error?: Error | string
  ): void {
    if (level < this.config.level) {
      return
    }

    const logEntry: EdgeLogEntry = {
      timestamp: new Date(),
      level,
      component,
      message,
      data,
      error,
    }

    // Store in memory (limited)
    this.logs.push(logEntry)
    if (this.logs.length > this.maxLogs) {
      this.logs.shift()
    }

    // Console output
    if (this.config.enableConsole) {
      this.writeToConsole(logEntry)
    }
  }

  /**
   * Write log entry to console
   */
  private writeToConsole(entry: EdgeLogEntry): void {
    const timestamp = entry.timestamp.toISOString()
    const levelName = LogLevel[entry.level]
    const logData = {
      timestamp,
      level: levelName,
      component: entry.component,
      message: entry.message,
      ...(entry.data && { data: entry.data }),
      ...(entry.error && { error: entry.error }),
    }

    const logString = JSON.stringify(logData)

    switch (entry.level) {
      case LogLevel.DEBUG:
        console.debug(logString)
        break
      case LogLevel.INFO:
        console.info(logString)
        break
      case LogLevel.WARN:
        console.warn(logString)
        break
      case LogLevel.ERROR:
      case LogLevel.FATAL:
        console.error(logString)
        break
      default:
        console.log(logString)
    }
  }

  /**
   * Debug level logging
   */
  debug(component: string, message: string, data?: any): void {
    this.log(LogLevel.DEBUG, component, message, data)
  }

  /**
   * Info level logging
   */
  info(component: string, message: string, data?: any): void {
    this.log(LogLevel.INFO, component, message, data)
  }

  /**
   * Warning level logging
   */
  warn(component: string, message: string, data?: any): void {
    this.log(LogLevel.WARN, component, message, data)
  }

  /**
   * Error level logging
   */
  error(component: string, message: string, error?: Error | string, data?: any): void {
    this.log(LogLevel.ERROR, component, message, data, error)
  }

  /**
   * Fatal level logging
   */
  fatal(component: string, message: string, error?: Error | string, data?: any): void {
    this.log(LogLevel.FATAL, component, message, data, error)
  }

  /**
   * Get recent logs
   */
  getRecentLogs(count: number = 50): EdgeLogEntry[] {
    return this.logs.slice(-count)
  }

  /**
   * Clear logs
   */
  clearLogs(): void {
    this.logs = []
  }
}

// Create and export a default instance
export const edgeLogger = new EdgeLogger({
  level: LogLevel.INFO,
  enableConsole: true,
  component: 'EdgeRuntime',
})

// Export default
export default edgeLogger
