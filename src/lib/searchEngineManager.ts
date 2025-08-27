/**
 * Search Engine Manager
 *
 * Manages search engine state, duplicate detection, and session-based disabling
 * for intelligent search engine management during scraping sessions.
 */

import { logger } from '@/utils/logger'
import { toast } from 'react-hot-toast'

export interface SearchEngineConfig {
  id: string
  name: string
  enabled: boolean
  isDisabledForSession: boolean
  duplicateCount: number
  lastResults: string[]
  sessionId: string | null
}

export interface SearchResult {
  url: string
  title: string
  snippet?: string
  domain?: string
}

export interface SearchEngineState {
  engines: Record<string, SearchEngineConfig>
  currentSessionId: string | null
  duplicateThreshold: number
}

/**
 * Search Engine Manager Class
 */
export class SearchEngineManager {
  private state: SearchEngineState
  private readonly STORAGE_KEY = 'search-engine-state'
  private readonly DUPLICATE_THRESHOLD = 2
  private readonly RESULT_COMPARISON_THRESHOLD = 0.8 // 80% similarity threshold

  constructor() {
    this.state = {
      engines: {
        google: {
          id: 'google',
          name: 'Google Search',
          enabled: true,
          isDisabledForSession: false,
          duplicateCount: 0,
          lastResults: [],
          sessionId: null,
        },
        azure: {
          id: 'azure',
          name: 'Azure AI Search',
          enabled: true,
          isDisabledForSession: false,
          duplicateCount: 0,
          lastResults: [],
          sessionId: null,
        },
        duckduckgo: {
          id: 'duckduckgo',
          name: 'DuckDuckGo',
          enabled: true,
          isDisabledForSession: false,
          duplicateCount: 0,
          lastResults: [],
          sessionId: null,
        },
      },
      currentSessionId: null,
      duplicateThreshold: this.DUPLICATE_THRESHOLD,
    }

    this.loadState()
  }

  /**
   * Start a new scraping session
   */
  startSession(sessionId: string): void {
    logger.info('SearchEngineManager', `Starting new session: ${sessionId}`)

    this.state.currentSessionId = sessionId

    // Reset session-specific state for all engines
    Object.values(this.state.engines).forEach(engine => {
      engine.isDisabledForSession = false
      engine.duplicateCount = 0
      engine.lastResults = []
      engine.sessionId = sessionId
    })

    this.saveState()
  }

  /**
   * End the current scraping session
   */
  endSession(): void {
    if (!this.state.currentSessionId) {
      return
    }

    logger.info('SearchEngineManager', `Ending session: ${this.state.currentSessionId}`)

    // Reset session-specific state
    Object.values(this.state.engines).forEach(engine => {
      engine.isDisabledForSession = false
      engine.duplicateCount = 0
      engine.lastResults = []
      engine.sessionId = null
    })

    this.state.currentSessionId = null
    this.saveState()
  }

  /**
   * Check if search results are duplicates and update engine state
   */
  checkAndUpdateResults(engineId: string, results: SearchResult[]): boolean {
    const engine = this.state.engines[engineId]
    if (!engine) {
      logger.warn('SearchEngineManager', `Unknown engine: ${engineId}`)
      return false
    }

    // Skip if engine is already disabled for session
    if (engine.isDisabledForSession) {
      return false
    }

    // Convert results to comparable format
    const resultSignature = this.createResultSignature(results)

    // Check for duplicates
    const isDuplicate = this.isResultDuplicate(engine.lastResults, resultSignature)

    if (isDuplicate) {
      engine.duplicateCount++
      logger.warn(
        'SearchEngineManager',
        `Duplicate results detected for ${engine.name} (count: ${engine.duplicateCount})`
      )

      // Disable engine if threshold reached
      if (engine.duplicateCount >= this.state.duplicateThreshold) {
        engine.isDisabledForSession = true
        this.notifyEngineDisabled(engine.name)
        logger.warn(
          'SearchEngineManager',
          `${engine.name} disabled for session due to duplicate results`
        )
      }
    } else {
      // Update last results
      engine.lastResults = resultSignature
    }

    this.saveState()
    return !engine.isDisabledForSession
  }

  /**
   * Manually enable/disable a search engine
   */
  setEngineEnabled(engineId: string, enabled: boolean): void {
    const engine = this.state.engines[engineId]
    if (!engine) {
      logger.warn('SearchEngineManager', `Unknown engine: ${engineId}`)
      return
    }

    engine.enabled = enabled
    this.saveState()

    logger.info('SearchEngineManager', `${engine.name} ${enabled ? 'enabled' : 'disabled'}`)

    // Show toast notification
    toast.success(`${engine.name} ${enabled ? 'enabled' : 'disabled'}`)
  }

  /**
   * Get list of available engines for searching
   */
  getAvailableEngines(): SearchEngineConfig[] {
    return Object.values(this.state.engines).filter(
      engine => engine.enabled && !engine.isDisabledForSession
    )
  }

  /**
   * Get all engines with their current state
   */
  getAllEngines(): SearchEngineConfig[] {
    return Object.values(this.state.engines)
  }

  /**
   * Check if any engines are available
   */
  hasAvailableEngines(): boolean {
    return this.getAvailableEngines().length > 0
  }

  /**
   * Reset all engines to enabled state (used during application reset)
   */
  resetAllEngines(): void {
    logger.info('SearchEngineManager', 'Resetting all search engines to enabled state')

    Object.values(this.state.engines).forEach(engine => {
      engine.enabled = true
      engine.isDisabledForSession = false
      engine.duplicateCount = 0
      engine.lastResults = []
    })

    this.saveState()
    toast.success('All search engines reset to enabled state')
  }

  /**
   * Create a signature for result comparison
   */
  private createResultSignature(results: SearchResult[]): string[] {
    return results
      .slice(0, 10) // Compare first 10 results
      .map(result => `${result.domain || new URL(result.url).hostname}:${result.title}`)
      .sort() // Sort for consistent comparison
  }

  /**
   * Check if two result sets are duplicates
   */
  private isResultDuplicate(lastResults: string[], currentResults: string[]): boolean {
    if (lastResults.length === 0 || currentResults.length === 0) {
      return false
    }

    // Calculate similarity ratio
    const intersection = lastResults.filter(result => currentResults.includes(result))
    const similarity = intersection.length / Math.max(lastResults.length, currentResults.length)

    return similarity >= this.RESULT_COMPARISON_THRESHOLD
  }

  /**
   * Show notification when engine is disabled
   */
  private notifyEngineDisabled(engineName: string): void {
    toast.error(`${engineName} has been disabled for this session due to duplicate results`, {
      duration: 6000,
      icon: '⚠️',
    })
  }

  /**
   * Save state to localStorage
   */
  private saveState(): void {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.state))
    } catch (error) {
      logger.error('SearchEngineManager', 'Failed to save state', error)
    }
  }

  /**
   * Load state from localStorage
   */
  private loadState(): void {
    try {
      const saved = localStorage.getItem(this.STORAGE_KEY)
      if (saved) {
        const loadedState = JSON.parse(saved)
        // Merge with default state to handle new engines
        this.state = {
          ...this.state,
          ...loadedState,
          engines: {
            ...this.state.engines,
            ...loadedState.engines,
          },
        }
      }
    } catch (error) {
      logger.error('SearchEngineManager', 'Failed to load state', error)
    }
  }
}

/**
 * Singleton instance
 */
export const searchEngineManager = new SearchEngineManager()
