/**
 * React Hook for AI Lead Scoring
 * Provides real-time lead scoring functionality with caching and error handling
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { BusinessRecord } from '@/types/business'
import { aiLeadScoringService, LeadScore } from '@/lib/aiLeadScoring'
import { logger } from '@/utils/logger'

export interface UseLeadScoringOptions {
  autoScore?: boolean
  cacheResults?: boolean
  batchSize?: number
  debounceMs?: number
}

export interface LeadScoringState {
  scores: Map<string, LeadScore>
  isLoading: boolean
  isInitialized: boolean
  error: string | null
  progress: {
    processed: number
    total: number
    percentage: number
  }
}

export interface LeadScoringActions {
  scoreBusinesses: (businesses: BusinessRecord[]) => Promise<void>
  scoreBusiness: (business: BusinessRecord) => Promise<LeadScore | null>
  clearScores: () => void
  retryFailed: () => Promise<void>
  updateConfig: (config: any) => void
}

/**
 * Hook for managing lead scoring functionality
 */
export function useLeadScoring(
  options: UseLeadScoringOptions = {}
): LeadScoringState & LeadScoringActions {
  const { autoScore = false, cacheResults = true, batchSize = 10, debounceMs = 300 } = options

  const [state, setState] = useState<LeadScoringState>({
    scores: new Map(),
    isLoading: false,
    isInitialized: false,
    error: null,
    progress: {
      processed: 0,
      total: 0,
      percentage: 0,
    },
  })

  const abortControllerRef = useRef<AbortController | null>(null)
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const failedBusinessesRef = useRef<BusinessRecord[]>([])

  // Initialize the AI service
  useEffect(() => {
    const initializeService = async () => {
      try {
        setState(prev => ({ ...prev, isLoading: true, error: null }))

        if (!aiLeadScoringService) {
          throw new Error('AI Lead Scoring Service not available')
        }

        await aiLeadScoringService.initialize()

        setState(prev => ({
          ...prev,
          isInitialized: true,
          isLoading: false,
        }))

        logger.info('useLeadScoring', 'AI Lead Scoring Service initialized')
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : 'Failed to initialize AI service'
        setState(prev => ({
          ...prev,
          error: errorMessage,
          isLoading: false,
        }))
        logger.error('useLeadScoring', 'Failed to initialize AI service', error)
      }
    }

    initializeService()

    // Cleanup on unmount
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current)
      }
    }
  }, [])

  /**
   * Score a single business
   */
  const scoreBusiness = useCallback(
    async (business: BusinessRecord): Promise<LeadScore | null> => {
      if (!state.isInitialized) {
        logger.warn('useLeadScoring', 'Service not initialized')
        return null
      }

      try {
        // Check cache first
        if (cacheResults && state.scores.has(business.id)) {
          return state.scores.get(business.id)!
        }

        const score = await aiLeadScoringService.getLeadScore(business)

        if (cacheResults) {
          setState(prev => ({
            ...prev,
            scores: new Map(prev.scores).set(business.id, score),
          }))
        }

        return score
      } catch (error) {
        logger.error('useLeadScoring', `Failed to score business ${business.id}`, error)
        return null
      }
    },
    [state.isInitialized, state.scores, cacheResults]
  )

  /**
   * Score multiple businesses with progress tracking
   */
  const scoreBusinesses = useCallback(
    async (businesses: BusinessRecord[]): Promise<void> => {
      if (!state.isInitialized) {
        setState(prev => ({ ...prev, error: 'Service not initialized' }))
        return
      }

      // Cancel any existing operation
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }

      abortControllerRef.current = new AbortController()
      const { signal } = abortControllerRef.current

      setState(prev => ({
        ...prev,
        isLoading: true,
        error: null,
        progress: {
          processed: 0,
          total: businesses.length,
          percentage: 0,
        },
      }))

      failedBusinessesRef.current = []

      try {
        const newScores = new Map(state.scores)
        let processed = 0

        // Process in batches to avoid overwhelming the system
        for (let i = 0; i < businesses.length; i += batchSize) {
          if (signal.aborted) {
            throw new Error('Operation cancelled')
          }

          const batch = businesses.slice(i, i + batchSize)
          const batchPromises = batch.map(async business => {
            try {
              // Skip if already cached
              if (cacheResults && newScores.has(business.id)) {
                return { business, score: newScores.get(business.id)! }
              }

              const score = await aiLeadScoringService.getLeadScore(business)
              return { business, score }
            } catch (error) {
              logger.error('useLeadScoring', `Failed to score business ${business.id}`, error)
              failedBusinessesRef.current.push(business)
              return null
            }
          })

          const batchResults = await Promise.all(batchPromises)

          // Update scores and progress
          batchResults.forEach(result => {
            if (result) {
              newScores.set(result.business.id, result.score)
            }
            processed++
          })

          const percentage = Math.round((processed / businesses.length) * 100)

          setState(prev => ({
            ...prev,
            scores: new Map(newScores),
            progress: {
              processed,
              total: businesses.length,
              percentage,
            },
          }))

          // Small delay between batches to prevent UI blocking
          if (i + batchSize < businesses.length) {
            await new Promise(resolve => setTimeout(resolve, 50))
          }
        }

        setState(prev => ({
          ...prev,
          isLoading: false,
          error:
            failedBusinessesRef.current.length > 0
              ? `Failed to score ${failedBusinessesRef.current.length} businesses`
              : null,
        }))

        logger.info('useLeadScoring', `Scored ${processed} businesses successfully`)
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Failed to score businesses'
        setState(prev => ({
          ...prev,
          isLoading: false,
          error: errorMessage,
        }))
        logger.error('useLeadScoring', 'Batch scoring failed', error)
      }
    },
    [state.isInitialized, state.scores, batchSize, cacheResults]
  )

  /**
   * Debounced version of scoreBusinesses
   */
  const debouncedScoreBusinesses = useCallback(
    (businesses: BusinessRecord[]) => {
      if (debounceTimeoutRef.current) {
        clearTimeout(debounceTimeoutRef.current)
      }

      debounceTimeoutRef.current = setTimeout(() => {
        scoreBusinesses(businesses)
      }, debounceMs)
    },
    [scoreBusinesses, debounceMs]
  )

  /**
   * Clear all scores
   */
  const clearScores = useCallback(() => {
    setState(prev => ({
      ...prev,
      scores: new Map(),
      error: null,
      progress: {
        processed: 0,
        total: 0,
        percentage: 0,
      },
    }))
    failedBusinessesRef.current = []
    logger.info('useLeadScoring', 'Scores cleared')
  }, [])

  /**
   * Retry failed businesses
   */
  const retryFailed = useCallback(async () => {
    if (failedBusinessesRef.current.length === 0) {
      return
    }

    const failedBusinesses = [...failedBusinessesRef.current]
    failedBusinessesRef.current = []

    await scoreBusinesses(failedBusinesses)
  }, [scoreBusinesses])

  /**
   * Update scoring configuration
   */
  const updateConfig = useCallback((config: any) => {
    try {
      aiLeadScoringService.updateConfig(config)
      logger.info('useLeadScoring', 'Configuration updated')
    } catch (error) {
      logger.error('useLeadScoring', 'Failed to update configuration', error)
      setState(prev => ({
        ...prev,
        error: 'Failed to update configuration',
      }))
    }
  }, [])

  // Auto-score functionality
  useEffect(() => {
    if (autoScore && state.isInitialized && !state.isLoading) {
      // This would be triggered by external business data changes
      // Implementation depends on how businesses are managed in the app
    }
  }, [autoScore, state.isInitialized, state.isLoading])

  return {
    ...state,
    scoreBusinesses: debounceMs > 0 ? debouncedScoreBusinesses : scoreBusinesses,
    scoreBusiness,
    clearScores,
    retryFailed,
    updateConfig,
  }
}
