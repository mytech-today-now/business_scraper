/**
 * Consent Management Hook
 * Manages client-side consent state synced with server
 */

import { useState, useEffect, useCallback } from 'react'
import { logger } from '@/utils/logger'

// Consent types
export enum ConsentType {
  NECESSARY = 'necessary',
  SCRAPING = 'scraping',
  STORAGE = 'storage',
  ENRICHMENT = 'enrichment',
  ANALYTICS = 'analytics',
  MARKETING = 'marketing',
  DATA_COLLECTION = 'data_collection',
  DATA_PROCESSING = 'data_processing',
  DATA_SHARING = 'data_sharing',
  THIRD_PARTY = 'third_party',
}

// Consent status
export enum ConsentStatus {
  GRANTED = 'granted',
  DENIED = 'denied',
  WITHDRAWN = 'withdrawn',
  PENDING = 'pending',
}

// Consent preferences interface
export interface ConsentPreferences {
  [key: string]: {
    status: ConsentStatus
    timestamp: Date
    version: string
  }
}

// Consent context
interface ConsentContext {
  preferences: ConsentPreferences | null
  loading: boolean
  error: string | null
  hasConsent: (type: ConsentType) => boolean
  grantConsent: (type: ConsentType, purpose?: string) => Promise<boolean>
  withdrawConsent: (type: ConsentType, reason?: string) => Promise<boolean>
  updatePreferences: (preferences: Record<ConsentType, ConsentStatus>) => Promise<boolean>
  refreshConsent: () => Promise<void>
  isConsentRequired: (operation: string) => ConsentType[]
  canPerformOperation: (operation: string) => boolean
}

/**
 * Consent management hook
 */
export function useConsent(): ConsentContext {
  const [preferences, setPreferences] = useState<ConsentPreferences | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Load consent preferences from server
  const loadConsentPreferences = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      // Try localStorage first for immediate access
      const stored = localStorage.getItem('consent-preferences')
      if (stored) {
        try {
          const parsed = JSON.parse(stored)
          setPreferences(parsed)
        } catch (e) {
          logger.warn('Consent Hook', 'Invalid stored consent preferences', e)
        }
      }

      // Fetch from server for authoritative data
      const response = await fetch('/api/compliance/consent/status')

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.success && data.preferences) {
        setPreferences(data.preferences)
        localStorage.setItem('consent-preferences', JSON.stringify(data.preferences))
      } else if (!data.hasConsent) {
        // No consent given yet
        setPreferences(null)
      }
    } catch (error) {
      logger.error('Consent Hook', 'Failed to load consent preferences', error)
      setError('Failed to load consent preferences')
    } finally {
      setLoading(false)
    }
  }, [])

  // Load preferences on mount
  useEffect(() => {
    loadConsentPreferences()
  }, [loadConsentPreferences])

  // Check if specific consent is granted
  const hasConsent = useCallback(
    (type: ConsentType): boolean => {
      if (!preferences) return false

      const consent = preferences[type]
      return consent?.status === ConsentStatus.GRANTED
    },
    [preferences]
  )

  // Grant consent for specific type
  const grantConsent = useCallback(
    async (type: ConsentType, purpose?: string): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/consent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            consentType: type,
            status: ConsentStatus.GRANTED,
            purpose: purpose || `User granted consent for ${type}`,
            timestamp: new Date().toISOString(),
          }),
        })

        if (response.ok) {
          await loadConsentPreferences() // Refresh from server
          return true
        } else {
          throw new Error('Failed to grant consent')
        }
      } catch (error) {
        logger.error('Consent Hook', 'Failed to grant consent', error)
        setError('Failed to grant consent')
        return false
      }
    },
    [loadConsentPreferences]
  )

  // Withdraw consent for specific type
  const withdrawConsent = useCallback(
    async (type: ConsentType, reason?: string): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/consent/withdraw', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            consentType: type,
            reason: reason || `User withdrew consent for ${type}`,
            timestamp: new Date().toISOString(),
          }),
        })

        if (response.ok) {
          await loadConsentPreferences() // Refresh from server
          return true
        } else {
          throw new Error('Failed to withdraw consent')
        }
      } catch (error) {
        logger.error('Consent Hook', 'Failed to withdraw consent', error)
        setError('Failed to withdraw consent')
        return false
      }
    },
    [loadConsentPreferences]
  )

  // Update multiple consent preferences
  const updatePreferences = useCallback(
    async (newPreferences: Record<ConsentType, ConsentStatus>): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/consent/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            preferences: newPreferences,
            timestamp: new Date().toISOString(),
          }),
        })

        if (response.ok) {
          await loadConsentPreferences() // Refresh from server
          return true
        } else {
          throw new Error('Failed to update preferences')
        }
      } catch (error) {
        logger.error('Consent Hook', 'Failed to update preferences', error)
        setError('Failed to update preferences')
        return false
      }
    },
    [loadConsentPreferences]
  )

  // Refresh consent from server
  const refreshConsent = useCallback(async (): Promise<void> => {
    await loadConsentPreferences()
  }, [loadConsentPreferences])

  // Get required consents for operation
  const isConsentRequired = useCallback((operation: string): ConsentType[] => {
    const operationConsents: Record<string, ConsentType[]> = {
      scraping: [ConsentType.DATA_COLLECTION, ConsentType.SCRAPING, ConsentType.STORAGE],
      export: [ConsentType.DATA_PROCESSING, ConsentType.DATA_SHARING],
      storage: [ConsentType.STORAGE, ConsentType.DATA_PROCESSING],
      sharing: [ConsentType.DATA_SHARING, ConsentType.THIRD_PARTY],
      analytics: [ConsentType.ANALYTICS, ConsentType.DATA_PROCESSING],
      marketing: [ConsentType.MARKETING, ConsentType.DATA_SHARING],
      enrichment: [ConsentType.ENRICHMENT, ConsentType.THIRD_PARTY],
    }

    return operationConsents[operation] || []
  }, [])

  // Check if user can perform operation
  const canPerformOperation = useCallback(
    (operation: string): boolean => {
      const requiredConsents = isConsentRequired(operation)

      if (requiredConsents.length === 0) {
        return true // No consent required
      }

      return requiredConsents.every(consentType => hasConsent(consentType))
    },
    [isConsentRequired, hasConsent]
  )

  return {
    preferences,
    loading,
    error,
    hasConsent,
    grantConsent,
    withdrawConsent,
    updatePreferences,
    refreshConsent,
    isConsentRequired,
    canPerformOperation,
  }
}

/**
 * Hook for checking specific consent
 */
export function useConsentCheck(type: ConsentType) {
  const { hasConsent, loading } = useConsent()

  return {
    hasConsent: hasConsent(type),
    loading,
  }
}

/**
 * Hook for operation-based consent checking
 */
export function useOperationConsent(operation: string) {
  const { canPerformOperation, isConsentRequired, loading } = useConsent()

  return {
    canPerform: canPerformOperation(operation),
    requiredConsents: isConsentRequired(operation),
    loading,
  }
}

/**
 * Consent enforcement decorator for functions
 */
export function withConsentCheck<T extends (...args: any[]) => any>(
  operation: string,
  fn: T
): (...args: Parameters<T>) => Promise<ReturnType<T> | null> {
  return async (...args: Parameters<T>): Promise<ReturnType<T> | null> => {
    // This would need to be used in a component context
    // For now, we'll check localStorage
    try {
      const stored = localStorage.getItem('consent-preferences')
      if (!stored) {
        logger.warn('Consent Check', `No consent found for operation: ${operation}`)
        return null
      }

      const preferences = JSON.parse(stored)
      const operationConsents: Record<string, ConsentType[]> = {
        scraping: [ConsentType.DATA_COLLECTION, ConsentType.SCRAPING, ConsentType.STORAGE],
        export: [ConsentType.DATA_PROCESSING, ConsentType.DATA_SHARING],
        storage: [ConsentType.STORAGE, ConsentType.DATA_PROCESSING],
        sharing: [ConsentType.DATA_SHARING, ConsentType.THIRD_PARTY],
      }

      const requiredConsents = operationConsents[operation] || []
      const hasAllConsents = requiredConsents.every(
        type => preferences[type]?.status === ConsentStatus.GRANTED
      )

      if (!hasAllConsents) {
        logger.warn('Consent Check', `Insufficient consent for operation: ${operation}`)
        return null
      }

      return await fn(...args)
    } catch (error) {
      logger.error('Consent Check', 'Error checking consent', error)
      return null
    }
  }
}

/**
 * Utility functions for consent management
 */
export const ConsentUtils = {
  /**
   * Check if GDPR applies (simplified check)
   */
  isGDPRApplicable: (): boolean => {
    // In production, this would check user's location
    return true // Default to applying GDPR for safety
  },

  /**
   * Check if CCPA applies (simplified check)
   */
  isCCPAApplicable: (): boolean => {
    // In production, this would check user's location
    return true // Default to applying CCPA for safety
  },

  /**
   * Get consent banner text based on jurisdiction
   */
  getConsentBannerText: (): string => {
    const gdpr = ConsentUtils.isGDPRApplicable()
    const ccpa = ConsentUtils.isCCPAApplicable()

    if (gdpr && ccpa) {
      return 'We use cookies and process data in accordance with GDPR and CCPA regulations.'
    } else if (gdpr) {
      return 'We use cookies and process data in accordance with GDPR regulations.'
    } else if (ccpa) {
      return 'We use cookies and process data in accordance with CCPA regulations.'
    } else {
      return 'We use cookies and process data to provide our services.'
    }
  },

  /**
   * Get required consent notice
   */
  getRequiredNotice: (operation: string): string => {
    const operationNames: Record<string, string> = {
      scraping: 'data scraping',
      export: 'data export',
      storage: 'data storage',
      sharing: 'data sharing',
      analytics: 'analytics',
      marketing: 'marketing communications',
    }

    const operationName = operationNames[operation] || operation
    return `This action requires your consent for ${operationName}. Please review and accept the necessary permissions.`
  },
}
