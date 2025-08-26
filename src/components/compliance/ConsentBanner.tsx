/**
 * GDPR Consent Banner Component
 * Provides granular consent management with opt-in toggles for scraping, storage, and enrichment
 */

'use client'

import React, { useState, useEffect } from 'react'
import { X, Shield, Database, Search, BarChart3, Mail, Cookie } from 'lucide-react'
import { logger } from '@/utils/logger'

// Consent types
export enum ConsentType {
  NECESSARY = 'necessary',
  SCRAPING = 'scraping',
  STORAGE = 'storage',
  ENRICHMENT = 'enrichment',
  ANALYTICS = 'analytics',
  MARKETING = 'marketing'
}

// Consent preferences interface
export interface ConsentPreferences {
  necessary: boolean
  scraping: boolean
  storage: boolean
  enrichment: boolean
  analytics: boolean
  marketing: boolean
}

// Consent banner props
interface ConsentBannerProps {
  onConsentChange?: (preferences: ConsentPreferences) => void
  showDetailedView?: boolean
  position?: 'bottom' | 'top'
  theme?: 'light' | 'dark'
}

// Default consent preferences
const defaultPreferences: ConsentPreferences = {
  necessary: true, // Always required
  scraping: false,
  storage: false,
  enrichment: false,
  analytics: false,
  marketing: false
}

// Consent descriptions
const consentDescriptions = {
  [ConsentType.NECESSARY]: {
    title: 'Necessary Cookies',
    description: 'Essential for the website to function properly. These cannot be disabled.',
    icon: Shield,
    required: true
  },
  [ConsentType.SCRAPING]: {
    title: 'Data Scraping',
    description: 'Allow us to scrape business data from public sources for your searches.',
    icon: Search,
    required: false
  },
  [ConsentType.STORAGE]: {
    title: 'Data Storage',
    description: 'Store your scraped data and search history for future access.',
    icon: Database,
    required: false
  },
  [ConsentType.ENRICHMENT]: {
    title: 'Data Enrichment',
    description: 'Enhance scraped data with additional information from third-party sources.',
    icon: BarChart3,
    required: false
  },
  [ConsentType.ANALYTICS]: {
    title: 'Analytics',
    description: 'Help us improve our service by analyzing usage patterns.',
    icon: Cookie,
    required: false
  },
  [ConsentType.MARKETING]: {
    title: 'Marketing',
    description: 'Receive updates about new features and business insights.',
    icon: Mail,
    required: false
  }
}

export default function ConsentBanner({
  onConsentChange,
  showDetailedView = false,
  position = 'bottom',
  theme = 'light'
}: ConsentBannerProps) {
  const [isVisible, setIsVisible] = useState(false)
  const [showDetails, setShowDetails] = useState(showDetailedView)
  const [preferences, setPreferences] = useState<ConsentPreferences>(defaultPreferences)
  const [isLoading, setIsLoading] = useState(false)

  // Check if consent has been given
  useEffect(() => {
    const checkConsentStatus = async () => {
      try {
        const response = await fetch('/api/compliance/consent/status')
        const data = await response.json()
        
        if (!data.hasConsent) {
          setIsVisible(true)
        } else {
          setPreferences(data.preferences || defaultPreferences)
        }
      } catch (error) {
        logger.error('Consent Banner', 'Failed to check consent status', error)
        setIsVisible(true) // Show banner if we can't determine status
      }
    }

    checkConsentStatus()
  }, [])

  // Handle preference change
  const handlePreferenceChange = (type: ConsentType, value: boolean) => {
    if (type === ConsentType.NECESSARY) return // Cannot change necessary cookies

    const newPreferences = {
      ...preferences,
      [type]: value
    }
    setPreferences(newPreferences)
  }

  // Accept all cookies
  const handleAcceptAll = async () => {
    const allAccepted: ConsentPreferences = {
      necessary: true,
      scraping: true,
      storage: true,
      enrichment: true,
      analytics: true,
      marketing: true
    }
    
    await saveConsent(allAccepted)
  }

  // Accept only necessary cookies
  const handleAcceptNecessary = async () => {
    await saveConsent(defaultPreferences)
  }

  // Save custom preferences
  const handleSavePreferences = async () => {
    await saveConsent(preferences)
  }

  // Save consent preferences
  const saveConsent = async (consentPreferences: ConsentPreferences) => {
    setIsLoading(true)
    
    try {
      const response = await fetch('/api/compliance/consent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          preferences: consentPreferences,
          timestamp: new Date().toISOString(),
          method: 'banner'
        })
      })

      if (response.ok) {
        setIsVisible(false)
        onConsentChange?.(consentPreferences)
        
        // Store in localStorage for immediate use
        localStorage.setItem('consent-preferences', JSON.stringify(consentPreferences))
        
        logger.info('Consent Banner', 'Consent preferences saved', consentPreferences)
      } else {
        throw new Error('Failed to save consent')
      }
    } catch (error) {
      logger.error('Consent Banner', 'Failed to save consent', error)
      alert('Failed to save consent preferences. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  if (!isVisible) return null

  const themeClasses = theme === 'dark' 
    ? 'bg-gray-900 text-white border-gray-700' 
    : 'bg-white text-gray-900 border-gray-200'

  const positionClasses = position === 'top' 
    ? 'top-0' 
    : 'bottom-0'

  return (
    <div className={`fixed ${positionClasses} left-0 right-0 z-50 border-t ${themeClasses} shadow-lg`}>
      <div className="max-w-7xl mx-auto p-4">
        {!showDetails ? (
          // Simple banner view
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <Cookie className="h-5 w-5 text-blue-600" />
                <h3 className="font-semibold">Cookie & Data Processing Consent</h3>
              </div>
              <p className="text-sm opacity-90">
                We use cookies and process data to provide our business scraping services. 
                You can customize your preferences or accept all to continue.
              </p>
            </div>
            
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setShowDetails(true)}
                className="px-4 py-2 text-sm border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
                disabled={isLoading}
              >
                Customize
              </button>
              <button
                onClick={handleAcceptNecessary}
                className="px-4 py-2 text-sm border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
                disabled={isLoading}
              >
                Necessary Only
              </button>
              <button
                onClick={handleAcceptAll}
                className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                disabled={isLoading}
              >
                {isLoading ? 'Saving...' : 'Accept All'}
              </button>
            </div>
          </div>
        ) : (
          // Detailed preferences view
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-blue-600" />
                <h3 className="font-semibold">Privacy Preferences</h3>
              </div>
              <button
                onClick={() => setShowDetails(false)}
                className="p-1 hover:bg-gray-100 rounded-md transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <p className="text-sm opacity-90">
              Choose which types of data processing you consent to. You can change these preferences at any time.
            </p>

            <div className="grid gap-4 sm:grid-cols-2">
              {Object.entries(consentDescriptions).map(([type, config]) => {
                const Icon = config.icon
                const isEnabled = preferences[type as keyof ConsentPreferences]
                
                return (
                  <div
                    key={type}
                    className={`p-4 border rounded-lg ${
                      config.required 
                        ? 'border-green-200 bg-green-50' 
                        : 'border-gray-200 hover:border-gray-300'
                    } transition-colors`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3 flex-1">
                        <Icon className={`h-5 w-5 mt-0.5 ${
                          config.required ? 'text-green-600' : 'text-gray-600'
                        }`} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h4 className="font-medium text-sm">{config.title}</h4>
                            {config.required && (
                              <span className="text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded-full">
                                Required
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-gray-600 mt-1">{config.description}</p>
                        </div>
                      </div>
                      
                      <div className="ml-3">
                        <label className="relative inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={isEnabled}
                            onChange={(e) => handlePreferenceChange(type as ConsentType, e.target.checked)}
                            disabled={config.required || isLoading}
                            className="sr-only peer"
                          />
                          <div className={`w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all ${
                            isEnabled ? 'peer-checked:bg-blue-600' : ''
                          } ${config.required ? 'opacity-50' : ''}`}></div>
                        </label>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>

            <div className="flex flex-col sm:flex-row gap-2 pt-4 border-t">
              <button
                onClick={handleAcceptNecessary}
                className="px-4 py-2 text-sm border border-gray-300 rounded-md hover:bg-gray-50 transition-colors"
                disabled={isLoading}
              >
                Necessary Only
              </button>
              <button
                onClick={handleSavePreferences}
                className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors flex-1"
                disabled={isLoading}
              >
                {isLoading ? 'Saving Preferences...' : 'Save Preferences'}
              </button>
              <button
                onClick={handleAcceptAll}
                className="px-4 py-2 text-sm bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
                disabled={isLoading}
              >
                Accept All
              </button>
            </div>

            <div className="text-xs text-gray-500 pt-2 border-t">
              <p>
                By continuing to use our service, you agree to our{' '}
                <a href="/privacy-policy" className="text-blue-600 hover:underline">Privacy Policy</a> and{' '}
                <a href="/cookie-policy" className="text-blue-600 hover:underline">Cookie Policy</a>.
                You can withdraw your consent at any time in your{' '}
                <a href="/privacy-settings" className="text-blue-600 hover:underline">Privacy Settings</a>.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * Hook to get current consent preferences
 */
export function useConsentPreferences() {
  const [preferences, setPreferences] = useState<ConsentPreferences | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadPreferences = async () => {
      try {
        // Try localStorage first for immediate access
        const stored = localStorage.getItem('consent-preferences')
        if (stored) {
          setPreferences(JSON.parse(stored))
        }

        // Then fetch from server for authoritative data
        const response = await fetch('/api/compliance/consent/status')
        const data = await response.json()
        
        if (data.hasConsent && data.preferences) {
          setPreferences(data.preferences)
          localStorage.setItem('consent-preferences', JSON.stringify(data.preferences))
        }
      } catch (error) {
        logger.error('Consent Hook', 'Failed to load consent preferences', error)
      } finally {
        setLoading(false)
      }
    }

    loadPreferences()
  }, [])

  return { preferences, loading }
}

/**
 * Check if a specific consent type is granted
 */
export function hasConsent(type: ConsentType, preferences?: ConsentPreferences | null): boolean {
  if (!preferences) return false
  return preferences[type] === true
}
