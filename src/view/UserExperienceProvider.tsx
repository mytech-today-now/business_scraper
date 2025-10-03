/**
 * User Experience Provider
 * Comprehensive UX optimization with progressive loading, accessibility, and theme management
 */

'use client'

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { logger } from '@/utils/logger'

export interface UserPreferences {
  theme: 'light' | 'dark' | 'system'
  language: string
  timezone: string
  dateFormat: string
  numberFormat: string
  accessibility: {
    highContrast: boolean
    largeText: boolean
    reducedMotion: boolean
    screenReader: boolean
  }
  notifications: {
    enabled: boolean
    sound: boolean
    desktop: boolean
    email: boolean
  }
  interface: {
    compactMode: boolean
    showTooltips: boolean
    keyboardNavigation: boolean
    autoSave: boolean
  }
  performance: {
    autoDetection: boolean
    forceDisableVirtualization: boolean
    forceEnablePagination: boolean
    pageSize: number
    enableMonitoring: boolean
    customThresholds: {
      advisory: number
      pagination: number
      virtualization: number
      memoryThreshold: number
    }
  }
}

export interface UXState {
  preferences: UserPreferences
  isLoading: boolean
  loadingStates: Record<string, boolean>
  errors: Record<string, string>
  undoStack: any[]
  redoStack: any[]
  onboardingStep: number
  tourActive: boolean
  keyboardShortcuts: Record<string, () => void>
}

export interface UXActions {
  updatePreferences: (updates: Partial<UserPreferences>) => void
  setLoading: (key: string, loading: boolean) => void
  setError: (key: string, error: string | null) => void
  addToUndoStack: (action: any) => void
  undo: () => void
  redo: () => void
  startTour: () => void
  nextOnboardingStep: () => void
  registerShortcut: (key: string, action: () => void) => void
  showToast: (message: string, type?: 'success' | 'error' | 'warning' | 'info') => void
}

const defaultPreferences: UserPreferences = {
  theme: 'system',
  language: 'en',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  dateFormat: 'MM/dd/yyyy',
  numberFormat: 'en-US',
  accessibility: {
    highContrast: false,
    largeText: false,
    reducedMotion: false,
    screenReader: false,
  },
  notifications: {
    enabled: true,
    sound: true,
    desktop: true,
    email: false,
  },
  interface: {
    compactMode: false,
    showTooltips: true,
    keyboardNavigation: true,
    autoSave: true,
  },
  performance: {
    autoDetection: true,
    forceDisableVirtualization: false,
    forceEnablePagination: false,
    pageSize: 50,
    enableMonitoring: true,
    customThresholds: {
      advisory: 1000,
      pagination: 2500,
      virtualization: 5000,
      memoryThreshold: 500 * 1024 * 1024, // 500MB
    },
  },
}

const UXContext = createContext<(UXState & UXActions) | null>(null)

export function UserExperienceProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<UXState>({
    preferences: defaultPreferences,
    isLoading: false,
    loadingStates: {},
    errors: {},
    undoStack: [],
    redoStack: [],
    onboardingStep: 0,
    tourActive: false,
    keyboardShortcuts: {},
  })

  // Load preferences from localStorage on mount
  useEffect(() => {
    loadPreferences()
    setupKeyboardListeners()
    setupAccessibilityFeatures()
    requestNotificationPermission()
  }, [
    loadPreferences,
    setupKeyboardListeners,
    setupAccessibilityFeatures,
    requestNotificationPermission,
  ])

  // Apply theme changes
  useEffect(() => {
    applyTheme(state.preferences.theme)
  }, [state.preferences.theme])

  // Apply accessibility settings
  useEffect(() => {
    applyAccessibilitySettings(state.preferences.accessibility)
  }, [state.preferences.accessibility])

  const loadPreferences = useCallback(() => {
    // Only access localStorage on client side
    if (typeof window === 'undefined') return

    try {
      const saved = localStorage.getItem('userPreferences')
      if (saved) {
        const preferences = { ...defaultPreferences, ...JSON.parse(saved) }
        setState(prev => ({ ...prev, preferences }))
      }
    } catch (error) {
      logger.error('UXProvider', 'Failed to load preferences', error)
    }
  }, [])

  const savePreferences = (preferences: UserPreferences) => {
    // Only access localStorage on client side
    if (typeof window === 'undefined') return

    try {
      localStorage.setItem('userPreferences', JSON.stringify(preferences))
    } catch (error) {
      logger.error('UXProvider', 'Failed to save preferences', error)
    }
  }

  const updatePreferences = useCallback((updates: Partial<UserPreferences>) => {
    setState(prev => {
      const newPreferences = { ...prev.preferences, ...updates }
      savePreferences(newPreferences)
      return { ...prev, preferences: newPreferences }
    })
  }, [])

  const setLoading = useCallback((key: string, loading: boolean) => {
    setState(prev => ({
      ...prev,
      loadingStates: { ...prev.loadingStates, [key]: loading },
      isLoading: loading || Object.values({ ...prev.loadingStates, [key]: loading }).some(Boolean),
    }))
  }, [])

  const setError = useCallback((key: string, error: string | null) => {
    setState(prev => {
      const newErrors = { ...prev.errors }
      // Validate key to prevent object injection
      if (typeof key === 'string' && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
        if (error) {
          newErrors[key] = error
        } else {
          delete newErrors[key]
        }
      }
      return {
        ...prev,
        errors: newErrors,
      }
    })
  }, [])

  const addToUndoStack = useCallback((action: any) => {
    setState(prev => ({
      ...prev,
      undoStack: [...prev.undoStack, action].slice(-50), // Keep last 50 actions
      redoStack: [], // Clear redo stack when new action is added
    }))
  }, [])

  const undo = useCallback(() => {
    setState(prev => {
      if (prev.undoStack.length === 0) return prev

      const lastAction = prev.undoStack[prev.undoStack.length - 1]
      const newUndoStack = prev.undoStack.slice(0, -1)
      const newRedoStack = [...prev.redoStack, lastAction]

      // Execute undo action
      if (lastAction.undo) {
        lastAction.undo()
      }

      return {
        ...prev,
        undoStack: newUndoStack,
        redoStack: newRedoStack,
      }
    })
  }, [])

  const redo = useCallback(() => {
    setState(prev => {
      if (prev.redoStack.length === 0) return prev

      const lastAction = prev.redoStack[prev.redoStack.length - 1]
      const newRedoStack = prev.redoStack.slice(0, -1)
      const newUndoStack = [...prev.undoStack, lastAction]

      // Execute redo action
      if (lastAction.redo) {
        lastAction.redo()
      }

      return {
        ...prev,
        undoStack: newUndoStack,
        redoStack: newRedoStack,
      }
    })
  }, [])

  const startTour = useCallback(() => {
    setState(prev => ({ ...prev, tourActive: true, onboardingStep: 0 }))
  }, [])

  const nextOnboardingStep = useCallback(() => {
    setState(prev => ({ ...prev, onboardingStep: prev.onboardingStep + 1 }))
  }, [])

  const registerShortcut = useCallback((key: string, action: () => void) => {
    setState(prev => ({
      ...prev,
      keyboardShortcuts: { ...prev.keyboardShortcuts, [key]: action },
    }))
  }, [])

  const showToast = useCallback(
    (message: string, type: 'success' | 'error' | 'warning' | 'info' = 'info') => {
      // This would integrate with a toast notification system
      logger.info('UXProvider', `Toast: ${type} - ${message}`)

      // Create a simple toast notification
      const toast = document.createElement('div')
      toast.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${getToastStyles(type)}`
      toast.textContent = message

      document.body.appendChild(toast)

      // Animate in
      toast.style.transform = 'translateX(100%)'
      toast.style.transition = 'transform 0.3s ease-in-out'
      setTimeout(() => {
        toast.style.transform = 'translateX(0)'
      }, 10)

      // Remove after 5 seconds
      setTimeout(() => {
        toast.style.transform = 'translateX(100%)'
        setTimeout(() => {
          document.body.removeChild(toast)
        }, 300)
      }, 5000)
    },
    []
  )

  const applyTheme = (theme: 'light' | 'dark' | 'system') => {
    const root = document.documentElement

    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
      root.classList.toggle('dark', prefersDark)
    } else {
      root.classList.toggle('dark', theme === 'dark')
    }
  }

  const applyAccessibilitySettings = (accessibility: UserPreferences['accessibility']) => {
    const root = document.documentElement

    root.classList.toggle('high-contrast', accessibility.highContrast)
    root.classList.toggle('large-text', accessibility.largeText)
    root.classList.toggle('reduced-motion', accessibility.reducedMotion)

    // Update CSS custom properties
    root.style.setProperty('--font-size-multiplier', accessibility.largeText ? '1.2' : '1')
    root.style.setProperty('--animation-duration', accessibility.reducedMotion ? '0s' : '0.3s')
  }

  const setupKeyboardListeners = useCallback(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!state.preferences.interface.keyboardNavigation) return

      const key = `${event.ctrlKey ? 'ctrl+' : ''}${event.shiftKey ? 'shift+' : ''}${event.altKey ? 'alt+' : ''}${event.key.toLowerCase()}`

      const shortcut = Object.prototype.hasOwnProperty.call(state.keyboardShortcuts, key)
        ? state.keyboardShortcuts[key as keyof typeof state.keyboardShortcuts]
        : null
      if (shortcut) {
        event.preventDefault()
        shortcut()
      }

      // Built-in shortcuts
      switch (key) {
        case 'ctrl+z':
          event.preventDefault()
          undo()
          break
        case 'ctrl+y':
        case 'ctrl+shift+z':
          event.preventDefault()
          redo()
          break
        case 'ctrl+/':
          event.preventDefault()
          showKeyboardShortcuts()
          break
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [state.preferences.interface.keyboardNavigation])

  const setupAccessibilityFeatures = useCallback(() => {
    // Detect screen reader
    const hasScreenReader =
      window.navigator.userAgent.includes('NVDA') ||
      window.navigator.userAgent.includes('JAWS') ||
      window.speechSynthesis !== undefined

    if (hasScreenReader) {
      updatePreferences({
        accessibility: { ...state.preferences.accessibility, screenReader: true },
      })
    }

    // Detect reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (prefersReducedMotion) {
      updatePreferences({
        accessibility: { ...state.preferences.accessibility, reducedMotion: true },
      })
    }
  }, [state.preferences.accessibility])

  const requestNotificationPermission = useCallback(async () => {
    if ('Notification' in window && state.preferences.notifications.desktop) {
      if (Notification.permission === 'default') {
        await Notification.requestPermission()
      }
    }
  }, [state.preferences.notifications.desktop])

  const showKeyboardShortcuts = () => {
    showToast('Keyboard shortcuts: Ctrl+Z (Undo), Ctrl+Y (Redo), Ctrl+/ (Show shortcuts)', 'info')
  }

  const getToastStyles = (type: string) => {
    switch (type) {
      case 'success':
        return 'bg-green-500 text-white'
      case 'error':
        return 'bg-red-500 text-white'
      case 'warning':
        return 'bg-yellow-500 text-black'
      default:
        return 'bg-blue-500 text-white'
    }
  }

  const contextValue = {
    ...state,
    updatePreferences,
    setLoading,
    setError,
    addToUndoStack,
    undo,
    redo,
    startTour,
    nextOnboardingStep,
    registerShortcut,
    showToast,
  }

  return (
    <UXContext.Provider value={contextValue}>
      {children}
      {state.isLoading && <GlobalLoadingIndicator />}
      {state.tourActive && <OnboardingTour step={state.onboardingStep} />}
    </UXContext.Provider>
  )
}

export function useUserExperience() {
  const context = useContext(UXContext)
  if (!context) {
    throw new Error('useUserExperience must be used within a UserExperienceProvider')
  }
  return context
}

// Loading indicator component
function GlobalLoadingIndicator() {
  return (
    <div className="fixed top-0 left-0 right-0 z-50">
      <div className="h-1 bg-blue-500 animate-pulse" />
    </div>
  )
}

// Onboarding tour component
function OnboardingTour({ step }: { step: number }) {
  const { nextOnboardingStep } = useUserExperience()

  const tourSteps = [
    { title: 'Welcome!', content: "Let's take a quick tour of the application." },
    { title: 'Campaign Management', content: 'Create and manage your scraping campaigns here.' },
    { title: 'Results Dashboard', content: 'View and analyze your scraped data.' },
    { title: 'Monitoring', content: 'Monitor system health and performance.' },
  ]

  const currentStep = tourSteps.at(step)

  if (!currentStep) return null

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center">
      <div className="bg-white rounded-lg p-6 max-w-md">
        <h3 className="text-lg font-semibold mb-2">{currentStep.title}</h3>
        <p className="text-gray-600 mb-4">{currentStep.content}</p>
        <div className="flex justify-between">
          <span className="text-sm text-gray-500">
            Step {step + 1} of {tourSteps.length}
          </span>
          <button
            onClick={nextOnboardingStep}
            className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          >
            {step < tourSteps.length - 1 ? 'Next' : 'Finish'}
          </button>
        </div>
      </div>
    </div>
  )
}
