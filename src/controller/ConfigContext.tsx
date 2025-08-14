'use client'

import React, { createContext, useContext, useReducer, useEffect, ReactNode } from 'react'
import { ScrapingConfig, IndustryCategory } from '@/types/business'
import { DEFAULT_INDUSTRIES } from '@/lib/industry-config'
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

/**
 * Configuration state interface
 */
export interface ConfigState {
  // Scraping configuration
  config: ScrapingConfig

  // Industry categories
  industries: IndustryCategory[]
  selectedIndustries: string[]

  // UI state
  isDarkMode: boolean
  isLoading: boolean

  // Application state
  isInitialized: boolean
  isDemoMode: boolean

  // Edit state tracking
  industriesInEditMode: string[]
}

/**
 * Configuration actions
 */
export type ConfigAction =
  | { type: 'SET_CONFIG'; payload: Partial<ScrapingConfig> }
  | { type: 'SET_INDUSTRIES'; payload: IndustryCategory[] }
  | { type: 'ADD_INDUSTRY'; payload: IndustryCategory }
  | { type: 'UPDATE_INDUSTRY'; payload: IndustryCategory }
  | { type: 'REMOVE_INDUSTRY'; payload: string }
  | { type: 'SET_SELECTED_INDUSTRIES'; payload: string[] }
  | { type: 'TOGGLE_INDUSTRY'; payload: string }
  | { type: 'SELECT_ALL_INDUSTRIES' }
  | { type: 'DESELECT_ALL_INDUSTRIES' }
  | { type: 'SET_DARK_MODE'; payload: boolean }
  | { type: 'SET_DEMO_MODE'; payload: boolean }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_INITIALIZED'; payload: boolean }
  | { type: 'RESET_CONFIG' }
  | { type: 'START_INDUSTRY_EDIT'; payload: string }
  | { type: 'END_INDUSTRY_EDIT'; payload: string }
  | { type: 'CLEAR_ALL_EDITS' }

/**
 * Default configuration state
 */
const defaultState: ConfigState = {
  config: {
    industries: [],
    zipCode: '',
    searchRadius: 25,
    searchDepth: 2,
    pagesPerSite: 5,
  },
  industries: DEFAULT_INDUSTRIES,
  selectedIndustries: [],
  isDarkMode: false,
  isLoading: false,
  isInitialized: false,
  isDemoMode: process.env.NODE_ENV === 'development', // Demo mode only in development, always false in production
  industriesInEditMode: [],
}

/**
 * Configuration reducer
 */
function configReducer(state: ConfigState, action: ConfigAction): ConfigState {
  switch (action.type) {
    case 'SET_CONFIG':
      return {
        ...state,
        config: { ...state.config, ...action.payload },
      }

    case 'SET_INDUSTRIES':
      return {
        ...state,
        industries: action.payload,
      }

    case 'ADD_INDUSTRY':
      return {
        ...state,
        industries: [...state.industries, action.payload],
      }

    case 'UPDATE_INDUSTRY':
      return {
        ...state,
        industries: state.industries.map(industry =>
          industry.id === action.payload.id ? action.payload : industry
        ),
      }

    case 'REMOVE_INDUSTRY':
      return {
        ...state,
        industries: state.industries.filter(industry => industry.id !== action.payload),
        selectedIndustries: state.selectedIndustries.filter(id => id !== action.payload),
      }

    case 'SET_SELECTED_INDUSTRIES':
      return {
        ...state,
        selectedIndustries: action.payload,
        config: {
          ...state.config,
          industries: action.payload,
        },
      }

    case 'TOGGLE_INDUSTRY':
      const isSelected = state.selectedIndustries.includes(action.payload)
      const newSelected = isSelected
        ? state.selectedIndustries.filter(id => id !== action.payload)
        : [...state.selectedIndustries, action.payload]
      
      return {
        ...state,
        selectedIndustries: newSelected,
        config: {
          ...state.config,
          industries: newSelected,
        },
      }

    case 'SELECT_ALL_INDUSTRIES':
      const allIds = state.industries.map(industry => industry.id)
      return {
        ...state,
        selectedIndustries: allIds,
        config: {
          ...state.config,
          industries: allIds,
        },
      }

    case 'DESELECT_ALL_INDUSTRIES':
      return {
        ...state,
        selectedIndustries: [],
        config: {
          ...state.config,
          industries: [],
        },
      }

    case 'SET_DARK_MODE':
      return {
        ...state,
        isDarkMode: action.payload,
      }

    case 'SET_DEMO_MODE':
      return {
        ...state,
        isDemoMode: action.payload,
      }

    case 'SET_LOADING':
      return {
        ...state,
        isLoading: action.payload,
      }

    case 'SET_INITIALIZED':
      return {
        ...state,
        isInitialized: action.payload,
      }

    case 'RESET_CONFIG':
      return {
        ...defaultState,
        isInitialized: state.isInitialized,
      }

    case 'START_INDUSTRY_EDIT':
      return {
        ...state,
        industriesInEditMode: [...state.industriesInEditMode, action.payload],
      }

    case 'END_INDUSTRY_EDIT':
      return {
        ...state,
        industriesInEditMode: state.industriesInEditMode.filter(id => id !== action.payload),
      }

    case 'CLEAR_ALL_EDITS':
      return {
        ...state,
        industriesInEditMode: [],
      }

    default:
      return state
  }
}

/**
 * Configuration context interface
 */
export interface ConfigContextType {
  state: ConfigState
  dispatch: React.Dispatch<ConfigAction>
  
  // Configuration methods
  updateConfig: (config: Partial<ScrapingConfig>) => Promise<void>
  resetConfig: () => Promise<void>
  saveConfig: () => Promise<void>
  loadConfig: () => Promise<void>
  
  // Industry methods
  addCustomIndustry: (industry: Omit<IndustryCategory, 'id' | 'isCustom'>) => Promise<void>
  updateIndustry: (industry: IndustryCategory, showToast?: boolean) => Promise<void>
  removeIndustry: (id: string) => Promise<void>
  setAllIndustries: (industries: IndustryCategory[]) => Promise<void>
  refreshDefaultIndustries: () => Promise<void>
  toggleIndustry: (id: string) => void
  selectAllIndustries: () => void
  deselectAllIndustries: () => void

  // Edit state methods
  startIndustryEdit: (id: string) => void
  endIndustryEdit: (id: string) => void
  clearAllEdits: () => void
  
  // Theme methods
  toggleDarkMode: () => void
  toggleDemoMode: () => void

  // Utility methods
  getSelectedIndustryNames: () => string[]
  isConfigValid: () => boolean
}

/**
 * Configuration context
 */
const ConfigContext = createContext<ConfigContextType | undefined>(undefined)

/**
 * Configuration provider props
 */
interface ConfigProviderProps {
  children: ReactNode
}

/**
 * Check if default industries need to be updated
 * This compares the current default industries with saved ones to detect changes
 */
async function checkIfDefaultIndustriesNeedUpdate(savedIndustries: IndustryCategory[]): Promise<boolean> {
  if (savedIndustries.length === 0) {
    return true // No saved industries, need to initialize
  }

  // Check if we have all default industries with correct data
  for (const defaultIndustry of DEFAULT_INDUSTRIES) {
    const savedIndustry = savedIndustries.find(saved => saved.id === defaultIndustry.id)

    if (!savedIndustry) {
      logger.info('ConfigProvider', `Missing default industry: ${defaultIndustry.id}`)
      return true // Missing default industry
    }

    // Check if keywords have changed
    if (JSON.stringify(savedIndustry.keywords.sort()) !== JSON.stringify(defaultIndustry.keywords.sort())) {
      logger.info('ConfigProvider', `Keywords changed for industry: ${defaultIndustry.id}`)
      return true
    }

    // Check if domain blacklist has changed
    const savedBlacklist = savedIndustry.domainBlacklist || []
    const defaultBlacklist = defaultIndustry.domainBlacklist || []
    if (JSON.stringify(savedBlacklist.sort()) !== JSON.stringify(defaultBlacklist.sort())) {
      logger.info('ConfigProvider', `Domain blacklist changed for industry: ${defaultIndustry.id}`)
      return true
    }

    // Check if name has changed
    if (savedIndustry.name !== defaultIndustry.name) {
      logger.info('ConfigProvider', `Name changed for industry: ${defaultIndustry.id}`)
      return true
    }
  }

  return false // No updates needed
}

/**
 * Update default industries while preserving custom industries
 */
async function updateDefaultIndustries(savedIndustries: IndustryCategory[]): Promise<IndustryCategory[]> {
  // Separate custom industries from default ones
  const customIndustries = savedIndustries.filter(industry => industry.isCustom)

  // Combine updated default industries with existing custom industries
  const updatedIndustries = [...DEFAULT_INDUSTRIES, ...customIndustries]

  // Clear all industries and save the updated set
  await storage.clearIndustries()
  for (const industry of updatedIndustries) {
    await storage.saveIndustry(industry)
  }

  logger.info('ConfigProvider', `Updated industries: ${DEFAULT_INDUSTRIES.length} default + ${customIndustries.length} custom`)
  return updatedIndustries
}

/**
 * Configuration provider component
 * Manages global application configuration and state
 */
export function ConfigProvider({ children }: ConfigProviderProps) {
  const [state, dispatch] = useReducer(configReducer, defaultState)

  /**
   * Initialize the configuration on mount
   */
  useEffect(() => {
    const initialize = async () => {
      try {
        dispatch({ type: 'SET_LOADING', payload: true })

        // Initialize storage
        await storage.initialize()

        // Load saved configuration
        await loadConfig()

        // Load industries (default + custom)
        const savedIndustries = await storage.getAllIndustries()

        // Check if we need to update default industries
        const needsUpdate = await checkIfDefaultIndustriesNeedUpdate(savedIndustries)

        if (savedIndustries.length > 0 && !needsUpdate) {
          dispatch({ type: 'SET_INDUSTRIES', payload: savedIndustries })
        } else {
          // Update/save default industries to storage
          const updatedIndustries = await updateDefaultIndustries(savedIndustries)
          dispatch({ type: 'SET_INDUSTRIES', payload: updatedIndustries })

          if (needsUpdate) {
            toast.success('Default industries updated with latest data')
            logger.info('ConfigProvider', 'Default industries updated successfully')
          }
        }
        
        // Load theme preference
        const savedTheme = localStorage.getItem('darkMode')
        if (savedTheme) {
          const isDark = JSON.parse(savedTheme)
          dispatch({ type: 'SET_DARK_MODE', payload: isDark })
          document.documentElement.classList.toggle('dark', isDark)
        }

        // Load demo mode preference (only in development)
        if (process.env.NODE_ENV === 'development') {
          const savedDemoMode = localStorage.getItem('demoMode')
          if (savedDemoMode) {
            const isDemoMode = JSON.parse(savedDemoMode)
            dispatch({ type: 'SET_DEMO_MODE', payload: isDemoMode })
          }
        } else {
          // Force disable demo mode in production
          dispatch({ type: 'SET_DEMO_MODE', payload: false })
          localStorage.removeItem('demoMode') // Clear any persisted demo mode
        }

        dispatch({ type: 'SET_INITIALIZED', payload: true })
        logger.info('ConfigProvider', 'Configuration initialized successfully')
      } catch (error) {
        logger.error('ConfigProvider', 'Failed to initialize configuration', error)
        toast.error('Failed to initialize application configuration')
      } finally {
        dispatch({ type: 'SET_LOADING', payload: false })
      }
    }

    initialize()
  }, [loadConfig])

  /**
   * Update configuration
   */
  const updateConfig = async (config: Partial<ScrapingConfig>) => {
    try {
      dispatch({ type: 'SET_CONFIG', payload: config })
      await saveConfig()
      logger.info('ConfigProvider', 'Configuration updated', config)
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to update configuration', error)
      toast.error('Failed to update configuration')
    }
  }

  /**
   * Reset configuration to defaults
   */
  const resetConfig = async () => {
    try {
      dispatch({ type: 'RESET_CONFIG' })
      await saveConfig()
      toast.success('Configuration reset to defaults')
      logger.info('ConfigProvider', 'Configuration reset to defaults')
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to reset configuration', error)
      toast.error('Failed to reset configuration')
    }
  }

  /**
   * Save current configuration to storage
   */
  const saveConfig = async () => {
    try {
      const configToSave = {
        id: 'default',
        ...state.config,
      }
      await storage.saveConfig(configToSave)
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to save configuration', error)
      throw error
    }
  }

  /**
   * Load configuration from storage
   */
  const loadConfig = useCallback(async () => {
    try {
      const savedConfig = await storage.getConfig('default')
      if (savedConfig) {
        const { id: _id, ...config } = savedConfig
        dispatch({ type: 'SET_CONFIG', payload: config })
        dispatch({ type: 'SET_SELECTED_INDUSTRIES', payload: config.industries })
      }
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to load configuration', error)
      throw error
    }
  }, [])

  /**
   * Add custom industry
   */
  const addCustomIndustry = async (industryData: Omit<IndustryCategory, 'id' | 'isCustom'>) => {
    try {
      const industry: IndustryCategory = {
        ...industryData,
        id: `custom-${Date.now()}`,
        isCustom: true,
      }

      await storage.saveIndustry(industry)
      dispatch({ type: 'ADD_INDUSTRY', payload: industry })
      toast.success(`Added custom industry: ${industry.name}`)
      logger.info('ConfigProvider', 'Custom industry added', industry)
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to add custom industry', error)
      toast.error('Failed to add custom industry')
    }
  }

  /**
   * Update existing industry
   */
  const updateIndustry = async (industry: IndustryCategory, showToast: boolean = true) => {
    try {
      await storage.saveIndustry(industry)
      dispatch({ type: 'UPDATE_INDUSTRY', payload: industry })
      if (showToast) {
        toast.success(`Updated industry: ${industry.name}`)
      }
      logger.info('ConfigProvider', 'Industry updated', industry)
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to update industry', error)
      if (showToast) {
        toast.error('Failed to update industry')
      }
    }
  }

  /**
   * Set all industries (overwrites current industries)
   */
  const setAllIndustries = async (industries: IndustryCategory[]) => {
    try {
      // Clear existing industries from storage
      await storage.clearIndustries()

      // Save all new industries
      for (const industry of industries) {
        await storage.saveIndustry(industry)
      }

      // Update state
      dispatch({ type: 'SET_INDUSTRIES', payload: industries })

      // Update selected industries to only include valid IDs
      const validIds = industries.map(i => i.id)
      const validSelectedIds = state.selectedIndustries.filter(id => validIds.includes(id))
      dispatch({ type: 'SET_SELECTED_INDUSTRIES', payload: validSelectedIds })

      logger.info('ConfigProvider', 'All industries replaced', { count: industries.length })
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to set all industries', error)
      throw error
    }
  }

  /**
   * Refresh default industries with latest data
   * This forces an update of all default industries while preserving custom ones
   */
  const refreshDefaultIndustries = async () => {
    try {
      const currentIndustries = await storage.getAllIndustries()
      const updatedIndustries = await updateDefaultIndustries(currentIndustries)
      dispatch({ type: 'SET_INDUSTRIES', payload: updatedIndustries })

      toast.success('Default industries refreshed with latest data')
      logger.info('ConfigProvider', 'Default industries manually refreshed')
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to refresh default industries', error)
      toast.error('Failed to refresh default industries')
    }
  }

  /**
   * Remove industry
   */
  const removeIndustry = async (id: string) => {
    try {
      const industry = state.industries.find(i => i.id === id)
      if (!industry) return
      
      if (!industry.isCustom) {
        toast.error('Cannot remove default industries')
        return
      }
      
      await storage.deleteIndustry(id)
      dispatch({ type: 'REMOVE_INDUSTRY', payload: id })
      toast.success(`Removed industry: ${industry.name}`)
      logger.info('ConfigProvider', 'Industry removed', { id, name: industry.name })
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to remove industry', error)
      toast.error('Failed to remove industry')
    }
  }

  /**
   * Toggle industry selection
   */
  const toggleIndustry = (id: string) => {
    dispatch({ type: 'TOGGLE_INDUSTRY', payload: id })
  }

  /**
   * Select all industries
   */
  const selectAllIndustries = () => {
    dispatch({ type: 'SELECT_ALL_INDUSTRIES' })
  }

  /**
   * Deselect all industries
   */
  const deselectAllIndustries = () => {
    dispatch({ type: 'DESELECT_ALL_INDUSTRIES' })
  }

  /**
   * Toggle dark mode
   */
  const toggleDarkMode = () => {
    const newDarkMode = !state.isDarkMode
    dispatch({ type: 'SET_DARK_MODE', payload: newDarkMode })
    document.documentElement.classList.toggle('dark', newDarkMode)
    localStorage.setItem('darkMode', JSON.stringify(newDarkMode))
    logger.info('ConfigProvider', 'Dark mode toggled', { darkMode: newDarkMode })
  }

  /**
   * Toggle demo mode
   */
  const toggleDemoMode = () => {
    const newDemoMode = !state.isDemoMode
    dispatch({ type: 'SET_DEMO_MODE', payload: newDemoMode })
    localStorage.setItem('demoMode', JSON.stringify(newDemoMode))
    logger.info('ConfigProvider', 'Demo mode toggled', { demoMode: newDemoMode })
    toast.success(`${newDemoMode ? 'Demo mode enabled' : 'Real scraping mode enabled'}`)
  }

  /**
   * Get selected industry names
   */
  const getSelectedIndustryNames = (): string[] => {
    return state.selectedIndustries
      .map(id => state.industries.find(industry => industry.id === id))
      .filter(Boolean)
      .map(industry => industry!.name)
  }

  /**
   * Check if configuration is valid
   */
  const isConfigValid = (): boolean => {
    return (
      state.selectedIndustries.length > 0 &&
      state.config.zipCode.trim().length > 0 &&
      state.config.searchRadius > 0 &&
      state.config.searchDepth > 0 &&
      state.config.pagesPerSite > 0
    )
  }

  /**
   * Start editing an industry
   */
  const startIndustryEdit = (id: string) => {
    dispatch({ type: 'START_INDUSTRY_EDIT', payload: id })
  }

  /**
   * End editing an industry
   */
  const endIndustryEdit = (id: string) => {
    dispatch({ type: 'END_INDUSTRY_EDIT', payload: id })
  }

  /**
   * Clear all industry edits
   */
  const clearAllEdits = () => {
    dispatch({ type: 'CLEAR_ALL_EDITS' })
  }

  const contextValue: ConfigContextType = {
    state,
    dispatch,
    updateConfig,
    resetConfig,
    saveConfig,
    loadConfig,
    addCustomIndustry,
    updateIndustry,
    removeIndustry,
    setAllIndustries,
    refreshDefaultIndustries,
    toggleIndustry,
    selectAllIndustries,
    deselectAllIndustries,
    startIndustryEdit,
    endIndustryEdit,
    clearAllEdits,
    toggleDarkMode,
    toggleDemoMode,
    getSelectedIndustryNames,
    isConfigValid,
  }

  return (
    <ConfigContext.Provider value={contextValue}>
      {children}
    </ConfigContext.Provider>
  )
}

/**
 * Hook to use configuration context
 * @returns Configuration context
 */
export function useConfig(): ConfigContextType {
  const context = useContext(ConfigContext)
  if (context === undefined) {
    throw new Error('useConfig must be used within a ConfigProvider')
  }
  return context
}
