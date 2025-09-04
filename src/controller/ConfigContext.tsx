'use client'

import React, {
  createContext,
  useContext,
  useReducer,
  useEffect,
  useCallback,
  ReactNode,
} from 'react'
import { ScrapingConfig, IndustryCategory, IndustrySubCategory } from '@/types/business'
import { DEFAULT_INDUSTRIES, DEFAULT_SUB_CATEGORIES } from '@/lib/industry-config'
import { storage } from '@/model/storage'
import { logger } from '@/utils/logger'
import { AddressInputHandler } from '@/utils/addressInputHandler'
import { DataResetService, DataResetResult } from '@/utils/dataReset'
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

  // Sub-categories
  subCategories: IndustrySubCategory[]

  // UI state
  isDarkMode: boolean
  isLoading: boolean

  // Application state
  isInitialized: boolean

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
  | { type: 'SELECT_SUB_CATEGORY_INDUSTRIES'; payload: string }
  | { type: 'DESELECT_SUB_CATEGORY_INDUSTRIES'; payload: string }
  | { type: 'SET_SUB_CATEGORIES'; payload: IndustrySubCategory[] }
  | { type: 'ADD_SUB_CATEGORY'; payload: IndustrySubCategory }
  | { type: 'UPDATE_SUB_CATEGORY'; payload: IndustrySubCategory }
  | { type: 'REMOVE_SUB_CATEGORY'; payload: string }
  | { type: 'SET_DARK_MODE'; payload: boolean }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_INITIALIZED'; payload: boolean }
  | { type: 'RESET_CONFIG' }
  | { type: 'RESET_STATE' }
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
    // Search configuration defaults
    duckduckgoSerpPages: 2,
    maxSearchResults: 1000,
    bbbAccreditedOnly: false,
    zipRadius: 10,
  },
  industries: DEFAULT_INDUSTRIES,
  selectedIndustries: [],
  subCategories: DEFAULT_SUB_CATEGORIES,
  isDarkMode: false,
  isLoading: false,
  isInitialized: false,
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

    case 'SELECT_SUB_CATEGORY_INDUSTRIES': {
      const subCategoryId = action.payload
      const industriesInSubCategory = state.industries
        .filter(industry => industry.subCategoryId === subCategoryId)
        .map(industry => industry.id)

      const newSelectedIndustries = [
        ...state.selectedIndustries.filter(id => !industriesInSubCategory.includes(id)),
        ...industriesInSubCategory
      ]

      return {
        ...state,
        selectedIndustries: newSelectedIndustries,
        config: {
          ...state.config,
          industries: newSelectedIndustries,
        },
      }
    }

    case 'DESELECT_SUB_CATEGORY_INDUSTRIES': {
      const subCategoryId = action.payload
      const industriesInSubCategory = state.industries
        .filter(industry => industry.subCategoryId === subCategoryId)
        .map(industry => industry.id)

      const newSelectedIndustries = state.selectedIndustries.filter(
        id => !industriesInSubCategory.includes(id)
      )

      return {
        ...state,
        selectedIndustries: newSelectedIndustries,
        config: {
          ...state.config,
          industries: newSelectedIndustries,
        },
      }
    }

    case 'SET_SUB_CATEGORIES':
      return {
        ...state,
        subCategories: action.payload,
      }

    case 'ADD_SUB_CATEGORY':
      return {
        ...state,
        subCategories: [...state.subCategories, action.payload],
      }

    case 'UPDATE_SUB_CATEGORY':
      return {
        ...state,
        subCategories: state.subCategories.map(subCategory =>
          subCategory.id === action.payload.id ? action.payload : subCategory
        ),
      }

    case 'REMOVE_SUB_CATEGORY':
      return {
        ...state,
        subCategories: state.subCategories.filter(subCategory => subCategory.id !== action.payload),
        // Also remove sub-category reference from industries
        industries: state.industries.map(industry =>
          industry.subCategoryId === action.payload
            ? { ...industry, subCategoryId: undefined }
            : industry
        ),
      }

    case 'SET_DARK_MODE':
      return {
        ...state,
        isDarkMode: action.payload,
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

    case 'RESET_STATE':
      return {
        ...defaultState,
        isInitialized: false,
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
  cleanupDuplicateIndustries: () => Promise<void>
  resetApplicationData: (options?: {
    includeApiCredentials?: boolean
    useAggressiveReset?: boolean
  }) => Promise<DataResetResult>
  toggleIndustry: (id: string) => void
  selectAllIndustries: () => void
  deselectAllIndustries: () => void
  selectSubCategoryIndustries: (subCategoryId: string) => void
  deselectSubCategoryIndustries: (subCategoryId: string) => void

  // Sub-category methods
  addSubCategory: (subCategory: Omit<IndustrySubCategory, 'id'>) => Promise<void>
  updateSubCategory: (subCategory: IndustrySubCategory) => Promise<void>
  removeSubCategory: (id: string) => Promise<void>
  setAllSubCategories: (subCategories: IndustrySubCategory[]) => Promise<void>
  moveIndustryToSubCategory: (industryId: string, subCategoryId: string) => Promise<void>

  // Edit state methods
  startIndustryEdit: (id: string) => void
  endIndustryEdit: (id: string) => void
  clearAllEdits: () => void

  // Theme methods
  toggleDarkMode: () => void

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
async function checkIfDefaultIndustriesNeedUpdate(
  savedIndustries: IndustryCategory[]
): Promise<boolean> {
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
    if (
      JSON.stringify(savedIndustry.keywords.sort()) !==
      JSON.stringify(defaultIndustry.keywords.sort())
    ) {
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
async function updateDefaultIndustries(
  savedIndustries: IndustryCategory[]
): Promise<IndustryCategory[]> {
  // Separate custom industries from default ones, but exclude duplicates of default industries
  const defaultIndustryNames = new Set(DEFAULT_INDUSTRIES.map(ind => ind.name.toLowerCase()))
  const customIndustries = savedIndustries.filter(
    industry => industry.isCustom && !defaultIndustryNames.has(industry.name.toLowerCase())
  )

  // Log any duplicate custom industries that are being removed
  const duplicateCustoms = savedIndustries.filter(
    industry => industry.isCustom && defaultIndustryNames.has(industry.name.toLowerCase())
  )

  if (duplicateCustoms.length > 0) {
    logger.info(
      'ConfigProvider',
      `Removing ${duplicateCustoms.length} duplicate custom industries: ${duplicateCustoms.map(i => i.name).join(', ')}`
    )
  }

  // Combine updated default industries with existing custom industries
  const updatedIndustries = [...DEFAULT_INDUSTRIES, ...customIndustries]

  // Clear all industries and save the updated set
  await storage.clearIndustries()
  for (const industry of updatedIndustries) {
    await storage.saveIndustry(industry)
  }

  logger.info(
    'ConfigProvider',
    `Updated industries: ${DEFAULT_INDUSTRIES.length} default + ${customIndustries.length} custom`
  )
  return updatedIndustries
}

/**
 * Configuration provider component
 * Manages global application configuration and state
 */
export function ConfigProvider({ children }: ConfigProviderProps) {
  const [state, dispatch] = useReducer(configReducer, defaultState)

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
   * Initialize the configuration on mount
   */
  useEffect(() => {
    const initialize = async () => {
      try {
        dispatch({ type: 'SET_LOADING', payload: true })

        // Check if we're in browser environment
        const isBrowser = typeof window !== 'undefined'

        if (isBrowser) {
          try {
            // Initialize storage only in browser with timeout
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

            // Load sub-categories
            const savedSubCategories = await storage.getAllSubCategories()
            if (savedSubCategories.length > 0) {
              dispatch({ type: 'SET_SUB_CATEGORIES', payload: savedSubCategories })
            } else {
              // Save default sub-categories to storage
              for (const subCategory of DEFAULT_SUB_CATEGORIES) {
                await storage.saveSubCategory(subCategory)
              }
              dispatch({ type: 'SET_SUB_CATEGORIES', payload: DEFAULT_SUB_CATEGORIES })
              logger.info('ConfigProvider', 'Default sub-categories saved to storage')
            }

            // Load theme preference
            const savedTheme = localStorage.getItem('darkMode')
            if (savedTheme) {
              const isDark = JSON.parse(savedTheme)
              dispatch({ type: 'SET_DARK_MODE', payload: isDark })
              document.documentElement.classList.toggle('dark', isDark)
            }

            // Clear any persisted demo mode from localStorage
            localStorage.removeItem('demoMode')
            logger.info('ConfigProvider', 'Real scraping mode enabled')
          } catch (storageError) {
            // Storage initialization failed, use default industries and sub-categories
            logger.warn(
              'ConfigProvider',
              'Storage initialization failed, using defaults',
              storageError
            )
            dispatch({ type: 'SET_INDUSTRIES', payload: DEFAULT_INDUSTRIES })
            dispatch({ type: 'SET_SUB_CATEGORIES', payload: DEFAULT_SUB_CATEGORIES })
            toast.warn('Storage unavailable - using default settings')
          }
        } else {
          // Server-side initialization - use default industries and sub-categories
          dispatch({ type: 'SET_INDUSTRIES', payload: DEFAULT_INDUSTRIES })
          dispatch({ type: 'SET_SUB_CATEGORIES', payload: DEFAULT_SUB_CATEGORIES })
          logger.info(
            'ConfigProvider',
            'Server-side initialization with default industries and sub-categories'
          )
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
   * Clean up duplicate custom industries
   * Removes custom industries that have the same name as default industries
   */
  const cleanupDuplicateIndustries = async () => {
    try {
      const savedIndustries = await storage.getAllIndustries()
      const defaultIndustryNames = new Set(DEFAULT_INDUSTRIES.map(ind => ind.name.toLowerCase()))

      // Find duplicate custom industries
      const duplicateCustoms = savedIndustries.filter(
        industry => industry.isCustom && defaultIndustryNames.has(industry.name.toLowerCase())
      )

      if (duplicateCustoms.length === 0) {
        toast.info('No duplicate industries found')
        return
      }

      // Remove duplicate custom industries
      for (const duplicate of duplicateCustoms) {
        await storage.deleteIndustry(duplicate.id)
        logger.info('ConfigProvider', `Removed duplicate custom industry: ${duplicate.name}`)
      }

      // Refresh the industry list
      const updatedIndustries = await storage.getAllIndustries()
      dispatch({ type: 'SET_INDUSTRIES', payload: updatedIndustries })

      toast.success(`Removed ${duplicateCustoms.length} duplicate custom industries`)
      logger.info(
        'ConfigProvider',
        `Cleaned up ${duplicateCustoms.length} duplicate custom industries`
      )
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to cleanup duplicate industries', error)
      toast.error('Failed to cleanup duplicate industries')
    }
  }

  /**
   * Reset all application data (complete data purge)
   * This will clear all user data and reset the application to a fresh state
   */
  const resetApplicationData = async (
    options: {
      includeApiCredentials?: boolean
      useAggressiveReset?: boolean
    } = {}
  ): Promise<DataResetResult> => {
    try {
      logger.info('ConfigProvider', 'Starting application data reset')

      // Get data statistics for logging
      const stats = await DataResetService.getDataStatistics()
      logger.info(
        'ConfigProvider',
        `Data before reset: ${stats.businesses} businesses, ${stats.configs} configs, ${stats.industries} industries, ${stats.sessions} sessions, ${stats.localStorageItems} localStorage items`
      )

      // Perform the reset
      const result = await DataResetService.resetAllData({
        includeApiCredentials: options.includeApiCredentials ?? true,
        includeLocalStorage: true,
        useAggressiveReset: options.useAggressiveReset ?? false,
        confirmationRequired: false, // Confirmation handled by UI
      })

      if (result.success) {
        // Reset the application state to initial values
        dispatch({ type: 'RESET_STATE' })

        // Reinitialize with default industries
        const updatedIndustries = await updateDefaultIndustries([])
        dispatch({ type: 'SET_INDUSTRIES', payload: updatedIndustries })

        toast.success(
          `Application reset successfully! Cleared ${result.clearedStores.length} data stores and ${result.clearedLocalStorage.length} localStorage items`
        )
        logger.info('ConfigProvider', `Application reset completed successfully`)

        // Optionally reload the page for a complete fresh start
        setTimeout(() => {
          window.location.reload()
        }, 2000)
      } else {
        const errorMessage = result.errors.length > 0 ? result.errors[0] : 'Unknown error'
        toast.error(`Reset partially failed: ${errorMessage}`)
        logger.error('ConfigProvider', `Application reset failed`, result.errors)
      }

      return result
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      toast.error(`Reset failed: ${errorMessage}`)
      logger.error('ConfigProvider', 'Failed to reset application data', error)

      return {
        success: false,
        clearedStores: [],
        clearedLocalStorage: [],
        errors: [errorMessage],
        fallbackUsed: false,
      }
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
   * Select all industries in a sub-category
   */
  const selectSubCategoryIndustries = (subCategoryId: string) => {
    dispatch({ type: 'SELECT_SUB_CATEGORY_INDUSTRIES', payload: subCategoryId })
  }

  /**
   * Deselect all industries in a sub-category
   */
  const deselectSubCategoryIndustries = (subCategoryId: string) => {
    dispatch({ type: 'DESELECT_SUB_CATEGORY_INDUSTRIES', payload: subCategoryId })
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
   * Get selected industry names
   */
  const getSelectedIndustryNames = (): string[] => {
    return state.selectedIndustries
      .map(id => state.industries.find(industry => industry.id === id))
      .filter((industry): industry is Industry => Boolean(industry))
      .map(industry => industry.name)
  }

  /**
   * Check if configuration is valid
   */
  const isConfigValid = (): boolean => {
    try {
      // Check basic requirements
      if (state.selectedIndustries.length === 0) {
        return false
      }

      if (
        state.config.searchRadius <= 0 ||
        state.config.searchDepth <= 0 ||
        state.config.pagesPerSite <= 0
      ) {
        return false
      }

      // Validate ZIP code using address input handler
      const zipCodeInput = state.config.zipCode.trim()
      if (zipCodeInput.length === 0) {
        return false
      }

      // Try to parse and extract ZIP code
      const parseResult = AddressInputHandler.parseAddressInput(zipCodeInput)
      return parseResult.zipCode !== null && !parseResult.error
    } catch (error) {
      logger.warn('ConfigContext', 'Error validating configuration', error)
      return false
    }
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

  /**
   * Add custom sub-category
   */
  const addSubCategory = async (subCategoryData: Omit<IndustrySubCategory, 'id'>) => {
    try {
      const subCategory: IndustrySubCategory = {
        ...subCategoryData,
        id: `subcategory-${Date.now()}`,
      }

      await storage.saveSubCategory(subCategory)
      dispatch({ type: 'ADD_SUB_CATEGORY', payload: subCategory })
      toast.success(`Added sub-category: ${subCategory.name}`)
      logger.info('ConfigProvider', 'Sub-category added', subCategory)
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to add sub-category', error)
      toast.error('Failed to add sub-category')
    }
  }

  /**
   * Update existing sub-category
   */
  const updateSubCategory = async (subCategory: IndustrySubCategory) => {
    try {
      await storage.saveSubCategory(subCategory)
      dispatch({ type: 'UPDATE_SUB_CATEGORY', payload: subCategory })
      toast.success(`Updated sub-category: ${subCategory.name}`)
      logger.info('ConfigProvider', 'Sub-category updated', subCategory)
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to update sub-category', error)
      toast.error('Failed to update sub-category')
    }
  }

  /**
   * Remove sub-category
   */
  const removeSubCategory = async (id: string) => {
    try {
      await storage.deleteSubCategory(id)
      dispatch({ type: 'REMOVE_SUB_CATEGORY', payload: id })
      toast.success('Sub-category removed')
      logger.info('ConfigProvider', 'Sub-category removed', { id })
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to remove sub-category', error)
      toast.error('Failed to remove sub-category')
    }
  }

  /**
   * Set all sub-categories (overwrites current sub-categories)
   */
  const setAllSubCategories = async (subCategories: IndustrySubCategory[]) => {
    try {
      // Clear existing sub-categories from storage
      await storage.clearSubCategories()

      // Save all new sub-categories
      for (const subCategory of subCategories) {
        await storage.saveSubCategory(subCategory)
      }

      dispatch({ type: 'SET_SUB_CATEGORIES', payload: subCategories })
      logger.info('ConfigProvider', `Set ${subCategories.length} sub-categories`)
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to set sub-categories', error)
      toast.error('Failed to update sub-categories')
    }
  }

  /**
   * Move industry to a different sub-category
   */
  const moveIndustryToSubCategory = async (industryId: string, subCategoryId: string) => {
    try {
      const industry = state.industries.find(i => i.id === industryId)
      if (!industry) {
        throw new Error(`Industry not found: ${industryId}`)
      }

      const updatedIndustry: IndustryCategory = {
        ...industry,
        subCategoryId,
      }

      await storage.saveIndustry(updatedIndustry)
      dispatch({ type: 'UPDATE_INDUSTRY', payload: updatedIndustry })
      logger.info('ConfigProvider', 'Industry moved to sub-category', { industryId, subCategoryId })
    } catch (error) {
      logger.error('ConfigProvider', 'Failed to move industry to sub-category', error)
      toast.error('Failed to move industry')
    }
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
    cleanupDuplicateIndustries,
    resetApplicationData,
    toggleIndustry,
    selectAllIndustries,
    deselectAllIndustries,
    selectSubCategoryIndustries,
    deselectSubCategoryIndustries,
    addSubCategory,
    updateSubCategory,
    removeSubCategory,
    setAllSubCategories,
    moveIndustryToSubCategory,
    startIndustryEdit,
    endIndustryEdit,
    clearAllEdits,
    toggleDarkMode,
    getSelectedIndustryNames,
    isConfigValid,
  }

  return <ConfigContext.Provider value={contextValue}>{children}</ConfigContext.Provider>
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
