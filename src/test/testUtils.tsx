/**
 * Test utilities for React component testing
 * Provides properly configured providers and mocks for testing
 */

import React from 'react'
import { render, RenderOptions, act } from '@testing-library/react'
import { ConfigProvider } from '@/controller/ConfigContext'
import { createContextMock, asMockedFunction } from '@/__tests__/utils/mockTypeHelpers'
import type { ConfigContextType } from '@/controller/ConfigContext'
import type { ScrapingState } from '@/controller/useScraperController'

// Mock storage with proper initialization
export const mockStorage = {
  initialize: jest.fn().mockResolvedValue(undefined),
  getConfig: jest.fn().mockResolvedValue({
    id: 'default',
    industries: [],
    zipCode: '90210',
    searchRadius: 25,
    searchDepth: 2,
    pagesPerSite: 5,
  }),
  saveConfig: jest.fn().mockResolvedValue(undefined),
  getAllIndustries: jest.fn().mockResolvedValue([
    {
      id: 'law-firms',
      name: 'Law Firms & Legal Services',
      keywords: ['law firm near me', 'corporate law office'],
      isCustom: false,
    },
  ]),
  saveIndustries: jest.fn().mockResolvedValue(undefined),
  getAllSubCategories: jest.fn().mockResolvedValue([]),
  saveSubCategory: jest.fn().mockResolvedValue(undefined),
  getAllBusinesses: jest.fn().mockResolvedValue([]),
  saveBusiness: jest.fn().mockResolvedValue(undefined),
  deleteBusiness: jest.fn().mockResolvedValue(undefined),
  clearAllBusinesses: jest.fn().mockResolvedValue(undefined),
}

// Mock scraper controller with proper typing
const mockScrapingState: ScrapingState = {
  isScrapingActive: false,
  currentUrl: '',
  progress: { current: 0, total: 0, percentage: 0 },
  results: [],
  stats: null,
  errors: [],
  processingSteps: [],
  sessionId: 'test-session',
  isStreamingEnabled: true,
  canStopEarly: false,
  hasCompletedScraping: false,
}

export const mockScraperController = {
  scrapingState: mockScrapingState,
  startScraping: asMockedFunction<() => Promise<void>>(jest.fn()),
  stopScraping: asMockedFunction<() => void>(jest.fn()),
  stopEarly: asMockedFunction<() => void>(jest.fn()),
  clearResults: asMockedFunction<() => void>(jest.fn()),
  removeBusiness: asMockedFunction<(id: string) => void>(jest.fn()),
  updateBusiness: asMockedFunction<(id: string, updates: any) => void>(jest.fn()),
  loadPreviousResults: asMockedFunction<() => Promise<void>>(jest.fn()),
  addProcessingStep: asMockedFunction<(step: any) => void>(jest.fn()),
  updateProcessingStep: asMockedFunction<(id: string, updates: any) => void>(jest.fn()),
  clearProcessingSteps: asMockedFunction<() => void>(jest.fn()),
  canStartScraping: true,
  hasResults: false,
  hasErrors: false,
  shouldShowResults: false,
}

// Mock localStorage
export const mockLocalStorage = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}

// Setup browser environment mocks
export const setupBrowserMocks = () => {
  // Mock localStorage
  Object.defineProperty(window, 'localStorage', {
    value: mockLocalStorage,
    writable: true,
  })

  // Mock sessionStorage
  Object.defineProperty(window, 'sessionStorage', {
    value: {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn(),
    },
    writable: true,
  })

  // Mock document.documentElement.classList
  Object.defineProperty(document.documentElement, 'classList', {
    value: {
      toggle: jest.fn(),
      add: jest.fn(),
      remove: jest.fn(),
      contains: jest.fn(),
    },
    writable: true,
  })

  // Mock window.matchMedia if not already mocked
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation(query => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    })
  }

  // Mock IndexedDB for storage tests
  const mockIDBRequest = {
    result: null,
    error: null,
    onsuccess: null,
    onerror: null,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
  }

  const mockIDBDatabase = {
    createObjectStore: jest.fn(),
    deleteObjectStore: jest.fn(),
    transaction: jest.fn(() => ({
      objectStore: jest.fn(() => ({
        add: jest.fn(() => mockIDBRequest),
        put: jest.fn(() => mockIDBRequest),
        get: jest.fn(() => mockIDBRequest),
        getAll: jest.fn(() => mockIDBRequest),
        delete: jest.fn(() => mockIDBRequest),
        clear: jest.fn(() => mockIDBRequest),
        createIndex: jest.fn(),
        deleteIndex: jest.fn(),
      })),
      oncomplete: null,
      onerror: null,
      onabort: null,
    })),
    close: jest.fn(),
  }

  if (!global.indexedDB) {
    global.indexedDB = {
      open: jest.fn(() => ({
        ...mockIDBRequest,
        result: mockIDBDatabase,
        onupgradeneeded: null,
      })),
      deleteDatabase: jest.fn(() => mockIDBRequest),
      databases: jest.fn(() => Promise.resolve([])),
    }
  }

  // NextRequest and NextResponse are now globally mocked in jest.setup.js
  // No need for conditional mocking here as the global mocks are comprehensive

  // Mock fetch with better error handling
  if (!global.fetch) {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
        blob: () => Promise.resolve(new Blob()),
      })
    )
  }

  // Mock ResizeObserver
  if (!global.ResizeObserver) {
    global.ResizeObserver = jest.fn().mockImplementation(() => ({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn(),
    }))
  }

  // Mock IntersectionObserver
  if (!global.IntersectionObserver) {
    global.IntersectionObserver = jest.fn().mockImplementation(() => ({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn(),
    }))
  }

  // Mock URL methods
  if (!global.URL.createObjectURL) {
    global.URL.createObjectURL = jest.fn(() => 'mocked-url')
    global.URL.revokeObjectURL = jest.fn()
  }

  // Mock crypto API
  if (!global.crypto) {
    Object.defineProperty(global, 'crypto', {
      value: {
        randomUUID: jest.fn(() => 'mocked-uuid'),
        getRandomValues: jest.fn(arr => {
          for (let i = 0; i < arr.length; i++) {
            arr[i] = Math.floor(Math.random() * 256)
          }
          return arr
        }),
      },
    })
  }

  // Mock performance API
  if (!window.performance) {
    Object.defineProperty(window, 'performance', {
      value: {
        now: jest.fn(() => Date.now()),
        mark: jest.fn(),
        measure: jest.fn(),
        getEntriesByType: jest.fn(() => []),
        getEntriesByName: jest.fn(() => []),
      },
    })
  }

  // Mock requestAnimationFrame
  if (!global.requestAnimationFrame) {
    global.requestAnimationFrame = jest.fn(cb => setTimeout(cb, 0))
    global.cancelAnimationFrame = jest.fn(id => clearTimeout(id))
  }
}

// Mock config state for testing
export const mockConfigState = {
  // Configuration object - this is what the App component expects
  config: {
    zipCode: '90210',
    searchRadius: 25,
    searchDepth: 2,
    pagesPerSite: 5,
  },

  // Industries
  industries: [
    {
      id: 'law-firms',
      name: 'Law Firms & Legal Services',
      keywords: ['law firm near me', 'corporate law office'],
      isCustom: false,
    },
  ],
  selectedIndustries: [],
  subCategories: [],

  // UI state
  isDarkMode: false,
  isLoading: false,

  // Application state - IMPORTANT: Set to true so App doesn't show loading screen
  isInitialized: true,

  // Edit state tracking
  industriesInEditMode: [],
}

export const mockConfigContext: ConfigContextType = createContextMock<ConfigContextType>({
  state: mockConfigState,
  dispatch: asMockedFunction(jest.fn()),
  updateConfig: asMockedFunction(jest.fn()),
  resetConfig: asMockedFunction(jest.fn()),
  saveConfig: asMockedFunction(jest.fn()),
  loadConfig: asMockedFunction(jest.fn()),
  addCustomIndustry: asMockedFunction(jest.fn()),
  updateIndustry: asMockedFunction(jest.fn()),
  removeIndustry: asMockedFunction(jest.fn()),
  setAllIndustries: asMockedFunction(jest.fn()),
  refreshDefaultIndustries: asMockedFunction(jest.fn()),
  cleanupDuplicateIndustries: asMockedFunction(jest.fn()),
  resetApplicationData: asMockedFunction(jest.fn()),
  toggleIndustry: asMockedFunction(jest.fn()),
  selectAllIndustries: asMockedFunction(jest.fn()),
  deselectAllIndustries: asMockedFunction(jest.fn()),
  selectSubCategoryIndustries: asMockedFunction(jest.fn()),
  deselectSubCategoryIndustries: asMockedFunction(jest.fn()),
  addSubCategory: asMockedFunction(jest.fn()),
  updateSubCategory: asMockedFunction(jest.fn()),
  removeSubCategory: asMockedFunction(jest.fn()),
  setAllSubCategories: asMockedFunction(jest.fn()),
  moveIndustryToSubCategory: asMockedFunction(jest.fn()),
  startIndustryEdit: asMockedFunction(jest.fn()),
  endIndustryEdit: asMockedFunction(jest.fn()),
  clearAllEdits: asMockedFunction(jest.fn()),
  toggleDarkMode: asMockedFunction(jest.fn()),
  getSelectedIndustryNames: asMockedFunction(jest.fn().mockReturnValue([])),
  isConfigValid: asMockedFunction(jest.fn().mockReturnValue(true)),
})

// Custom render function that includes providers
interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialConfigState?: Partial<any>
}

export const renderWithProviders = (ui: React.ReactElement, options: CustomRenderOptions = {}) => {
  const { initialConfigState, ...renderOptions } = options

  // Setup browser mocks
  setupBrowserMocks()

  const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
    return <ConfigProvider>{children}</ConfigProvider>
  }

  return render(ui, { wrapper: AllTheProviders, ...renderOptions })
}

// Wait for ConfigProvider to initialize
export const waitForConfigInitialization = async () => {
  // Since we're using MockConfigProvider, initialization should be immediate
  // Just give a small delay for React to render
  await act(async () => {
    await new Promise(resolve => setTimeout(resolve, 50))
  })
}

// Reset all mocks
export const resetAllMocks = () => {
  jest.clearAllMocks()
  Object.values(mockStorage).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockClear()
    }
  })
  Object.values(mockLocalStorage).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockClear()
    }
  })
}

// Export everything from testing-library
export * from '@testing-library/react'
export { renderWithProviders as render }
